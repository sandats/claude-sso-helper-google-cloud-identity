// Offline protocol/security tests; no real Google account or gateway is contacted.
package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var testKey *rsa.PrivateKey

func TestMain(m *testing.M) {
	var err error
	if testKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

type harness struct {
	t     *testing.T
	cfg   *Config
	mu    sync.Mutex
	token http.HandlerFunc // Fake Google token endpoint.
	calls []url.Values
	login int
}

func setup(t *testing.T) *harness {
	h := &harness{t: t}
	h.cfg = &Config{
		Mode:         "oauth",
		ClientID:     "test.apps.googleusercontent.com",
		ClientSecret: "desktop-value",
		Domains:      []string{"example.com"},
		CacheDir:     filepath.Join(t.TempDir(), "cache", "client"),
		MinValidity:  360 * time.Second,
	}
	der, err := x509.MarshalPKIXPublicKey(&testKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	certs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"test-key": string(public)})
	}))
	t.Cleanup(certs.Close)
	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		h.mu.Lock()
		h.calls = append(h.calls, r.PostForm)
		handler := h.token
		h.mu.Unlock()
		if handler == nil {
			t.Errorf("unexpected token request")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(tokens.Close)

	saved := []func(){
		restore(&certsURL, certs.URL),
		restore(&tokenURL, tokens.URL),
		restore(&loadConfig, func() (*Config, error) { return h.cfg, nil }),
		restore(&authorizeFn, func(context.Context, *Config, bool, io.Writer) (Record, error) {
			h.login++
			return Record{}, authErr("unexpected login")
		}),
		restore(&openBrowser, func(string) { t.Errorf("unexpected browser launch") }),
		restore(&runGcloud, func(context.Context, ...string) (string, error) {
			t.Errorf("unexpected gcloud call")
			return "", authErr("unexpected gcloud")
		}),
		restore(&AutoLoginLockTimeout, AutoLoginLockTimeout),
	}
	t.Cleanup(func() {
		for _, undo := range saved {
			undo()
		}
	})
	return h
}

func restore[T any](target *T, value T) func() {
	old := *target
	*target = value
	return func() { *target = old }
}

func (h *harness) claims(updates map[string]any) map[string]any {
	claims := map[string]any{
		"iss":            "https://accounts.google.com",
		"aud":            h.cfg.ClientID,
		"sub":            "user-123",
		"email":          "user@example.com",
		"email_verified": true,
		"hd":             "example.com",
		"iat":            time.Now().Unix() - 5,
		"exp":            time.Now().Unix() + 3600,
	}
	for key, value := range updates {
		claims[key] = value
	}
	return claims
}

func segment(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (h *harness) jwt(updates map[string]any) string {
	signingInput := segment(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key"}) +
		"." + segment(h.claims(updates))
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, testKey, crypto.SHA256, digest[:])
	if err != nil {
		h.t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (h *harness) respond(status int, body any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = nil
	h.token = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
	}
}

func (h *harness) tokenCalls() []url.Values {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

func (h *harness) seed(modify func(*Record)) Record {
	record := Record{
		IDToken:      h.jwt(nil),
		RefreshToken: "refresh-old",
		ExpiresAt:    float64(time.Now().Unix() + 3600),
		Sub:          "user-123",
	}
	if modify != nil {
		modify(&record)
	}
	err := WithCacheLock(context.Background(), h.cfg, LockTimeout, func() error {
		return writeCache(h.cfg, record)
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return record
}

func (h *harness) cached() map[string]any {
	value, err := readCache(h.cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	return value
}

func asMap(record Record) map[string]any {
	raw, _ := json.Marshal(record)
	var value map[string]any
	json.Unmarshal(raw, &value)
	return value
}

func (h *harness) assertCache(want Record) {
	h.t.Helper()
	if got := h.cached(); !reflect.DeepEqual(got, asMap(want)) {
		h.t.Fatalf("cache = %v, want %v", got, asMap(want))
	}
}

func (h *harness) loginRecord(updates map[string]any) Record {
	claims := Claims{}
	for key, value := range h.claims(updates) {
		if n, ok := value.(int64); ok {
			value = json.Number(fmt.Sprint(n))
		}
		claims[key] = value
	}
	record, err := cacheRecord(&tokenResponse{IDToken: h.jwt(updates), RefreshToken: "refresh-new"}, claims, "")
	if err != nil {
		h.t.Fatal(err)
	}
	return record
}

func (h *harness) stubLogin(record Record, err error) {
	authorizeFn = func(context.Context, *Config, bool, io.Writer) (Record, error) {
		h.login++
		return record, err
	}
}

func runHelperCtx(ctx context.Context, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Main(ctx, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func runHelper(args ...string) (int, string, string) {
	return runHelperCtx(context.Background(), args...)
}

func TestRealSignatureValidation(t *testing.T) {
	h := setup(t)
	claims, err := VerifyToken(context.Background(), h.jwt(nil), h.cfg, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sub, _ := claims.String("sub"); sub != "user-123" {
		t.Fatalf("sub = %q", sub)
	}
}

func TestRejectInvalidIdentityClaims(t *testing.T) {
	h := setup(t)
	for _, updates := range []map[string]any{
		{"iss": "https://attacker.invalid"},
		{"aud": "other-client"},
		{"aud": []string{"test.apps.googleusercontent.com"}},
		{"exp": time.Now().Unix() - 1},
		{"iat": time.Now().Unix() + 600},
		{"hd": "other.example"},
		{"hd": nil},
		{"email_verified": false},
		{"email_verified": "true"},
		{"sub": ""},
		{"azp": "other-client"},
		{"azp": nil},
	} {
		if _, err := VerifyToken(context.Background(), h.jwt(updates), h.cfg, VerifyOptions{}); err == nil {
			t.Errorf("accepted %v", updates)
		}
	}
}

func TestRejectTamperedSignatureAndHeader(t *testing.T) {
	h := setup(t)
	parts := strings.Split(h.jwt(nil), ".")
	tampered := "A" + parts[2][1:]
	if parts[2][0] == 'A' {
		tampered = "B" + parts[2][1:]
	}
	for _, token := range []string{
		parts[0] + "." + parts[1] + "." + tampered,
		segment(map[string]string{"alg": "none", "kid": "test-key"}) + "." + parts[1] + ".",
		segment(map[string]string{"alg": "RS256", "kid": "other"}) + "." + parts[1] + "." + parts[2],
	} {
		if _, err := VerifyToken(context.Background(), token, h.cfg, VerifyOptions{}); err == nil {
			t.Errorf("accepted %q", token)
		}
	}
}

func TestRejectOpaqueAccessToken(t *testing.T) {
	h := setup(t)
	_, err := VerifyToken(context.Background(), "ya29.opaque-google-access-token", h.cfg, VerifyOptions{})
	if err == nil || !strings.Contains(err.Error(), "ID token") {
		t.Fatalf("err = %v", err)
	}
}

func TestNonceAndRefreshSubject(t *testing.T) {
	h := setup(t)
	token := h.jwt(map[string]any{"nonce": "expected"})
	for _, opts := range []VerifyOptions{{Nonce: "different"}, {Subject: "different"}} {
		if _, err := VerifyToken(context.Background(), token, h.cfg, opts); err == nil {
			t.Errorf("accepted %+v", opts)
		}
	}
	if _, err := VerifyToken(context.Background(), token, h.cfg,
		VerifyOptions{Nonce: "expected", Subject: "user-123"}); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedAccount(t *testing.T) {
	h := setup(t)
	h.cfg.Account = "someone@example.com"
	if _, err := VerifyToken(context.Background(), h.jwt(nil), h.cfg, VerifyOptions{}); err == nil {
		t.Fatal("accepted another account")
	}
}

func TestValidCacheAvoidsRefresh(t *testing.T) {
	h := setup(t)
	cached := h.seed(nil)
	token, err := OAuthToken(context.Background(), h.cfg)
	if err != nil || token != cached.IDToken {
		t.Fatalf("token = %q, err = %v", token, err)
	}
	if calls := h.tokenCalls(); len(calls) != 0 {
		t.Fatalf("refresh called: %v", calls)
	}
}

func TestRefreshPreservesRefreshTokenAndDropsAccessToken(t *testing.T) {
	h := setup(t)
	h.seed(func(r *Record) {
		r.ExpiresAt = 0
		r.IDToken = h.jwt(map[string]any{"exp": time.Now().Unix() - 1})
	})
	fresh := h.jwt(nil)
	h.respond(200, map[string]any{"id_token": fresh, "access_token": "ya29.do-not-use"})
	token, err := OAuthToken(context.Background(), h.cfg)
	if err != nil || token != fresh {
		t.Fatalf("token = %q, err = %v", token, err)
	}
	calls := h.tokenCalls()
	if len(calls) != 1 || calls[0].Get("grant_type") != "refresh_token" ||
		calls[0].Get("refresh_token") != "refresh-old" || calls[0].Get("client_secret") != "desktop-value" {
		t.Fatalf("calls = %v", calls)
	}
	cached := h.cached()
	if cached["refresh_token"] != "refresh-old" {
		t.Fatalf("refresh_token = %v", cached["refresh_token"])
	}
	if _, ok := cached["access_token"]; ok {
		t.Fatal("access token stored")
	}
}

func TestRefreshRotation(t *testing.T) {
	h := setup(t)
	h.seed(func(r *Record) { r.ExpiresAt = 0 })
	h.respond(200, map[string]any{"id_token": h.jwt(nil), "refresh_token": "rotated"})
	if _, err := OAuthToken(context.Background(), h.cfg); err != nil {
		t.Fatal(err)
	}
	if got := h.cached()["refresh_token"]; got != "rotated" {
		t.Fatalf("refresh_token = %v", got)
	}
}

func TestRefreshRejectsAccountChangeAndKeepsCache(t *testing.T) {
	h := setup(t)
	cached := h.seed(func(r *Record) { r.ExpiresAt = 0 })
	h.respond(200, map[string]any{"id_token": h.jwt(map[string]any{"sub": "user-other"})})
	if _, err := OAuthToken(context.Background(), h.cfg); err == nil {
		t.Fatal("accepted account change")
	}
	h.assertCache(cached)
}

func TestNearExpiryRefreshForHelperTTL(t *testing.T) {
	h := setup(t)
	h.seed(func(r *Record) { r.ExpiresAt = float64(time.Now().Unix() + 300) })
	h.respond(200, map[string]any{"id_token": h.jwt(nil)})
	if _, err := OAuthToken(context.Background(), h.cfg); err != nil {
		t.Fatal(err)
	}
	if calls := h.tokenCalls(); len(calls) != 1 {
		t.Fatalf("calls = %d", len(calls))
	}
}

func TestNoFallbackToAccessToken(t *testing.T) {
	h := setup(t)
	h.respond(200, map[string]any{"access_token": "opaque"})
	if _, err := tokenRequest(context.Background(), h.cfg, url.Values{}); err == nil {
		t.Fatal("accepted a response without id_token")
	}
}

func TestInvalidGrantDoesNotLogResponseSecrets(t *testing.T) {
	h := setup(t)
	h.respond(400, map[string]any{"error": "invalid_grant", "error_description": "SECRET-REFRESH-TOKEN"})
	_, err := tokenRequest(context.Background(), h.cfg, url.Values{})
	if !IsLoginRequired(err) || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v", err)
	}
}

func TestTokenRequestUsesFormBodyAndNoRedirects(t *testing.T) {
	h := setup(t)
	h.respond(200, map[string]any{"id_token": h.jwt(nil)})
	if _, err := tokenRequest(context.Background(), h.cfg, url.Values{"refresh_token": {"a+b&c"}}); err != nil {
		t.Fatal(err)
	}
	if got := h.tokenCalls()[0].Get("refresh_token"); got != "a+b&c" {
		t.Fatalf("refresh_token = %q", got)
	}
	redirected := false
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer elsewhere.Close()
	h.token = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}
	if _, err := tokenRequest(context.Background(), h.cfg, url.Values{}); err == nil || redirected {
		t.Fatalf("err = %v, redirected = %v", err, redirected)
	}
}

func TestCallbackRequiresStateAndUniqueCode(t *testing.T) {
	if code, err := callbackCode("/?code=a%2Bb&state=state", "state"); err != nil || code != "a+b" {
		t.Fatalf("code = %q, err = %v", code, err)
	}
	for _, path := range []string{
		"/?code=x",
		"/?code=x&state=wrong",
		"/?code=x&state=%E3%81%82",
		"/?code=x&code=y&state=state",
		"/?code=x&state=state&state=state",
		"/?code=&state=state",
		"/?error=access_denied&state=state",
		"/favicon.ico",
	} {
		if _, err := callbackCode(path, "state"); err == nil {
			t.Errorf("accepted %q", path)
		}
	}
}

func TestAutoLoginBrowserFlowPKCENonceLoopbackAndScopes(t *testing.T) {
	h := setup(t)
	authorizeFn = Authorize
	var mu sync.Mutex
	var captured url.Values
	callbackStatus := make(chan int, 1)
	openBrowser = func(loginURL string) {
		parsed, _ := url.Parse(loginURL)
		params := parsed.Query()
		mu.Lock()
		captured = params
		mu.Unlock()
		go func() {
			// An unrelated localhost request must not end the login.
			if response, err := http.Get(params.Get("redirect_uri") + "favicon.ico"); err == nil {
				response.Body.Close()
			}
			query := url.Values{"code": {"code+a&b"}, "state": {params.Get("state")}}
			response, err := http.Get(params.Get("redirect_uri") + "?" + query.Encode())
			if err != nil {
				callbackStatus <- 0
				return
			}
			response.Body.Close()
			callbackStatus <- response.StatusCode
		}()
	}
	h.token = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		nonce := captured.Get("nonce")
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"id_token":      h.jwt(map[string]any{"nonce": nonce}),
			"refresh_token": "new-refresh",
		})
	}
	code, stdout, stderr := runHelper("token", "--auto-login")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if status := <-callbackStatus; status != 200 {
		t.Fatalf("callback status = %d", status)
	}
	cached := h.cached()
	if stdout != cached["id_token"].(string)+"\n" {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "Open on this computer") || strings.Contains(stderr, cached["id_token"].(string)) {
		t.Fatalf("stderr = %q", stderr)
	}
	if captured.Get("scope") != "openid email" || captured.Get("access_type") != "offline" ||
		captured.Get("code_challenge_method") != "S256" || captured.Get("hd") != "example.com" {
		t.Fatalf("auth params = %v", captured)
	}
	redirect, _ := url.Parse(captured.Get("redirect_uri"))
	if redirect.Hostname() != "127.0.0.1" {
		t.Fatalf("redirect = %v", redirect)
	}
	form := h.tokenCalls()[0]
	if form.Get("code") != "code+a&b" || form.Get("grant_type") != "authorization_code" ||
		form.Get("redirect_uri") != captured.Get("redirect_uri") {
		t.Fatalf("form = %v", form)
	}
	sum := sha256.Sum256([]byte(form.Get("code_verifier")))
	if captured.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("PKCE challenge mismatch")
	}
	if cached["refresh_token"] != "new-refresh" {
		t.Fatalf("refresh_token = %v", cached["refresh_token"])
	}
}

func TestAutoLoginReusesValidCacheAndRefreshesWithoutBrowser(t *testing.T) {
	for _, expired := range []bool{false, true} {
		h := setup(t)
		cached := h.seed(func(r *Record) {
			if expired {
				r.ExpiresAt = 0
			}
		})
		h.respond(200, map[string]any{"id_token": cached.IDToken})
		code, stdout, stderr := runHelper("token", "--auto-login")
		if code != 0 || stdout != cached.IDToken+"\n" || stderr != "" {
			t.Fatalf("expired=%v: %d %q %q", expired, code, stdout, stderr)
		}
		if calls := len(h.tokenCalls()); calls != map[bool]int{false: 0, true: 1}[expired] || h.login != 0 {
			t.Fatalf("expired=%v: refresh calls %d, logins %d", expired, calls, h.login)
		}
	}
}

func TestAutoLoginReplacesIncompleteCacheAndSupportsNoBrowser(t *testing.T) {
	h := setup(t)
	h.seed(func(r *Record) { r.RefreshToken = "" })
	record := h.loginRecord(nil)
	var gotNoBrowser bool
	authorizeFn = func(_ context.Context, _ *Config, noBrowser bool, _ io.Writer) (Record, error) {
		h.login++
		gotNoBrowser = noBrowser
		return record, nil
	}
	code, stdout, _ := runHelper("--auto-login", "--no-browser")
	if code != 0 || stdout != record.IDToken+"\n" || h.login != 1 || !gotNoBrowser {
		t.Fatalf("%d %q logins=%d noBrowser=%v", code, stdout, h.login, gotNoBrowser)
	}
	h.assertCache(record)
}

func TestAutoLoginRecoversInvalidGrantOnlyWhenEnabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		h := setup(t)
		record := h.loginRecord(nil)
		cached := h.seed(func(r *Record) { r.ExpiresAt = 0 })
		h.respond(400, map[string]any{"error": "invalid_grant"})
		h.stubLogin(record, nil)
		args := []string{"token"}
		if enabled {
			args = append(args, "--auto-login")
		}
		code, stdout, _ := runHelper(args...)
		if enabled {
			if code != 0 || stdout != record.IDToken+"\n" || h.login != 1 {
				t.Fatalf("enabled: %d %q logins=%d", code, stdout, h.login)
			}
			h.assertCache(record)
		} else {
			if code != 1 || stdout != "" || h.login != 0 {
				t.Fatalf("disabled: %d %q logins=%d", code, stdout, h.login)
			}
			h.assertCache(cached)
		}
	}
}

func TestAutoLoginDoesNotHideNetworkClientOrProtocolErrors(t *testing.T) {
	cases := []struct {
		status int
		body   any
	}{
		{0, nil}, // Connection failure.
		{200, map[string]any{"access_token": "SECRET"}},
		{200, []any{}},
		{400, map[string]any{"error": "invalid_client"}},
		{401, map[string]any{"error": "unauthorized_client"}},
		{503, map[string]any{"error": "server_error"}},
	}
	for _, c := range cases {
		h := setup(t)
		cached := h.seed(func(r *Record) { r.ExpiresAt = 0 })
		if c.status == 0 {
			h.token = func(w http.ResponseWriter, _ *http.Request) {
				connection, _, _ := w.(http.Hijacker).Hijack()
				connection.Close()
			}
		} else {
			h.respond(c.status, c.body)
		}
		code, stdout, stderr := runHelper("token", "--auto-login")
		if code != 1 || stdout != "" || strings.Contains(stderr, "SECRET") || h.login != 0 {
			t.Fatalf("%v: %d %q %q logins=%d", c, code, stdout, stderr, h.login)
		}
		h.assertCache(cached)
	}
}

func TestAutoLoginDoesNotHideTokenVerificationErrors(t *testing.T) {
	for _, updates := range []map[string]any{{"aud": "wrong"}, {"hd": "wrong"}, {"sub": "user-other"}} {
		h := setup(t)
		cached := h.seed(func(r *Record) { r.IDToken = h.jwt(updates) })
		code, stdout, _ := runHelper("token", "--auto-login")
		if code != 1 || stdout != "" || h.login != 0 {
			t.Fatalf("%v: %d %q logins=%d", updates, code, stdout, h.login)
		}
		h.assertCache(cached)
	}
}

func TestAutoLoginDoesNotReplaceCorruptOrUnsafeCache(t *testing.T) {
	type corrupt struct {
		content string
		mode    os.FileMode
	}
	cases := []corrupt{{"not json", 0o600}, {"[]", 0o600}}
	if runtime.GOOS != "windows" {
		cases = append(cases, corrupt{"{}", 0o644})
	}
	for _, c := range cases {
		h := setup(t)
		h.seed(nil)
		path := cacheFile(h.cfg)
		if err := os.WriteFile(path, []byte(c.content), c.mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(path, c.mode)
		code, stdout, _ := runHelper("token", "--auto-login")
		if code != 1 || stdout != "" || h.login != 0 {
			t.Fatalf("%v: %d %q logins=%d", c, code, stdout, h.login)
		}
		if raw, _ := os.ReadFile(path); string(raw) != c.content {
			t.Fatalf("cache replaced: %q", raw)
		}
	}
}

func TestFailedAutoLoginKeepsCacheAndNeverRetriesLogin(t *testing.T) {
	for _, failure := range []error{
		authErr("Google login was denied"),
		authErr("Login timed out"),
		loginRequired("Authorization code rejected"),
		context.Canceled,
	} {
		h := setup(t)
		cached := h.seed(func(r *Record) { r.ExpiresAt = 0 })
		h.respond(400, map[string]any{"error": "invalid_grant"})
		ctx, cancel := context.WithCancel(context.Background())
		authorizeFn = func(context.Context, *Config, bool, io.Writer) (Record, error) {
			h.login++
			if failure == context.Canceled {
				cancel() // Simulates Ctrl+C during the browser login.
			}
			return Record{}, failure
		}
		code, stdout, _ := runHelperCtx(ctx, "token", "--auto-login")
		cancel()
		want := 1
		if failure == context.Canceled {
			want = 130
		}
		if code != want || stdout != "" || h.login != 1 {
			t.Fatalf("%v: %d %q logins=%d", failure, code, stdout, h.login)
		}
		h.assertCache(cached)
	}
}

func TestAutoLoginRejectsAccountChangeAndShortLivedTokens(t *testing.T) {
	for _, updates := range []map[string]any{{"sub": "user-other"}, {"exp": time.Now().Unix() + 30}} {
		h := setup(t)
		cached := h.seed(func(r *Record) { r.ExpiresAt = 0 })
		h.respond(400, map[string]any{"error": "invalid_grant"})
		h.stubLogin(h.loginRecord(updates), nil)
		code, stdout, _ := runHelper("token", "--auto-login")
		if code != 1 || stdout != "" {
			t.Fatalf("%v: %d %q", updates, code, stdout)
		}
		h.assertCache(cached)
	}
}

func TestAutoLoginWaitsForExistingLoginAndReusesItsCache(t *testing.T) {
	h := setup(t)
	record := h.loginRecord(nil)
	acquired, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- WithCacheLock(context.Background(), h.cfg, LockTimeout, func() error {
			close(acquired)
			time.Sleep(500 * time.Millisecond) // Another caller's browser interaction.
			return writeCache(h.cfg, record)
		})
	}()
	<-acquired
	code, stdout, stderr := runHelper("token", "--auto-login")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if code != 0 || stdout != record.IDToken+"\n" || h.login != 0 {
		t.Fatalf("%d %q %q logins=%d", code, stdout, stderr, h.login)
	}
}

func TestAutoLoginLockWaitIsBounded(t *testing.T) {
	h := setup(t)
	AutoLoginLockTimeout = 300 * time.Millisecond
	release, done := make(chan struct{}), make(chan error, 1)
	acquired := make(chan struct{})
	go func() {
		done <- WithCacheLock(context.Background(), h.cfg, LockTimeout, func() error {
			close(acquired)
			<-release
			return nil
		})
	}()
	<-acquired
	code, stdout, stderr := runHelper("token", "--auto-login")
	close(release)
	<-done
	if code != 1 || stdout != "" || !strings.Contains(stderr, "Another helper/login is running") {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
}

func TestAutoLoginRejectsOtherCommandsAndGcloudMode(t *testing.T) {
	h := setup(t)
	for _, command := range []string{"login", "status", "logout"} {
		if code, stdout, _ := runHelper(command, "--auto-login"); code != 2 || stdout != "" {
			t.Fatalf("%s: %d %q", command, code, stdout)
		}
	}
	h.cfg.Mode = "gcloud"
	code, stdout, stderr := runHelper("token", "--auto-login")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "requires OAuth mode") || h.login != 0 {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
}

func TestArgumentParsing(t *testing.T) {
	setup(t)
	for _, args := range [][]string{{"bogus"}, {"token", "login"}, {"--unknown"}} {
		if code, stdout, stderr := runHelper(args...); code != 2 || stdout != "" || !strings.Contains(stderr, "usage:") {
			t.Fatalf("%v: %d %q %q", args, code, stdout, stderr)
		}
	}
	if code, stdout, _ := runHelper("--help"); code != 0 || !strings.Contains(stdout, "--auto-login") {
		t.Fatalf("help: %d %q", code, stdout)
	}
}

func TestLoginLogoutAndStatus(t *testing.T) {
	h := setup(t)
	record := h.loginRecord(nil)
	h.stubLogin(record, nil)
	if code, stdout, stderr := runHelper("login"); code != 0 || stdout != "" || !strings.Contains(stderr, "Login saved") {
		t.Fatalf("login: %d %q %q", code, stdout, stderr)
	}
	h.assertCache(record)
	code, stdout, _ := runHelper("status")
	var status map[string]any
	if code != 0 || json.Unmarshal([]byte(stdout), &status) != nil || status["sub"] != "user-123" ||
		status["email"] != "user@example.com" || strings.Contains(stdout, record.IDToken) {
		t.Fatalf("status: %d %q", code, stdout)
	}
	if code, stdout, _ := runHelper("logout"); code != 0 || stdout != "" {
		t.Fatalf("logout: %d %q", code, stdout)
	}
	if len(h.cached()) != 0 {
		t.Fatal("cache not removed")
	}
}

func TestCacheFilePermissionsAndSymlinkRejection(t *testing.T) {
	h := setup(t)
	h.seed(nil)
	path := cacheFile(h.cfg)
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatalf("cache mode = %v", info.Mode())
		}
		if info, _ := os.Stat(h.cfg.CacheDir); info.Mode().Perm() != 0o700 {
			t.Fatalf("cache dir mode = %v", info.Mode())
		}
		os.Chmod(path, 0o644)
		if _, err := readCache(h.cfg); err == nil {
			t.Fatal("accepted a group/world-readable cache")
		}
	}
	os.Remove(path)
	elsewhere := filepath.Join(filepath.Dir(h.cfg.CacheDir), "elsewhere")
	os.WriteFile(elsewhere, []byte("{}"), 0o600)
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := readCache(h.cfg); err == nil {
		t.Fatal("followed a symlinked cache")
	}
}

func TestStdoutContainsOnlyIDToken(t *testing.T) {
	h := setup(t)
	cached := h.seed(nil)
	code, stdout, stderr := runHelper("token")
	if code != 0 || stdout != cached.IDToken+"\n" || stderr != "" {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
}

func TestFailureHasEmptyStdout(t *testing.T) {
	setup(t)
	code, stdout, stderr := runHelper("token")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "login first") {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
}

func TestGcloudChecksAccountAudienceAndValidity(t *testing.T) {
	h := setup(t)
	h.cfg.Account = "user@example.com"
	var gotArgs []string
	output := h.jwt(nil) + "\n"
	runGcloud = func(_ context.Context, args ...string) (string, error) {
		gotArgs = args
		return output, nil
	}
	if _, err := GcloudToken(context.Background(), h.cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(gotArgs, " "), "--account=user@example.com") {
		t.Fatalf("args = %v", gotArgs)
	}
	output = h.jwt(map[string]any{"exp": time.Now().Unix() + 30})
	if _, err := GcloudToken(context.Background(), h.cfg); err == nil {
		t.Fatal("accepted a near-expiry token")
	}
}

func clearEnv(t *testing.T, values map[string]string) {
	for _, key := range []string{
		"GOOGLE_CLAUDE_AUTH_MODE", "GOOGLE_CLAUDE_DOMAINS", "GOOGLE_CLAUDE_CLIENT_ID",
		"GOOGLE_CLAUDE_CLIENT_FILE", "GOOGLE_CLAUDE_ACCOUNT", "GOOGLE_CLAUDE_CACHE_DIR",
		"CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
	} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
}

func TestRejectWebClientAndUnsafeTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	os.WriteFile(path, []byte(`{"web": {"client_id": "test.apps.googleusercontent.com"}}`), 0o600)
	clearEnv(t, map[string]string{"GOOGLE_CLAUDE_CLIENT_FILE": path, "GOOGLE_CLAUDE_DOMAINS": "example.com"})
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("accepted a web client")
	}
	clearEnv(t, map[string]string{
		"GOOGLE_CLAUDE_AUTH_MODE":           "gcloud",
		"GOOGLE_CLAUDE_DOMAINS":             "example.com",
		"GOOGLE_CLAUDE_ACCOUNT":             "user@example.com",
		"GOOGLE_CLAUDE_CLIENT_ID":           "test.apps.googleusercontent.com",
		"CLAUDE_CODE_API_KEY_HELPER_TTL_MS": "3000000",
	})
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("accepted an unsafe TTL")
	}
}

func TestConfigFromEnvSharesPythonCacheDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	os.WriteFile(path, []byte(`{"installed": {"client_id": "test.apps.googleusercontent.com", "client_secret": "s"}}`), 0o600)
	clearEnv(t, map[string]string{
		"GOOGLE_CLAUDE_CLIENT_FILE": path,
		"GOOGLE_CLAUDE_DOMAINS":     " Example.com, example.com ,",
		"GOOGLE_CLAUDE_CACHE_DIR":   dir,
	})
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	// Reference values computed with the Python helper's cache-key expression.
	if want := filepath.Join(dir, "d2229ac2c336b75ed11a241d"); cfg.CacheDir != want {
		t.Fatalf("cache dir = %s, want %s", cfg.CacheDir, want)
	}
	if cfg.MinValidity != 360*time.Second || cfg.ClientSecret != "s" || len(cfg.Domains) != 1 {
		t.Fatalf("cfg = %+v", cfg)
	}
	key := cacheKey("gcloud", "x.apps.googleusercontent.com", []string{"a.example", "b.example"}, "ü@a.example")
	if key != "0aa280a734d06de90a3fba4b" {
		t.Fatalf("unicode cache key = %s", key)
	}
}

func TestConfigRejectsMismatchedClientAndWildcardDomains(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	os.WriteFile(path, []byte(`{"installed": {"client_id": "test.apps.googleusercontent.com", "client_secret": "s"}}`), 0o600)
	for _, env := range []map[string]string{
		{"GOOGLE_CLAUDE_CLIENT_FILE": path, "GOOGLE_CLAUDE_DOMAINS": "example.com",
			"GOOGLE_CLAUDE_CLIENT_ID": "other.apps.googleusercontent.com"},
		{"GOOGLE_CLAUDE_CLIENT_FILE": path, "GOOGLE_CLAUDE_DOMAINS": "*"},
		{"GOOGLE_CLAUDE_CLIENT_FILE": path, "GOOGLE_CLAUDE_DOMAINS": "user@example.com"},
		{"GOOGLE_CLAUDE_CLIENT_FILE": path},
		{"GOOGLE_CLAUDE_AUTH_MODE": "gcloud", "GOOGLE_CLAUDE_DOMAINS": "example.com",
			"GOOGLE_CLAUDE_CLIENT_ID": "test.apps.googleusercontent.com"},
	} {
		clearEnv(t, env)
		if _, err := ConfigFromEnv(); err == nil {
			t.Errorf("accepted %v", env)
		}
	}
}
