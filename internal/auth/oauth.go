package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	authURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenURL = "https://oauth2.googleapis.com/token"
)

// Do not follow redirects carrying client or refresh credentials.
var tokenClient = &http.Client{
	Timeout:       30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

var loginTimeout = 180 * time.Second

type tokenResponse struct {
	IDToken      string
	RefreshToken string
}

func tokenRequest(ctx context.Context, cfg *Config, fields url.Values) (*tokenResponse, error) {
	body := url.Values{"client_id": {cfg.ClientID}, "client_secret": {cfg.ClientSecret}}
	for key, values := range fields {
		body[key] = values
	}
	unavailable := authErr("Google token endpoint unavailable or returned invalid JSON; retry later.")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, unavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := tokenClient.Do(request)
	if err != nil {
		return nil, unavailable
	}
	defer response.Body.Close()
	var decoded any
	if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&decoded) != nil {
		return nil, unavailable
	}
	data, ok := decoded.(map[string]any)
	if !ok {
		return nil, authErr("Google returned an invalid token response.")
	}
	if response.StatusCode != http.StatusOK || truthy(data["error"]) {
		switch data["error"] {
		case "invalid_grant":
			return nil, loginRequired("Google requires a new login (invalid_grant); run login again.")
		case "invalid_client", "unauthorized_client":
			return nil, authErr("Google rejected the OAuth client; check the Desktop client JSON and admin policy.")
		}
		return nil, authErr(fmt.Sprintf(
			"Google token request failed (HTTP %d); check OAuth/admin configuration.", response.StatusCode))
	}
	idToken, _ := data["id_token"].(string)
	if idToken == "" {
		return nil, authErr("No id_token returned. Authorize with openid email; run login again.")
	}
	refresh, _ := data["refresh_token"].(string)
	return &tokenResponse{IDToken: idToken, RefreshToken: refresh}, nil
}

// truthy mirrors Python truthiness for decoded JSON values.
func truthy(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case float64:
		return v != 0
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	}
	return true
}

// queryParams mirrors Python's parse_qs: blank values are dropped.
func queryParams(rawQuery string) url.Values {
	parsed, _ := url.ParseQuery(rawQuery)
	params := url.Values{}
	for key, values := range parsed {
		for _, value := range values {
			if value != "" {
				params[key] = append(params[key], value)
			}
		}
	}
	return params
}

func callbackCode(path, expectedState string) (string, error) {
	parsed, err := url.Parse(path)
	if err != nil || parsed.EscapedPath() != "/" {
		return "", authErr("Unknown callback path.")
	}
	params := queryParams(parsed.RawQuery)
	states := params["state"]
	if len(states) != 1 || subtle.ConstantTimeCompare([]byte(states[0]), []byte(expectedState)) != 1 {
		return "", authErr("OAuth state mismatch.")
	}
	if len(params["error"]) > 0 {
		return "", authErr("Google login was denied; check consent and administrator policy.")
	}
	codes := params["code"]
	if len(codes) != 1 {
		return "", authErr("Missing or ambiguous authorization code.")
	}
	return codes[0], nil
}

func tokenURLSafe(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // crypto/rand never fails on supported platforms.
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type callbackOutcome struct {
	code string
	err  error
}

// Authorize runs the browser login with PKCE, state and nonce over a loopback callback.
func Authorize(ctx context.Context, cfg *Config, noBrowser bool, stderr io.Writer) (Record, error) {
	verifier := tokenURLSafe(64)
	state := tokenURLSafe(32)
	nonce := tokenURLSafe(32)
	outcomes := make(chan callbackOutcome, 1)
	record := func(outcome callbackOutcome) {
		select {
		case outcomes <- outcome:
		default: // The first decisive callback wins.
		}
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, body := http.StatusBadRequest, "Login callback rejected. Return to your terminal."
		var outcome *callbackOutcome
		if r.Method != http.MethodGet {
			status, body = http.StatusNotImplemented, "Unsupported method."
		} else if code, err := callbackCode(r.RequestURI, state); err != nil {
			// Unrelated localhost requests must not terminate the real login.
			if parsed, perr := url.Parse(r.RequestURI); perr == nil {
				params := queryParams(parsed.RawQuery)
				if len(params["state"]) == 1 && params.Get("state") == state && len(params["error"]) > 0 {
					outcome = &callbackOutcome{err: err}
				}
			}
		} else {
			outcome = &callbackOutcome{code: code}
			status, body = http.StatusOK, "Login response received. Close this tab and return to your terminal."
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(status)
		io.WriteString(w, body)
		if outcome != nil {
			record(*outcome)
		}
	})

	// Bind BEFORE opening the browser; ephemeral IPv4 loopback port, no LAN listener.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Record{}, err
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		// Callback URLs contain authorization codes: never log them.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go server.Serve(listener)
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/", listener.Addr().(*net.TCPAddr).Port)

	params := url.Values{
		"client_id":             {cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"access_type":           {"offline"},
		"prompt":                {"consent select_account"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"nonce":                 {nonce},
		"hd":                    {"*"},
	}
	if len(cfg.Domains) == 1 {
		params.Set("hd", cfg.Domains[0])
	}
	if cfg.Account != "" {
		params.Set("login_hint", cfg.Account)
	}
	loginURL := authURL + "?" + params.Encode()
	fmt.Fprintln(stderr, "[google-auth] Open on this computer:\n"+loginURL)
	if !noBrowser {
		openBrowser(loginURL)
	}

	var outcome callbackOutcome
	timer := time.NewTimer(loginTimeout)
	select {
	case outcome = <-outcomes:
	case <-timer.C:
		outcome.err = authErr(fmt.Sprintf(
			"Login timed out after %d seconds; run login again.", int(loginTimeout.Seconds())))
	case <-ctx.Done():
		outcome.err = ctx.Err()
	}
	timer.Stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	server.Shutdown(shutdownCtx) // Lets the browser receive the final response.
	cancel()
	if outcome.err != nil {
		return Record{}, outcome.err
	}

	data, err := tokenRequest(ctx, cfg, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {outcome.code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	if err != nil {
		return Record{}, err
	}
	claims, err := VerifyToken(ctx, data.IDToken, cfg, VerifyOptions{Nonce: nonce})
	if err != nil {
		return Record{}, err
	}
	if data.RefreshToken == "" {
		return Record{}, authErr("Google did not return a refresh token; check offline consent and run login again.")
	}
	return cacheRecord(data, claims, "")
}

func cacheRecord(data *tokenResponse, claims Claims, previousRefresh string) (Record, error) {
	refresh := data.RefreshToken
	if refresh == "" {
		refresh = previousRefresh
	}
	if refresh == "" {
		return Record{}, authErr("No refresh token available; run login again.")
	}
	sub, _ := claims.String("sub")
	return Record{IDToken: data.IDToken, RefreshToken: refresh, Sub: sub, ExpiresAt: claims.Exp()}, nil
}

// OAuthToken returns a verified cached ID token, refreshing it when it is near expiry.
// The caller must hold the cache lock.
func OAuthToken(ctx context.Context, cfg *Config) (string, error) {
	cached, err := readCache(cfg)
	if err != nil {
		return "", err
	}
	idToken, _ := cached["id_token"].(string)
	refreshToken, _ := cached["refresh_token"].(string)
	sub, _ := cached["sub"].(string)
	if idToken == "" || refreshToken == "" || sub == "" {
		return "", loginRequired("No complete login cached; run login first.")
	}
	// Cached expiry is only a refresh hint. Never output a token without verification.
	if expiry, ok := cached["expires_at"].(float64); ok && expiry > nowSeconds()+cfg.MinValidity.Seconds() {
		claims, err := VerifyToken(ctx, idToken, cfg, VerifyOptions{Subject: sub})
		if err != nil {
			return "", err
		}
		if claims.Exp() > nowSeconds()+cfg.MinValidity.Seconds() {
			return idToken, nil
		}
	}
	data, err := tokenRequest(ctx, cfg, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
	if err != nil {
		return "", err
	}
	claims, err := VerifyToken(ctx, data.IDToken, cfg, VerifyOptions{Subject: sub})
	if err != nil {
		return "", err
	}
	if claims.Exp() <= nowSeconds()+cfg.MinValidity.Seconds() {
		return "", authErr("Refreshed ID token expires too soon for the helper TTL.")
	}
	record, err := cacheRecord(data, claims, refreshToken)
	if err != nil {
		return "", err
	}
	if err := writeCache(cfg, record); err != nil {
		return "", err
	}
	return data.IDToken, nil
}
