package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
)

// Fixed Google certificate endpoint: never trust a token-supplied jku.
var certsURL = "https://www.googleapis.com/oauth2/v1/certs"

var certsClient = &http.Client{Timeout: 20 * time.Second}

var googleIssuers = []string{"accounts.google.com", "https://accounts.google.com"}

// now is replaceable in tests.
var now = time.Now

func nowSeconds() float64 { return float64(now().UnixNano()) / 1e9 }

// Claims are the decoded, verified ID-token claims. Numbers are json.Number.
type Claims map[string]any

func (c Claims) String(key string) (string, bool) {
	s, ok := c[key].(string)
	return s, ok
}

func (c Claims) Number(key string) (float64, bool) {
	n, ok := c[key].(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
}

// Exp returns the verified expiry; VerifyToken guarantees it is numeric.
func (c Claims) Exp() float64 {
	exp, _ := c.Number("exp")
	return exp
}

// VerifyOptions add the OIDC nonce and refresh-subject checks; empty skips a check.
type VerifyOptions struct {
	Nonce   string
	Subject string
}

// VerifyToken verifies a Google ID token and the helper's identity policy.
func VerifyToken(ctx context.Context, token string, cfg *Config, opts VerifyOptions) (Claims, error) {
	if strings.Count(token, ".") != 2 || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return nil, authErr("Expected a Google ID token (JWT), not an access token.")
	}
	claims, err := verifyGoogleJWT(ctx, token, cfg.ClientID)
	if err != nil {
		return nil, authErr("Google ID-token signature/issuer/audience/expiry verification failed, or Google is unreachable.")
	}
	if hd, _ := claims.String("hd"); !slices.Contains(cfg.Domains, hd) {
		return nil, authErr("The signed hd claim is missing or outside the allowed domains.")
	}
	email, _ := claims.String("email")
	if claims["email_verified"] != true || email == "" {
		return nil, authErr("A verified Google account email is required.")
	}
	if cfg.Account != "" && strings.ToLower(email) != cfg.Account {
		return nil, authErr("The Google account differs from GOOGLE_CLAUDE_ACCOUNT.")
	}
	sub, _ := claims.String("sub")
	if sub == "" {
		return nil, authErr("Missing Google subject.")
	}
	if azp, present := claims["azp"]; present && azp != any(cfg.ClientID) {
		return nil, authErr("Unexpected authorized party (azp).")
	}
	if nonce, _ := claims.String("nonce"); opts.Nonce != "" && nonce != opts.Nonce {
		return nil, authErr("OIDC nonce mismatch.")
	}
	if opts.Subject != "" && sub != opts.Subject {
		return nil, authErr("Account changed during refresh; run login again.")
	}
	if _, ok := claims.Number("exp"); !ok {
		return nil, authErr("Missing token expiry.")
	}
	return claims, nil
}

// verifyGoogleJWT checks the RS256 signature against Google's published keys and
// the iss, aud, iat and exp claims, as google-auth's verify_oauth2_token does.
func verifyGoogleJWT(ctx context.Context, token, audience string) (Claims, error) {
	parts := strings.Split(token, ".")
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, err
	}
	if header.Alg != "RS256" || header.Kid == "" {
		return nil, errors.New("unsupported token header")
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[2], "="))
	if err != nil {
		return nil, err
	}
	keys, err := fetchGoogleKeys(ctx)
	if err != nil {
		return nil, err
	}
	key, ok := keys[header.Kid]
	if !ok {
		return nil, errors.New("unknown key id")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, err
	}
	var claims Claims
	if err := decodeSegment(parts[1], &claims); err != nil || claims == nil {
		return nil, errors.New("invalid payload")
	}
	current := float64(now().Unix())
	iat, okIat := claims.Number("iat")
	exp, okExp := claims.Number("exp")
	if !okIat || !okExp || current < iat || exp < current {
		return nil, errors.New("token not yet valid or expired")
	}
	if aud, _ := claims.String("aud"); aud != audience {
		return nil, errors.New("audience mismatch")
	}
	if iss, _ := claims.String("iss"); !slices.Contains(googleIssuers, iss) {
		return nil, errors.New("issuer mismatch")
	}
	return claims, nil
}

func decodeSegment(segment string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(segment, "="))
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(v)
}

func fetchGoogleKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, certsURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := certsClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("certificate fetch failed")
	}
	var certs map[string]string
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&certs); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(certs))
	for kid, text := range certs {
		if key, err := parseRSAPublicKey(text); err == nil {
			keys[kid] = key
		}
	}
	return keys, nil
}

func parseRSAPublicKey(text string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	var public any
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		public = cert.PublicKey
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		public = key
	default:
		return nil, errors.New("unsupported PEM block")
	}
	key, ok := public.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return key, nil
}
