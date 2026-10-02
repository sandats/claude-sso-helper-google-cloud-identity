// Package auth implements the Google user ID-token helper for Claude Code -> Kong.
//
// Configure GOOGLE_CLAUDE_CLIENT_FILE (Desktop OAuth JSON) and GOOGLE_CLAUDE_DOMAINS,
// then use `token --auto-login` in apiKeyHelper, or run `login` once before using the
// noninteractive `token` command. Only `token` writes a credential to stdout.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AuthError carries safe, credential-free error text for stderr.
type AuthError struct {
	Msg string
	// LoginRequired marks a missing login or a rejected grant that browser
	// authentication can replace.
	LoginRequired bool
}

func (e *AuthError) Error() string { return e.Msg }

func authErr(msg string) error { return &AuthError{Msg: msg} }

func loginRequired(msg string) error { return &AuthError{Msg: msg, LoginRequired: true} }

// IsLoginRequired reports whether err is an AuthError that a new login can resolve.
func IsLoginRequired(err error) bool {
	var ae *AuthError
	return errors.As(err, &ae) && ae.LoginRequired
}

// Config is the validated helper configuration.
type Config struct {
	Mode         string
	ClientID     string
	ClientSecret string
	Domains      []string
	Account      string
	CacheDir     string
	MinValidity  time.Duration
}

// getenv mirrors Python's os.environ.get(key, default): a set but empty value is kept.
func getenv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// ConfigFromEnv reads and validates the GOOGLE_CLAUDE_* environment.
func ConfigFromEnv() (*Config, error) {
	mode := getenv("GOOGLE_CLAUDE_AUTH_MODE", "oauth")
	if mode != "oauth" && mode != "gcloud" {
		return nil, authErr("GOOGLE_CLAUDE_AUTH_MODE must be oauth or gcloud.")
	}
	unique := map[string]bool{}
	for _, d := range strings.Split(getenv("GOOGLE_CLAUDE_DOMAINS", ""), ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			unique[d] = true
		}
	}
	domains := make([]string, 0, len(unique))
	for d := range unique {
		if d == "*" || strings.ContainsAny(d, "/@") {
			return nil, authErr("Set GOOGLE_CLAUDE_DOMAINS to the allowed hosted domains.")
		}
		domains = append(domains, d)
	}
	if len(domains) == 0 {
		return nil, authErr("Set GOOGLE_CLAUDE_DOMAINS to the allowed hosted domains.")
	}
	sort.Strings(domains)

	clientID := getenv("GOOGLE_CLAUDE_CLIENT_ID", "")
	var secret any = ""
	if mode == "oauth" {
		filename := getenv("GOOGLE_CLAUDE_CLIENT_FILE", "")
		if filename == "" {
			return nil, authErr("Set GOOGLE_CLAUDE_CLIENT_FILE to a Desktop OAuth client JSON file.")
		}
		fileID, fileSecret, err := readClientFile(expandUser(filename))
		if err != nil {
			return nil, err
		}
		if clientID != "" && fileID != any(clientID) {
			return nil, authErr("GOOGLE_CLAUDE_CLIENT_ID differs from the client JSON.")
		}
		clientID, _ = fileID.(string) // A non-string ID fails the audience check below.
		secret = fileSecret
	}
	if !strings.HasSuffix(clientID, ".apps.googleusercontent.com") {
		return nil, authErr("Set a Google OAuth client ID as the expected audience.")
	}
	clientSecret, ok := secret.(string)
	if !ok {
		return nil, authErr("Invalid client_secret in client JSON.")
	}
	account := strings.ToLower(strings.TrimSpace(getenv("GOOGLE_CLAUDE_ACCOUNT", "")))
	if mode == "gcloud" && account == "" {
		return nil, authErr("Set GOOGLE_CLAUDE_ACCOUNT explicitly for gcloud mode.")
	}
	ttl, err := strconv.Atoi(strings.TrimSpace(getenv("CLAUDE_CODE_API_KEY_HELPER_TTL_MS", "300000")))
	if err != nil {
		return nil, authErr("CLAUDE_CODE_API_KEY_HELPER_TTL_MS must be an integer.")
	}
	if ttl < 0 || ttl > 300000 {
		return nil, authErr("Use a helper TTL between 0 and 300000 ms (at most five minutes).")
	}
	root := expandUser(getenv("GOOGLE_CLAUDE_CACHE_DIR", "~/.claude/google-sso"))
	if root == "" {
		root = "."
	}
	return &Config{
		Mode:         mode,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Domains:      domains,
		Account:      account,
		CacheDir:     filepath.Join(root, cacheKey(mode, clientID, domains, account)),
		MinValidity:  time.Duration(ttl)*time.Millisecond + 60*time.Second,
	}, nil
}

func readClientFile(filename string) (clientID, clientSecret any, err error) {
	invalid := authErr("Cannot read a valid Desktop OAuth client JSON (installed section).")
	raw, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, invalid
	}
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil {
		return nil, nil, invalid
	}
	installed, ok := data["installed"].(map[string]any)
	if !ok {
		return nil, nil, invalid
	}
	clientID, hasID := installed["client_id"]
	clientSecret, hasSecret := installed["client_secret"]
	if !hasID || !hasSecret {
		return nil, nil, invalid
	}
	return clientID, clientSecret, nil
}

// cacheKey matches the Python helper's
// sha256(json.dumps([mode, client_id, domains, account]))[:24], so both
// implementations share the same cache directory.
func cacheKey(mode, clientID string, domains []string, account string) string {
	quoted := make([]string, len(domains))
	for i, d := range domains {
		quoted[i] = pyJSON(d)
	}
	text := "[" + pyJSON(mode) + ", " + pyJSON(clientID) + ", [" + strings.Join(quoted, ", ") +
		"], " + pyJSON(account) + "]"
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])[:24]
}

// expandUser mirrors Python's Path.expanduser for "~" and "~/..." paths.
func expandUser(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") &&
		!(runtime.GOOS == "windows" && strings.HasPrefix(path, `~\`)) {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[1:])
}
