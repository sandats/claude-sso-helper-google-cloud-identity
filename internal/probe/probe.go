// Package probe sends three minimal inference probes, printing statuses only
// (never credentials). It uses the same GOOGLE_CLAUDE_* environment as
// google-claude-auth. The valid-token probe consumes a small amount of model usage.
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sandats/claude-sso-helper-google-cloud-identity/internal/auth"
)

const usage = "usage: google-claude-verify-gateway [-h] --base-url BASE_URL --model MODEL"

var client = &http.Client{
	Timeout:       60 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Main runs the gateway probe CLI and returns the process exit code.
func Main(ctx context.Context, argv []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("google-claude-verify-gateway", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	baseURL := flags.String("base-url", "", "Kong URL including route prefix, without /v1/messages")
	model := flags.String("model", "", "Existing gateway model name")
	usageError := func(message string) int {
		fmt.Fprintf(stderr, "%s\ngoogle-claude-verify-gateway: error: %s\n", usage, message)
		return 2
	}
	if err := flags.Parse(argv); errors.Is(err, flag.ErrHelp) {
		fmt.Fprintf(stdout, "%s\n\nSend three minimal inference probes, printing statuses only.\n\n", usage)
		flags.SetOutput(stdout)
		flags.PrintDefaults()
		return 0
	} else if err != nil {
		return usageError(err.Error())
	}
	if flags.NArg() > 0 {
		return usageError("unrecognized arguments: " + strings.Join(flags.Args(), " "))
	}
	if *baseURL == "" || *model == "" {
		return usageError("the following arguments are required: --base-url, --model")
	}
	parsed, err := url.Parse(*baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return usageError("--base-url must be an HTTPS URL without credentials, query, or fragment")
	}

	passed, err := probe(ctx, strings.TrimRight(*baseURL, "/")+"/v1/messages", *model, stdout)
	var authError *auth.AuthError
	switch {
	case err == nil && passed:
		return 0
	case err == nil:
		return 1
	case errors.As(err, &authError):
		fmt.Fprintf(stderr, "[probe] %s\n", authError.Msg)
	default:
		fmt.Fprintln(stderr, "[probe] Local credentials or gateway unavailable; no token or response body was logged.")
	}
	return 1
}

func probe(ctx context.Context, endpoint, model string, stdout io.Writer) (bool, error) {
	cfg, err := auth.ConfigFromEnv()
	if err != nil {
		return false, err
	}
	var token string
	if cfg.Mode == "gcloud" {
		token, err = auth.GcloudToken(ctx, cfg)
	} else {
		err = auth.WithCacheLock(ctx, cfg, auth.LockTimeout, func() (err error) {
			token, err = auth.OAuthToken(ctx, cfg)
			return err
		})
	}
	if err != nil {
		return false, err
	}
	parts := strings.Split(token, ".")
	badSignature := "A" + parts[2][1:]
	if parts[2][0] == 'A' {
		badSignature = "B" + parts[2][1:]
	}
	invalid := strings.Join([]string{parts[0], parts[1], badSignature}, ".")
	payload, err := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 8,
		"messages":   []map[string]string{{"role": "user", "content": "Reply OK."}},
	})
	if err != nil {
		return false, err
	}
	passed := true
	for _, c := range []struct{ label, credential string }{
		{"missing_token", ""},
		{"tampered_signature", invalid},
		{"valid_google_id_token", token},
	} {
		status, isMessage, err := send(ctx, endpoint, c.credential, payload)
		if err != nil {
			return false, err
		}
		ok := status == http.StatusUnauthorized || status == http.StatusForbidden
		if c.label == "valid_google_id_token" {
			ok = isMessage
		}
		fmt.Fprintf(stdout, "{\"case\": %s, \"http_status\": %d, \"passed\": %t}\n",
			auth.PyJSON(c.label), status, ok)
		passed = passed && ok
	}
	return passed, nil
}

func send(ctx context.Context, endpoint, credential string, payload []byte) (int, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, false, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("anthropic-version", "2023-06-01")
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, false, nil
	}
	var body struct {
		Type    string          `json:"type"`
		Content json.RawMessage `json:"content"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&body) != nil {
		return response.StatusCode, false, nil
	}
	isList := bytes.HasPrefix(bytes.TrimSpace(body.Content), []byte("["))
	return response.StatusCode, body.Type == "message" && isList, nil
}
