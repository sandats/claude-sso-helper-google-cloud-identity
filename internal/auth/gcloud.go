package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// runGcloud returns gcloud's stdout or a safe AuthError; replaceable in tests.
var runGcloud = func(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, "gcloud", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	var exitErr *exec.ExitError
	if err != nil && ctx.Err() == nil && errors.As(err, &exitErr) {
		return "", authErr("gcloud failed; run gcloud auth login for GOOGLE_CLAUDE_ACCOUNT.")
	}
	if err != nil {
		return "", authErr("Cannot execute gcloud; install it and run gcloud auth login first.")
	}
	return stdout.String(), nil
}

// GcloudToken obtains and verifies an ID token from the gcloud CLI.
func GcloudToken(ctx context.Context, cfg *Config) (string, error) {
	stdout, err := runGcloud(ctx, "auth", "print-identity-token", "--account="+cfg.Account, "--quiet")
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(stdout)
	claims, err := VerifyToken(ctx, token, cfg, VerifyOptions{})
	if err != nil {
		return "", err
	}
	if claims.Exp() <= nowSeconds()+cfg.MinValidity.Seconds() {
		return "", authErr("gcloud returned a near-expiry token; use TTL=0 for PoC or the dedicated OAuth mode.")
	}
	return token, nil
}

// openBrowser best-effort launches the default browser; replaceable in tests.
// Its output goes to stderr so stdout stays credential-only.
var openBrowser = func(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if cmd.Start() == nil {
		go cmd.Wait()
	}
}
