// Command google-claude-auth prints a verified Google ID token for Claude Code's apiKeyHelper.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/sandats/claude-sso-helper-google-cloud-identity/internal/auth"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := auth.Main(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
