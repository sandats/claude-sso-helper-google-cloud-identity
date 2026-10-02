// Command google-claude-verify-gateway probes a Kong gateway's ID-token enforcement.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/sandats/claude-sso-helper-google-cloud-identity/internal/probe"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := probe.Main(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
