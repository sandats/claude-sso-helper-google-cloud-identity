package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Version is set at build time with -ldflags "-X .../internal/auth.Version=1.2.3".
var Version = "dev"

const usage = "usage: google-claude-auth [-h] [--version] [--auto-login] [--no-browser] [{login,token,status,logout}]"

const help = usage + `

Google user ID-token helper for Claude Code -> Kong (macOS/Linux/Windows).

Configure GOOGLE_CLAUDE_CLIENT_FILE (Desktop OAuth JSON) and GOOGLE_CLAUDE_DOMAINS,
then use "token --auto-login" in apiKeyHelper, or run "login" once before using
the noninteractive "token" command. Only "token" writes a credential to stdout.
See README.md for the gateway policy.

positional arguments:
  {login,token,status,logout}

options:
  -h, --help     show this help message and exit
  --version      show the helper version and exit
  --auto-login   with token in OAuth mode, start browser login when no login is
                 cached or refresh is revoked
  --no-browser   print login URL; still requires local loopback callback
`

// Replaceable in tests.
var (
	loadConfig  = ConfigFromEnv
	authorizeFn = Authorize
)

type cliArgs struct {
	command   string
	autoLogin bool
	noBrowser bool
	version   bool
}

func parseArgs(argv []string) (cliArgs, string, bool) {
	args := cliArgs{command: "token"}
	positional := 0
	flagsDone := false
	for _, arg := range argv {
		switch {
		case !flagsDone && arg == "--":
			flagsDone = true
		case !flagsDone && (arg == "-h" || arg == "--help"):
			return args, "", true
		case !flagsDone && arg == "--version":
			args.version = true
		case !flagsDone && arg == "--auto-login":
			args.autoLogin = true
		case !flagsDone && arg == "--no-browser":
			args.noBrowser = true
		case !flagsDone && strings.HasPrefix(arg, "-") && arg != "-":
			return args, "unrecognized arguments: " + arg, false
		default:
			positional++
			if positional > 1 {
				return args, "unrecognized arguments: " + arg, false
			}
			switch arg {
			case "login", "token", "status", "logout":
				args.command = arg
			default:
				return args, fmt.Sprintf("argument command: invalid choice: '%s' "+
					"(choose from 'login', 'token', 'status', 'logout')", arg), false
			}
		}
	}
	if args.autoLogin && args.command != "token" {
		return args, "--auto-login is only supported with token", false
	}
	return args, "", false
}

// Main runs the helper CLI and returns the process exit code.
func Main(ctx context.Context, argv []string, stdout, stderr io.Writer) int {
	args, parseError, showHelp := parseArgs(argv)
	if showHelp {
		io.WriteString(stdout, help)
		return 0
	}
	if args.version && parseError == "" {
		fmt.Fprintf(stdout, "google-claude-auth %s\n", Version)
		return 0
	}
	if parseError != "" {
		fmt.Fprintf(stderr, "%s\ngoogle-claude-auth: error: %s\n", usage, parseError)
		return 2
	}
	output, err := run(ctx, args, stderr)
	var authError *AuthError
	switch {
	case err == nil:
		io.WriteString(stdout, output)
		return 0
	case ctx.Err() != nil:
		fmt.Fprintln(stderr, "[google-auth] Cancelled.")
		return 130
	case errors.As(err, &authError):
		fmt.Fprintf(stderr, "[google-auth] %s\n", authError.Msg)
		return 1
	default:
		fmt.Fprintln(stderr, "[google-auth] Local file, browser, or callback operation failed; check permissions and retry.")
		return 1
	}
}

// run returns what to print on stdout; nothing is printed unless it succeeds.
func run(ctx context.Context, args cliArgs, stderr io.Writer) (string, error) {
	cfg, err := loadConfig()
	if err != nil {
		return "", err
	}
	var token string
	if cfg.Mode == "gcloud" {
		if args.autoLogin {
			return "", authErr("--auto-login requires OAuth mode; use gcloud auth login in gcloud mode.")
		}
		if args.command != "token" && args.command != "status" {
			return "", authErr("gcloud mode: manage login/logout with gcloud auth commands.")
		}
		if token, err = GcloudToken(ctx, cfg); err != nil {
			return "", err
		}
	} else {
		finished := false
		timeout := LockTimeout
		if args.autoLogin {
			// Allow other auto-login callers to wait for the browser callback and token exchange.
			timeout = AutoLoginLockTimeout
		}
		err = WithCacheLock(ctx, cfg, timeout, func() error {
			switch args.command {
			case "login":
				record, err := authorizeFn(ctx, cfg, args.noBrowser, stderr)
				if err != nil {
					return err
				}
				if err := writeCache(cfg, record); err != nil {
					return err
				}
				fmt.Fprintln(stderr, "[google-auth] Login saved; apiKeyHelper can now run token.")
				finished = true
				return nil
			case "logout":
				if err := removeCache(cfg); err != nil {
					return err
				}
				fmt.Fprintln(stderr, "[google-auth] Local cache removed. Google authorization was not revoked.")
				finished = true
				return nil
			}
			var err error
			token, err = OAuthToken(ctx, cfg)
			if err == nil || !IsLoginRequired(err) || !args.autoLogin {
				return err
			}
			fmt.Fprintln(stderr, "[google-auth] Login required; starting Google authentication.")
			previous, err := readCache(cfg)
			if err != nil {
				return err
			}
			record, err := authorizeFn(ctx, cfg, args.noBrowser, stderr)
			if err != nil {
				return err
			}
			if sub, _ := previous["sub"].(string); sub != "" && record.Sub != sub {
				return authErr("Account changed during automatic login; run login explicitly to switch accounts.")
			}
			if record.ExpiresAt <= nowSeconds()+cfg.MinValidity.Seconds() {
				return authErr("Login ID token expires too soon for the helper TTL.")
			}
			if err := writeCache(cfg, record); err != nil {
				return err
			}
			token = record.IDToken
			return nil
		})
		if err != nil || finished {
			return "", err
		}
	}
	if args.command == "token" {
		return token + "\n", nil
	}
	claims, err := VerifyToken(ctx, token, cfg, VerifyOptions{})
	if err != nil {
		return "", err
	}
	keys := []string{"iss", "aud", "sub", "email", "hd", "exp"}
	lines := make([]string, len(keys))
	for i, key := range keys {
		lines[i] = "  " + pyJSON(key) + ": " + pyJSON(claims[key])
	}
	return "{\n" + strings.Join(lines, ",\n") + "\n}\n", nil
}
