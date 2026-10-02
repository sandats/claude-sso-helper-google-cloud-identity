# Contributing

Bug reports and pull requests are welcome. For authentication vulnerabilities, follow [SECURITY.md](SECURITY.md).

## Development

Use Go 1.24 or later on macOS, Linux or Windows, from the repository root:

```bash
test -z "$(gofmt -l .)"
go vet ./...
go test -count=1 ./...
go build -trimpath -o bin/ ./cmd/...
```

Tests generate their own RSA key and replace Google's endpoints with local HTTP servers. The browser-flow test opens a temporary HTTP listener on `127.0.0.1`; it requires permission to bind and connect to loopback. No Google login or model usage is needed. GitLab CI runs the checks on Linux and cross-compiles every platform; GitHub Actions runs them natively on Linux, macOS and Windows.

The module has no third-party dependencies; keep it that way unless a dependency is clearly justified. Shared logic lives in `internal/auth`, the gateway probe in `internal/probe`, and the two commands under `cmd/`. Platform-specific file handling is isolated in `fs_unix.go` and `fs_windows.go`; change both together. Tests live next to the code in `*_test.go` files.

Shared editor settings are provided for VS Code (`.vscode/`) and GoLand / IntelliJ IDEA with the Go plugin (run configurations in `.run/`); both follow `.editorconfig`. The debug configurations read the `GOOGLE_CLAUDE_*` variables from an untracked `.env` file in the repository root.

Use `gofmt -w .` to format Go. `ci/build.sh` cross-compiles the release binaries into `dist/`, and `ci/gitlab-release.sh` publishes a GitLab release from the default branch; see the README's Releases section.

Write each Markdown prose paragraph on one source line and let the editor soft-wrap it. Keep headings, list items, table rows and fenced code on their own lines. Do not manually wrap prose to a fixed column width.

Keep changes focused. Include a regression test for changes to signature or claim validation, refresh behavior, credential output, or local storage. Update the setup guide when changing environment variables or user-visible behavior. Keep English and Japanese instructions consistent.

Never attach client JSON, ID/refresh tokens, real user claims, personal email addresses, private gateway URLs, or internal discussion transcripts. Use `example.com` and synthetic data in examples. Report the command, sanitized error, operating system, and `google-claude-auth --version` output instead.

Contributions are provided under the repository's license. Submit only material you have permission to contribute.
