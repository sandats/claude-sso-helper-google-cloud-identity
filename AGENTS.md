# Repository Guidelines

## Project Structure & Module Organization

- `cmd/google-claude-auth/` and `cmd/google-claude-verify-gateway/` are thin entry points for the two commands.
- `internal/auth/` implements configuration, ID-token verification, the OAuth login flow, token storage and the CLI. `fs_unix.go` and `fs_windows.go` hold the platform-specific file handling. `internal/probe/` provides the optional gateway probe.
- Tests live next to the code as `*_test.go`; `examples/` holds Claude Code JSON and Kong YAML configuration samples.
- `docs/` contains English and Japanese setup guides. Keep both consistent.
- `ci/` contains the build and release scripts. `.gitlab-ci.yml` tests merge requests and publishes a release from the default branch; `.github/workflows/ci.yml` runs the checks on GitHub.

## Build, Test, and Development Commands

Use Go 1.24+ on macOS, Linux or Windows, from the repository root:

```bash
test -z "$(gofmt -l .)"                # Check formatting
go vet ./...                           # Static checks
go test -count=1 ./...                 # Offline tests
go build -trimpath -o bin/ ./cmd/...   # Build both commands into bin/
bin/google-claude-auth --help          # Inspect the CLI
ci/build.sh                            # Cross-compile release binaries into dist/
```

Use `gofmt -w .` to apply formatting.

## Coding Style & Naming Conventions

Follow standard Go style as formatted by gofmt. Use only the standard library unless a dependency is clearly justified. Keep the module compatible with the Go version in `go.mod`. YAML and JSON use two spaces; follow `.editorconfig` for UTF-8 and LF endings. Write each Markdown prose paragraph on one source line; use editor soft wrapping.

## Testing Guidelines

Name test files `*_test.go` and test functions `Test*`. Add regression tests for authentication, refresh, credential output and storage changes. No numerical coverage threshold is configured.

Tests generate RSA keys and replace Google's endpoints with local `httptest` servers. The callback test requires local `127.0.0.1` socket access. Live gateway probes consume model usage and are separate from offline tests.

## Commit & Pull Request Guidelines

Use short imperative subjects, such as `Fix refresh token rotation`. Keep changes focused. Pull or merge requests should explain the problem, resulting behavior and validation, link relevant issues, and update affected guides/examples. Run the checks above before submitting.

## Security & Configuration

Keep OAuth client JSON and token caches outside the checkout. Never commit credentials, real identity claims or private gateway URLs; use synthetic examples. Preserve credential-only stdout for `token` and send diagnostics to stderr. Follow [SECURITY.md](SECURITY.md) for vulnerability reporting and gateway trust boundaries.
