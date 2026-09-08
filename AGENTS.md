# Repository Guidelines

## Project Structure & Module Organization

- `src/google_claude_auth/` contains the installable package. `auth.py` implements authentication and token storage; `verify_gateway.py` provides the optional gateway probe; `__main__.py` supports module execution.
- `tests/` contains protocol and security tests; `examples/` holds Claude Code JSON and Kong YAML configuration samples.
- `docs/` contains English and Japanese setup guides. Keep both consistent.
- `pyproject.toml` defines dependencies, CLI entry points, packaging, pytest and Ruff settings. `.github/workflows/ci.yml` runs quality checks.

## Build, Test, and Development Commands

Use Python 3.10+ on macOS or Linux, from the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'  # Editable install with development tools
.venv/bin/python -m ruff check .           # Lint
.venv/bin/python -m ruff format --check .  # Check formatting
.venv/bin/python -m pytest -v              # Offline tests
.venv/bin/python -m pip check              # Dependency compatibility
.venv/bin/python -m build                  # Build sdist and wheel in dist/
.venv/bin/google-claude-auth --help        # Inspect the installed CLI
```

Use `ruff format .` to apply formatting and review any `ruff check --fix .` changes.

## Coding Style & Naming Conventions

Use four-space Python indentation, Ruff's 100-character line length, `snake_case` functions/modules and `PascalCase` classes. Preserve Python 3.10 compatibility. YAML and JSON use two spaces; follow `.editorconfig` for UTF-8 and LF endings. Write each Markdown prose paragraph on one source line; use editor soft wrapping.

## Testing Guidelines

Name files `tests/test_*.py` and test methods `test_*`. Pytest collects existing `unittest.TestCase` classes and imports the installed package without path manipulation. Add regression tests for authentication, refresh, credential output and storage changes. No numerical coverage threshold is configured.

Tests generate RSA keys and mock Google responses. The callback test requires local `127.0.0.1` socket access. Live gateway probes consume model usage and are separate from offline tests.

## Commit & Pull Request Guidelines

There are no commits yet, so no historical message convention exists. Use short imperative subjects, such as `Fix refresh token rotation`. Keep changes focused. PRs should explain the problem, resulting behavior and validation, link relevant issues, and update affected guides/examples. Run the checks above before submitting.

## Security & Configuration

Keep OAuth client JSON and token caches outside the checkout. Never commit credentials, real identity claims or private gateway URLs; use synthetic examples. Preserve credential-only stdout for `token` and send diagnostics to stderr. Follow [SECURITY.md](SECURITY.md) for vulnerability reporting and gateway trust boundaries.
