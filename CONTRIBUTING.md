# Contributing

Bug reports and pull requests are welcome. For authentication vulnerabilities, follow [SECURITY.md](SECURITY.md).

## Development

Use macOS or Linux with Python 3.10 or later, from the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m pytest -v
.venv/bin/python -m pip check
.venv/bin/python -m build
```

Tests generate their own RSA key and replace Google network responses. The browser-flow test opens a temporary HTTP listener on `127.0.0.1`; it requires permission to bind and connect to loopback. No Google login or model usage is needed. CI covers Python 3.10–3.14 on Linux and Python 3.14 on macOS. CI also checks Ruff lint/format results, builds a source distribution and wheel, and checks the installed CLI outside the checkout.

Project metadata, dependencies, CLI entry points, pytest options and Ruff settings live in `pyproject.toml`. Install with `-e '.[dev]'` for development so edits under `src/` are immediately available. Tests live in `tests/` and import the installed package; no `PYTHONPATH` or `sys.path` changes are needed. Existing `unittest.TestCase` tests are collected by pytest.

Use `.venv/bin/python -m ruff format .` to format Python and `.venv/bin/python -m ruff check --fix .` for available lint fixes. Review fixes before committing. Ruff covers common Python errors, unused imports, import ordering, Python syntax modernization and bug-prone patterns. It does not provide static type checking.

Write each Markdown prose paragraph on one source line and let the editor soft-wrap it. Keep headings, list items, table rows and fenced code on their own lines. Do not manually wrap prose to a fixed column width.

Keep changes focused. Include a regression test for changes to signature or claim validation, refresh behavior, credential output, or local storage. Update the setup guide when changing environment variables or user-visible behavior. Keep English and Japanese instructions consistent.

Never attach client JSON, ID/refresh tokens, real user claims, personal email addresses, private gateway URLs, or internal discussion transcripts. Use `example.com` and synthetic data in examples. Report the command, sanitized error, operating system, Python version, and dependency versions instead.

Contributions are provided under the repository's license. Submit only material you have permission to contribute.
