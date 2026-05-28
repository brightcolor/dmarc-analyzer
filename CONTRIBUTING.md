# Contributing

Thank you for considering contributing to DMARC Analyzer!

## Development setup

```bash
git clone https://github.com/yourorg/dmarc-analyzer.git
cd dmarc-analyzer
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
make dev
cp .env.example .env          # edit with your local settings
make upgrade                  # apply migrations
make run                      # start the dev server
```

## Running tests

```bash
make test         # run the test suite
make cov          # run with coverage report
make lint         # ruff linter
```

All tests use an in-memory SQLite database — no external services required.

## Submitting changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Write tests for new behaviour
4. Ensure `make test` and `make lint` pass
5. Open a pull request against `main`; fill in the PR template

## Security constraints (non-negotiable)

- Every new DB query **must** filter by `organization_id` to preserve tenant isolation
- No new code may process XML using the stdlib `xml.etree` — always use `defusedxml`
- No code may accept a RCPT silently and discard later — reject at `RCPT TO` time
- Secrets must never be committed; check `.gitignore` before pushing

## Code style

- Python 3.11+, type hints where practical
- Line length ≤ 100 characters (`ruff` enforced)
- No comments that explain *what* — only *why* (non-obvious constraints, workarounds)
- No docstrings longer than one line
