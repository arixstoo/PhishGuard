# Contributing to PhishGuard

Thanks for helping! Bug reports, detection feedback, translations, tests and code are all welcome.

## Set up

Requires Python 3.11+ and git. On Windows, work inside WSL2.

```bash
git clone https://github.com/arixstoo/PhishGuard.git && cd PhishGuard
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pre-commit install          # ruff (lint + format) and gitleaks (secret scan) on every commit
pytest --cov=phishguard     # run the test suite
```

## Workflow

1. Open or pick an issue, then create a branch: `feat/m1-url-features`, `fix/…`, `docs/…`.
2. Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`,
   `test:`, `chore:`, `ci:`.
3. Add tests for any behaviour change. Every bug fixed becomes a regression test.
4. Open a pull request against `master`; CI (ruff + pytest) must be green.

## Lab safety rules

PhishGuard handles hostile data. These rules are not optional:

- Treat phishing URLs **only as strings**. Never open them in your everyday browser. When
  you paste one in an issue or PR, defang it: `hxxps://evil[.]example/login`.
- **Never commit raw datasets** or anything containing personal data (real email addresses,
  phone numbers, message bodies). Commit the script that downloads the data, not the data.
- **Never commit API keys.** Use a local `.env` file (ignored by git, copied from
  `.env.example`). If a key leaks, revoke it immediately: deleting the commit is not enough.
  See [docs/secrets.md](docs/secrets.md).
- Never send test phishing messages to real people.

## Reporting

- Wrong verdict (false positive / false negative): use the *Detection feedback* issue template.
- Security vulnerability: see [SECURITY.md](SECURITY.md), never a public issue.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
