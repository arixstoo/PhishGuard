# Contributing to PhishGuard

Thanks for helping! Bug reports, detection feedback, translations, tests, docs and code
are all welcome. This guide is meant to answer every question you would otherwise have
to ask. If it does not, that is a bug in this guide: open an issue.

Most project documents are in French; code comments are in French too. Issues and pull
requests are welcome in **French or English**.

## Where to start

- Issues labelled [**good first issue**](https://github.com/arixstoo/PhishGuard/labels/good%20first%20issue)
  are fully described: context, files, commands to run, and when it is done. No prior
  knowledge of the project is needed.
- [**help wanted**](https://github.com/arixstoo/PhishGuard/labels/help%20wanted): an
  outside contribution is especially useful (translation, accessibility testing…).
- Comment "I'm on it" on an issue before starting, so two people do not do the same work.
  An issue with no news for 14 days is free again.

| Label | Meaning |
| --- | --- |
| `bug`, `enhancement`, `documentation`, `tests`, `ci`, `translation`, `accessibility` | kind of work |
| `area:extension`, `area:api`, `area:detection` | part of the code |
| `needs-retraining` | changes the model's reference data (see [below](#changes-that-need-retraining)) |
| `security` | security topic; **vulnerabilities go through [SECURITY.md](SECURITY.md), never an issue** |
| `triage`, `detection-feedback`, `roadmap` | maintainer's tracking |

The full list is versioned in [`.github/labels.json`](.github/labels.json).

## Set up

### Python (API, models, bot)

Requires Python 3.11+ and git. On Windows, work inside WSL2.

```bash
git clone https://github.com/arixstoo/PhishGuard.git && cd PhishGuard
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'     # or `make sync`: exact versions and hashes from uv.lock
pre-commit install          # ruff (lint + format) and gitleaks (secret scan) on every commit
make test                   # test suite, coverage >= 90 %
make audit                  # pip-audit, bandit, gitleaks (same checks as CI)
```

Changed a dependency in `pyproject.toml`? Run `make lock` and commit `uv.lock`: CI installs
with `uv sync --locked` and fails on a stale lock file.

Most tests need no dataset and no model: they build small synthetic ones. Training a real
model needs the data pipeline (`make data`, see the README), which you do not need for most
contributions.

### Extension

Requires Node.js 20 or newer (CI uses Node.js 24).

```bash
make extension-install      # npm ci: exact versions from package-lock.json, no install scripts
make extension-test         # TypeScript checks + vitest (parity with Python, network, privacy audit)
cd extension && node build.mjs --allow-missing-model   # dist/ without the signed model
npx playwright install chromium && npm run test:e2e    # end-to-end journeys in Chromium
```

To try it: `chrome://extensions` → *Developer mode* → *Load unpacked* → `extension/dist/`.
A build without model shows "model unavailable"; to analyse for real, ask for the signed
model in your issue or build with `make export sign` if you trained one (see
[docs/model-registry.md](docs/model-registry.md)). Architecture:
[docs/extension-design.md](docs/extension-design.md).

### Documentation site

```bash
pip install -e '.[docs]'
mkdocs serve                # http://127.0.0.1:8000, reloads on save
mkdocs build --strict       # what CI runs: broken links fail the build
```

## Workflow

1. Create a branch from `master`: `feat/…`, `fix/…`, `docs/…`, `test/…`.
2. Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`,
   `test:`, `chore:`, `ci:`. One logical change per commit.
3. Add tests for any behaviour change. Every bug fixed becomes a regression test.
4. Update the docs (README, `docs/`) when behaviour changes, and add a line under
   *[Non publié]* in [CHANGELOG.md](CHANGELOG.md) for anything a user or operator would
   notice.
5. Open a pull request against `master` and fill in the template. CI must be green:
   `ci` (ruff, pytest, fuzzing), `security` (bandit, pip-audit, gitleaks), `extension`
   (types, tests, build, e2e, npm audit), `docs`. See [docs/ci-security.md](docs/ci-security.md).

**Review.** The maintainer answers every pull request and issue within **7 days**, usually
sooner. A review asks for changes in plain words; nothing personal.

## Changes that need retraining

Some files are part of the model's **reference data**: `src/phishguard/urls/data/brands.json`,
`src/phishguard/urls/data/shorteners.json`, the keyword lists and the feature list. Their
fingerprint (`reference_data_sha256`) is embedded in every exported model, and the
extension refuses a model built for different reference data. Changing them is welcome,
but the change only takes effect with a retrained model, so such pull requests are
labelled `needs-retraining` and merged together with the next monthly retraining
([docs/model-updates.md](docs/model-updates.md)). After editing them, run
`make extension-data` and commit `extension/src/generated/`.

Lists that do **not** need retraining: `common_legitimate_urls.json` (false-positive gate)
and `hosting.json` (error analysis).

## Translations

The interface exists in French, English and Arabic (right-to-left).

| What | Where |
| --- | --- |
| extension | `extension/static/_locales/<lang>/messages.json` (same keys in every language, checked by `extension/test/i18n.test.ts`) |
| reasons shown to users (API, extension, bot) | `src/phishguard/explain/templates.<lang>.yml` (same keys and placeholders, checked by the tests) |
| Telegram bot | `src/phishguard/bot/texts.py` |
| documents | a translated copy next to the original, e.g. `docs/phishing-101.en.md` |

Adding a new interface language touches code (language lists in
`extension/src/i18n.ts` and `src/phishguard/explain/reasons.py`): open an issue first.

## Versioning and releases

- The application follows [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`,
  one minor version per roadmap module before 1.0 (`v0.5.0` = module 5). Pre-releases use
  `-beta.N` (`0.5.0-beta.1`). The version is kept identical in `pyproject.toml` (PEP 440
  spelling, `0.5.0b1`) and `extension/package.json`; the deploy workflow refuses a tag that
  does not match `pyproject.toml`.
- Models have their own **dated** releases (`2026.12.02`), produced by the monthly
  workflow and signed by the maintainer. The model name (`url_v2`) changes only with a new
  training recipe.
- The analysis response schema has its own version (`docs/schema/`), changed only for an
  incompatible change.
- [CHANGELOG.md](CHANGELOG.md) follows [Keep a Changelog](https://keepachangelog.com/):
  one section per version, newest first, written for users.

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
- Any change that sends new data off the user's device must be opt-in, documented in
  [PRIVACY.md](PRIVACY.md) and [docs/extension-privacy.md](docs/extension-privacy.md), and
  tested; `tests/test_privacy_policy.py` and `extension/test/audit.test.ts` will remind you.

## Reporting

- Wrong verdict (false positive / false negative): use the *Detection feedback* issue template.
- Bug or idea: the *Bug report* or *Feature request* template.
- Security vulnerability: see [SECURITY.md](SECURITY.md), never a public issue.

## Licence

By contributing, you agree that your contribution is released under the project's
[MIT licence](LICENSE). No contributor licence agreement to sign.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
