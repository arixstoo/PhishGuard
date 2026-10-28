# PhishGuard

[![CI](https://github.com/arixstoo/PhishGuard/actions/workflows/ci.yaml/badge.svg)](https://github.com/arixstoo/PhishGuard/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Status](https://img.shields.io/badge/status-in%20development-orange)

**Open-source, explainable and privacy-first phishing detection for URLs, SMS and emails.**
PhishGuard warns people at the exact moment they are about to click, with a clear verdict
and a one-sentence explanation, in French, English and Arabic.

> 🚧 **Work in progress.** The project is being rebuilt in public, module by module.
> Nothing below is production-ready yet; the [roadmap](#roadmap) shows what exists today.

<!-- Demo GIF goes here once the browser extension exists (module 5). -->

## Why

Phishing is still one of the main initial access vectors
([MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/)). Existing protections
are either paid enterprise products or reactive blocklists that only catch a site once it
has already been reported. PhishGuard aims to fill the gap for non-technical users:

- **Local-first**: the detection model runs on the user's device; by default no email
  content and no browsing history ever leave it.
- **Explainable**: every verdict comes with plain-language reasons, plus a technical view
  for analysts.
- **Honest**: metrics are measured on a temporal split, false positives are tracked as
  closely as missed detections, and robustness against evasion is benchmarked and published.

## Planned features

- [x] Reproducible SMS spam/smishing baseline with honest metrics
- [ ] URL analysis: verdict (safe / suspicious / phishing) + 0–100 score
- [ ] SMS / text and raw email (`.eml`) analysis: SPF, DKIM, DMARC, display-vs-real links
- [ ] Opt-in Threat Intelligence enrichment (Safe Browsing, VirusTotal, urlscan.io, RDAP, CT logs)
- [ ] Explanations (SHAP + readable reasons) and MITRE ATT&CK mapping
- [ ] Adversarial robustness benchmark (homoglyphs, typosquatting, zero-width characters…)
- [ ] Hardened REST API (FastAPI, OpenAPI, rate limiting, SSRF guard)
- [ ] Chrome extension (local inference, Gmail banner, link hover), Telegram bot, web page
- [ ] FR / EN / AR interface (RTL)

## Current results

<!-- generated:current-results-url:start -->
**URL model** (`url_v1`, LightGBM, 25 offline lexical features), measured once on the most recent 21,004 URLs (temporal, domain-grouped test set). Full numbers and caveats: [`docs/model-card-url.md`](docs/model-card-url.md).

| PR-AUC | Recall @ 1 % FPR | Recall at decision threshold | FPR (homepages / internal pages) | Precision if 1 % of URLs are phishing |
| ---: | ---: | ---: | ---: | ---: |
| 0.939 | 0.755 | 73.9 % | 0.2 % / 6.4 % | 47.3 % |
<!-- generated:current-results-url:end -->

**SMS baseline** (TF-IDF + logistic regression on the
[UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection)),
spam = positive class, threshold 0.5. Full output: [`docs/metrics/sms_baseline.json`](docs/metrics/sms_baseline.json).

| Protocol | Precision | Recall | F1 | False positives | PR-AUC | Recall @ 1 % FPR | Test messages already seen in training |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Naive random split (original 2022 project) | 0.952 | 0.933 | 0.942 | 7 / 966 | 0.978 | 0.946 | **139 / 1115** |
| **Deduplicated, then split (reference)** | **0.889** | **0.938** | **0.912** | **15 / 904** | **0.971** | **0.922** | **0** |

**Lesson learned:** the corpus contains 414 duplicate messages. With a naive random split,
12.5 % of the test set had already been seen during training, which inflated precision and
halved the apparent number of false positives. The original project reported "96 % accuracy";
on a dataset where 87 % of messages are legitimate, accuracy alone says very little. This
baseline is a starting point: the current false positive rate (1.7 %) is above the project
target of 1 %.

## Quick start

Requires Python 3.11+. On Windows, use WSL2.

```bash
git clone https://github.com/arixstoo/PhishGuard.git && cd PhishGuard
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'

pytest --cov=phishguard                 # run the tests
python scripts/train_sms_baseline.py    # download the dataset (SHA-256 verified) and reproduce the metrics
python scripts/fetch_feeds.py           # collect timestamped phishing and legitimate feeds into data/raw/
python scripts/build_dataset.py         # build data/processed/urls.parquet (normalized, deduplicated)
python scripts/audit_bias.py            # look for dataset shortcuts before training (docs/data-bias.md)
python scripts/split_dataset.py         # temporal, domain-grouped train/validation/test split (docs/split.md)
python scripts/evaluate_url_features.py # measure what each URL feature adds, on validation (docs/url-features.md)
make train-url                          # train and compare logistic regression, Random Forest, LightGBM (docs/url-models.md)
make evaluate-url                       # test-set evaluation at realistic phishing prevalence (docs/evaluation.md)
make errors-url                         # classify the 50 worst false positives and false negatives (docs/error-analysis-url.md)
make train-text                         # compare SMS text models, English corpus + French/Arabic set (docs/text-models.md)
python scripts/parse_email.py msg.eml   # SPF/DKIM/DMARC, sender mismatches, deceptive links, risky attachments (docs/email-parser.md)
make email-corpora && make train-email  # email score: transparent rules vs learned models (docs/email-score.md)
python -m phishguard.config             # which Threat Intel sources are enabled (optional keys in .env, docs/secrets.md)
```

Run `make help` to list the available commands.

## Roadmap

Each step is tracked as a GitHub issue, grouped by milestone.

| Module | Content | Status |
| --- | --- | --- |
| M0 Foundations | Repo structure, CI, community files, SMS baseline, phishing 101 | ✅ done |
| M1 Detection | URL / text / email detectors, temporal split, model cards | ✅ done (`v0.1.0`) |
| M2 Threat Intel | Enrichers, SSRF guard, signal fusion, MITRE mapping | 🚧 in progress |
| M3 XAI & adversarial | SHAP explanations, evasion catalogue, robustness report | ⏳ planned |
| M4 Secure API | FastAPI, rate limiting, fuzzing, security CI, hardened Docker image | ⏳ planned |
| M5 Extension & bot | Chrome MV3 extension, Telegram bot, user tests | ⏳ planned |
| M6 Launch | Deployment, Chrome Web Store, docs site, v1.0 | ⏳ planned |

## Repository layout

```
src/phishguard/   reusable package (data loading, evaluation, detectors, API…)
scripts/          one-command data collection and training scripts
tests/            pytest suite
docs/             documentation, metrics, threat model, reports
notebooks/legacy/ original 2022 SMS spam detector (tag v0-legacy)
extension/        Chrome extension (module 5)
bot/              Telegram bot (module 5)
data/, models/    generated locally, never committed
```

## Learn more

- [Phishing 101](docs/phishing-101.md): how phishing works and how to spot it (French)
- [Data bias audit](docs/data-bias.md): shortcuts found in the URL dataset and how they are handled (French)
- [Train / validation / test split](docs/split.md): temporal and grouped by registered domain, with no domain leakage (French)
- [URL features](docs/url-features.md): 26 offline lexical features (typosquatting, homographs, TLD, shorteners) and what each one adds (French)
- [URL models](docs/url-models.md): logistic regression vs Random Forest vs LightGBM, tuned on validation, with recall at 1 % FPR and inference cost (French)
- [Realistic evaluation](docs/evaluation.md): precision at 1 % and 0.1 % phishing prevalence, and how the decision threshold is chosen (French)
- [URL error analysis](docs/error-analysis-url.md): the worst errors by category, and why static features alone cannot catch phishing on trusted platforms (French)
- [SMS text models](docs/text-models.md): word vs character n-grams vs hand-written smishing features, and how they transfer to French and Arabic (French)
- [Email parser](docs/email-parser.md): defensive `.eml` parsing, authentication results, deceptive links, hidden text and risky attachments (French)
- [Email score](docs/email-score.md): explainable rules vs learned models, and why public email corpora are biased by era (French)
- [API keys and secrets](docs/secrets.md): optional Threat Intelligence keys, how they are loaded, and what to do if one leaks (French)
- Model cards: [URL](docs/model-card-url.md) · [SMS text](docs/model-card-text.md) · [email](docs/model-card-email.md): intended use, data, metrics, known biases and limits (French)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md)

## History

PhishGuard started in 2022 as a small SMS spam detector (TF-IDF + logistic regression).
That version is preserved under the [`v0-legacy`](https://github.com/arixstoo/PhishGuard/tree/v0-legacy)
tag and in `notebooks/legacy/`, as a record of where the project came from.

## License

[MIT](LICENSE) for now, to keep reuse simple. The final licence choice will be made and
explained before v1.0.

## Author

**arixstoo** · [LinkedIn](https://www.linkedin.com/in/saidi-mohamed-rostom-21b3b525a/)
