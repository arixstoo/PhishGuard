# Security Policy

PhishGuard is a security tool, which makes it a target. Reports are welcome and taken
seriously. This policy says how to report a problem, what you can expect in return, and
how fixes are disclosed.

## Supported versions

The project is pre-1.0 and maintained by one person: only the newest code receives
security fixes.

| Component | Supported |
| --- | --- |
| `master` and the latest `v0.x` release tag | ✅ |
| browser extension: the latest published version (Chrome updates it automatically) | ✅ |
| signed model channel `models-stable` | ✅ |
| older tags (`v0.x` before the latest, `v0-legacy`) | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub private vulnerability reporting:
[**Report a vulnerability**](https://github.com/arixstoo/PhishGuard/security/advisories/new)
(Security tab → *Report a vulnerability*). Only the maintainer and you can see the report.
If you cannot use GitHub, open a public issue that says only "I need a private security
contact", with no technical detail, and you will be contacted.

Please include:

- the affected component (API, browser extension, Telegram bot, web page, model/data
  pipeline, model update channel, CI, deployment scripts);
- the version or commit;
- steps to reproduce or a minimal proof of concept;
- the impact you observed (data exposure, SSRF, XSS, model tampering, bypass…);
- any suggested fix.

## What to expect

These delays are commitments, counted in calendar days from your report:

| Step | Delay |
| --- | --- |
| Acknowledgement | within **72 hours** |
| Initial assessment (confirmed or not, severity) | within **7 days** |
| Fix or mitigation plan | within **30 days** for high and critical issues; next release for the others |
| Public disclosure | coordinated with you, at most **90 days** after the report |

If a delay cannot be met, you will be told why and given a new date before it expires.

## Disclosure policy

PhishGuard follows **coordinated disclosure**:

1. The issue is confirmed and fixed privately, in a temporary private fork of the
   advisory, with a regression test.
2. The fix is released (new tag, new extension version, or a new signed model release).
3. A [GitHub Security Advisory](https://github.com/arixstoo/PhishGuard/security/advisories)
   is published with the affected and fixed versions, the impact, and the workaround if
   any. A CVE is requested through GitHub for anything rated medium or higher.
4. The [CHANGELOG](CHANGELOG.md) links to the advisory.

You are credited in the advisory unless you prefer to stay anonymous. Please do not
disclose before the advisory is published, or before the 90-day limit if no fix was
released by then. If the issue is actively exploited, disclosure may happen sooner, with
your agreement.

## Scope

In scope:

- server-side request forgery, injection or authentication flaws in the API;
- XSS, excessive permissions or data leaks in the browser extension;
- any path where email content or browsing data leaves the user's device without consent,
  or any behaviour that contradicts the [privacy policy](PRIVACY.md);
- **model tampering**: any way to make the extension or the API accept a model that was
  not signed by the project key, or an older signed model (rollback);
- tampering with datasets, releases, images or workflows (supply chain);
- secrets committed to the repository.

Out of scope:

- **missed detections and false positives**: use the
  [detection feedback template](https://github.com/arixstoo/PhishGuard/issues/new?template=detection_feedback.yml)
  instead. They are expected for an ML-based detector, and evasion techniques are tracked
  publicly in the [evasion catalog](docs/evasion-catalog.md);
- volumetric denial of service against the hosted demo;
- vulnerabilities in third-party services (VirusTotal, Google Safe Browsing, urlscan.io,
  Vercel, Telegram…): report them to the vendor.

## Model signing key

Models are signed with Ed25519 ([docs/model-registry.md](docs/model-registry.md)). The
public key is [`keys/model-signing.pub`](keys/model-signing.pub), key id
**`cc23eb1b2e3855a8`** (first 16 hex characters of the SHA-256 of the raw key). The private
key never leaves the maintainer's signing machine; CI never signs. If the key is ever
compromised, a new key is published in a new extension version and API image, an advisory
is issued, and every model signed by the old key is treated as untrusted.

## Safe harbor

Good-faith research that respects this policy will not lead to legal action from the
maintainer. Please test only against your own deployment (`docker compose up`), never
against other users, never access or keep data that is not yours, and never send real
phishing to real people.
