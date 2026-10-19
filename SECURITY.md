# Security Policy

PhishGuard is a security tool, which makes it a target. Reports are welcome and taken seriously.

## Supported versions

The project is pre-1.0. Only the latest commit on `master` receives security fixes.

| Version | Supported |
| ------- | --------- |
| `master` | ✅ |
| older tags (`v0.x`, `v0-legacy`) | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub private vulnerability reporting:
[**Report a vulnerability**](https://github.com/arixstoo/PhishGuard/security/advisories/new)
(Security tab → *Report a vulnerability*).

Please include:

- the affected component (API, browser extension, Telegram bot, model/data pipeline, CI);
- steps to reproduce or a minimal proof of concept;
- the impact you observed (data exposure, SSRF, XSS, model tampering, bypass…);
- any suggested fix.

## What to expect

| Step | Target delay |
| ---- | ------------ |
| Acknowledgement | 72 hours |
| Initial assessment | 7 days |
| Fix or mitigation plan | 30 days for high/critical issues |
| Public disclosure | coordinated with you, at most 90 days after the report |

You will be credited in the advisory unless you prefer to stay anonymous.

## Scope

In scope:

- server-side request forgery, injection or authentication flaws in the API;
- XSS, excessive permissions or data leaks in the browser extension;
- any path where email content or browsing data leaves the user's device without consent;
- tampering with models, datasets or releases (supply chain);
- secrets committed to the repository.

Out of scope:

- **missed detections and false positives**: use the
  [detection feedback template](https://github.com/arixstoo/PhishGuard/issues/new?template=detection_feedback.yml)
  instead. They are expected for an ML-based detector;
- volumetric denial of service against the hosted demo;
- vulnerabilities in third-party services (VirusTotal, Google Safe Browsing, urlscan.io…).

## Safe harbor

Good-faith research that respects this policy will not lead to legal action from the
maintainer. Please test only against your own deployment (`docker compose up`), never
against other users, and never send real phishing to real people.
