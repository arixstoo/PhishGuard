---
title: Translate "Phishing 101" into English
labels: good first issue, translation, documentation
---

## Context

[docs/phishing-101.md](docs/phishing-101.md) explains, in ten minutes and without
jargon, how phishing works and how to spot it. It is linked from the README, which is in
English, but the guide itself only exists in French.

## To do

1. Create `docs/phishing-101.en.md`, an English translation of `docs/phishing-101.md`.
2. Keep the structure, the examples (already defanged: `hxxps://`, `[.]`) and the links.
   Never turn a defanged example back into a clickable link.
3. In `README.md`, point the "Phishing 101" link to the English version and mention the
   French one.

## Check

Open both files side by side in your editor's Markdown preview: same sections, same
order, same examples.

## Done when

- `docs/phishing-101.en.md` exists and follows the French version section by section;
- the README links to it.
