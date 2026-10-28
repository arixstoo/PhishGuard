"""Télécharge les corpus publics d'emails de l'étape 1.11 dans data/raw/emails/.

    python scripts/fetch_email_corpora.py          # ou : make email-corpora

- **Légitime** : SpamAssassin public corpus, parties « ham » (easy_ham, easy_ham_2,
  hard_ham), 2002-2003. https://spamassassin.apache.org/old/publiccorpus/
- **Phishing** : corpus de Jose Nazario, fichiers mbox annuels.
  https://monkey.org/~jose/phishing/

Les archives sont gardées telles quelles (``phishguard.email.corpus`` les lit sans les
extraire) et décrites par data/raw/emails/manifest_corpora.json (URL, taille, SHA-256,
date). Un fichier absent du serveur (404) est signalé et ignoré : la liste des années
Nazario évolue, vérifiez-la sur la page du corpus et passez --nazario-years.

Ces corpus ne sont **jamais versionnés** : ils contiennent de vrais emails, avec des
adresses et des noms réels.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

from phishguard.data.integrity import download_bounded, sha256_bytes

ROOT = Path(__file__).resolve().parents[1]
SPAMASSASSIN_URL = "https://spamassassin.apache.org/old/publiccorpus/{name}"
SPAMASSASSIN_FILES = (
    "20030228_easy_ham.tar.bz2",
    "20030228_easy_ham_2.tar.bz2",
    "20030228_hard_ham.tar.bz2",
)
NAZARIO_URL = "https://monkey.org/~jose/phishing/phishing-{year}"
DEFAULT_NAZARIO_YEARS = (2020, 2021, 2022, 2023, 2024)
MAX_FILE_BYTES = 200 * 1024 * 1024
USER_AGENT = "PhishGuard-Collector/0.2 (+https://github.com/arixstoo/PhishGuard)"

logger = logging.getLogger("fetch_email_corpora")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--output-dir", type=Path, default=ROOT / "data/raw/emails")
    p.add_argument("--nazario-years", type=int, nargs="+", default=list(DEFAULT_NAZARIO_YEARS))
    p.add_argument("--skip-spamassassin", action="store_true")
    p.add_argument("--skip-nazario", action="store_true")
    return p.parse_args(argv)


def planned_downloads(args: argparse.Namespace) -> list[tuple[str, str, Path]]:
    """``(label, URL, destination)`` de chaque fichier à télécharger."""
    plan = []
    if not args.skip_spamassassin:
        for name in SPAMASSASSIN_FILES:
            dest = args.output_dir / "spamassassin" / name
            plan.append(("ham", SPAMASSASSIN_URL.format(name=name), dest))
    if not args.skip_nazario:
        for year in args.nazario_years:
            dest = args.output_dir / "nazario" / f"phishing-{year}.mbox"
            plan.append(("phishing", NAZARIO_URL.format(year=year), dest))
    return plan


def fetch(client: httpx.Client, args: argparse.Namespace) -> list[dict[str, object]]:
    entries = []
    for label, url, dest in planned_downloads(args):
        try:
            data = download_bounded(client, url, MAX_FILE_BYTES)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                logger.warning("absent du serveur, ignoré : %s", url)
                continue
            raise
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        logger.info("%s : %s (%d octets)", label, dest.name, len(data))
        entries.append(
            {
                "label": label,
                "url": url,
                "file": dest.relative_to(args.output_dir).as_posix(),
                "bytes": len(data),
                "sha256": sha256_bytes(data),
            }
        )
    return entries


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    args = parse_args(argv)
    with httpx.Client(
        headers={"User-Agent": USER_AGENT}, timeout=120.0, follow_redirects=True
    ) as client:
        try:
            entries = fetch(client, args)
        except httpx.HTTPError as exc:
            logger.error("téléchargement interrompu : %s", exc)
            return 1
    manifest = {
        "collected_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "sources": {
            "spamassassin": "https://spamassassin.apache.org/old/publiccorpus/",
            "nazario": "https://monkey.org/~jose/phishing/",
        },
        "files": entries,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = args.output_dir / "manifest_corpora.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    logger.info("%d fichiers, manifeste : %s", len(entries), path)
    return 0 if entries else 1


if __name__ == "__main__":
    sys.exit(main())
