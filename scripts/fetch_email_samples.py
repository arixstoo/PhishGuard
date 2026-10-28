"""Télécharge des emails de phishing réels du corpus public Phishing Pot (étape 1.10).

    python scripts/fetch_email_samples.py                 # 50 emails
    python scripts/fetch_email_samples.py --count 200

Source : https://github.com/rf-peixoto/phishing_pot, emails reçus par des pots de miel et
anonymisés par leurs contributeurs (adresse du destinataire remplacée par
``phishing@pot``). Licence **CC BY-NC 4.0** : usage non commercial, attribution
obligatoire. Les fichiers vont dans data/raw/emails/phishing_pot/, **jamais dans le
dépôt** (sous licence MIT).

Les emails sont choisis de façon déterministe (``sample-<n>.eml`` pour n = 1, 1 + pas,
…), avec un manifeste (URL, taille, SHA-256) pour retrouver exactement le même jeu.
Ce sont des emails hostiles : ils ne sont lus que comme des octets, par
``phishguard.email.parse_eml``. Ne jamais les ouvrir dans un client de messagerie.
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
SOURCE = "https://github.com/rf-peixoto/phishing_pot"
RAW_URL = "https://raw.githubusercontent.com/rf-peixoto/phishing_pot/main/email/sample-{n}.eml"
LICENSE = "CC BY-NC 4.0"
MAX_EMAIL_BYTES = 10 * 1024 * 1024
USER_AGENT = "PhishGuard-Collector/0.2 (+https://github.com/arixstoo/PhishGuard)"

logger = logging.getLogger("fetch_email_samples")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--output-dir", type=Path, default=ROOT / "data/raw/emails/phishing_pot")
    p.add_argument("--count", type=int, default=50, help="nombre d'emails visés")
    p.add_argument("--step", type=int, default=61, help="écart entre deux numéros d'email")
    p.add_argument("--max-tries", type=int, default=None, help="numéros essayés au plus")
    args = p.parse_args(argv)
    if args.count <= 0 or args.step <= 0:
        p.error("--count et --step doivent être strictement positifs")
    return args


def sample_numbers(step: int, max_tries: int) -> list[int]:
    """Numéros candidats ``1, 1 + step, …`` (certains n'existent pas dans le corpus)."""
    return [1 + i * step for i in range(max_tries)]


def fetch(client: httpx.Client, args: argparse.Namespace) -> list[dict[str, object]]:
    args.output_dir.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, object]] = []
    for n in sample_numbers(args.step, args.max_tries or args.count * 3):
        if len(entries) >= args.count:
            break
        url = RAW_URL.format(n=n)
        try:
            data = download_bounded(client, url, MAX_EMAIL_BYTES)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                continue  # numéro absent du corpus
            raise
        name = f"sample-{n}.eml"
        (args.output_dir / name).write_bytes(data)
        entries.append({"file": name, "url": url, "bytes": len(data), "sha256": sha256_bytes(data)})
    return entries


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # une ligne par requête sinon
    args = parse_args(argv)
    with httpx.Client(
        headers={"User-Agent": USER_AGENT}, timeout=30.0, follow_redirects=True
    ) as client:
        try:
            entries = fetch(client, args)
        except httpx.HTTPError as exc:
            logger.error("téléchargement interrompu : %s", exc)
            return 1
    manifest = {
        "source": SOURCE,
        "license": LICENSE,
        "attribution": "Phishing Pot, rf-peixoto et contributeurs",
        "collected_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "count": len(entries),
        "files": entries,
    }
    path = args.output_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    logger.info("%d emails dans %s (manifeste : %s)", len(entries), args.output_dir, path.name)
    return 0 if entries else 1


if __name__ == "__main__":
    sys.exit(main())
