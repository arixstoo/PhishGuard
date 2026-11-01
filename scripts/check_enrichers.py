"""Interroge les vraies sources de Threat Intelligence au sujet d'une URL.

Sert à vérifier, sur sa machine et avec ses propres clés (fichier .env), que chaque
enrichisseur fonctionne contre la vraie API. Les tests automatiques, eux, n'utilisent
que des réponses simulées.

    python scripts/check_enrichers.py https://testsafebrowsing.appspot.com/s/phishing.html
    python scripts/check_enrichers.py https://example.com --source google_safe_browsing

**L'URL est envoyée aux services tiers.** N'y mets pas une URL qui contient des données
personnelles (adresse email, jeton de réinitialisation…). Traite les URLs de phishing
comme des chaînes : ce script ne les visite jamais lui-même.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from phishguard.enrichers.registry import build_enrichers
from phishguard.urls.features import InvalidUrlError, parse_url


async def check(url: str, sources: set[str] | None) -> int:
    try:
        domain = parse_url(url).registered_domain
    except InvalidUrlError as exc:
        print(exc, file=sys.stderr)
        return 2
    enrichers = [e for e in build_enrichers() if not sources or e.name in sources]
    if not enrichers:
        print("aucune source ne correspond", file=sys.stderr)
        return 2
    signals = await asyncio.gather(*(e.enrich(url, domain) for e in enrichers))
    for signal in signals:
        print(json.dumps(signal.model_dump(mode="json"), ensure_ascii=False, indent=2))
    return 0 if all(s.status != "error" for s in signals) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("url")
    parser.add_argument("--source", action="append", help="limiter à une source (répétable)")
    args = parser.parse_args(argv)
    return asyncio.run(check(args.url, set(args.source or ())))


if __name__ == "__main__":
    raise SystemExit(main())
