"""Interroge les vraies sources de Threat Intelligence au sujet d'une URL.

Sert à vérifier, sur sa machine et avec ses propres clés (fichier .env), que chaque
enrichisseur fonctionne contre la vraie API. Les sources sont interrogées en parallèle
par l'orchestrateur (étape 2.9), sous son budget de temps. Les tests automatiques, eux,
n'utilisent que des réponses simulées.

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

from phishguard.enrichers.orchestrator import DEFAULT_BUDGET_S, Orchestrator
from phishguard.urls.features import InvalidUrlError, parse_url


async def check(url: str, sources: set[str] | None, budget_s: float) -> int:
    try:
        parse_url(url)
    except InvalidUrlError as exc:
        print(exc, file=sys.stderr)
        return 2
    async with Orchestrator.from_settings(budget_s=budget_s) as orchestrator:
        unknown = (sources or set()) - set(orchestrator.sources)
        if unknown:
            known = ", ".join(orchestrator.sources)
            print(f"sources inconnues : {sorted(unknown)} (connues : {known})", file=sys.stderr)
            return 2
        result = await orchestrator.enrich(url, sources=sources or None)
    for signal in result.signals:
        print(json.dumps(signal.model_dump(mode="json"), ensure_ascii=False, indent=2))
    print(
        f"{len(result.signals)} sources en {result.latency_ms} ms "
        f"(budget {result.budget_ms} ms, hors délai : {', '.join(result.timed_out) or 'aucune'})",
        file=sys.stderr,
    )
    return 0 if all(s.status != "error" for s in result.signals) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("url")
    parser.add_argument("--source", action="append", help="limiter à une source (répétable)")
    parser.add_argument(
        "--budget", type=float, default=DEFAULT_BUDGET_S, help="budget de temps global (s)"
    )
    args = parser.parse_args(argv)
    return asyncio.run(check(args.url, set(args.source or ()), args.budget))


if __name__ == "__main__":
    raise SystemExit(main())
