"""Configuration du proxy Vercel devant l'API (étape 6.2, docs/deployment.md).

Le nom public de l'API est un sous-domaine gratuit de Vercel
(``api-phishguard.vercel.app``) : TLS, HTTP/2 et HTTP/3, pare-feu et absorption des
abus sont fournis par Vercel. Vercel relaie chaque requête vers l'origine (Caddy sur le
serveur) en y ajoutant l'en-tête secret ``X-PhishGuard-Origin-Auth``, lu dans la variable
d'environnement ``PHISHGUARD_ORIGIN_SECRET`` du projet Vercel (type « Sensitive ») : le
secret n'est jamais écrit dans ce fichier ni dans le dépôt.

Le nom de l'origine n'est pas commité non plus (il désigne l'adresse du serveur) : la CI le
lit dans un secret GitHub et produit ``vercel.json`` juste avant le déploiement.

    python scripts/render_edge_config.py proxy --origin-host phishguard-origin.duckdns.org
    python scripts/render_edge_config.py maintenance     # 503 tant qu'aucune origine n'existe

Sortie : ``deploy/edge/dist/`` (``vercel.json`` et ``public/``), ignoré par git.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "deploy" / "edge" / "dist"

ORIGIN_AUTH_HEADER = "x-phishguard-origin-auth"
SECRET_ENV = "PHISHGUARD_ORIGIN_SECRET"
SCHEMA_URL = "https://openapi.vercel.sh/vercel.json"

# Nom DNS en minuscules, au moins deux étiquettes, suffixe alphabétique : ni adresse IP
# (pas de certificat public), ni port, ni chemin, ni identifiants.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOST_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z]{{2,63}}$")
# Le proxy lui-même : une origine sur Vercel ferait boucler les requêtes.
FORBIDDEN_SUFFIXES = (".vercel.app", ".vercel.sh", ".now.sh")

UNAVAILABLE_BODY = {
    "error": {
        "code": "service_unavailable",
        "message": "L'API PhishGuard n'est pas encore en service. L'analyse locale de "
        "l'extension continue de fonctionner.",
    }
}


class EdgeConfigError(ValueError):
    """Paramètre refusé : rien n'est écrit."""


def validate_origin_host(host: str) -> str:
    host = host.strip()
    if len(host) > 253 or not HOST_RE.fullmatch(host):
        raise EdgeConfigError(
            f"nom d'origine invalide : {host!r} (attendu : nom DNS en minuscules, "
            "ex. phishguard-origin.duckdns.org, sans schéma, port ni chemin)"
        )
    if host.endswith(FORBIDDEN_SUFFIXES):
        raise EdgeConfigError(f"origine hébergée sur Vercel refusée (boucle) : {host!r}")
    return host


def proxy_config(origin_host: str) -> dict[str, Any]:
    """Toutes les requêtes vers ``https://<origine>``, avec l'en-tête secret."""
    host = validate_origin_host(origin_host)
    return {
        "$schema": SCHEMA_URL,
        "framework": None,
        "buildCommand": "",
        "installCommand": "",
        "outputDirectory": "public",
        "routes": [
            {
                "src": "/(.*)",
                "dest": f"https://{host}/$1",
                "transforms": [
                    {
                        # « set » remplace toute valeur envoyée par le visiteur : il ne
                        # peut pas fournir son propre en-tête pour atteindre l'origine.
                        "type": "request.headers",
                        "op": "set",
                        "target": {"key": ORIGIN_AUTH_HEADER},
                        "args": f"${SECRET_ENV}",
                        "env": [SECRET_ENV],
                    }
                ],
            }
        ],
    }


def maintenance_config() -> dict[str, Any]:
    """503 JSON sur tout chemin : le nom public existe, l'origine pas encore."""
    return {
        "$schema": SCHEMA_URL,
        "framework": None,
        "buildCommand": "",
        "installCommand": "",
        "outputDirectory": "public",
        "routes": [
            {
                "src": "/.*",
                "dest": "/unavailable.json",
                "status": 503,
                "headers": {
                    "Content-Type": "application/json; charset=utf-8",
                    "Cache-Control": "no-store",
                    "Retry-After": "3600",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                },
            }
        ],
    }


def write_output(config: dict[str, Any], output: Path) -> Path:
    public = output / "public"
    public.mkdir(parents=True, exist_ok=True)
    (public / "unavailable.json").write_text(
        json.dumps(UNAVAILABLE_BODY, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    target = output / "vercel.json"
    target.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    modes = parser.add_subparsers(dest="mode", required=True)
    proxy = modes.add_parser("proxy", help="relais vers l'origine")
    proxy.add_argument("--origin-host", required=True)
    modes.add_parser("maintenance", help="503 sur tout chemin")
    args = parser.parse_args(argv)
    try:
        config = proxy_config(args.origin_host) if args.mode == "proxy" else maintenance_config()
    except EdgeConfigError as exc:
        print(f"erreur : {exc}", file=sys.stderr)
        return 2
    target = write_output(config, args.output)
    # Le nom de l'origine n'est pas affiché : la sortie de la CI est publique.
    print(f"{target} écrit (mode {args.mode})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
