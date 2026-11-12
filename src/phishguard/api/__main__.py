"""Lance l'API : ``python -m phishguard.api [--host H] [--port P]``.

Préféré à ``uvicorn phishguard.api.main:app`` en production, parce qu'il fixe deux
options de sécurité d'uvicorn :

- ``proxy_headers=False`` : uvicorn ne réécrit pas l'IP du client d'après
  ``X-Forwarded-For``. C'est l'API qui le fait, en ne croyant que les proxys déclarés
  (``PHISHGUARD_API_TRUSTED_PROXIES``, voir ``phishguard.api.security``) ;
- ``server_header=False`` : pas d'en-tête ``Server: uvicorn`` qui annonce la pile.

Et des bornes de connexion (étape 4.5) :

- ``--limit-concurrency`` (100) : au-delà, uvicorn répond 503 au lieu d'accepter des
  connexions jusqu'à épuisement de la mémoire ;
- ``--timeout-keep-alive`` (5 s) : une connexion inactive est fermée ;
- en-têtes HTTP bornés à 16 Kio (``h11_max_incomplete_event_size``), contre les
  requêtes aux en-têtes démesurés.

Journal (étape 4.6) : ``access_log=False`` (celui d'uvicorn contient le chemin brut, la
chaîne de requête et l'IP du client) et ``log_config=None`` (uvicorn ne remplace pas la
configuration) ; l'API écrit sa propre ligne par requête, sans donnée personnelle
(``phishguard.api.logs``).

Le délai d'une requête, corps compris, est borné par l'application
(``PHISHGUARD_API_REQUEST_TIMEOUT_SECONDS``, voir ``hardening.py``).

Par défaut, l'API n'écoute que sur ``127.0.0.1`` : l'exposer est un choix explicite.
"""

from __future__ import annotations

import argparse
import os

import uvicorn

from phishguard.api.logs import configure_logging
from phishguard.api.settings import get_api_settings

MAX_HEADER_BYTES = 16 * 1024


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m phishguard.api", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument(
        "--log-level",
        type=str.upper,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="remplace PHISHGUARD_API_LOG_LEVEL (défaut INFO)",
    )
    parser.add_argument("--limit-concurrency", type=int, default=100)
    parser.add_argument("--timeout-keep-alive", type=int, default=5)
    args = parser.parse_args(argv)
    if args.log_level:
        # Par l'environnement : l'application (et chaque worker) relit la configuration.
        os.environ["PHISHGUARD_API_LOG_LEVEL"] = args.log_level
        get_api_settings.cache_clear()
    settings = get_api_settings()
    configure_logging(settings)
    uvicorn.run(
        "phishguard.api.main:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_level=settings.log_level.lower(),
        log_config=None,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        date_header=True,
        limit_concurrency=args.limit_concurrency,
        timeout_keep_alive=args.timeout_keep_alive,
        timeout_graceful_shutdown=10,
        h11_max_incomplete_event_size=MAX_HEADER_BYTES,
    )


if __name__ == "__main__":
    main()
