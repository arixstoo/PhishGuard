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

Le délai d'une requête, corps compris, est borné par l'application
(``PHISHGUARD_API_REQUEST_TIMEOUT_SECONDS``, voir ``hardening.py``).

Par défaut, l'API n'écoute que sur ``127.0.0.1`` : l'exposer est un choix explicite.
"""

from __future__ import annotations

import argparse

import uvicorn

MAX_HEADER_BYTES = 16 * 1024


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m phishguard.api", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--log-level", default="info")
    parser.add_argument("--limit-concurrency", type=int, default=100)
    parser.add_argument("--timeout-keep-alive", type=int, default=5)
    args = parser.parse_args(argv)
    uvicorn.run(
        "phishguard.api.main:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_level=args.log_level,
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
