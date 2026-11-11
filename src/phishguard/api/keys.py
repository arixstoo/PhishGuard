"""Gestion des clés d'API en ligne de commande (étape 4.4).

::

    python -m phishguard.api.keys create --name extension-dev
    python -m phishguard.api.keys list
    python -m phishguard.api.keys revoke 3f9a1c0b2d4e

La clé n'est affichée **qu'une fois**, à sa création : la base n'en garde que l'empreinte
SHA-256 et ne peut pas la redonner. Une clé perdue se révoque et se remplace.

La base est celle de l'API (``PHISHGUARD_API_DATABASE_PATH``), ou ``--database``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from phishguard.api.settings import get_api_settings
from phishguard.api.storage import Database


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m phishguard.api.keys")
    parser.add_argument("--database", type=Path, help="base SQLite (défaut : celle de l'API)")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="crée une clé et l'affiche une seule fois")
    create.add_argument("--name", required=True, help="usage de la clé (ex. extension-dev)")
    commands.add_parser("list", help="liste les clés, sans leur secret")
    revoke = commands.add_parser("revoke", help="révoque une clé")
    revoke.add_argument("key_id")
    args = parser.parse_args(argv)

    database = Database(args.database or get_api_settings().database_path)
    if args.command == "create":
        record, key = database.create_key(args.name)
        print(
            f"clé {record.key_id} ({record.name}) créée. À conserver, elle ne sera plus affichée :"
        )
        print(key)
        return 0
    if args.command == "list":
        for record in database.list_keys():
            state = "active" if record.active else f"révoquée le {record.revoked_at}"
            print(f"{record.key_id}  {record.created_at}  {state:<32}  {record.name}")
        return 0
    if database.revoke_key(args.key_id):
        print(f"clé {args.key_id} révoquée")
        return 0
    print(f"clé {args.key_id} introuvable ou déjà révoquée", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
