"""Écrit le schéma JSON de la réponse d'analyse (étape 2.11 bis).

    python scripts/export_schema.py            # ou : make schema

Le fichier docs/schema/analysis-response.v1.json est versionné : l'extension et le bot
(module 5) s'en servent pour valider les réponses de l'API. tests/test_response_schema.py
échoue s'il n'est pas à jour avec phishguard.schema.
"""

from __future__ import annotations

import sys
from pathlib import Path

from phishguard.schema import json_schema_text

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/schema/analysis-response.v1.json"


def main() -> int:
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json_schema_text(), encoding="utf-8", newline="\n")
    print(f"Schéma écrit : {OUTPUT.relative_to(ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
