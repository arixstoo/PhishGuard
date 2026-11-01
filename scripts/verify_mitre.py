"""Vérifie le catalogue MITRE ATT&CK du projet contre les données officielles (étape 2.11).

    python scripts/verify_mitre.py                       # télécharge les données de MITRE
    python scripts/verify_mitre.py --stix enterprise-attack.json
    python scripts/verify_mitre.py --write               # met à jour noms et version

Les identifiants et intitulés de src/phishguard/fusion/mitre_attack.json sont comparés
au paquet STIX officiel d'ATT&CK Enterprise (github.com/mitre-attack/attack-stix-data) :
chaque technique doit exister, ne pas être révoquée ni dépréciée, et garder le même
nom et la même tactique. À relancer à chaque nouvelle version d'ATT&CK (deux par an).

Le fichier STIX (plus de 50 Mo) est une donnée externe : il n'est lu que comme du JSON.
Code de sortie : 0 si le catalogue est à jour, 1 sinon.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "src/phishguard/fusion/mitre_attack.json"
STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


def index_stix(bundle: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], str | None]:
    """``{identifiant: {name, parent, tactics, revoked, deprecated}}`` et version ATT&CK."""
    techniques: dict[str, dict[str, Any]] = {}
    version = None
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version", version)
        if obj.get("type") != "attack-pattern":
            continue
        ref = next(
            (
                r
                for r in obj.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if ref is None:
            continue
        techniques[ref["external_id"]] = {
            "name": obj.get("name"),
            "tactics": [p.get("phase_name") for p in obj.get("kill_chain_phases", [])],
            "revoked": bool(obj.get("revoked")),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
        }
    return techniques, version


def check(catalog: dict[str, Any], stix: dict[str, dict[str, Any]]) -> list[str]:
    """Écarts entre le catalogue et les données officielles (liste vide : à jour)."""
    problems = []
    for technique_id, entry in catalog["techniques"].items():
        official = stix.get(technique_id)
        if official is None:
            problems.append(f"{technique_id} : absente d'ATT&CK")
            continue
        if official["revoked"] or official["deprecated"]:
            problems.append(f"{technique_id} : révoquée ou dépréciée")
        if official["name"] != entry["name"]:
            problems.append(
                f"{technique_id} : nom {entry['name']!r}, officiel {official['name']!r}"
            )
        if entry["tactic"] not in official["tactics"]:
            problems.append(
                f"{technique_id} : tactique {entry['tactic']!r}, officielles {official['tactics']}"
            )
        parent = technique_id.split(".")[0]
        if "." in technique_id and parent not in catalog["techniques"]:
            problems.append(f"{technique_id} : la technique parente {parent} manque au catalogue")
    return problems


def updated(catalog: dict[str, Any], stix: dict[str, dict[str, Any]], version: str | None) -> dict:
    """Catalogue avec les noms officiels et la version vérifiée (identifiants inchangés)."""
    result = json.loads(json.dumps(catalog))
    for technique_id, entry in result["techniques"].items():
        if technique_id in stix:
            entry["name"] = stix[technique_id]["name"]
    result["attack_version"] = version or result.get("attack_version")
    result["verified_at"] = datetime.now(UTC).date().isoformat()
    return result


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--stix", type=Path, help="fichier STIX local (sinon téléchargé)")
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--write", action="store_true", help="met à jour le catalogue")
    args = parser.parse_args(argv)

    if args.stix:
        bundle = json.loads(args.stix.read_text(encoding="utf-8"))
    else:
        response = httpx.get(STIX_URL, timeout=60, follow_redirects=False)
        response.raise_for_status()
        bundle = response.json()
    stix, version = index_stix(bundle)
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    problems = check(catalog, stix)

    print(f"ATT&CK {version} : {len(catalog['techniques'])} techniques vérifiées")
    for problem in problems:
        print(f"  - {problem}")
    if args.write and not any("absente" in p or "révoquée" in p for p in problems):
        args.catalog.write_text(
            json.dumps(updated(catalog, stix, version), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"Catalogue mis à jour : {args.catalog}")
        return 0
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
