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
    """``{identifiant: {name, tactics, revoked, deprecated}}`` et version ATT&CK."""
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
        entry = {
            "name": obj.get("name"),
            "tactics": [p.get("phase_name") for p in obj.get("kill_chain_phases", [])],
            "revoked": bool(obj.get("revoked")),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
        }
        # Un identifiant ne devrait apparaître qu'une fois ; sinon, l'objet actif prime
        # sur une ancienne version révoquée, quel que soit l'ordre du paquet.
        previous = techniques.get(ref["external_id"])
        if previous is None or _active(entry) >= _active(previous):
            techniques[ref["external_id"]] = entry
    return techniques, version


def _active(entry: dict[str, Any]) -> bool:
    return not (entry["revoked"] or entry["deprecated"])


def problems(catalog: dict[str, Any], stix: dict[str, dict[str, Any]]) -> list[tuple[str, bool]]:
    """Écarts entre le catalogue et ATT&CK, chacun avec un drapeau : ``True`` si
    ``--write`` sait le corriger seul (un nom changé), ``False`` s'il faut décider à la main
    (technique absente, révoquée ou dépréciée, tactique changée, parent manquant).
    """
    found: list[tuple[str, bool]] = []
    for technique_id, entry in catalog["techniques"].items():
        official = stix.get(technique_id)
        if official is None:
            found.append((f"{technique_id} : absente d'ATT&CK", False))
            continue
        if not _active(official):
            found.append((f"{technique_id} : révoquée ou dépréciée", False))
        if official["name"] != entry["name"]:
            text = f"{technique_id} : nom {entry['name']!r}, officiel {official['name']!r}"
            found.append((text, True))
        if entry["tactic"] not in official["tactics"]:
            text = (
                f"{technique_id} : tactique {entry['tactic']!r}, officielles {official['tactics']}"
            )
            found.append((text, False))
        parent = technique_id.split(".")[0]
        if "." in technique_id and parent not in catalog["techniques"]:
            found.append((f"{technique_id} : la technique parente {parent} manque", False))
    return found


def check(catalog: dict[str, Any], stix: dict[str, dict[str, Any]]) -> list[str]:
    """Écarts entre le catalogue et les données officielles (liste vide : à jour)."""
    return [text for text, _ in problems(catalog, stix)]


def updated(catalog: dict[str, Any], stix: dict[str, dict[str, Any]], version: str | None) -> dict:
    """Catalogue avec les noms officiels et la version vérifiée (identifiants inchangés)."""
    result = json.loads(json.dumps(catalog))
    for technique_id, entry in result["techniques"].items():
        if technique_id in stix:
            entry["name"] = stix[technique_id]["name"]
    result["attack_version"] = version or result.get("attack_version")
    result["verified_at"] = datetime.now(UTC).date().isoformat()
    return result


def dump_catalog(catalog: dict[str, Any]) -> str:
    """JSON du catalogue, une technique par ligne comme le fichier versionné (diffs lisibles)."""
    lines = ["{"]
    head = {k: v for k, v in catalog.items() if k != "techniques"}
    for key, value in head.items():
        lines.append(f"  {json.dumps(key)}: {json.dumps(value, indent=2, ensure_ascii=False)},")
    lines = [line.replace("\n", "\n  ") for line in lines]
    rows = [
        f"    {json.dumps(tid)}: {json.dumps(entry, ensure_ascii=False)}"
        for tid, entry in catalog["techniques"].items()
    ]
    lines.append('  "techniques": {')
    lines.append(",\n".join(rows))
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--stix", type=Path, help="fichier STIX local (sinon téléchargé)")
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--write", action="store_true", help="met à jour noms et version")
    args = parser.parse_args(argv)

    if args.stix:
        bundle = json.loads(args.stix.read_text(encoding="utf-8"))
    else:
        response = httpx.get(STIX_URL, timeout=60, follow_redirects=False)
        response.raise_for_status()
        bundle = response.json()
    stix, version = index_stix(bundle)
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    found = problems(catalog, stix)

    print(f"ATT&CK {version} : {len(catalog['techniques'])} techniques vérifiées")
    for text, _ in found:
        print(f"  - {text}")
    if not args.write:
        return 1 if found else 0
    if any(not fixable for _, fixable in found):
        print("Catalogue non modifié : ces écarts demandent une décision à la main.")
        return 1
    args.catalog.write_text(dump_catalog(updated(catalog, stix, version)), encoding="utf-8")
    print(f"Catalogue mis à jour : {args.catalog}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
