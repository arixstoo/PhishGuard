"""Jeu de test défensif de messages rédigés par un LLM (étape 3.10).

Les messages de phishing générés par un LLM sont grammaticalement parfaits : un détecteur
qui compte sur les fautes, les majuscules ou le vocabulaire du spam d'il y a quinze ans
y perd beaucoup. Ce jeu mesure cette dégradation, et les faux positifs sur des courriers
professionnels légitimes **aussi bien écrits**.

**Défensif et local.** Le fichier (``data/llm_phishing/messages.jsonl``) n'est pas
versionné, comme toutes les données du projet : il ne sort pas de la machine et n'est
envoyé à personne. Seuls son empreinte, son protocole (``docs/llm-phishing.md``) et les
mesures sont publiés. :func:`load_llm_messages` refuse un fichier qui ne respecte pas
les règles du protocole :

- **domaines réservés seulement** (RFC 2606 et RFC 6761) : ``example.com``,
  ``example.net``, ``example.org`` et les TLD ``.test``, ``.example``, ``.invalid`` ;
- **aucune coordonnée réelle** : pas d'adresse email hors de ces domaines, pas de numéro
  de téléphone de 9 chiffres ou plus (seuls les numéros fictifs ``555-01xx`` du plan
  nord-américain passent) ;
- **organisations fictives** : le protocole impose des noms inventés, partagés par les
  deux classes, pour qu'aucune marque ne trahisse l'étiquette ;
- **deux familles de même taille**, phishing et légitime.

Format, une ligne JSON par message : ``id`` (unique), ``label`` (1 phishing, 0 légitime),
``family`` (type de leurre ou de courrier), ``channel`` (``sms`` ou ``email``), ``text``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path

import pandas as pd

CHANNELS = ("sms", "email")
REQUIRED_FIELDS = ("id", "label", "family", "channel", "text")
MAX_TEXT_CHARS = 2_000

# Domaines réservés à la documentation et aux tests (RFC 2606, RFC 6761).
RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
RESERVED_TLDS = frozenset({"test", "example", "invalid", "localhost"})

# Un nom d'hôte : au moins deux labels, le dernier alphabétique de 2 lettres ou plus.
_HOST_RE = re.compile(
    r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})(?![\w-])", re.IGNORECASE
)
_EMAIL_RE = re.compile(r"[\w.+-]+@((?:[\w-]+\.)+[a-z]{2,})", re.IGNORECASE)
# Suite de chiffres séparés ou non ; 9 chiffres ou plus font un numéro de téléphone
# probable (un numéro de facture comme « 2026-118 » n'en a que 7).
_PHONE_RE = re.compile(r"(?<![\w$.,])\+?\d[\d ()./-]{5,}\d(?![\w])")
PHONE_MIN_DIGITS = 9
_FICTIONAL_PHONE_RE = re.compile(r"55501\d\d$")
# Mots qui ressemblent à un hôte sans en être un (abréviations, fichiers).
_NOT_HOSTS = frozenset({"e.g", "i.e"})
_FILE_SUFFIXES = (".pdf", ".docx", ".xlsx", ".zip", ".png", ".jpg")


class UnsafeMessageError(ValueError):
    """Un message enfreint une règle du protocole (domaine réel, coordonnée…)."""


def is_reserved_host(host: str) -> bool:
    """Vrai si ``host`` appartient à un domaine ou à un TLD réservé."""
    host = host.lower().rstrip(".")
    labels = host.split(".")
    if labels[-1] in RESERVED_TLDS:
        return True
    return ".".join(labels[-2:]) in RESERVED_DOMAINS


def hosts_in(text: str) -> list[str]:
    """Noms d'hôte cités dans ``text`` (liens, adresses, domaines nus)."""
    found = []
    for match in _HOST_RE.finditer(text):
        host = match.group(1).lower()
        if host in _NOT_HOSTS or host.endswith(_FILE_SUFFIXES):
            continue
        found.append(host)
    return found


def safety_violations(text: str) -> list[str]:
    """Règles du protocole que ``text`` enfreint (liste vide s'il est conforme)."""
    problems = []
    for host in hosts_in(text):
        if not is_reserved_host(host):
            problems.append(f"domaine non réservé : {host}")
    for match in _EMAIL_RE.finditer(text):
        if not is_reserved_host(match.group(1)):
            problems.append(f"adresse email réelle possible : domaine {match.group(1)}")
    for match in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if len(digits) >= PHONE_MIN_DIGITS and not _FICTIONAL_PHONE_RE.search(digits):
            problems.append("numéro de téléphone non fictif")
    return problems


def _validate(records: Iterable[dict], source: str, *, balanced: bool) -> pd.DataFrame:
    rows = list(records)
    if not rows:
        raise ValueError(f"{source} : aucun message")
    ids: set[str] = set()
    for n, row in enumerate(rows, start=1):
        where = f"{source}, ligne {n}"
        missing = [k for k in REQUIRED_FIELDS if k not in row]
        if missing:
            raise ValueError(f"{where} : champs manquants {missing}")
        if row["id"] in ids:
            raise ValueError(f"{where} : identifiant en double {row['id']!r}")
        ids.add(row["id"])
        if row["label"] not in (0, 1) or isinstance(row["label"], bool):
            raise ValueError(f"{where} : label 0 ou 1 attendu")
        if row["channel"] not in CHANNELS:
            raise ValueError(f"{where} : canal {row['channel']!r}, {CHANNELS} attendus")
        text = row["text"]
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"{where} : texte vide")
        if len(text) > MAX_TEXT_CHARS:
            raise ValueError(f"{where} : plus de {MAX_TEXT_CHARS} caractères")
        problems = safety_violations(text)
        if problems:
            # Le texte n'est pas recopié dans l'erreur : seulement l'identifiant.
            raise UnsafeMessageError(f"{where} ({row['id']}) : {'; '.join(problems)}")
    frame = pd.DataFrame(rows, columns=list(REQUIRED_FIELDS))
    counts = frame["label"].value_counts()
    if balanced and counts.get(0, 0) != counts.get(1, 0):
        raise ValueError(
            f"{source} : familles de tailles différentes "
            f"({counts.get(1, 0)} phishing, {counts.get(0, 0)} légitimes)"
        )
    return frame


def load_llm_messages(path: Path, *, balanced: bool = True) -> pd.DataFrame:
    """Charge et valide le jeu. Lève :class:`UnsafeMessageError` si une règle est enfreinte.

    ``balanced=False`` pour un jeu de contrôle d'une seule classe (FPR seulement).
    """
    path = Path(path)
    records = []
    with path.open(encoding="utf-8") as handle:
        for n, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}, ligne {n} : JSON invalide ({exc.msg})") from None
    return _validate(records, path.name, balanced=balanced)
