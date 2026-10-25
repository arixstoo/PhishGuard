"""UCI PhiUSIIL Phishing URL Dataset : téléchargement vérifié et mise au schéma commun.

Source : https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset (CC BY 4.0).
Prasad, A. et Chandra, S. (2024), « PhiUSIIL: A diverse security profile empowered phishing
URL detection framework based on similarity index and incremental learning », *Computers
& Security*, 136.

Le jeu sert uniquement de point de comparaison externe (étape 1.3), jamais
d'entraînement : ses URLs de phishing datent de 2023 et chevauchent PhishTank.

**Attention** : dans PhiUSIIL, ``label = 1`` désigne une URL **légitime**. Le chargeur
inverse l'étiquette pour respecter la convention du projet (1 = phishing).
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pandas as pd
import tldextract

from phishguard.data.integrity import download_zip_member
from phishguard.data.urls import (
    COLUMNS,
    LABEL_LEGITIMATE,
    LABEL_PHISHING,
    make_domain_extractor,
    normalize_url,
    registered_domain,
)

UCI_ZIP_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
ZIP_MEMBER = "PhiUSIIL_Phishing_URL_Dataset.csv"
# Empreinte du CSV publié par l'UCI (version du 04/03/2024, 235 795 lignes).
EXPECTED_SHA256 = "a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6"
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 128 * 1024 * 1024
SOURCE = "phiusiil"

# Étiquettes PhiUSIIL -> convention du projet.
_LABELS = {1: LABEL_LEGITIMATE, 0: LABEL_PHISHING}


def download_phiusiil(dest: Path, *, client: httpx.Client | None = None) -> Path:
    """Télécharge le CSV dans ``dest`` (ne fait rien s'il est déjà présent et intact)."""
    return download_zip_member(
        UCI_ZIP_URL,
        ZIP_MEMBER,
        EXPECTED_SHA256,
        dest,
        max_download_bytes=MAX_DOWNLOAD_BYTES,
        max_member_bytes=MAX_MEMBER_BYTES,
        client=client,
    )


def load_phiusiil(
    path: Path, extractor: tldextract.TLDExtract | None = None
) -> tuple[pd.DataFrame, dict[str, int]]:
    """Charge PhiUSIIL au schéma :data:`phishguard.data.urls.COLUMNS`.

    Les URLs sont normalisées comme celles du jeu principal ; les invalides, celles aux
    étiquettes contradictoires et les doublons sont retirés. ``first_seen`` est vide : le
    jeu ne publie pas de date par URL.

    Retourne le DataFrame et les effectifs de chaque étape.
    """
    raw = pd.read_csv(
        path,
        usecols=["URL", "label"],
        dtype={"URL": str, "label": "Int8"},
        encoding="utf-8-sig",  # le fichier commence par un BOM
        keep_default_na=False,
    )
    unknown = set(raw["label"].dropna().unique()) - _LABELS.keys()
    if unknown or raw["label"].isna().any():
        raise ValueError(f"étiquettes PhiUSIIL inattendues : {sorted(unknown)}")

    extractor = extractor or make_domain_extractor()
    parsed = raw["URL"].map(normalize_url)
    valid = parsed.notna()
    df = pd.DataFrame(
        {
            "url": parsed[valid].map(lambda pair: pair[0]),
            "label": raw.loc[valid, "label"].map(_LABELS).astype("int8"),
            "host": parsed[valid].map(lambda pair: pair[1]),
        }
    )
    domains = {host: registered_domain(host, extractor) for host in df["host"].unique()}
    df["registered_domain"] = df["host"].map(domains)
    known_suffix = df["registered_domain"].notna()
    df = df[known_suffix]

    labels_per_url = df.groupby("url")["label"].nunique()
    conflicting = labels_per_url.index[labels_per_url > 1]
    consistent = df[~df["url"].isin(conflicting)]
    clean = consistent.drop_duplicates("url").assign(
        source=SOURCE,
        first_seen=pd.Series(pd.NaT, index=consistent.index, dtype="datetime64[ns, UTC]"),
    )
    stats = {
        "rows_raw": len(raw),
        "invalid_url": int((~valid).sum()),
        "unknown_suffix": int((~known_suffix).sum()),
        "label_conflicts": len(conflicting),
        "duplicates_removed": len(consistent) - len(clean),
        "rows": len(clean),
    }
    return clean[COLUMNS].reset_index(drop=True), stats
