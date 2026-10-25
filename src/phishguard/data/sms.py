"""UCI SMS Spam Collection : téléchargement vérifié, chargement et dédoublonnage.

Source : https://archive.ics.uci.edu/dataset/228/sms+spam+collection (CC BY 4.0).
Format : une ligne par message, ``<ham|spam>\\t<texte>``.
"""

from __future__ import annotations

import csv
from pathlib import Path

import httpx
import pandas as pd

from phishguard.data.integrity import DatasetIntegrityError, download_zip_member, sha256_bytes

UCI_ZIP_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
ZIP_MEMBER = "SMSSpamCollection"
# Empreinte du fichier SMSSpamCollection publié par l'UCI. Si elle change, la source a
# été modifiée (ou compromise) : on refuse plutôt que d'entraîner sur des données inconnues.
EXPECTED_SHA256 = "7d039a24a6083ed9ef0f806ebad56bbb976e3aeb8de05669173bfdc4996c239d"
MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024

LABELS = {"ham": 0, "spam": 1}

__all__ = [
    "DatasetIntegrityError",
    "deduplicate",
    "download_sms_collection",
    "load_fr_ar_sms",
    "load_sms_collection",
    "sha256_bytes",
]


def download_sms_collection(
    dest: Path, *, client: httpx.Client | None = None, timeout: float = 30.0
) -> Path:
    """Télécharge le corpus dans ``dest`` et vérifie son intégrité.

    Ne fait rien si un fichier valide est déjà présent.
    """
    return download_zip_member(
        UCI_ZIP_URL,
        ZIP_MEMBER,
        EXPECTED_SHA256,
        dest,
        max_download_bytes=MAX_DOWNLOAD_BYTES,
        max_member_bytes=MAX_DOWNLOAD_BYTES,
        client=client,
        timeout=timeout,
    )


def load_sms_collection(path: Path) -> pd.DataFrame:
    """Charge le corpus en DataFrame ``[label, text]`` avec ``label`` = 1 pour spam.

    Lève ``ValueError`` si une ligne est mal formée ou porte une étiquette inconnue.
    """
    df = pd.read_csv(
        path,
        sep="\t",
        names=["label", "text"],
        header=None,
        dtype=str,
        quoting=csv.QUOTE_NONE,  # certains SMS contiennent des guillemets non fermés
        encoding="utf-8",
        keep_default_na=False,
    )
    unknown = set(df["label"]) - LABELS.keys()
    if unknown:
        raise ValueError(f"étiquettes inconnues : {sorted(unknown)}")
    if (df["text"].str.len() == 0).any():
        raise ValueError("message vide détecté")
    df["label"] = df["label"].map(LABELS).astype(int)
    return df


def deduplicate(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, int]]:
    """Supprime les messages en double (texte identique après ``strip``).

    Les doublons sont la première source de fuite entre entraînement et test : un message
    vu à l'entraînement puis « retrouvé » au test gonfle artificiellement les scores.
    Un texte présent avec des étiquettes contradictoires est entièrement retiré.
    """
    key = df["text"].str.strip()
    labels_per_text = df.groupby(key)["label"].nunique()
    conflicting = labels_per_text[labels_per_text > 1].index

    clean = df[~key.isin(conflicting)]
    clean = clean.loc[~clean["text"].str.strip().duplicated(keep="first")].reset_index(drop=True)

    stats = {
        "rows_before": len(df),
        "rows_after": len(clean),
        "duplicates_removed": len(df) - len(clean),
        "conflicting_texts": len(conflicting),
    }
    return clean, stats


FR_AR_COLUMNS = ("lang", "label", "theme", "text")


def load_fr_ar_sms(path: Path) -> pd.DataFrame:
    """Charge le petit jeu complémentaire français / arabe (``datasets/sms_fr_ar.csv``).

    Colonnes : ``lang`` (``fr`` ou ``ar``), ``label`` (1 = smishing), ``theme``, ``text``.
    Voir ``docs/sms-fr-ar.md`` pour sa constitution et ses limites.
    """
    df = pd.read_csv(path, dtype={"label": int}, keep_default_na=False, encoding="utf-8")
    missing = set(FR_AR_COLUMNS) - set(df.columns)
    if missing:
        raise ValueError(f"colonnes manquantes : {sorted(missing)}")
    if not set(df["label"]) <= {0, 1}:
        raise ValueError("label doit valoir 0 ou 1")
    if (df["text"].str.strip().str.len() == 0).any():
        raise ValueError("message vide détecté")
    return df[list(FR_AR_COLUMNS)]
