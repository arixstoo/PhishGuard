"""UCI SMS Spam Collection : téléchargement vérifié, chargement et dédoublonnage.

Source : https://archive.ics.uci.edu/dataset/228/sms+spam+collection (CC BY 4.0).
Format : une ligne par message, ``<ham|spam>\\t<texte>``.
"""

from __future__ import annotations

import csv
import io
import zipfile
from pathlib import Path

import httpx
import pandas as pd

from phishguard.data.integrity import DatasetIntegrityError, sha256_bytes

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
    "load_sms_collection",
    "sha256_bytes",
]


def download_sms_collection(
    dest: Path, *, client: httpx.Client | None = None, timeout: float = 30.0
) -> Path:
    """Télécharge le corpus dans ``dest`` et vérifie son intégrité.

    Ne fait rien si un fichier valide est déjà présent.
    """
    dest = Path(dest)
    if dest.exists() and sha256_bytes(dest.read_bytes()) == EXPECTED_SHA256:
        return dest

    owns_client = client is None
    client = client or httpx.Client(timeout=timeout, follow_redirects=True)
    try:
        response = client.get(UCI_ZIP_URL)
        response.raise_for_status()
    finally:
        if owns_client:
            client.close()
    if len(response.content) > MAX_DOWNLOAD_BYTES:
        raise DatasetIntegrityError("archive anormalement volumineuse")

    # On lit uniquement le membre attendu, sans extractall() : pas de risque de
    # « zip slip » (chemins du type ../../ qui écrivent hors du dossier cible).
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        payload = archive.read(ZIP_MEMBER)

    digest = sha256_bytes(payload)
    if digest != EXPECTED_SHA256:
        raise DatasetIntegrityError(
            f"SHA-256 inattendu pour {ZIP_MEMBER} : {digest} (attendu {EXPECTED_SHA256})"
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(payload)
    return dest


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
