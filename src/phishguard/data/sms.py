"""UCI SMS Spam Collection : téléchargement vérifié, chargement et dédoublonnage.

Source : https://archive.ics.uci.edu/dataset/228/sms+spam+collection (CC BY 4.0).
Format : une ligne par message, ``<ham|spam>\\t<texte>``.
"""

from __future__ import annotations

import csv
import re
import unicodedata
from pathlib import Path

import httpx
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

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
    "load_sms_collection",
    "sha256_bytes",
    "split_sms",
    "template_key",
    "template_overlap",
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


# --------------------------------------------------------------------------- #
# Split groupé par gabarit (étape 1.9)
# --------------------------------------------------------------------------- #

SMS_SPLITS = ("train", "validation", "test")
_DIGIT_RUN_RE = re.compile(r"\d+")
_SPACE_RE = re.compile(r"\s+")


def template_key(text: str) -> str:
    """Gabarit d'un message : minuscules, nombres remplacés par ``0``, espaces réduits.

    Une campagne de spam envoie le même texte avec un numéro, un montant ou un code
    différent. Le dédoublonnage exact ne les voit pas ; deux messages au même gabarit
    vont donc toujours dans le même bloc.
    """
    text = unicodedata.normalize("NFKC", text).casefold()
    return _SPACE_RE.sub(" ", _DIGIT_RUN_RE.sub("0", text)).strip()


def split_sms(
    df: pd.DataFrame,
    fractions: tuple[float, float, float] = (0.70, 0.15, 0.15),
    seed: int = 42,
) -> pd.Series:
    """Bloc (``train``, ``validation``, ``test``) de chaque message de ``df``.

    Stratifié par étiquette et groupé par :func:`template_key` : aucun gabarit n'est
    dans deux blocs. Le corpus UCI n'a pas de date, le split ne peut pas être temporel.
    Les messages sont répartis en 20 plis équilibrés (``StratifiedGroupKFold``), puis les
    plis sont attribués aux blocs selon ``fractions`` (multiples de 5 %).
    """
    n_folds = 20
    counts = [round(f * n_folds) for f in fractions]
    exact = all(np.isclose(f * n_folds, c) for f, c in zip(fractions, counts, strict=False))
    if len(fractions) != len(SMS_SPLITS) or not exact or sum(counts) != n_folds or min(counts) < 1:
        raise ValueError("fractions : trois parts positives, multiples de 0,05, de somme 1")
    if df.empty:
        raise ValueError("jeu vide")

    groups = df["text"].map(template_key)
    folds = np.empty(len(df), dtype=np.int64)
    splitter = StratifiedGroupKFold(n_splits=n_folds, shuffle=True, random_state=seed)
    for fold, (_, members) in enumerate(splitter.split(df["text"], df["label"], groups)):
        folds[members] = fold
    bounds = np.cumsum(counts)
    codes = np.searchsorted(bounds, folds, side="right")
    return pd.Series(
        pd.Categorical.from_codes(codes, categories=list(SMS_SPLITS)), index=df.index, name="split"
    )


def template_overlap(train_texts: pd.Series, other_texts: pd.Series) -> int:
    """Messages de ``other_texts`` dont le gabarit est déjà vu à l'entraînement."""
    seen = set(train_texts.map(template_key))
    return int(other_texts.map(template_key).isin(seen).sum())


# --------------------------------------------------------------------------- #
# Jeu complémentaire français / arabe (étape 1.9)
# --------------------------------------------------------------------------- #

FR_AR_COLUMNS = ["id", "lang", "label", "category", "text"]
FR_AR_LANGS = frozenset({"fr", "ar"})


def load_sms_fr_ar(path: Path) -> pd.DataFrame:
    """Charge ``datasets/sms_fr_ar.csv`` (voir ``datasets/README.md``) et le valide.

    Lève ``ValueError`` si une colonne manque, si une langue ou une étiquette est inconnue,
    si un identifiant est répété ou si un message est vide.
    """
    df = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8")
    missing = [c for c in FR_AR_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"colonnes absentes : {missing}")
    if not set(df["lang"]) <= FR_AR_LANGS:
        raise ValueError(f"langues inconnues : {sorted(set(df['lang']) - FR_AR_LANGS)}")
    if not set(df["label"]) <= {"0", "1"}:
        raise ValueError("étiquettes attendues : 0 (légitime) ou 1 (smishing)")
    if df["id"].duplicated().any():
        raise ValueError("identifiants en double")
    if (df["text"].str.strip() == "").any():
        raise ValueError("message vide détecté")
    return df[FR_AR_COLUMNS].astype({"label": int})
