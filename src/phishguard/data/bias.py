"""Audit des biais du jeu d'URLs, à mener avant tout entraînement (étape 1.3).

Un jeu de données peut contenir des *raccourcis* : des indices qui séparent les classes
dans le jeu mais pas dans la réalité. Un modèle qui les apprend obtient d'excellents
scores hors ligne et devient inutile en production. Ce module en cherche quatre :

1. **Structure (biais de chemin)** : les URLs légitimes viennent de Tranco, qui ne
   publie que des domaines. Si aucune URL légitime n'a de chemin, de ``http`` ou de
   sous-domaine, ces traits suffisent à « détecter » le phishing.
2. **Source** : si le phishing provient d'une seule source, le modèle apprend son style.
3. **Domaine** : un domaine vu à l'entraînement et retrouvé au test gonfle les scores.
4. **Temps** : les deux classes n'ont pas été observées sur la même période.

Méthode : un *modèle sonde* volontairement simple (n-grammes de caractères + régression
logistique, :func:`make_probe`). Ce n'est pas le modèle final (étapes 1.5 et 1.6) : il
sert de détecteur de raccourcis. On compare ses scores selon la partie de l'URL qu'on lui
montre (:data:`REPRESENTATIONS`), selon le protocole de découpage et selon la source.

Toutes les sorties sont agrégées : aucune URL ni aucun domaine n'y figure, elles peuvent
être versionnées dans un dépôt public.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler

from phishguard.data.urls import LABEL_LEGITIMATE, LABEL_PHISHING
from phishguard.evaluation.metrics import binary_report

logger = logging.getLogger(__name__)

# Ce que le modèle sonde voit de l'URL, du plus complet au plus pauvre. Seul le domaine
# enregistré a la même forme dans les deux classes : c'est la représentation de référence.
REPRESENTATIONS = ("url", "origin", "host", "registered_domain")

BOOLEAN_TRAITS = (
    "is_http",
    "has_path",
    "has_query",
    "has_fragment",
    "has_userinfo",
    "has_port",
    "is_ip",
    "has_www",
    "has_subdomain",
)
NUMERIC_TRAITS = ("subdomain_depth", "path_depth", "url_length")
TRAITS = BOOLEAN_TRAITS + NUMERIC_TRAITS

# Métriques retenues dans le rapport (voir phishguard.evaluation.metrics).
_REPORTED_METRICS = ("pr_auc", "roc_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct")


@dataclass(frozen=True)
class ProbeConfig:
    """Paramètres du modèle sonde et des découpages."""

    ngram_range: tuple[int, int] = (3, 5)
    min_df: int = 3
    max_features: int = 2**18
    C: float = 1.0
    test_size: float = 0.2
    seed: int = 42
    # Effectif minimal d'une source de phishing pour l'évaluer séparément.
    min_source_rows: int = 200


# --------------------------------------------------------------------------- #
# Structure des URLs
# --------------------------------------------------------------------------- #


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def url_traits(df: pd.DataFrame) -> pd.DataFrame:
    """Traits structurels de chaque URL (colonnes :data:`TRAITS`).

    ``df`` suit le schéma de :mod:`phishguard.data.urls` : URLs normalisées, dont le
    chemin vaut au moins ``/``.
    """
    parts = df["url"].map(urlsplit)
    path = parts.map(lambda p: p.path)
    host_labels = df["host"].str.count(r"\.") + 1
    domain_labels = df["registered_domain"].str.count(r"\.") + 1
    is_ip = df["host"].map(_is_ip)

    traits = pd.DataFrame(index=df.index)
    traits["is_http"] = parts.map(lambda p: p.scheme == "http")
    traits["has_path"] = path != "/"
    traits["has_query"] = parts.map(lambda p: p.query != "")
    traits["has_fragment"] = parts.map(lambda p: p.fragment != "")
    traits["has_userinfo"] = parts.map(lambda p: "@" in p.netloc)
    traits["has_port"] = parts.map(lambda p: p.port is not None)
    traits["is_ip"] = is_ip
    traits["has_www"] = df["host"].str.startswith("www.")
    traits["subdomain_depth"] = (host_labels - domain_labels).where(~is_ip, 0).clip(lower=0)
    traits["has_subdomain"] = traits["subdomain_depth"] > 0
    traits["path_depth"] = path.map(lambda p: sum(1 for segment in p.split("/") if segment))
    traits["url_length"] = df["url"].str.len()
    return traits[list(TRAITS)]


def structure_profile(df: pd.DataFrame, by: str) -> dict[str, dict[str, float]]:
    """Profil structurel par groupe (``label`` ou ``source``).

    Traits booléens : part des URLs concernées. Traits numériques : médiane.
    """
    traits = url_traits(df)
    profile: dict[str, dict[str, float]] = {}
    for key, group in traits.groupby(df[by]):
        row = {name: round(float(group[name].mean()), 4) for name in BOOLEAN_TRAITS}
        row.update({f"{name}_median": float(group[name].median()) for name in NUMERIC_TRAITS})
        row["rows"] = len(group)
        profile[str(key)] = row
    return profile


def trait_auc(df: pd.DataFrame) -> dict[str, float]:
    """ROC-AUC obtenue en utilisant **un seul** trait comme score de phishing.

    0,5 : le trait ne sépare pas les classes. Loin de 0,5 (dans un sens ou dans l'autre) :
    le trait suffit à lui seul à séparer les classes, ce qui signale un raccourci quand il
    n'a pas de raison d'être aussi discriminant dans la réalité.
    """
    traits = url_traits(df)
    return {
        name: round(float(roc_auc_score(df["label"], traits[name].astype(float))), 4)
        for name in TRAITS
    }


def represent(df: pd.DataFrame, level: str) -> pd.Series:
    """Partie de l'URL montrée au modèle sonde (voir :data:`REPRESENTATIONS`).

    - ``url`` : URL complète ;
    - ``origin`` : schéma et hôte (``https://a.b.example/``), sans chemin ni paramètres ;
    - ``host`` : hôte seul, sans schéma ;
    - ``registered_domain`` : domaine enregistré seul, sans sous-domaine.
    """
    if level == "url":
        return df["url"]
    if level == "origin":
        scheme = df["url"].str.extract(r"^([a-z]+)://", expand=False)
        return scheme + "://" + df["host"] + "/"
    if level in ("host", "registered_domain"):
        return df[level]
    raise ValueError(f"représentation inconnue : {level!r} (attendu : {REPRESENTATIONS})")


# --------------------------------------------------------------------------- #
# Modèle sonde et protocoles
# --------------------------------------------------------------------------- #


def make_probe(cfg: ProbeConfig) -> Pipeline:
    """N-grammes de caractères TF-IDF + régression logistique à classes équilibrées."""
    return make_pipeline(
        TfidfVectorizer(
            analyzer="char",
            ngram_range=cfg.ngram_range,
            min_df=cfg.min_df,
            max_features=cfg.max_features,
            sublinear_tf=True,
            lowercase=False,
            dtype=np.float32,
        ),
        LogisticRegression(C=cfg.C, class_weight="balanced", max_iter=2000),
    )


def _structure_model() -> Pipeline:
    """Régression logistique sur les seuls traits structurels."""
    return make_pipeline(
        StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=2000)
    )


def grouped_holdout(df: pd.DataFrame, test_size: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Positions ``(train, test)`` telles qu'aucun domaine enregistré ne soit des deux côtés.

    ``test_size`` est une proportion de *domaines*, pas de lignes.
    """
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train, test = next(splitter.split(df, groups=df["registered_domain"]))
    return train, test


def _fit_and_score(
    model: Pipeline, x_train: Any, y_train: pd.Series, x_test: Any, y_test: pd.Series
) -> dict[str, Any]:
    model.fit(x_train, y_train)
    report = binary_report(y_test, model.predict_proba(x_test)[:, 1])
    return {
        "train_rows": len(y_train),
        "test_rows": len(y_test),
        "test_phishing_rate": round(float(np.mean(y_test)), 4),
        **{name: report[name] for name in _REPORTED_METRICS},
    }


def _probe_score(train: pd.DataFrame, test: pd.DataFrame, level: str, cfg: ProbeConfig) -> dict:
    return _fit_and_score(
        make_probe(cfg),
        represent(train, level),
        train["label"],
        represent(test, level),
        test["label"],
    )


def representation_ablation(df: pd.DataFrame, cfg: ProbeConfig) -> dict[str, dict]:
    """Score du modèle sonde pour chaque représentation, sur un même split groupé.

    Si l'URL complète fait nettement mieux que le domaine enregistré, une partie du score
    vient du chemin, du schéma ou des sous-domaines, que les deux classes ne partagent pas.
    S'y ajoute un modèle qui ne voit **que** les traits structurels : son score mesure
    directement la force du raccourci.
    """
    train_pos, test_pos = grouped_holdout(df, cfg.test_size, cfg.seed)
    train, test = df.iloc[train_pos], df.iloc[test_pos]

    results: dict[str, dict] = {}
    for level in REPRESENTATIONS:
        logger.info("ablation : représentation %s", level)
        results[level] = _probe_score(train, test, level, cfg)
    logger.info("ablation : traits structurels seuls")
    results["structural_traits_only"] = _fit_and_score(
        _structure_model(),
        url_traits(train).astype(float),
        train["label"],
        url_traits(test).astype(float),
        test["label"],
    )
    return results


def domain_leakage(df: pd.DataFrame, cfg: ProbeConfig, level: str = "url") -> dict[str, dict]:
    """Compare un split aléatoire et un split groupé par domaine enregistré.

    Le split aléatoire laisse un même domaine des deux côtés : le modèle reconnaît alors le
    domaine au lieu de juger l'URL, et le score obtenu est optimiste.
    """
    random_train, random_test = train_test_split(
        df, test_size=cfg.test_size, random_state=cfg.seed, stratify=df["label"]
    )
    train_pos, test_pos = grouped_holdout(df, cfg.test_size, cfg.seed)
    splits = {
        "random": (random_train, random_test),
        "grouped_by_domain": (df.iloc[train_pos], df.iloc[test_pos]),
    }

    results: dict[str, dict] = {}
    for name, (train, test) in splits.items():
        logger.info("fuite par domaine : split %s", name)
        leaked = test["registered_domain"].isin(set(train["registered_domain"]))
        results[name] = {
            "test_rows_with_domain_in_train": int(leaked.sum()),
            "test_share_with_domain_in_train": round(float(leaked.mean()), 4),
            **_probe_score(train, test, level, cfg),
        }
    return results


def phishing_sources(df: pd.DataFrame, min_rows: int) -> list[str]:
    """Sources de phishing assez fournies pour être évaluées séparément."""
    counts = df.loc[df["label"] == LABEL_PHISHING, "source"].value_counts()
    return sorted(counts.index[counts >= min_rows])


def cross_source(df: pd.DataFrame, cfg: ProbeConfig, level: str = "url") -> dict[str, dict]:
    """Évalue la généralisation d'une source de phishing à l'autre.

    Pour chaque source cible, un même jeu de test (une part groupée de la source cible et
    une part groupée du légitime) départage deux modèles :

    - ``with_target`` : entraîné sur toutes les sources, part de test exclue ;
    - ``without_target`` : entraîné sans **aucune** URL de la source cible.

    Un écart important signifie que le modèle reconnaît le style d'une source plutôt que
    le phishing. Aucun domaine de test n'apparaît à l'entraînement, quelle que soit sa classe.
    """
    phishing = df[df["label"] == LABEL_PHISHING]
    legit = df[df["label"] == LABEL_LEGITIMATE]
    legit_train_pos, legit_test_pos = grouped_holdout(legit, cfg.test_size, cfg.seed)
    legit_train, legit_test = legit.iloc[legit_train_pos], legit.iloc[legit_test_pos]

    sources = phishing_sources(df, cfg.min_source_rows)
    results: dict[str, dict] = {}
    for target in sources:
        target_rows = phishing[phishing["source"] == target]
        others = phishing[phishing["source"] != target]
        if others.empty:
            continue
        target_train_pos, target_test_pos = grouped_holdout(target_rows, cfg.test_size, cfg.seed)
        test = pd.concat([target_rows.iloc[target_test_pos], legit_test])
        test_domains = set(test["registered_domain"])

        def disjoint(frame: pd.DataFrame, domains: set[str] = test_domains) -> pd.DataFrame:
            return frame[~frame["registered_domain"].isin(domains)]

        trainings = {
            "with_target": pd.concat(
                [
                    disjoint(target_rows.iloc[target_train_pos]),
                    disjoint(others),
                    disjoint(legit_train),
                ]
            ),
            "without_target": pd.concat([disjoint(others), disjoint(legit_train)]),
        }
        results[target] = {}
        for name, train in trainings.items():
            logger.info("biais de source : cible %s, modèle %s", target, name)
            results[target][name] = _probe_score(train, test, level, cfg)
        results[target]["pr_auc_drop"] = round(
            results[target]["with_target"]["pr_auc"] - results[target]["without_target"]["pr_auc"],
            4,
        )
    return results


def source_fingerprint(df: pd.DataFrame, cfg: ProbeConfig, level: str = "url") -> dict[str, float]:
    """ROC-AUC d'un modèle qui devine la source d'une URL de phishing (un contre tous).

    Proche de 0,5 : les sources se ressemblent. Proche de 1 : chaque source a un style
    reconnaissable, que le détecteur risque d'apprendre à la place du phishing.
    """
    sources = phishing_sources(df, cfg.min_source_rows)
    if len(sources) < 2:
        return {}
    phishing = df[(df["label"] == LABEL_PHISHING) & df["source"].isin(sources)]
    train_pos, test_pos = grouped_holdout(phishing, cfg.test_size, cfg.seed)
    train, test = phishing.iloc[train_pos], phishing.iloc[test_pos]

    # Avec deux sources, « A contre B » et « B contre A » donnent la même AUC.
    targets = sources if len(sources) > 2 else sources[:1]
    results: dict[str, float] = {}
    for source in targets:
        logger.info("empreinte de source : %s", source)
        model = make_probe(cfg).fit(represent(train, level), train["source"] == source)
        scores = model.predict_proba(represent(test, level))[:, 1]
        results[source] = round(float(roc_auc_score(test["source"] == source, scores)), 4)
    return results


# --------------------------------------------------------------------------- #
# Faux positifs sur les pages internes légitimes
# --------------------------------------------------------------------------- #

HOMEPAGE_SOURCE = "tranco"
INTERNAL_PAGE_SOURCE = "commoncrawl"


def _flagged(scores: np.ndarray, threshold: float) -> float:
    return round(float(np.mean(scores > threshold)), 4)


def internal_page_fpr(
    df: pd.DataFrame, cfg: ProbeConfig, level: str = "url", max_fpr: float = 0.01
) -> dict[str, Any]:
    """Faux positifs du modèle sonde sur des pages internes légitimes jamais vues.

    Un même split groupé par domaine départage deux modèles :

    - ``without_internal_pages`` : entraîné sans les pages Common Crawl, comme avant
      l'étape 1.3 bis (le légitime n'est fait que de pages d'accueil) ;
    - ``with_internal_pages`` : entraîné avec.

    Le seuil de chaque modèle est réglé pour ``max_fpr`` faux positifs sur les pages
    d'accueil du test, c'est-à-dire tel qu'on l'aurait validé avec Tranco seul. On mesure
    alors la part des pages internes du test signalées à tort, et le rappel du phishing.
    Un modèle qui a appris « chemin = phishing » signale beaucoup plus de pages internes
    que de pages d'accueil.
    """
    if not (df["source"] == INTERNAL_PAGE_SOURCE).any():
        return {}
    train_pos, test_pos = grouped_holdout(df, cfg.test_size, cfg.seed)
    train, test = df.iloc[train_pos], df.iloc[test_pos]
    groups = {
        "homepages": test[
            (test["label"] == LABEL_LEGITIMATE) & (test["source"] == HOMEPAGE_SOURCE)
        ],
        "internal_pages": test[test["source"] == INTERNAL_PAGE_SOURCE],
        "phishing": test[test["label"] == LABEL_PHISHING],
    }
    if any(group.empty for group in groups.values()):
        logger.warning("pages internes : une catégorie est absente du test, mesure ignorée")
        return {}

    trainings = {
        "without_internal_pages": train[train["source"] != INTERNAL_PAGE_SOURCE],
        "with_internal_pages": train,
    }
    results: dict[str, Any] = {
        "max_fpr_on_homepages": max_fpr,
        "test_rows": {name: len(group) for name, group in groups.items()},
    }
    for name, training in trainings.items():
        logger.info("pages internes : modèle %s", name)
        model = make_probe(cfg).fit(represent(training, level), training["label"])
        scores = {
            key: model.predict_proba(represent(group, level))[:, 1] for key, group in groups.items()
        }
        # Plus petit seuil laissant au plus max_fpr des pages d'accueil au-dessus.
        threshold = float(np.quantile(scores["homepages"], 1 - max_fpr, method="higher"))
        results[name] = {
            "train_rows": len(training),
            "threshold": round(threshold, 6),
            "fpr_homepages": _flagged(scores["homepages"], threshold),
            "fpr_internal_pages": _flagged(scores["internal_pages"], threshold),
            "recall_phishing": _flagged(scores["phishing"], threshold),
            "fpr_internal_pages_at_0_5": _flagged(scores["internal_pages"], 0.5),
            "recall_phishing_at_0_5": _flagged(scores["phishing"], 0.5),
        }
    return results


# --------------------------------------------------------------------------- #
# Temps et domaines partagés
# --------------------------------------------------------------------------- #


def temporal_profile(
    df: pd.DataFrame, fractions: tuple[float, float, float] = (0.70, 0.15, 0.15)
) -> dict[str, Any]:
    """Période couverte par chaque source et effet d'un split temporel naïf.

    Le split naïf trie tout le jeu par ``first_seen`` et le coupe selon ``fractions``
    (entraînement, validation, test) : c'est ce que ferait l'étape 1.4 sans précaution.
    """
    if not np.isclose(sum(fractions), 1.0):
        raise ValueError("les fractions doivent sommer à 1")

    by_source = {}
    for source, group in df.groupby("source"):
        seen = group["first_seen"]
        by_source[str(source)] = {
            "rows": len(group),
            "min": seen.min().isoformat(),
            "median": seen.median().isoformat(),
            "max": seen.max().isoformat(),
        }

    ordered = df.sort_values("first_seen", kind="stable")
    cuts = np.rint(np.cumsum([0.0, *fractions]) * len(ordered)).astype(int)
    blocks = {}
    for name, start, stop in zip(("train", "validation", "test"), cuts[:-1], cuts[1:], strict=True):
        block = ordered.iloc[start:stop]
        blocks[name] = {
            "rows": len(block),
            "phishing_rate": round(float(block["label"].mean()), 4) if len(block) else None,
        }

    legit_start = df.loc[df["label"] == LABEL_LEGITIMATE, "first_seen"].min()
    phishing_seen = df.loc[df["label"] == LABEL_PHISHING, "first_seen"]
    return {
        "by_source": by_source,
        "naive_temporal_split": blocks,
        # Phishing observé avant la première URL légitime : aucune URL légitime de la même
        # époque ne lui fait face.
        "phishing_share_before_first_legitimate": round(
            float((phishing_seen < legit_start).mean()), 4
        ),
    }


def shared_domains(df: pd.DataFrame) -> dict[str, int]:
    """Domaines enregistrés présents dans les deux classes (hébergeurs, raccourcisseurs…)."""
    labels_per_domain = df.groupby("registered_domain")["label"].nunique()
    shared = labels_per_domain.index[labels_per_domain > 1]
    rows = df["registered_domain"].isin(shared)
    return {
        "domains": len(shared),
        "rows": int(rows.sum()),
        "phishing_rows": int((rows & (df["label"] == LABEL_PHISHING)).sum()),
    }


# --------------------------------------------------------------------------- #
# Validation externe
# --------------------------------------------------------------------------- #


def external_validation(
    train: pd.DataFrame, external: pd.DataFrame, cfg: ProbeConfig
) -> dict[str, Any]:
    """Entraîne la sonde sur tout ``train`` et la teste sur un jeu indépendant.

    Les domaines déjà présents dans ``train`` sont retirés du jeu externe. Une sonde qui
    s'effondre sur l'URL complète mais tient sur le domaine enregistré a appris la forme des
    URLs de son jeu, pas le phishing.
    """
    known = external["registered_domain"].isin(set(train["registered_domain"]))
    test = external[~known]
    results: dict[str, Any] = {
        "rows": len(external),
        "rows_excluded_known_domain": int(known.sum()),
        "structure_by_label": structure_profile(external, "label"),
        "trait_auc": trait_auc(external),
        "probe": {},
    }
    if test["label"].nunique() < 2:
        logger.warning("validation externe : une seule classe après exclusion des domaines")
        return results
    for level in REPRESENTATIONS:
        logger.info("validation externe : représentation %s", level)
        results["probe"][level] = _probe_score(train, test, level, cfg)
    return results


# --------------------------------------------------------------------------- #
# Audit complet
# --------------------------------------------------------------------------- #


def audit(
    df: pd.DataFrame, cfg: ProbeConfig | None = None, external: pd.DataFrame | None = None
) -> dict[str, Any]:
    """Exécute tous les contrôles et retourne un rapport agrégé (aucune URL)."""
    cfg = cfg or ProbeConfig()
    if df["label"].nunique() < 2:
        raise ValueError("le jeu doit contenir les deux classes")

    report: dict[str, Any] = {
        "config": asdict(cfg),
        "dataset": {
            "rows": len(df),
            "rows_by_label": {str(k): int(v) for k, v in df["label"].value_counts().items()},
            "rows_by_source": {str(k): int(v) for k, v in df["source"].value_counts().items()},
        },
        "structure": {
            "by_label": structure_profile(df, "label"),
            "by_source": structure_profile(df, "source"),
            "trait_auc": trait_auc(df),
            "representation_ablation": representation_ablation(df, cfg),
            "internal_page_fpr": internal_page_fpr(df, cfg),
        },
        "source": {
            "cross_source": cross_source(df, cfg),
            "fingerprint_roc_auc": source_fingerprint(df, cfg),
        },
        "domain": {
            "shared_between_labels": shared_domains(df),
            "leakage": domain_leakage(df, cfg),
        },
        "time": temporal_profile(df),
    }
    if external is not None:
        report["external_validation"] = external_validation(df, external, cfg)
    return report
