"""Mises à jour planifiées du modèle URL et garde-fou de non-régression (étape 6.8).

Le phishing change vite : un modèle vieillit en quelques mois. Chaque mois, le workflow
``model-update.yml`` réentraîne un **candidat** avec les données récentes. Ce module dit
s'il a le droit de remplacer le modèle en service.

Trois jeux d'évaluation, trois questions :

- **test figé** (``freeze_test_set``) : un bloc de test gelé une fois pour toutes,
  chiffré hors du dépôt, dont l'empreinte est versionnée. Il répond à « le candidat
  est-il au moins aussi bon que l'actuel **sur la même mesure** ? ». Ses domaines sont
  retirés des données d'entraînement du candidat (``exclude_frozen_domains``), sinon le
  candidat serait jugé sur des sites qu'il a appris ;
- **test récent** : le bloc de test du nouveau split, les domaines les plus récents de
  chaque source. Il répond à « le candidat suit-il les campagnes actuelles ? ». Il est
  rapporté pour les deux modèles et doit, lui aussi, ne pas baisser ;
- **sites légitimes courants** (``urls/data/common_legitimate_urls.json``) : pages de
  connexion et d'accueil de services que tout le monde utilise. Une alerte sur l'une
  d'elles coûte la confiance de l'utilisateur ; le candidat ne doit pas en signaler une
  de plus que l'actuel.

Règle (``decide``) : le candidat n'est publié que si **aucune** vérification n'échoue.
Le rappel à 1 % de faux positifs ne doit pas baisser (tolérance nulle par défaut) et le
nombre de faux positifs sur les sites courants ne doit pas augmenter. Le garde-fou ne
signe rien : la signature reste sur la machine de l'auteur (docs/model-registry.md).
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

import numpy as np
import pandas as pd

from phishguard.evaluation.metrics import recall_at_fpr

GATE_VERSION = "1.0.0"
FROZEN_FORMAT_VERSION = 1
MAX_FPR = 0.01
FROZEN_COLUMNS = ("url", "label", "source", "first_seen", "registered_domain")
LEGITIMATE_URLS_RESOURCE = "common_legitimate_urls.json"


class ScoringModel(Protocol):
    """Ce que le garde-fou attend d'un modèle (``phishguard.urls.model.UrlModel``)."""

    def score(self, urls: Iterable[str]) -> np.ndarray: ...

    def predict(self, urls: Iterable[str]) -> np.ndarray: ...


# --------------------------------------------------------------------------- #
# Test figé
# --------------------------------------------------------------------------- #


def _frame_sha256(frame: pd.DataFrame) -> str:
    """Empreinte du contenu, indépendante du fichier parquet (compression, version)."""
    digest = hashlib.sha256()
    ordered = frame.loc[:, list(FROZEN_COLUMNS)].sort_values(["url", "label"], kind="stable")
    for row in ordered.itertuples(index=False):
        first_seen = row.first_seen.isoformat() if not pd.isna(row.first_seen) else ""
        line = "\t".join(
            [row.url, str(int(row.label)), row.source, first_seen, row.registered_domain]
        )
        digest.update(line.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def freeze_test_set(split_path: Path, output: Path, *, created_at: datetime | None = None) -> dict:
    """Gèle le bloc de test de ``split_path`` dans ``output`` et décrit ce qui a été gelé.

    Le rapport ne contient ni URL ni domaine : il est versionné
    (``docs/metrics/frozen_test.json``) et son empreinte sert d'ancre d'intégrité au
    fichier chiffré, lui hors du dépôt.
    """
    frame = pd.read_parquet(
        split_path, columns=[*FROZEN_COLUMNS], filters=[("split", "==", "test")]
    )
    if frame.empty or frame["label"].nunique() != 2:
        raise ValueError("bloc de test vide ou sans les deux classes")
    frame = frame.reset_index(drop=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(output, index=False)
    created = (created_at or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    return {
        "format_version": FROZEN_FORMAT_VERSION,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "rows": len(frame),
        "phishing": int(frame["label"].sum()),
        "registered_domains": int(frame["registered_domain"].nunique()),
        "sources": {k: int(v) for k, v in frame["source"].value_counts().sort_index().items()},
        "first_seen": {
            "min": frame["first_seen"].min().isoformat(),
            "max": frame["first_seen"].max().isoformat(),
        },
        "content_sha256": _frame_sha256(frame),
    }


def load_frozen_test_set(path: Path, expected_sha256: str) -> pd.DataFrame:
    """Relit le test figé et refuse tout contenu différent de celui gelé."""
    frame = pd.read_parquet(path, columns=[*FROZEN_COLUMNS])
    actual = _frame_sha256(frame)
    if actual != expected_sha256:
        raise ValueError(
            f"test figé modifié : empreinte {actual[:16]}…, attendue {expected_sha256[:16]}…"
        )
    return frame


def exclude_frozen_domains(dataset: pd.DataFrame, frozen: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Retire du jeu d'entraînement tout domaine enregistré présent dans le test figé.

    Sans cela, le nouveau split pourrait placer en entraînement un domaine du test figé,
    et le candidat serait jugé sur des sites qu'il a appris (fuite mesurée à l'étape 1.3).
    """
    frozen_domains = set(frozen["registered_domain"])
    keep = ~dataset["registered_domain"].isin(frozen_domains)
    return dataset.loc[keep].reset_index(drop=True), int((~keep).sum())


# --------------------------------------------------------------------------- #
# Sites légitimes courants
# --------------------------------------------------------------------------- #


def load_legitimate_urls() -> list[str]:
    """URLs légitimes courantes (accueil et connexion), relues depuis le paquet."""
    text = (
        resources.files("phishguard.urls")
        .joinpath("data", LEGITIMATE_URLS_RESOURCE)
        .read_text(encoding="utf-8")
    )
    document = json.loads(text)
    urls = [url for group in document["groups"] for url in group["urls"]]
    if len(set(urls)) != len(urls):
        raise ValueError(f"{LEGITIMATE_URLS_RESOURCE} : URL en double")
    return urls


# --------------------------------------------------------------------------- #
# Évaluation et décision
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ModelEvaluation:
    model_version: str
    recall_frozen: float
    recall_recent: float
    legitimate_false_positives: tuple[str, ...]

    @property
    def legitimate_false_positive_count(self) -> int:
        return len(self.legitimate_false_positives)


def _recall(model: ScoringModel, frame: pd.DataFrame) -> float:
    if frame.empty or frame["label"].nunique() != 2:
        raise ValueError("jeu d'évaluation vide ou sans les deux classes")
    return recall_at_fpr(frame["label"].to_numpy(), model.score(frame["url"]), MAX_FPR)


def evaluate_model(
    model: ScoringModel,
    *,
    model_version: str,
    frozen: pd.DataFrame,
    recent: pd.DataFrame,
    legitimate_urls: Sequence[str],
) -> ModelEvaluation:
    flagged = np.asarray(model.predict(list(legitimate_urls)), dtype=bool)
    return ModelEvaluation(
        model_version=model_version,
        recall_frozen=_recall(model, frozen),
        recall_recent=_recall(model, recent),
        legitimate_false_positives=tuple(
            u for u, f in zip(legitimate_urls, flagged, strict=True) if f
        ),
    )


@dataclass(frozen=True)
class GateCheck:
    name: str
    current: float
    candidate: float
    passed: bool
    rule: str


@dataclass(frozen=True)
class GateDecision:
    passed: bool
    checks: tuple[GateCheck, ...]
    new_false_positives: tuple[str, ...] = field(default=())
    recall_tolerance: float = 0.0


def decide(
    current: ModelEvaluation, candidate: ModelEvaluation, *, recall_tolerance: float = 0.0
) -> GateDecision:
    """Le candidat passe si aucune vérification n'échoue (voir la doc du module)."""
    if not 0.0 <= recall_tolerance < 0.05 or math.isnan(recall_tolerance):
        raise ValueError("tolérance de rappel : entre 0 et 0,05")

    # Arrondi à 1e-9 : deux modèles identiques ne doivent pas échouer sur un bruit flottant.
    def not_lower(new: float, old: float) -> bool:
        return round(new - old + recall_tolerance, 9) >= 0

    checks = (
        GateCheck(
            "recall_at_fpr_1pct_frozen",
            current.recall_frozen,
            candidate.recall_frozen,
            not_lower(candidate.recall_frozen, current.recall_frozen),
            "rappel à 1 % de FPR sur le test figé : ne baisse pas",
        ),
        GateCheck(
            "recall_at_fpr_1pct_recent",
            current.recall_recent,
            candidate.recall_recent,
            not_lower(candidate.recall_recent, current.recall_recent),
            "rappel à 1 % de FPR sur le test récent : ne baisse pas",
        ),
        GateCheck(
            "legitimate_false_positives",
            current.legitimate_false_positive_count,
            candidate.legitimate_false_positive_count,
            candidate.legitimate_false_positive_count <= current.legitimate_false_positive_count,
            "faux positifs sur les sites légitimes courants : n'augmentent pas",
        ),
    )
    known = set(current.legitimate_false_positives)
    new_fp = tuple(url for url in candidate.legitimate_false_positives if url not in known)
    return GateDecision(
        passed=all(c.passed for c in checks),
        checks=checks,
        new_false_positives=new_fp,
        recall_tolerance=recall_tolerance,
    )


def gate_report(
    decision: GateDecision,
    current: ModelEvaluation,
    candidate: ModelEvaluation,
    *,
    frozen_rows: int,
    recent_rows: int,
    legitimate_rows: int,
    generated_at: datetime | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Rapport JSON du garde-fou, publié avec le candidat (aucune donnée personnelle)."""
    generated = (generated_at or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    return {
        "gate_version": GATE_VERSION,
        "generated_at": generated.isoformat().replace("+00:00", "Z"),
        "passed": decision.passed,
        "recall_tolerance": decision.recall_tolerance,
        "rows": {"frozen": frozen_rows, "recent": recent_rows, "legitimate": legitimate_rows},
        "checks": [asdict(c) for c in decision.checks],
        "current": {
            **asdict(current),
            "legitimate_false_positives": list(current.legitimate_false_positives),
        },
        "candidate": {
            **asdict(candidate),
            "legitimate_false_positives": list(candidate.legitimate_false_positives),
        },
        "new_false_positives": list(decision.new_false_positives),
        **(extra or {}),
    }


def render_markdown(report: dict[str, Any]) -> str:
    """Résumé lisible pour le résumé du job GitHub Actions et la release."""
    verdict = "✅ **Candidat accepté**" if report["passed"] else "❌ **Candidat refusé**"
    lines = [
        f"## Garde-fou de non-régression : {verdict}",
        "",
        "| Vérification | Actuel | Candidat | Résultat |",
        "| --- | ---: | ---: | :---: |",
    ]
    for check in report["checks"]:
        fmt = (
            (lambda v: f"{v:.4f}")
            if check["name"].startswith("recall")
            else (lambda v: f"{int(v)}")
        )
        mark = "✅" if check["passed"] else "❌"
        lines.append(
            f"| {check['rule']} | {fmt(check['current'])} | {fmt(check['candidate'])} | {mark} |"
        )
    rows = report["rows"]
    lines += [
        "",
        (
            f"Jeux : test figé {rows['frozen']} URLs, test récent {rows['recent']} URLs, "
            f"{rows['legitimate']} sites légitimes courants. Tolérance de rappel : "
            f"{report['recall_tolerance']}."
        ),
    ]
    if report["new_false_positives"]:
        lines += ["", "Nouveaux faux positifs sur les sites courants :", ""]
        lines += [f"- `{url}`" for url in report["new_false_positives"]]
    return "\n".join(lines) + "\n"
