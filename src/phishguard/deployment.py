"""Modèles déployés et chargement des trois analyseurs (étape 3.12).

Point unique qui dit **quels** modèles servent l'analyse : l'API (module 4), le bot et
la page web (module 5) chargent leurs analyseurs par :func:`load_analyzers`, jamais en
codant un chemin en dur. Changer de modèle, c'est changer :data:`DEPLOYED_MODELS`, et
le diff le montre.

Choix de l'étape 3.12, mesurés dans ``docs/robustness-report.md`` :

- **texte : ``text_v2``** (entraînement adversarial, étape 3.9). Rappel propre
  identique à ``text_v1``, faux positifs plus bas (1,18 % contre 1,47 %), moitié moins
  de faux positifs sous leetspeak ;
- **URL : ``url_v2``** (entraînement adversarial, étape 3.9). C'est un compromis
  assumé : sur le test, la PR-AUC passe de 0,939 à 0,910 et le rappel au seuil de
  décision de 73,9 % à 63,6 %. En échange, deux sous-domaines ajoutés ne font plus
  perdre 12,5 points de rappel, et un long paramètre de suivi (liens d'emailing) ne fait
  plus signaler 49 % des URLs légitimes, mais 0,8 %. ``url_v1`` gagne sur un test
  construit comme son entraînement ; ``url_v2`` tient face à un attaquant qui ajoute
  ``support.`` devant son hôte. La Threat Intelligence (module 2) compense une partie
  du rappel perdu ;
- **email : règles transparentes** de l'étape 1.11, avec la règle ``url_model`` sur le
  modèle URL déployé. Chaque point a une raison lisible.

Les fichiers (``models/*.joblib``) ne sont pas versionnés : ils sont produits par
``make train train-adversarial`` puis calibrés (``scripts/calibrate_url.py`` et
``scripts/calibrate_text.py`` avec ``--model``). La distribution signée arrive à
l'étape 4.12. **Charger un modèle exécute du code (pickle)** : fichiers de confiance
seulement.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from phishguard.analysis import EmailAnalyzer, TextAnalyzer, UrlAnalyzer
from phishguard.enrichers.orchestrator import Orchestrator
from phishguard.fusion.calibration import ScoreCalibrator

logger = logging.getLogger(__name__)

DEPLOYED_MODELS: dict[str, str] = {"url": "url_v2", "text": "text_v2"}
DEFAULT_MODELS_DIR = Path("models")


@dataclass(frozen=True)
class ModelFiles:
    """Fichiers d'un modèle déployé : l'artefact et sa calibration (facultative)."""

    version: str
    model: Path
    calibration: Path


@dataclass(frozen=True)
class Analyzers:
    url: UrlAnalyzer
    text: TextAnalyzer
    email: EmailAnalyzer


def model_files(models_dir: Path = DEFAULT_MODELS_DIR) -> dict[str, ModelFiles]:
    """Chemins des modèles déployés dans ``models_dir``."""
    models_dir = Path(models_dir)
    return {
        kind: ModelFiles(
            version,
            models_dir / f"{version}.joblib",
            models_dir / f"{version}_calibration.json",
        )
        for kind, version in DEPLOYED_MODELS.items()
    }


def _calibrator(files: ModelFiles) -> ScoreCalibrator | None:
    if files.calibration.is_file():
        return ScoreCalibrator.load(files.calibration)
    logger.warning("%s introuvable : %s non calibré", files.calibration, files.version)
    return None


def load_analyzers(
    models_dir: Path = DEFAULT_MODELS_DIR,
    *,
    orchestrator: Orchestrator | None = None,
    trusted_authserv_ids: list[str] | None = None,
) -> Analyzers:
    """Les trois analyseurs, sur les modèles déployés.

    ``orchestrator`` : Threat Intelligence pour les URLs, utilisée seulement si
    l'utilisateur l'active pour une analyse. ``trusted_authserv_ids`` : identifiants des
    serveurs de réception de confiance (``mx.google.com``…) ; sans eux, un
    ``Authentication-Results`` forgé par l'expéditeur peut encore fournir DKIM et DMARC
    quand le serveur n'en écrit pas (docs/email-parser.md). Lève ``FileNotFoundError`` si
    un modèle déployé manque, avec la commande qui le produit.
    """
    from phishguard.text.models import TextModel
    from phishguard.urls.model import UrlModel

    files = model_files(models_dir)
    for item in files.values():
        if not item.model.is_file():
            raise FileNotFoundError(
                f"{item.model} introuvable : modèle déployé {item.version}, produit par "
                "« make train train-adversarial » (docs/robustness-report.md)"
            )
        logger.info("modèle déployé %s : %s", item.version, item.model)
    url_model = UrlModel.load(files["url"].model)
    text_model = TextModel.load(files["text"].model)
    for kind, model in (("url", url_model), ("text", text_model)):
        found = model.metadata.get("model_version")
        if found != files[kind].version:
            raise ValueError(
                f"{files[kind].model} contient le modèle {found!r}, {files[kind].version!r} attendu"
            )
    return Analyzers(
        url=UrlAnalyzer(url_model, calibrator=_calibrator(files["url"]), orchestrator=orchestrator),
        text=TextAnalyzer(text_model, calibrator=_calibrator(files["text"])),
        email=EmailAnalyzer(url_model, trusted_authserv_ids=trusted_authserv_ids),
    )
