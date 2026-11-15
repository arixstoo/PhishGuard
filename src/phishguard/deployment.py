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
``scripts/calibrate_text.py`` avec ``--model``). **Charger un modèle exécute du code
(pickle)** : fichiers de confiance seulement.

**Modèles signés (étape 4.12).** Avec ``public_key``, :func:`load_analyzers` vérifie la
signature Ed25519 du manifeste (``models/manifest.json``) **avant** de lire le moindre
modèle, puis désérialise les octets dont l'empreinte vient d'être contrôlée, jamais le
fichier relu ensuite. Un fichier modifié d'un seul octet, absent du manifeste ou remplacé
pendant le démarrage empêche le démarrage (:mod:`phishguard.registry`).
"""

from __future__ import annotations

import io
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from phishguard.analysis import EmailAnalyzer, TextAnalyzer, UrlAnalyzer
from phishguard.enrichers.orchestrator import Orchestrator
from phishguard.fusion.calibration import ScoreCalibrator
from phishguard.registry import VerifiedManifest, verify_manifest

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from phishguard.email.parser import EmailLimits

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
    # Manifeste signé vérifié au chargement ; None si les modèles ne sont pas signés.
    manifest: VerifiedManifest | None = None


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


def _calibrator(files: ModelFiles, manifest: VerifiedManifest | None) -> ScoreCalibrator | None:
    if manifest is not None:
        # Modèles signés : une calibration est signée avec son modèle, ou absente des deux.
        if files.calibration.name not in manifest.artifacts:
            logger.warning("%s non signée : %s non calibré", files.calibration.name, files.version)
            return None
        data = manifest.read(files.calibration.name)
        return ScoreCalibrator.from_dict(json.loads(data.decode("utf-8")))
    if files.calibration.is_file():
        return ScoreCalibrator.load(files.calibration)
    logger.warning("%s introuvable : %s non calibré", files.calibration, files.version)
    return None


def _model_source(item: ModelFiles, manifest: VerifiedManifest | None) -> Path | io.BytesIO:
    """Ce que l'on désérialise : les octets vérifiés si les modèles sont signés."""
    return item.model if manifest is None else io.BytesIO(manifest.read(item.model.name))


def load_analyzers(
    models_dir: Path = DEFAULT_MODELS_DIR,
    *,
    orchestrator: Orchestrator | None = None,
    email_limits: EmailLimits | None = None,
    public_key: Ed25519PublicKey | None = None,
    trusted_authserv_ids: list[str] | None = None,
) -> Analyzers:
    """Les trois analyseurs, sur les modèles déployés.

    ``orchestrator`` : Threat Intelligence pour les URLs, utilisée seulement si
    l'utilisateur l'active pour une analyse. ``email_limits`` : bornes du parseur
    d'email (l'API les resserre, étape 4.2). ``trusted_authserv_ids`` : identifiants des
    serveurs de réception de confiance (``mx.google.com``…) ; sans eux, un
    ``Authentication-Results`` forgé par l'expéditeur peut encore fournir DKIM et DMARC
    quand le serveur n'en écrit pas (docs/email-parser.md). ``public_key`` : exiger un
    manifeste signé par cette clé (lève :class:`~phishguard.registry.ManifestError`
    sinon). Lève ``FileNotFoundError`` si un modèle déployé manque, avec la commande qui
    le produit.
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
    manifest = verify_manifest(Path(models_dir), public_key) if public_key is not None else None
    if manifest is not None:
        logger.info(
            "manifeste %s vérifié (clé %s, %d fichiers)",
            manifest.release,
            manifest.key_id,
            len(manifest.artifacts),
        )
    # Un modèle hors du manifeste lève IntegrityError ici, avant toute désérialisation.
    url_source = _model_source(files["url"], manifest)
    text_source = _model_source(files["text"], manifest)
    url_model = UrlModel.load(url_source)
    text_model = TextModel.load(text_source)
    for kind, model in (("url", url_model), ("text", text_model)):
        found = model.metadata.get("model_version")
        if found != files[kind].version:
            raise ValueError(
                f"{files[kind].model} contient le modèle {found!r}, {files[kind].version!r} attendu"
            )
    return Analyzers(
        url=UrlAnalyzer(
            url_model, calibrator=_calibrator(files["url"], manifest), orchestrator=orchestrator
        ),
        text=TextAnalyzer(text_model, calibrator=_calibrator(files["text"], manifest)),
        email=EmailAnalyzer(
            url_model, limits=email_limits, trusted_authserv_ids=trusted_authserv_ids
        ),
        manifest=manifest,
    )
