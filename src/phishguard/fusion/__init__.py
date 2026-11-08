"""Fusion des signaux : modèle local calibré, Threat Intelligence et règles dures."""

from phishguard.fusion.calibration import ScoreCalibrator, adjust_prevalence
from phishguard.fusion.score import FusionConfig, FusionResult, default_config, fuse

__all__ = [
    "FusionConfig",
    "FusionResult",
    "ScoreCalibrator",
    "adjust_prevalence",
    "default_config",
    "fuse",
]
