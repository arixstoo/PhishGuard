"""Fusion des signaux : modèle local calibré, Threat Intelligence et règles dures."""

from phishguard.fusion.calibration import ScoreCalibrator, adjust_prevalence
from phishguard.fusion.mitre import Observations, Technique, map_techniques
from phishguard.fusion.score import FusionConfig, FusionResult, default_config, fuse

__all__ = [
    "FusionConfig",
    "FusionResult",
    "Observations",
    "ScoreCalibrator",
    "Technique",
    "adjust_prevalence",
    "default_config",
    "fuse",
    "map_techniques",
]
