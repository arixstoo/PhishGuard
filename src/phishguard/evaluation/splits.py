"""Split stratifié et groupé en trois blocs, commun aux SMS et aux emails.

Les blocs (entraînement, validation, test) sont formés de plis ``StratifiedGroupKFold`` :
chaque groupe (gabarit de SMS, domaine d'expéditeur…) n'est que dans un bloc, et chaque
bloc garde la proportion des classes. Les parts doivent être des multiples de 1/20.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from numpy.typing import ArrayLike
from sklearn.model_selection import StratifiedGroupKFold

BLOCKS = ("train", "validation", "test")
N_FOLDS = 20


def stratified_group_blocks(
    labels: ArrayLike,
    groups: ArrayLike,
    fractions: Sequence[float] = (0.70, 0.15, 0.15),
    seed: int = 42,
) -> np.ndarray:
    """Indice de bloc (0, 1, 2 pour :data:`BLOCKS`) de chaque élément."""
    counts = [round(f * N_FOLDS) for f in fractions]
    exact = all(np.isclose(f * N_FOLDS, c) for f, c in zip(fractions, counts, strict=False))
    if len(fractions) != len(BLOCKS) or not exact or sum(counts) != N_FOLDS or min(counts) < 1:
        raise ValueError("fractions : trois parts positives, multiples de 0,05, de somme 1")
    labels, groups = np.asarray(labels), np.asarray(groups)
    if labels.size == 0:
        raise ValueError("jeu vide")
    if labels.shape != groups.shape:
        raise ValueError("labels et groups doivent avoir la même taille")

    folds = np.empty(labels.size, dtype=np.int64)
    splitter = StratifiedGroupKFold(n_splits=N_FOLDS, shuffle=True, random_state=seed)
    for fold, (_, members) in enumerate(splitter.split(np.zeros(labels.size), labels, groups)):
        folds[members] = fold
    return np.searchsorted(np.cumsum(counts), folds, side="right")
