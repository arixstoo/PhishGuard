"""Précision d'un détecteur à la prévalence réelle (étape 1.7).

Le rappel et le taux de faux positifs (FPR) ne dépendent pas de la proportion de
phishing ; la **précision**, si. Pour une prévalence ``p`` :

    précision = p × rappel / (p × rappel + (1 − p) × FPR)

Le jeu de test contient 20 % de phishing ; parmi les URLs qu'un utilisateur visite, il y
en a bien moins de 1 %. Avec un FPR de 1 % et une prévalence de 0,1 %, un détecteur parfait
en rappel produit dix fausses alertes pour une vraie.

Deux calculs, qui doivent concorder :

- :func:`precision_at_prevalence` : la formule ci-dessus, à partir du rappel et du FPR
  mesurés ;
- :func:`resample_at_prevalence` : on simule des échantillons à la prévalence voulue en
  tirant avec remise dans le légitime et dans le phishing du test (bootstrap), ce qui
  donne aussi un intervalle de confiance. Tirer ``k`` URLs avec remise parmi des URLs dont
  une part ``r`` est signalée revient à tirer une loi binomiale ``B(k, r)`` : c'est ce qui
  est fait, sans matérialiser les échantillons.
"""

from __future__ import annotations

import math

import numpy as np
from numpy.typing import ArrayLike

REALISTIC_PREVALENCES = (0.01, 0.001)
PER_URLS = 10_000


def _check_rate(name: str, value: float, *, open_interval: bool = False) -> None:
    low_ok = value > 0 if open_interval else value >= 0
    high_ok = value < 1 if open_interval else value <= 1
    if not (low_ok and high_ok):
        raise ValueError(f"{name} doit être dans {'] 0, 1 [' if open_interval else '[0, 1]'}")


def precision_at_prevalence(recall: float, fpr: float, prevalence: float) -> float:
    """Précision attendue à ``prevalence`` ; NaN si aucune URL n'est signalée."""
    _check_rate("recall", recall)
    _check_rate("fpr", fpr)
    _check_rate("prevalence", prevalence, open_interval=True)
    true_alerts = prevalence * recall
    alerts = true_alerts + (1 - prevalence) * fpr
    return true_alerts / alerts if alerts > 0 else math.nan


def alerts_per_urls(
    recall: float, fpr: float, prevalence: float, per: int = PER_URLS
) -> dict[str, float]:
    """Vraies et fausses alertes attendues pour ``per`` URLs visitées."""
    precision_at_prevalence(recall, fpr, prevalence)  # validation des entrées
    true_alerts = per * prevalence * recall
    false_alerts = per * (1 - prevalence) * fpr
    return {
        "true_alerts": true_alerts,
        "false_alerts": false_alerts,
        "false_per_true": false_alerts / true_alerts if true_alerts > 0 else math.inf,
    }


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Intervalle de confiance de Wilson (95 % par défaut) d'une proportion.

    Plus fiable que l'intervalle normal pour les proportions proches de 0 ou de 1, comme
    un taux de faux positifs de 0,1 %.
    """
    if trials <= 0 or not 0 <= successes <= trials:
        raise ValueError("il faut 0 <= successes <= trials et trials > 0")
    p = successes / trials
    denominator = 1 + z**2 / trials
    centre = (p + z**2 / (2 * trials)) / denominator
    half = z * math.sqrt(p * (1 - p) / trials + z**2 / (4 * trials**2)) / denominator
    return max(0.0, centre - half), min(1.0, centre + half)


def resample_at_prevalence(
    y_true: ArrayLike,
    flagged: ArrayLike,
    prevalence: float,
    *,
    rounds: int = 2000,
    seed: int = 0,
) -> dict[str, float]:
    """Précision sur des échantillons bootstrap à la prévalence ``prevalence``.

    Chaque échantillon garde autant d'URLs légitimes que le jeu (tirées avec remise) et
    ``k`` URLs de phishing, avec ``k`` choisi pour atteindre la prévalence. Retourne la
    précision moyenne et l'intervalle à 95 % (percentiles 2,5 et 97,5) ; un échantillon
    sans aucune alerte est ignoré (précision indéfinie).
    """
    _check_rate("prevalence", prevalence, open_interval=True)
    y = np.asarray(y_true).astype(int)
    flagged = np.asarray(flagged).astype(bool)
    if y.shape != flagged.shape:
        raise ValueError("y_true et flagged doivent avoir la même taille")
    n_legit, n_phish = int((y == 0).sum()), int((y == 1).sum())
    if n_legit == 0 or n_phish == 0:
        raise ValueError("il faut des URLs des deux classes")

    k = max(1, round(n_legit * prevalence / (1 - prevalence)))
    recall = float(flagged[y == 1].mean())
    fpr = float(flagged[y == 0].mean())
    rng = np.random.default_rng(seed)
    tp = rng.binomial(k, recall, size=rounds)
    fp = rng.binomial(n_legit, fpr, size=rounds)
    alerts = tp + fp
    defined = alerts > 0
    precision = tp[defined] / alerts[defined]
    if precision.size == 0:
        mean = low = high = math.nan
    else:
        mean = float(precision.mean())
        low, high = (float(v) for v in np.percentile(precision, [2.5, 97.5]))
    return {
        "prevalence": prevalence,
        "phishing_per_sample": k,
        "legitimate_per_sample": n_legit,
        "precision_mean": mean,
        "precision_low": low,
        "precision_high": high,
        "rounds_without_alert": int((~defined).sum()),
        "phishing_available": n_phish,
    }
