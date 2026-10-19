import numpy as np
import pytest

from phishguard.evaluation.metrics import binary_report, recall_at_fpr


def test_perfect_classifier():
    y = [0, 0, 0, 1, 1]
    report = binary_report(y, [0.1, 0.2, 0.3, 0.8, 0.9])
    assert report["confusion_matrix"] == {"tn": 3, "fp": 0, "fn": 0, "tp": 2}
    assert report["precision"] == report["recall"] == report["f1"] == 1.0
    assert report["fpr"] == 0.0
    assert report["pr_auc"] == 1.0


def test_confusion_matrix_and_rates():
    y_true = [0, 0, 0, 0, 1, 1]
    y_score = [0.9, 0.1, 0.2, 0.3, 0.8, 0.4]  # 1 FP, 1 FN
    report = binary_report(y_true, y_score)
    assert report["confusion_matrix"] == {"tn": 3, "fp": 1, "fn": 1, "tp": 1}
    assert report["precision"] == 0.5
    assert report["recall"] == 0.5
    assert report["fpr"] == 0.25


def test_threshold_is_applied():
    report = binary_report([0, 1], [0.4, 0.6], threshold=0.7)
    assert report["confusion_matrix"]["tp"] == 0


def test_accuracy_hides_a_useless_model():
    # 95 % d'accuracy alors qu'aucun spam n'est détecté : la raison d'être de ce module.
    y_true = np.array([0] * 95 + [1] * 5)
    report = binary_report(y_true, np.zeros(100))
    assert report["accuracy"] == 0.95
    assert report["recall"] == 0.0


def test_recall_at_fpr():
    y_true = [0, 0, 0, 0, 1, 1]
    y_score = [0.1, 0.2, 0.3, 0.9, 0.95, 0.5]
    assert recall_at_fpr(y_true, y_score, 0.0) == 0.5  # seul 0.95 passe sans FP
    assert recall_at_fpr(y_true, y_score, 0.25) == 1.0


@pytest.mark.parametrize("max_fpr", [-0.1, 1.5])
def test_recall_at_fpr_rejects_invalid_bound(max_fpr):
    with pytest.raises(ValueError):
        recall_at_fpr([0, 1], [0.1, 0.9], max_fpr)


def test_rejects_single_class():
    with pytest.raises(ValueError):
        binary_report([0, 0], [0.1, 0.2])


def test_rejects_shape_mismatch():
    with pytest.raises(ValueError):
        binary_report([0, 1], [0.1])
