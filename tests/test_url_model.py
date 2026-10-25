"""Tests de l'artefact de modèle URL (étape 1.6)."""

import logging

import joblib
import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression

from phishguard.urls import model as M
from phishguard.urls.features import InvalidUrlError, UrlFeatureExtractor, feature_names
from phishguard.urls.tld import TldRiskTable

TABLE = TldRiskTable.fit(["xyz", "com", "org", "xyz"], [1, 0, 0, 1])
URLS = [
    "http://secure-login-1.xyz/verify/account",
    "https://alpha.com/",
    "https://www.nova.org/blog/post",
    "http://paypa1-secure.xyz/login?next=1",
]
LABELS = np.array([1, 0, 0, 1])


def fitted(columns=None, table=TABLE) -> M.UrlModel:
    columns = tuple(columns or feature_names(exclude_groups=("scheme",)))
    x = UrlFeatureExtractor(tld_table=TABLE).transform(URLS)[list(columns)]
    estimator = LogisticRegression().fit(x, LABELS)
    return M.UrlModel(estimator, columns, table, thresholds={"fpr_1pct": 0.5}, metadata={"a": 1})


def test_scores_raw_urls_like_the_training_features():
    model = fitted()
    x = UrlFeatureExtractor(tld_table=TABLE).transform(URLS)[list(model.feature_names)]
    np.testing.assert_allclose(model.score(URLS), model.estimator.predict_proba(x)[:, 1])
    assert list(model.features(URLS).columns) == list(model.feature_names)


def test_predict_uses_a_strict_threshold():
    model = fitted()
    scores = model.score(URLS)
    np.testing.assert_array_equal(
        model.predict(URLS, threshold=float(scores[0])), scores > scores[0]
    )
    assert set(model.predict(URLS)) <= {0, 1}
    with pytest.raises(KeyError, match="disponibles"):
        model.predict(URLS, threshold="fpr_5pct")


def test_save_and_load_round_trip(tmp_path):
    model = fitted()
    path = model.save(tmp_path / "sub" / "url.joblib")
    loaded = M.UrlModel.load(path)
    np.testing.assert_allclose(loaded.score(URLS), model.score(URLS))
    assert loaded.feature_names == model.feature_names
    assert loaded.thresholds == {"fpr_1pct": 0.5}
    assert loaded.metadata == {"a": 1}
    assert loaded.tld_table.rates == TABLE.rates


def test_model_without_tld_feature_needs_no_table():
    columns = feature_names(families=("base", "brand"))
    model = fitted(columns, table=None)
    assert model.score(URLS).shape == (len(URLS),)


def test_tld_feature_requires_its_table():
    columns = feature_names()
    estimator = fitted().estimator
    with pytest.raises(ValueError, match="table des TLD"):
        M.UrlModel(estimator, columns, None)


@pytest.mark.parametrize(
    ("columns", "message"),
    [((), "au moins"), (("nope",), "inconnues"), (("host_len", "host_len"), "double")],
)
def test_rejects_invalid_feature_lists(columns, message):
    with pytest.raises(ValueError, match=message):
        M.UrlModel(fitted().estimator, columns, TABLE)


def test_rejects_an_estimator_without_probabilities():
    with pytest.raises(TypeError):
        M.UrlModel(object(), ("host_len",))


def test_invalid_url_is_rejected():
    with pytest.raises(InvalidUrlError):
        fitted().score(["javascript:alert(1)"])


def test_load_rejects_unknown_files(tmp_path):
    path = tmp_path / "other.joblib"
    joblib.dump({"format_version": 999}, path)
    with pytest.raises(ValueError, match="format"):
        M.UrlModel.load(path)


def test_load_warns_on_library_version_mismatch(tmp_path, caplog):
    path = fitted().save(tmp_path / "url.joblib")
    payload = joblib.load(path)
    payload["library_versions"]["scikit-learn"] = "0.0.1"
    joblib.dump(payload, path)
    with caplog.at_level(logging.WARNING, logger=M.__name__):
        M.UrlModel.load(path)
    assert "scikit-learn 0.0.1" in caplog.text
