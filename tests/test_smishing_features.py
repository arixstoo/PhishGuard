import numpy as np
import pytest

from phishguard.text.smishing import FEATURE_NAMES, SmishingFeatures, smishing_features


def test_keys_are_stable():
    assert tuple(smishing_features("hello")) == FEATURE_NAMES


@pytest.mark.parametrize(
    "text",
    [
        "Verify now at https://bank-verif.example/login",
        "Mettez à jour vos informations : www.suivi-colis.example",
        "ادفع الآن: https://colis-ma.example",
        "go to secure-login.xyz/account",
    ],
)
def test_detects_urls(text):
    assert smishing_features(text)["has_url"] == 1.0


def test_no_url_in_plain_message():
    f = smishing_features("On se voit à 19h. Bisous.")
    assert f["has_url"] == 0.0


def test_short_code_vs_phone():
    short = smishing_features("Text WIN to 87121 to claim")
    phone = smishing_features("Appelez le 01 00 00 00 00 immédiatement")
    assert short["has_short_code"] == 1.0 and short["has_phone"] == 0.0
    assert phone["has_phone"] == 1.0 and phone["has_short_code"] == 0.0


def test_otp_code_counts_as_short_code_not_phone():
    assert smishing_features("Votre code est 482913")["has_short_code"] == 1.0


@pytest.mark.parametrize(
    "text",
    ["You won £1000 cash", "Réglez 35 € aujourd'hui", "1,99 EUR en attente", "رسوم 15 درهم",
     "مبلغ 1200 دينار", "khlles 12 dh"],
)  # fmt: skip
def test_detects_money(text):
    assert smishing_features(text)["has_money"] == 1.0


def test_urgency_multilingual():
    assert smishing_features("URGENT! Act now")["urgency_hits"] >= 2
    assert smishing_features("Vérifiez immédiatement votre compte suspendu")["urgency_hits"] >= 3
    assert smishing_features("تنبيه عاجل: تأكيد حسابك فوراً")["urgency_hits"] >= 3


def test_urgency_respects_word_boundaries():
    # « now » ne doit pas être compté dans « know » ni « free » dans « freedom ».
    assert smishing_features("I know about freedom")["urgency_hits"] == 0


def test_upper_ratio_ignores_uncased_scripts():
    assert smishing_features("FREE PRIZE")["upper_ratio"] == 1.0
    assert smishing_features("مبروك ربحت")["upper_ratio"] == 0.0


@pytest.mark.parametrize("text", ["", " ", "!!!", "\x00\x01", "é" * 10_000, "🙂🙂", "١٢٣٤٥"])
def test_never_crashes_on_odd_input(text):
    f = smishing_features(text)
    assert all(np.isfinite(v) for v in f.values())


def test_rejects_non_string():
    with pytest.raises(TypeError):
        smishing_features(None)


def test_transformer_shape_and_range():
    x = SmishingFeatures().fit_transform(["hello", "WIN £500 now http://a.example", ""])
    assert x.shape == (3, len(FEATURE_NAMES))
    assert np.isfinite(x).all() and (x >= 0).all()
    assert list(SmishingFeatures().get_feature_names_out()) == list(FEATURE_NAMES)
