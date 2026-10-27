"""Tests des features smishing (étape 1.9)."""

import socket

import pytest

from phishguard.text import smishing as S

X = S.SmishingFeatureExtractor()


def f(text):
    return X.extract(text)


def test_contract_and_order():
    values = f("hello")
    assert tuple(values) == S.FEATURE_NAMES
    assert len(S.FEATURE_NAMES) == len(set(S.FEATURE_NAMES)) == 13
    assert all(isinstance(v, float) for v in values.values())


def test_classic_english_spam():
    v = f("URGENT! You have WON a £1000 prize. Call 09061701461 or text WIN to 87121")
    assert v["has_amount"] == v["has_phone"] == v["has_short_code"] == 1
    assert v["urgency_hits"] == 1 and v["reward_hits"] >= 2
    assert v["n_exclamations"] == 1 and v["upper_ratio"] > 0.2


@pytest.mark.parametrize(
    ("text", "n_urls"),
    [
        ("go to http://example.com/x now", 1),
        ("see www.example.org", 1),
        ("suivi-colis.example/r/8F2K", 1),
        ("visit example.fr today, or bit.ly/abc", 2),
        ("meet at 10.30 near the station", 0),
        ("ok. see you", 0),
        # domaine nu réservé, sans chemin (jeu FR/AR)
        ("payez sur carte-vitale-renouvellement.example", 1),
        ("go to news.bbc.co.uk", 1),
        # phrases collées et adresses email (corpus UCI) : pas des liens
        ("Howz pain.it will come down today", 0),
        ("Sorry da thangam.it's my mistake", 0),
        ("try to change in reply.Be nice", 0),
        ("It's yijue@hotmail.com", 0),
    ],
)
def test_urls(text, n_urls):
    assert f(text)["n_urls"] == n_urls
    assert f(text)["has_url"] == float(n_urls > 0)


def test_shortener_uses_the_shared_list():
    assert f("check bit.ly/3abc")["has_shortener"] == 1
    assert f("check https://www.bit.ly/3abc")["has_shortener"] == 1
    assert f("check https://example.com/bit.ly")["has_shortener"] == 0


@pytest.mark.parametrize(
    ("text", "short_code", "phone"),
    [
        ("Code : 482913.", 1, 0),
        ("text STOP to 87121!", 1, 0),
        ("rdv à 10:30", 0, 0),
        ("1.99 euros", 0, 0),
        ("£1000 cash", 0, 0),
        ("2026-10-27", 0, 0),
        ("appelle le 06 39 98 41 22", 0, 1),
        ("call +44 7700 900123", 0, 1),
        ("http://example.com/87121/0639984122", 0, 0),  # les chiffres d'un lien ne comptent pas
    ],
)
def test_numbers(text, short_code, phone):
    v = f(text)
    assert (v["has_short_code"], v["has_phone"]) == (short_code, phone)


@pytest.mark.parametrize(
    "text",
    ["£5", "5 €", "1,99 €", "25000 دج", "8000 DA", "USD 20", "350 dinars", "$ 1 000"],
)
def test_amounts(text):
    assert f(f"payez {text} maintenant")["has_amount"] == 1


@pytest.mark.parametrize(
    "text",
    [
        "j'ai 25 ans et 3 enfants",
        "data plan",  # « da » doit être un mot
        "1. Over 2. Jada 3. Kusruthi",  # ni à la fin d'un mot
        "Is ur changes 2 da report big?",  # argot : « to the »
        "DEAD 2 DA WRLD",
        "I'm mad 2day",
        "back to europe 2 days",
    ],
)
def test_no_amount_without_currency(text):
    assert f(text)["has_amount"] == 0


def test_french_keywords_without_accents_or_case():
    v = f("Votre COLIS est BLOQUÉ : vérifiez sous 24h")
    assert v["urgency_hits"] >= 2  # bloque, sous 24
    assert v["account_hits"] >= 2  # colis, verifiez


def test_arabic_keywords_with_diacritics_and_alif_forms():
    v = f("عَاجِل: تم تعليق حسابك. تأكيد الهوية فوراً")
    assert v["urgency_hits"] >= 3  # عاجل, تعليق, فورا
    assert v["account_hits"] >= 2  # حساب, تاكيد
    assert f("مبروك ربحت جائزة")["reward_hits"] == 3


def test_eastern_arabic_digits_count_as_digits():
    assert f("الرمز ٤٨٢٩١٣")["has_short_code"] == 1
    assert f("٤٨٢٩١٣")["digit_ratio"] == 1.0


def test_latin_keywords_must_start_a_word():
    assert f("carefree weekend")["reward_hits"] == 0
    assert f("freebies for you")["reward_hits"] == 1
    assert f("spinning")["account_hits"] == 0  # « pin » au milieu d'un mot


def test_keywords_are_counted_once():
    assert f("urgent urgent URGENT")["urgency_hits"] == 1


def test_normalize():
    assert S.normalize("Sécurité VÉRIFIEZ") == "securite verifiez"
    assert S.normalize("تأكيد") == "تاكيد"
    assert S.normalize("سِرّ") == "سر"
    assert S.normalize("ﬁ") == "fi"  # NFKC


def test_benign_messages_have_no_signal():
    for text in ("Ok lar... Joking wif u oni...", "Tu peux acheter du pain ?", "وصلت إلى البيت"):
        v = f(text)
        assert v["has_url"] == v["has_phone"] == v["has_amount"] == 0
        assert v["urgency_hits"] == v["reward_hits"] == 0


def test_edge_inputs():
    empty = f("")
    assert empty["length"] == 0 and empty["upper_ratio"] == 0 and empty["digit_ratio"] == 0
    assert f("x" * 100_000)["length"] == 100_000
    assert f("\u200b\u202e emoji 🎁")["length"] > 0
    with pytest.raises(TypeError):
        X.extract(None)


def test_transform_keeps_the_index():
    import pandas as pd

    texts = pd.Series(["a", "WIN £5"], index=[10, 20])
    frame = X.transform(texts)
    assert list(frame.index) == [10, 20]
    assert list(frame.columns) == list(S.FEATURE_NAMES)
    assert X.to_array(["a"]).shape == (1, 13)


def test_features_never_use_the_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("accès réseau interdit")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    S.SmishingFeatureExtractor().extract("http://example.com bit.ly/x 87121 £5")


def test_invisible_format_characters_do_not_split_keywords():
    # U+200B (espace sans chasse) et U+2060 glissés pour couper « urgent » et « compte ».
    v = f("URG\u200bENT : votre com\u2060pte est bloqu\u200bé")
    assert v["urgency_hits"] >= 2 and v["account_hits"] >= 1
    assert S.normalize("a\u200bb\u202ec") == "abc"
