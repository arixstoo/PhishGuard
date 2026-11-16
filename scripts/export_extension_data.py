"""Données de référence de l'extension, générées depuis Python (étape 5.3).

::

    make extension-data
    python scripts/export_extension_data.py [--check]

L'extension refait l'extracteur de features en TypeScript (``extension/src/core``). Pour
retrouver **exactement** les valeurs Python, elle ne recopie rien à la main : tout ce qui,
hors code, détermine une feature est exporté ici, depuis les objets Python eux-mêmes.

- ``extension/src/generated/reference-data.json`` : marques, raccourcisseurs, mots-clés,
  confusables, combinaisons d'écritures admises, seuils de la fusion, et la **liste des
  suffixes publics embarquée par tldextract** (la version de ``tldextract`` fixe
  ``host_n_subdomains`` et le domaine enregistré ; une autre liste, par exemple celle de
  ``tldts``, donnerait d'autres features en silence) ;
- ``extension/src/generated/unicode-data.json`` : les propriétés Unicode **telles que
  Python les voit** (``str.isalpha``, ``str.isdigit``, ``str.isspace``, catégories Cf et
  Cc, ``unicodedata.combining``, écriture déduite du nom par
  :func:`phishguard.urls.idn.char_script`), en plages de points de code. Les expressions
  ``\\p{...}`` de JavaScript suivent une autre version d'Unicode et d'autres définitions
  (``isdigit`` inclut les exposants, l'écriture vient du *nom* du caractère) ;
- ``extension/test/fixtures/python-parity.json`` : des cas difficiles et leur résultat
  Python, composant par composant (``urlsplit``, ``unquote``, Punycode, tldextract, IP,
  alerte d'hôte) et features complètes, plus un corpus de fuzzing déterministe. Les
  tests TypeScript les rejouent : chaque écart découvert devient un cas de ce fichier.

``--check`` régénère en mémoire et échoue si un fichier versionné est périmé (CI). Les
tables Unicode dépendent de la version d'Unicode de l'interpréteur : elles ne sont
comparées que si elle est la même que celle du fichier.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
import unicodedata
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import idna
import tldextract

from phishguard.data.urls import make_domain_extractor, normalize_url
from phishguard.fusion.score import default_config
from phishguard.security.normalize import NORMALIZATION_VERSION, host_script_alert
from phishguard.urls import brands as brands_module
from phishguard.urls import idn
from phishguard.urls.brands import GENERIC_USE_CCTLDS, load_brands, load_shorteners
from phishguard.urls.features import (
    BRAND_DISTANCE_CAP,
    FEATURE_EXTRACTOR_VERSION,
    FEATURE_NAMES,
    KEYWORDS,
    InvalidUrlError,
    UrlFeatureExtractor,
    is_ip_host,
    parse_url,
    reference_data_sha256,
)
from phishguard.urls.tld import top_level_domain

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "extension" / "src" / "generated"
REFERENCE_PATH = GENERATED / "reference-data.json"
UNICODE_PATH = GENERATED / "unicode-data.json"
PARITY_PATH = ROOT / "extension" / "test" / "fixtures" / "python-parity.json"
FORMAT_VERSION = 1
FUZZ_SEED = 20261116
FUZZ_COUNT = 600
MAX_CODE_POINT = 0x10FFFF


# --------------------------------------------------------------------------- #
# Données de référence
# --------------------------------------------------------------------------- #


def _suffix_lists() -> tuple[list[str], list[str]]:
    """Suffixes publics et privés de la liste embarquée par tldextract (hors ligne)."""
    extractor = make_domain_extractor()
    lists = extractor._get_tld_extractor()  # pas d'accès public aux listes
    if lists.include_psl_private_domains is not True or list(extractor.extra_suffixes):
        raise SystemExit("extracteur inattendu : suffixes privés exigés, aucun suffixe ajouté")
    return list(lists.public_tlds), list(lists.private_tlds)


def _check_idn_suffixes(suffixes: Iterable[str]) -> None:
    """Chaque label non ASCII de la liste doit être atteignable depuis sa forme Punycode.

    tldextract décode un label ``xn--`` avec ``idna`` (IDNA 2008, strict) avant de le
    chercher ; l'extension utilise le décodeur Punycode seul. Les deux ne trouvent les
    mêmes suffixes que si chaque label de la liste est un U-label valide.
    """
    for suffix in suffixes:
        for label in suffix.split("."):
            if label.isascii() or label in {"*"} or label.startswith("!"):
                continue
            a_label = "xn--" + label.encode("punycode").decode("ascii")
            if idna.decode(a_label) != label:
                raise SystemExit(f"suffixe {suffix!r} : label {label!r} non atteignable")


def reference_data() -> dict[str, Any]:
    public, private = _suffix_lists()
    _check_idn_suffixes([*public, *private])
    brands = load_brands()
    config = default_config()
    return {
        "format_version": FORMAT_VERSION,
        "description": (
            "Données de l'extracteur de features d'URL, exportées depuis Python. "
            "Ne pas modifier : régénérer avec `make extension-data`."
        ),
        "feature_extractor": {
            "version": FEATURE_EXTRACTOR_VERSION,
            "reference_data_sha256": reference_data_sha256(),
            "normalization_version": NORMALIZATION_VERSION,
        },
        "feature_names": list(FEATURE_NAMES),
        "keywords": list(KEYWORDS),
        "brand_distance_cap": BRAND_DISTANCE_CAP,
        "min_loose_name_length": brands_module.MIN_LOOSE_NAME_LENGTH,
        "min_typo_token_length": brands_module.MIN_TYPO_TOKEN_LENGTH,
        "generic_use_cctlds": sorted(GENERIC_USE_CCTLDS),
        "brands": [
            {
                "name": b.name,
                "domains": sorted(b.domains),
                "strict": b.strict,
                "any_cctld": b.any_cctld,
            }
            for b in brands.brands
        ],
        "shorteners": sorted(load_shorteners()),
        "confusables": dict(idn.CONFUSABLES),
        "allowed_script_mixes": [sorted(mix) for mix in idn._ALLOWED_SCRIPT_MIXES],
        "fusion": {
            "version": config.version,
            "thresholds": config.thresholds.model_dump(),
            "model_weight": config.weights["model"],
        },
        "public_suffix_list": {
            "source": f"tldextract {tldextract.__version__} (liste embarquée)",
            "public": public,
            "private": private,
        },
    }


# --------------------------------------------------------------------------- #
# Propriétés Unicode, vues par Python
# --------------------------------------------------------------------------- #


def _ranges(predicate: Callable[[str], bool]) -> list[list[int]]:
    """Plages ``[début, fin]`` (incluses) des points de code qui vérifient ``predicate``."""
    ranges: list[list[int]] = []
    for cp in range(MAX_CODE_POINT + 1):
        if predicate(chr(cp)):
            if ranges and ranges[-1][1] == cp - 1:
                ranges[-1][1] = cp
            else:
                ranges.append([cp, cp])
    return ranges


def _script_ranges() -> tuple[list[str], list[list[int]]]:
    """Écriture de chaque lettre (``str.isalpha``) : ``[début, fin, indice]``."""
    names: list[str] = []
    index: dict[str, int] = {}
    ranges: list[list[int]] = []
    for cp in range(MAX_CODE_POINT + 1):
        script = idn.char_script(chr(cp))
        if script is None:
            continue
        if script not in index:
            index[script] = len(names)
            names.append(script)
        i = index[script]
        if ranges and ranges[-1][1] == cp - 1 and ranges[-1][2] == i:
            ranges[-1][1] = cp
        else:
            ranges.append([cp, cp, i])
    return names, ranges


def unicode_data() -> dict[str, Any]:
    scripts, script_ranges = _script_ranges()
    return {
        "format_version": FORMAT_VERSION,
        "description": (
            "Propriétés Unicode telles que Python les calcule (str.isalpha, str.isdigit, "
            "str.isspace, catégories Cf et Cc, unicodedata.combining, écriture déduite du "
            "nom). Ne pas modifier : régénérer avec `make extension-data`."
        ),
        "unidata_version": unicodedata.unidata_version,
        "scripts": scripts,
        "letters": script_ranges,
        "digit": _ranges(str.isdigit),
        "space": _ranges(str.isspace),
        "format": _ranges(lambda c: unicodedata.category(c) == "Cf"),
        "control": _ranges(lambda c: unicodedata.category(c) == "Cc"),
        "combining": _ranges(lambda c: unicodedata.combining(c) != 0),
    }


# --------------------------------------------------------------------------- #
# Cas de parité
# --------------------------------------------------------------------------- #

# Chaque URL exerce une branche de urlsplit, de la normalisation ou de l'extracteur.
PARITY_URLS = [
    # schéma, casse, espaces
    "example.com",
    "EXAMPLE.com/Path",
    "HTTP://Example.COM:80/",
    "https://example.com:443",
    "https://example.com:0443/x",
    "ftp://example.com/",
    "javascript:alert(1)",
    "mailto:someone@example.com",
    "  https://example.com/  ",
    "https://exa mple.com/",
    "https://example.com/a\tb",
    "\u00a0https://example.com/",
    "https://example.com/\u3000x",
    "",
    "http://",
    "http:///path",
    "//example.com/x",
    "http:example.com",
    "1http://example.com",
    "h+t.t-p://example.com",
    # ports
    "http://example.com:/x",
    "http://example.com:8080",
    "http://example.com:65535/",
    "http://example.com:65536/",
    "http://example.com:-1/",
    "http://example.com:８０/",
    "http://example.com:80a/",
    "http://example.com::80/",
    # identifiants
    "https://user@example.com/",
    "https://user:pass@example.com:8443/",
    "https://paypal.com@evil.example/",
    "https://a@b@evil.example/",
    "https://@example.com/",
    "https://user:p@ss:word@example.com/",
    # IP
    "http://127.0.0.1/",
    "http://0x7f000001/",
    "http://0x/",
    "http://0X7F.1/",
    "http://2130706433/",
    "http://017700000001/",
    "http://1.2.3.4.5/",
    "http://256.256.256.256/",
    "http://01.02.03.04/",
    "http://example.123/",
    "http://[::1]/",
    "http://[::1]:8080/x",
    "http://[2001:DB8::1]/",
    "http://[2001:db8::192.0.2.1]/",
    "http://[::ffff:192.0.2.1]/",
    "http://[fe80::1%25eth0]/",
    "http://[fe80::1%eth0]/",
    "http://[1:2:3:4:5:6:7:8]/",
    "http://[1:2:3:4:5:6:7:8:9]/",
    "http://[1::2::3]/",
    "http://[::]/",
    "http://[12345::1]/",
    "http://[192.0.2.1]/",
    "http://[v1.fe80::a+en1]/",
    "http://[v1.abc:def]/",
    "http://[vz.abc]/",
    "http://[::1/",
    "http://::1]/",
    "http://x[::1]/",
    "http://[::1]x/",
    "http://[::1]:x/",
    # hôtes
    "http://example.com./",
    "http://example.com../",
    "http://a..b.example/",
    "http://.example.com/",
    "http://-example-.com/",
    "http://exa_mple.com/",
    "http://localhost/",
    "http://intranet/",
    "http://www.www.example.com/",
    "http://WWW.Example.co.uk/",
    "http://a.b.c.d.e.f.g.example.com/",
    "http://co.uk/",
    "http://com/",
    "http://www.ck/",
    "http://a.b.ck/",
    "http://city.kawasaki.jp/",
    "http://x.city.kawasaki.jp/",
    "http://foo.kawasaki.jp/",
    "http://someone.github.io/",
    "http://github.io/",
    "http://a.b.blogspot.com/",
    "http://s3.amazonaws.com/",
    "http://bucket.s3.amazonaws.com/",
    "http://example.xn--p1ai/",
    "http://пример.рф/",
    "http://例え.テスト/",
    "http://東京tokyo.jp/",
    "http://example.中国/",
    "http://www.xn--com-/",
    "http://xn--/",
    "http://xn--a/",
    "http://xn--zzzzzzzzzzzz/",
    "http://xn--ls8h.example/",
    "http://xn--80ak6aa92e.com/",
    "http://xn--pple-43d.com/",
    "http://XN--PPLE-43D.COM/",
    "http://xn--ab-/",
    "http://xn--a-ecp.ru/",
    "http://bücher.example/",
    "http://BÜCHER.example/",
    "http://straße.de/",
    "http://İstanbul.example/",
    "http://ΣΟΦΟΣ.gr/",
    "http://ﬁnance.example/",
    "http://ｅｘａｍｐｌｅ．ｃｏｍ/",
    "http://example。com/",
    "http://example｡com/",
    "http://exa\u200dmple.com/",
    "http://exa\u00admple.com/",
    "http://\u202eexample.com/",
    "http://exa\x00mple.com/",
    "http://\U0001f600.example/",
    "http://\U0001f600\U0001f601\U0001f602.example/",
    "http://" + "é" * 70 + ".example/",
    "http://" + "a" * 70 + ".example/",
    "http://" + "x" * 300 + ".example/",
    "http://\u0430pple.com/",
    "http://\u0440\u0430\u0443\u0440\u0430l.com/",
    "http://\u0440\u0430\u0443\u0440\u0430\u04cf.com/",
    "http://g\u043e\u043egle.com/",
    "http://p\u03b1ypal.com/",
    "http://pàypal.com/",
    "http://ma\u0131l.example/",
    "http://とーきょう.jp/",
    "http://ｶﾀｶﾅ.jp/",
    "http://ᵃpple.com/",
    "http://\u0661\u0662\u0663.example/",
    "http://test\u00b2.example/",
    "http://café.example/",
    "http://cafe\u0301.example/",
    # marques
    "https://paypal.com/",
    "https://www.paypal.com/",
    "https://paypal.co.uk/",
    "https://paypal.co/",
    "https://google.co.th/",
    "https://google.io/",
    "https://amazon.com.mx/",
    "https://secure-paypal-login.example/",
    "https://paypa1.com/",
    "https://arnazon.com/",
    "https://micros0ft-support.example/",
    "https://mail.example/",
    "https://gmail.example/",
    "https://icloud-verify.example/",
    "https://cloud.example/",
    "https://ups-suivi.example/",
    "https://upsale.example/",
    "https://orange.example/",
    "https://credit-agricole-securite.example/",
    "https://example.com/paypal/login",
    "https://example.com/?next=PayPal",
    "https://paypal.com/paypal",
    "https://www.netflix.com.account-update.example/",
    # chemin, requête, fragment
    "https://example.com",
    "https://example.com?",
    "https://example.com?a=1",
    "https://example.com#frag",
    "https://example.com/?#",
    "https://example.com/a?b?c#d#e",
    "https://example.com/a#b?c",
    "https://example.com/?a=1&&b=2&",
    "https://example.com/?&",
    "https://example.com//a///b/",
    "https://example.com/%",
    "https://example.com/%2",
    "https://example.com/%zz",
    "https://example.com/%6c%6F%67%69%6E",
    "https://example.com/%E2%82%AC",
    "https://example.com/%E2%82",
    "https://example.com/%C3%28",
    "https://example.com/%F0%9F%98%80",
    "https://example.com/%ED%A0%80",
    "https://example.com/%F0%80%80",
    "https://example.com/%EF%BB%BFlogin",
    "https://example.com/%C3é%A9",
    "https://example.com/é%41",
    "https://example.com/%25%32%35",
    "https://example.com/%68ttp%3A//evil",
    "https://example.com/redirect?u=https%3A%2F%2Fevil.example",
    "https://example.com/WWW.evil.example",
    "https://example.com/\u00b2\u00b3\u2460",
    "https://example.com/\U0001f600/\U0001f600",
    "https://example.com/" + "%41" * 50,
    "https://example.com/securite/compte/paiement/identifiant/connexion",
    "https://example.com/LOGIN/SignIn/VERIFY",
]


def _python_parse(url: str) -> dict[str, Any] | None:
    try:
        parsed = parse_url(url)
    except ValueError:
        return None
    return {
        "url": parsed.url,
        "scheme": parsed.scheme,
        "host": parsed.host,
        "host_unicode": parsed.host_unicode,
        "is_ip": parsed.is_ip,
        "registered_domain": parsed.registered_domain,
        "domain_label": parsed.domain_label,
        "subdomains": list(parsed.subdomains),
        "has_userinfo": parsed.has_userinfo,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
    }


def _urlsplit(url: str) -> dict[str, Any]:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return {"error": True}
    return {
        "scheme": parts.scheme,
        "netloc": parts.netloc,
        "path": parts.path,
        "query": parts.query,
        "fragment": parts.fragment,
        "hostname": parts.hostname,
        "port": port,
    }


def _url_case(url: str, extractor: UrlFeatureExtractor) -> dict[str, Any]:
    normalized = normalize_url(url)
    parsed = _python_parse(url)
    case: dict[str, Any] = {
        "input": url,
        "urlsplit": _urlsplit(url),
        "normalize_url": None if normalized is None else list(normalized),
        "parsed": parsed,
    }
    if parsed is not None:
        case["features"] = extractor.extract(url)
        case["host_alert"] = host_script_alert(parsed["host"])
        case["top_level_domain"] = top_level_domain(parsed["host"])
    return case


# Alphabet du fuzzing : ce qui casse un découpeur d'URL, et ce qu'emploient les leurres.
_FUZZ_ALPHABET = (
    list("abcdefghijklmnopqrstuvwxyzABCXYZ0123456789")
    + list("-._~:/?#[]@!$&'()*+,;=%")
    + ["%2", "%41", "%E2%82%AC", "%C3", "%ZZ", "%25", "xn--", "www.", "http:", "//"]
    + list("éÉßİıΣσςабвгдежзийклмнопрстуфхцчшщъыьэюяαβγδεοκρτυχω")
    + list("\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u04cf\u03bf\u03b1")
    + list("東京とーきょうカタカナ한국어١٢٣عربيעברית")
    + ["\u200b", "\u200d", "\u00ad", "\u202e", "\ufeff", "\u00a0", "\u3000", "\u3002", "\uff0e"]
    + ["\U0001f600", "\U0001d41a", "\u00b2", "\u2460", "\u2126", "\u212a", "\ufb01", "\uff21"]
    + list("0123456789")
    + ["paypal", "apple", "amazon", "google", "login", "secure", "verify", "compte"]
)
_FUZZ_HOST_ENDINGS = ["", ".com", ".co.uk", ".github.io", ".example", ".jp", ".рф", ".ck", "."]


def fuzz_urls(count: int = FUZZ_COUNT, seed: int = FUZZ_SEED) -> list[str]:
    """URLs déterministes, souvent invalides ou étranges, pour le test différentiel."""
    rng = random.Random(seed)  # nosec B311 - données de test
    urls: list[str] = []
    while len(urls) < count:
        host = "".join(rng.choice(_FUZZ_ALPHABET) for _ in range(rng.randrange(1, 8)))
        host += rng.choice(_FUZZ_HOST_ENDINGS)
        rest = "".join(rng.choice(_FUZZ_ALPHABET) for _ in range(rng.randrange(0, 10)))
        scheme = rng.choice(["http://", "https://", "", "HTTPS://", "http://user@", "ftp://"])
        url = f"{scheme}{host}{rng.choice(['', '/', ':8080/', '?', '#'])}{rest}"
        if url not in urls:
            urls.append(url)
    return urls


def _nullable(values: Iterable[float]) -> list[float | None]:
    """NaN → ``null`` : JSON n'a pas de NaN."""
    return [None if math.isnan(v) else float(v) for v in values]


def synthetic_model_cases() -> list[dict[str, Any]]:
    """Deux petits modèles LightGBM exportés, avec valeurs manquantes, et leurs scores.

    Le vrai modèle n'est pas versionné : sans ces cas, la CI ne testerait pas le parcours
    des arbres de l'extension. Ils exercent aussi ce que les features d'URL n'atteignent
    jamais : ``missing_type`` ``NaN`` et ``Zero`` (``zero_as_missing``), et une calibration
    isotone à points répétés (``numpy.interp``).
    """
    import lightgbm
    import numpy as np
    import pandas as pd

    from phishguard.fusion.calibration import ScoreCalibrator
    from phishguard.urls.export import (
        calibrated_probability,
        export_url_model,
        predict_probability,
        predict_raw,
    )
    from phishguard.urls.model import UrlModel

    names = [n for n in FEATURE_NAMES if n != "tld_phish_rate"][:6]
    rng = np.random.default_rng(7)
    x = rng.normal(size=(500, len(names)))
    x[rng.random(x.shape) < 0.15] = np.nan
    x[rng.random(x.shape) < 0.15] = 0.0
    y = np.nan_to_num(x[:, 0]) - np.nan_to_num(x[:, 1]) + rng.normal(scale=0.5, size=500) > 0
    frame = pd.DataFrame(x, columns=names)
    calibrator = ScoreCalibrator(
        "isotonic", x=(0.0, 0.2, 0.2, 0.5, 0.5, 0.9, 1.0), y=(0.0, 0.1, 0.3, 0.3, 0.6, 0.6, 1.0)
    )
    cases = []
    for zero_as_missing in (False, True):
        estimator = lightgbm.LGBMClassifier(
            n_estimators=25,
            num_leaves=8,
            min_child_samples=5,
            zero_as_missing=zero_as_missing,
            random_state=0,
            verbose=-1,
        ).fit(frame, y.astype(int))
        model = UrlModel(
            estimator=estimator,
            feature_names=tuple(names),
            thresholds={"fpr_1pct": 0.5},
            metadata={"model_version": f"synthetic_zero_as_missing_{zero_as_missing}".lower()},
        )
        exported = json.loads(json.dumps(export_url_model(model, calibrator)))
        probe = np.vstack([x[:60], np.full((1, len(names)), np.nan), np.zeros((1, len(names)))])
        lightgbm_scores = model.score_features(pd.DataFrame(probe, columns=names))
        vectors = []
        for row, expected in zip(probe.tolist(), lightgbm_scores, strict=True):
            probability = predict_probability(exported, row)
            if abs(probability - float(expected)) > 1e-12:
                raise SystemExit("référence Python ≠ LightGBM sur le modèle synthétique")
            vectors.append(
                {
                    "x": _nullable(row),
                    "raw_score": predict_raw(exported, row),
                    "probability": probability,
                    "calibrated_probability": calibrated_probability(exported, row),
                }
            )
        cases.append({"model": exported, "vectors": vectors})
    return cases


def interp_cases() -> list[dict[str, Any]]:
    """``numpy.interp`` sur des points répétés, aux bords et hors bornes."""
    import numpy as np

    xp = [0.0, 0.2, 0.2, 0.5, 0.5, 0.5, 0.9, 1.0]
    fp = [0.0, 0.1, 0.3, 0.3, 0.4, 0.6, 0.6, 1.0]
    queries = [-1.0, 0.0, 0.1, 0.2, 0.2000001, 0.35, 0.5, 0.7, 0.9, 0.95, 1.0, 2.0]
    return [{"xp": xp, "fp": fp, "x": q, "output": float(np.interp(q, xp, fp))} for q in queries]


def parity_cases() -> dict[str, Any]:
    extractor = UrlFeatureExtractor()  # toutes les familles sauf ``tld`` (sans table)
    domain_extractor = make_domain_extractor()

    def tld(host: str) -> dict[str, Any]:
        ext = domain_extractor(host)
        return {
            "subdomain": ext.subdomain,
            "domain": ext.domain,
            "suffix": ext.suffix,
            "is_private": ext.is_private,
            "top_domain_under_public_suffix": ext.top_domain_under_public_suffix,
        }

    unquote_inputs = [
        "",
        "plain",
        "%",
        "%%",
        "%4",
        "%41",
        "%4g",
        "%41%42%43",
        "a%20b",
        "%E2%82%AC",
        "%e2%82%ac",
        "%E2%82",
        "%E2%82%",
        "%C3%28",
        "%A0%A1",
        "%F0%9F%98%80",
        "%F0%9F%98",
        "%ED%A0%80",
        "%ED%B0%80",
        "%F4%90%80%80",
        "%F0%80%80%80",
        "%C0%AF",
        "%E0%80%AF",
        "%FF%FE",
        "%EF%BB%BF%EF%BB%BF",
        "é%41",
        "%C3é%A9",
        "%C3%A9é%C3%A9",
        "\U0001f600%F0%9F%98%80",
        "%25%32%35",
        "%%41",
        "%0041",
        "%2F%2f",
        "%00%01%7F%80",
    ]
    labels = [
        "",
        "com",
        "COM",
        "xn--",
        "xn--a",
        "xn--p1ai",
        "xn--P1AI",
        "xn--pple-43d",
        "xn--80ak6aa92e",
        "xn--ls8h",
        "xn--bcher-kva",
        "xn--com-",
        "xn--ab-",
        "xn---",
        "xn--a-",
        "xn--99999999999",
        "xn--zzzzzzzzzzzzzz",
        "xn--a-ecp",
        "xn--" + "9" * 59,
        "xn--" + "a" * 70,
        "xn--ab-cd-ef",
        "xn--1",
        "xn--ab_cd",
        "bücher",
        "BÜCHER",
        "straße",
        "ﬁnance",
        "ｅｘａｍｐｌｅ",
        "пример",
        "рф",
        "例え",
        "東京tokyo",
        "\U0001f600",
        "a\U0001f600b",
        "é" * 63,
        "é" * 64,
        "İ",
        "ΣΟΦΟΣ",
        "\u0430pple",
        "\ud800",
        "a\udfffb",
    ]
    hosts = [
        "example.com",
        "www.example.co.uk",
        "co.uk",
        "uk",
        "a.b.ck",
        "www.ck",
        "ck",
        "city.kawasaki.jp",
        "x.city.kawasaki.jp",
        "a.foo.kawasaki.jp",
        "someone.github.io",
        "github.io",
        "a.b.blogspot.com",
        "bucket.s3.amazonaws.com",
        "example.xn--p1ai",
        "a.xn--p1ai",
        "xn--p1ai",
        "example.XN--P1AI",
        "example.xn--fiqs8s",
        "localhost",
        "a..com",
        ".com",
        "com.",
        "example.com:8080",
        "user@example.com",
        "v1.abc:def",
        "example.xn--com-",
        "example.xn--",
        "1.2.3.4",
        "1.2.3.4.5",
        "example.com/path",
        "Example.COM",
    ]
    ip_hosts = [
        "127.0.0.1",
        "0x7f000001",
        "0x",
        "0xg",
        "2130706433",
        "example.123",
        "example.123.",
        "123.example",
        "١٢٣",
        "example.١٢٣",
        "::1",
        "2001:db8::1",
        "2001:db8::192.0.2.1",
        "fe80::1%eth0",
        "fe80::1%",
        "1::2::3",
        "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7:8:9",
        "12345::1",
        "::ffff:01.2.3.4",
        "v1.abc:def",
        "gggg::1",
        ":1",
        "1:",
        "::",
        ":::",
        "1:2:3:4:5:6:7::",
        "::1:2:3:4:5:6:7",
        "::1:2:3:4:5:6:7:8",
    ]
    skeleton_inputs = ["paypal", "раураl", "pàypal", "ΡΑΥΡΑL", "ﬁ", "ma\u0131l", "Å", "ǅ", "ⓐ"]
    return {
        "format_version": FORMAT_VERSION,
        "description": (
            "Résultats Python de référence, composant par composant. Ne pas modifier : "
            "régénérer avec `make extension-data`."
        ),
        "unidata_version": unicodedata.unidata_version,
        "python": sys.version.split()[0],
        "feature_extractor": {
            "version": FEATURE_EXTRACTOR_VERSION,
            "reference_data_sha256": reference_data_sha256(),
        },
        "feature_names": list(extractor.feature_names),
        "unquote": [{"input": s, "output": unquote(s)} for s in unquote_inputs],
        "labels": [
            {
                "input": label,
                "to_ascii": idn.label_to_ascii(label),
                "to_unicode": idn.label_to_unicode(label),
            }
            for label in labels
        ],
        "tldextract": [{"input": host, "output": tld(host)} for host in hosts],
        "is_ip_host": [{"input": host, "output": is_ip_host(host)} for host in ip_hosts],
        "skeleton": [{"input": s, "output": idn.skeleton(s)} for s in skeleton_inputs],
        "interp": interp_cases(),
        "synthetic_models": synthetic_model_cases(),
        "urls": [_url_case(url, extractor) for url in PARITY_URLS],
        "fuzz": [_url_case(url, extractor) for url in fuzz_urls()],
    }


# --------------------------------------------------------------------------- #


def _dump(document: dict[str, Any]) -> str:
    # ensure_ascii : les fichiers restent lisibles par n'importe quel outil, et les
    # surrogates isolés (Punycode malformé) sont représentables en JSON.
    return json.dumps(document, ensure_ascii=True, indent=1) + "\n"


def _compact(document: dict[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n"


def outputs() -> dict[Path, str]:
    return {
        REFERENCE_PATH: _dump(reference_data()),
        UNICODE_PATH: _compact(unicode_data()),
        PARITY_PATH: _dump(parity_cases()),
    }


def _stale(path: Path, expected: str) -> bool:
    if not path.is_file():
        return True
    current = path.read_text(encoding="utf-8")
    if current == expected:
        return False
    # Version d'Unicode différente (Python 3.12 en CI, 3.13 en local) : ces fichiers ne
    # se comparent qu'à version égale.
    if (
        path in (UNICODE_PATH, PARITY_PATH)
        and json.loads(current).get("unidata_version") != unicodedata.unidata_version
    ):
        print(f"{path.name} : Unicode {unicodedata.unidata_version} ici, comparaison sautée")
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="échoue si un fichier est périmé")
    args = parser.parse_args(argv)

    try:
        generated = outputs()
    except InvalidUrlError as exc:  # pragma: no cover - garde-fou
        raise SystemExit(str(exc)) from None
    if args.check:
        stale = [p for p, text in generated.items() if _stale(p, text)]
        for path in stale:
            print(f"périmé : {path.relative_to(ROOT)} (make extension-data)")
        return 1 if stale else 0
    for path, text in generated.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"{path.relative_to(ROOT)} ({path.stat().st_size / 1024:.0f} Kio)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
