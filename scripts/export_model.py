"""Export du modèle URL pour l'extension et vecteurs de référence (étape 4.11).

::

    make export
    python scripts/export_model.py [--models-dir models] [--golden tests/golden/url_vectors.json]

Produit :

- ``models/<version>.json`` : arbres LightGBM, calibration et métadonnées
  (:func:`phishguard.urls.export.export_url_model`), sans pickle ;
- ``tests/golden/url_vectors.json`` : 200 URLs avec, pour chacune, les valeurs des
  features **et** les scores calculés par Python. Les tests TypeScript de l'extension
  (étape 5.3) devront retrouver exactement ces valeurs, à 1e-6 près. Sans ce garde-fou,
  les deux implémentations divergeraient en silence.

Avant d'écrire quoi que ce soit, le script vérifie que l'implémentation de référence en
Python pur (:func:`phishguard.urls.export.predict_raw`, qui ne lit que le JSON) retrouve
le score de LightGBM sur les 200 URLs. Un écart arrête l'export.

**Les URLs sont synthétiques et déterministes**, jamais tirées des flux de phishing : une
URL de phishing réelle contient souvent l'adresse email ou l'identifiant de sa victime,
et ce fichier est versionné. Elles couvrent les cas difficiles de l'extracteur : IDN et
punycode, homographes, IP (décimale, hexadécimale, IPv6), ports, identifiants, URL
imbriquée, encodage pourcent, caractères invisibles, raccourcisseurs, marques.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import sys
from pathlib import Path

from phishguard.deployment import model_files
from phishguard.fusion.calibration import ScoreCalibrator
from phishguard.urls.export import (
    calibrated_probability,
    export_url_model,
    predict_probability,
    predict_raw,
)
from phishguard.urls.features import InvalidUrlError
from phishguard.urls.model import UrlModel

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_FORMAT_VERSION = 1
GOLDEN_COUNT = 200
GOLDEN_TOLERANCE = 1e-6
# L'implémentation de référence doit être bien plus proche que la tolérance publiée.
REFERENCE_TOLERANCE = 1e-12
SEED = 20261112

# Cas choisis à la main : chacun exerce une branche de l'extracteur.
HANDPICKED = [
    "https://www.paypal.com/signin",
    "http://paypa1-secure.com/login",
    "http://xn--pple-43d.com/",
    "http://\u0430pple.com/",  # a cyrillique (U+0430)
    "https://www.google.com/",
    "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fmail.google.com",
    "http://192.0.2.10/paypal/login.php",
    "http://0xC0000201/verify",
    "http://3221225994/login",
    "http://[2001:db8::1]/account",
    "https://user:pass@secure-bank.example/",
    "http://login.example.com:8080/verify",
    "https://example.com:443/",
    "http://bit.ly/3abcXYZ",
    "https://t.co/abc123",
    "HTTPS://WWW.EXAMPLE.COM/Path/To/Page",
    "https://example.com/redirect?url=http://evil.example/login",
    "https://example.com/%6C%6F%67%69%6E",
    "https://exa\u200bmple.com/login",  # espace de largeur nulle
    "https://example.com/\u202elogin",  # inversion de sens
    "http://secure-login-verify.example/verify/account/123456",
    "https://amaz0n-account-update.test/confirm",
    "https://microsoft-365-signin.example.net/owa/",
    "https://appleid.apple.com.verify-account.example/",
    "http://www.bücher.example/",
    "http://xn--bcher-kva.example/",
    "https://sub1.sub2.sub3.sub4.example.co.uk/a/b/c/d/e",
    "https://github.io/",
    "https://someone.github.io/login",
    "https://drive.google.com/file/d/1AbCdEfGh/view?usp=sharing",
    "https://example.com/?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8",
    "https://example.com/" + "a" * 300,
    "https://" + "x" * 60 + ".example/",
    "http://example.com/wp-admin/includes/paiement/compte/securite.php",
    "https://banque-identifiant-connexion.example/fr/",
    "https://example.com/#login",
    "http://example.com.",
    "https://e.xample-wallet-confirm.example/wallet",
    "http://p\u0430yp\u0430l.com/",  # deux a cyrilliques (U+0430)
    "https://www.xn--80ak6aa92e.com/",
]

_WORDS = [
    "secure",
    "login",
    "verify",
    "account",
    "update",
    "bank",
    "wallet",
    "mail",
    "cloud",
    "shop",
    "news",
    "blog",
    "photo",
    "travel",
    "support",
    "portal",
    "app",
]
_BRANDS = [
    "paypal",
    "apple",
    "amazon",
    "microsoft",
    "netflix",
    "google",
    "facebook",
    "laposte",
    "ameli",
    "impots",
    "chase",
    "dhl",
]
_TLDS = ["example", "test", "example.com", "example.net", "example.org", "example.co.uk"]
_PATHS = [
    "/",
    "/login",
    "/signin.php",
    "/verify/account",
    "/a/b/c",
    "/index.html",
    "/wp-content/uploads/2026/doc.pdf",
    "/confirm?id=12345",
    "/secure/update?token=x",
]


def synthetic_urls(count: int, seed: int = SEED) -> list[str]:
    """``count`` URLs déterministes : les cas choisis, puis des combinaisons tirées."""
    # URLs de test : aucun usage cryptographique.
    rng = random.Random(seed)  # nosec B311
    urls = list(dict.fromkeys(HANDPICKED))
    while len(urls) < count:
        kind = rng.randrange(5)
        scheme = rng.choice(["http", "https"])
        tld = rng.choice(_TLDS)
        path = rng.choice(_PATHS)
        if kind == 0:  # marque dans le sous-domaine ou typosquat
            brand = rng.choice(_BRANDS)
            typo = brand.replace("a", "4", 1) if rng.random() < 0.5 else brand + "-secure"
            host = f"{rng.choice([brand, typo])}.{rng.choice(_WORDS)}-{rng.randrange(999)}.{tld}"
        elif kind == 1:  # mots-clés et tirets
            host = "-".join(rng.sample(_WORDS, rng.randrange(1, 4))) + f".{tld}"
        elif kind == 2:  # sous-domaines en nombre
            host = ".".join(rng.sample(_WORDS, rng.randrange(1, 5))) + f".{tld}"
        elif kind == 3:  # chiffres
            host = f"{rng.choice(_WORDS)}{rng.randrange(10**6)}.{tld}"
        else:  # IPv4 de documentation
            host = f"{rng.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rng.randrange(256)}"
        query = f"?ref={rng.randrange(10**9)}" if rng.random() < 0.3 else ""
        url = f"{scheme}://{host}{path}{query}"
        if url not in urls:
            urls.append(url)
    return urls[:count]


def _canonical(document: object) -> bytes:
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build(models_dir: Path) -> tuple[dict, dict]:
    files = model_files(models_dir)["url"]
    model = UrlModel.load(files.model)
    calibrator = ScoreCalibrator.load(files.calibration) if files.calibration.is_file() else None
    exported = export_url_model(model, calibrator)
    exported_bytes = _canonical(exported)

    vectors = []
    for url in synthetic_urls(GOLDEN_COUNT):
        try:
            frame = model.features([url])
        except InvalidUrlError:
            raise SystemExit(f"URL de référence invalide pour l'extracteur : {url!r}") from None
        values = [float(v) for v in frame.iloc[0].tolist()]
        lightgbm_score = float(model.score_features(frame)[0])
        reference_score = predict_probability(exported, values)
        if abs(reference_score - lightgbm_score) > REFERENCE_TOLERANCE:
            raise SystemExit(
                f"implémentation de référence ≠ LightGBM pour {url!r} : "
                f"{reference_score!r} contre {lightgbm_score!r}"
            )
        calibrated = calibrated_probability(exported, values)
        if not all(map(math.isfinite, (*values, lightgbm_score, calibrated))):
            raise SystemExit(f"valeur non finie pour {url!r}")
        vectors.append(
            {
                "url": url,
                "features": dict(zip(model.feature_names, values, strict=True)),
                "raw_score": predict_raw(exported, values),
                "probability": lightgbm_score,
                "calibrated_probability": calibrated,
            }
        )

    golden = {
        "format_version": GOLDEN_FORMAT_VERSION,
        "description": (
            "Vecteurs de référence du modèle URL : features et scores calculés par Python. "
            "L'implémentation TypeScript doit les retrouver à `tolerance` près. "
            "Régénérer avec `make export`."
        ),
        "tolerance": GOLDEN_TOLERANCE,
        "model_version": exported["model_version"],
        "model_export_sha256": hashlib.sha256(exported_bytes).hexdigest(),
        "feature_extractor": exported["feature_extractor"],
        "feature_names": exported["feature_names"],
        "vectors": vectors,
    }
    return exported, golden


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--models-dir", type=Path, default=ROOT / "models")
    parser.add_argument("--golden", type=Path, default=ROOT / "tests/golden/url_vectors.json")
    args = parser.parse_args(argv)

    exported, golden = build(args.models_dir)
    target = args.models_dir / f"{exported['model_version']}.json"
    target.write_bytes(_canonical(exported))
    args.golden.parent.mkdir(parents=True, exist_ok=True)
    args.golden.write_text(
        json.dumps(golden, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n"
    )
    size_kib = target.stat().st_size / 1024
    print(f"modèle exporté : {target} ({size_kib:.0f} Kio, {golden['model_export_sha256'][:16]}…)")
    print(f"vecteurs de référence : {args.golden} ({len(golden['vectors'])} URLs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
