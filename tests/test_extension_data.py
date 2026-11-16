"""Données de l'extension (étape 5.3) : à jour avec l'extracteur Python.

L'extension relit ``extension/src/generated/reference-data.json`` pour calculer les mêmes
features que Python. Si une liste change côté Python (``brands.json``, mots-clés,
version de tldextract…) sans ``make extension-data``, l'extension calculerait d'autres
features en silence : ce test l'empêche. Les tables Unicode et les cas de parité, plus
longs à régénérer, sont vérifiés par ``scripts/export_extension_data.py --check`` et
par les tests TypeScript (``npm test``).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _script():
    name = "export_extension_data"
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_committed_reference_data_matches_the_python_extractor() -> None:
    script = _script()
    committed = json.loads(script.REFERENCE_PATH.read_text(encoding="utf-8"))
    assert committed == script.reference_data(), "données périmées : make extension-data"


def test_reference_data_carries_the_extractor_fingerprint() -> None:
    from phishguard.urls.features import FEATURE_EXTRACTOR_VERSION, reference_data_sha256

    committed = json.loads(_script().REFERENCE_PATH.read_text(encoding="utf-8"))
    assert committed["feature_extractor"]["version"] == FEATURE_EXTRACTOR_VERSION
    assert committed["feature_extractor"]["reference_data_sha256"] == reference_data_sha256()


def test_every_idn_suffix_is_reachable_from_its_a_label() -> None:
    # Hypothèse du port TypeScript de tldextract (voir _check_idn_suffixes).
    script = _script()
    public, private = script._suffix_lists()
    script._check_idn_suffixes([*public, *private])


def test_fuzz_corpus_is_deterministic() -> None:
    script = _script()
    assert script.fuzz_urls(50) == script.fuzz_urls(50)
    assert len(set(script.fuzz_urls(200))) == 200
