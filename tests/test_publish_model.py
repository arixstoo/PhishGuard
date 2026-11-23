"""Vérifications de ``scripts/publish_model.py`` avant toute signature (étape 6.8).

Le script signe sur la machine de l'auteur ce qu'a produit le workflow ``model-update`` :
il doit refuser une release brouillon modifiée, incomplète, augmentée d'un fichier, ou
dont le garde-fou a échoué. ``gh`` n'est jamais appelé ici.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("publish_model", ROOT / "scripts/publish_model.py")
assert _spec is not None and _spec.loader is not None
publish_model = importlib.util.module_from_spec(_spec)
sys.modules["publish_model"] = publish_model
_spec.loader.exec_module(publish_model)


def write_release(directory: Path, files: dict[str, bytes]) -> None:
    lines = []
    for name, content in files.items():
        (directory / name).write_bytes(content)
        lines.append(f"{hashlib.sha256(content).hexdigest()}  {name}")
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


FILES = {
    "url_v2.joblib": b"pickle",
    "url_v2.json": b'{"model": 1}',
    "gate_report.json": json.dumps({"passed": True, "gate_version": "1.0.0"}).encode(),
}


def test_intact_release_passes(tmp_path: Path) -> None:
    write_release(tmp_path, FILES)
    publish_model.check_sums(tmp_path)
    assert publish_model.check_gate(tmp_path)["passed"] is True


def test_modified_file_is_refused(tmp_path: Path) -> None:
    write_release(tmp_path, FILES)
    (tmp_path / "url_v2.json").write_bytes(b'{"model": 2}')
    with pytest.raises(publish_model.PublishError, match="url_v2.json"):
        publish_model.check_sums(tmp_path)


def test_missing_or_extra_file_is_refused(tmp_path: Path) -> None:
    write_release(tmp_path, FILES)
    (tmp_path / "url_v2.joblib").unlink()
    with pytest.raises(publish_model.PublishError, match="absents"):
        publish_model.check_sums(tmp_path)
    write_release(tmp_path, FILES)
    (tmp_path / "ajout.joblib").write_bytes(b"code")
    with pytest.raises(publish_model.PublishError, match="non listés"):
        publish_model.check_sums(tmp_path)


@pytest.mark.parametrize("report", [{"passed": False}, {}, {"passed": "true"}])
def test_failed_gate_is_never_signed(tmp_path: Path, report: dict) -> None:
    (tmp_path / "gate_report.json").write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(publish_model.PublishError, match="garde-fou"):
        publish_model.check_gate(tmp_path)


def test_channel_uploads_manifest_and_signature_last(tmp_path: Path) -> None:
    manifest = {"artifacts": [{"name": "url_v2.joblib"}, {"name": "url_v2.json"}]}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    names = [p.name for p in publish_model.channel_files(tmp_path)]
    assert names == ["url_v2.joblib", "url_v2.json", "manifest.json", "manifest.json.sig"]


@pytest.mark.parametrize("release", ["2026.12.2", "latest", "v0.6.0", "2026.12.02-rc"])
def test_release_names_are_dated(release: str) -> None:
    assert publish_model.RELEASE_RE.fullmatch(release) is None
    assert publish_model.main(["publish", release]) == 1
