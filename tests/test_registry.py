"""Registre de modèles signé (étape 4.12).

Critère de fin : un script signe les modèles, un autre les vérifie, **en échouant si un
seul octet est modifié**. Chaque octet du manifeste et de la signature est modifié tour
à tour ; pour les modèles, un échantillon de positions réparties sur tout le fichier, plus
le premier et le dernier octet.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
from pathlib import Path

import pytest
from api_support import ROOT, api_client, settings_for
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phishguard.deployment import load_analyzers
from phishguard.registry import (
    MANIFEST_NAME,
    SIGNATURE_NAME,
    IntegrityError,
    ManifestError,
    SignatureError,
    build_manifest,
    canonical_json,
    load_private_key,
    load_public_key,
    sign_manifest,
    verify_manifest,
    write_private_key,
    write_public_key,
    write_signed_manifest,
)


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sign_script = _load_script("sign_models")
verify_script = _load_script("verify_models")


@pytest.fixture
def keys(tmp_path) -> tuple[Path, Path, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    private, public = tmp_path / "keys/signing.key", tmp_path / "keys/signing.pub"
    write_private_key(key, private, passphrase=None, forbidden_dir=None)
    write_public_key(key.public_key(), public)
    return private, public, key


@pytest.fixture
def signed_dir(api_models_dir, tmp_path, keys) -> Path:
    """Copie des modèles de test, signée par le vrai script."""
    models = tmp_path / "models"
    shutil.copytree(api_models_dir, models)
    (models / "url_v2.json").write_text('{"booster": {}}', encoding="utf-8")  # export factice
    assert (
        sign_script.main(
            [
                "sign",
                "--private-key",
                str(keys[0]),
                "--models-dir",
                str(models),
                "--release",
                "2026.11.12",
            ]
        )
        == 0
    )
    return models


def verify(models: Path, public: Path) -> int:
    return verify_script.main(["--models-dir", str(models), "--public-key", str(public)])


def _flip(path: Path, position: int) -> bytes:
    original = path.read_bytes()
    data = bytearray(original)
    data[position] ^= 0x01
    path.write_bytes(bytes(data))
    return original


def _positions(size: int, samples: int = 64) -> list[int]:
    return sorted({0, size - 1, *(i * size // samples for i in range(samples))})


# --------------------------------------------------------------------------- #
# Signer puis vérifier
# --------------------------------------------------------------------------- #


def test_signed_models_verify(signed_dir, keys, capsys):
    assert verify(signed_dir, keys[1]) == 0
    out = capsys.readouterr().out
    assert "manifeste 2026.11.12 valide" in out
    manifest = json.loads((signed_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
    names = {a["name"]: a["role"] for a in manifest["artifacts"]}
    assert names == {
        "url_v2.joblib": "url-model",
        "text_v2.joblib": "text-model",
        "url_v2.json": "url-export",
    }
    assert manifest["models"]["url"]["version"] == "url_v2"
    assert manifest["models"]["url"]["feature_extractor"]["version"]
    assert manifest["models"]["url"]["trained_at"] == "2026-11-01T00:00:00+00:00"
    # Octets écrits = JSON canonique : la signature porte sur eux seuls.
    assert (signed_dir / MANIFEST_NAME).read_bytes() == canonical_json(manifest)


@pytest.mark.parametrize("target", [MANIFEST_NAME, SIGNATURE_NAME])
def test_any_single_byte_change_in_manifest_or_signature_fails(signed_dir, keys, target):
    path = signed_dir / target
    size = len(path.read_bytes())
    for position in range(size):  # chaque octet, sans exception
        original = _flip(path, position)
        try:
            with pytest.raises(ManifestError):
                verify_manifest(signed_dir, load_public_key(keys[1]))
        finally:
            path.write_bytes(original)
    assert verify(signed_dir, keys[1]) == 0


@pytest.mark.parametrize("name", ["url_v2.joblib", "text_v2.joblib", "url_v2.json"])
def test_any_single_byte_change_in_a_model_fails(signed_dir, keys, name, capsys):
    path = signed_dir / name
    for position in _positions(path.stat().st_size):
        original = _flip(path, position)
        try:
            assert verify(signed_dir, keys[1]) == 1
        finally:
            path.write_bytes(original)
    assert "empreinte SHA-256 différente" in capsys.readouterr().err
    assert verify(signed_dir, keys[1]) == 0


@pytest.mark.parametrize("change", ["append", "truncate", "delete"])
def test_size_changes_and_missing_files_fail(signed_dir, keys, change):
    path = signed_dir / "text_v2.joblib"
    if change == "append":
        path.write_bytes(path.read_bytes() + b"\0")
    elif change == "truncate":
        path.write_bytes(path.read_bytes()[:-1])
    else:
        path.unlink()
    with pytest.raises(IntegrityError):
        verify_manifest(signed_dir, load_public_key(keys[1]))


def test_another_key_is_refused(signed_dir, tmp_path):
    other = tmp_path / "other.pub"
    write_public_key(Ed25519PrivateKey.generate().public_key(), other)
    with pytest.raises(SignatureError, match="clé"):
        verify_manifest(signed_dir, load_public_key(other))


def test_signature_of_an_attacker_is_refused_even_with_matching_key_id(signed_dir, keys):
    """L'identifiant de clé n'est qu'une étiquette : seule la signature compte."""
    attacker = Ed25519PrivateKey.generate()
    forged = json.loads(sign_manifest((signed_dir / MANIFEST_NAME).read_bytes(), attacker))
    genuine = json.loads((signed_dir / SIGNATURE_NAME).read_bytes())
    forged["key_id"] = genuine["key_id"]
    (signed_dir / SIGNATURE_NAME).write_bytes(canonical_json(forged))
    with pytest.raises(SignatureError, match="invalide"):
        verify_manifest(signed_dir, load_public_key(keys[1]))


def test_file_replaced_after_verification_is_never_loaded(signed_dir, keys):
    verified = verify_manifest(signed_dir, load_public_key(keys[1]))
    (signed_dir / "url_v2.json").write_text('{"booster": {"evil": 1}}', encoding="utf-8")
    with pytest.raises(IntegrityError):
        verified.read("url_v2.json")  # relu et revérifié au moment du chargement


# --------------------------------------------------------------------------- #
# Contenu du manifeste : interprété seulement une fois signé, et borné
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", ["../url_v2.joblib", "/etc/passwd", "a/b", ".hidden", "..", ""])
def test_artifact_paths_are_flat_names(signed_dir, keys, name):
    manifest = json.loads((signed_dir / MANIFEST_NAME).read_bytes())
    manifest["artifacts"][0]["name"] = name
    write_signed_manifest_unchecked(signed_dir, manifest, keys[2])
    with pytest.raises(ManifestError, match="nom d'artefact"):
        verify_manifest(signed_dir, load_public_key(keys[1]))


def write_signed_manifest_unchecked(directory: Path, manifest: dict, key) -> None:
    data = canonical_json(manifest)
    (directory / MANIFEST_NAME).write_bytes(data)
    (directory / SIGNATURE_NAME).write_bytes(sign_manifest(data, key))


@pytest.mark.skipif(os.name != "posix", reason="liens symboliques")
def test_symlinked_artifact_is_refused(signed_dir, keys, tmp_path):
    target = signed_dir / "url_v2.json"
    moved = tmp_path / "elsewhere.json"
    target.rename(moved)
    target.symlink_to(moved)
    with pytest.raises(IntegrityError, match="ordinaire"):
        verify_manifest(signed_dir, load_public_key(keys[1]))


def test_oversized_manifest_is_refused_before_parsing(signed_dir, keys):
    (signed_dir / MANIFEST_NAME).write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(ManifestError, match="volumineux"):
        verify_manifest(signed_dir, load_public_key(keys[1]))


def test_build_manifest_refuses_bad_input(signed_dir):
    with pytest.raises(ValueError):
        build_manifest(signed_dir, [], release="1", models={})
    with pytest.raises(ValueError):
        build_manifest(signed_dir, [("url_v2.json", "x")], release="../1", models={})
    with pytest.raises(ManifestError):
        build_manifest(signed_dir, [("absent.bin", "x")], release="1", models={})


# --------------------------------------------------------------------------- #
# Clé privée
# --------------------------------------------------------------------------- #


def test_private_key_is_refused_inside_the_repository():
    with pytest.raises(ValueError, match="dépôt"):
        write_private_key(
            Ed25519PrivateKey.generate(),
            ROOT / "keys/oops.key",
            passphrase=None,
            forbidden_dir=ROOT,
        )
    assert not (ROOT / "keys/oops.key").exists()


def test_existing_private_key_is_never_overwritten(keys):
    with pytest.raises(FileExistsError):
        write_private_key(
            Ed25519PrivateKey.generate(), keys[0], passphrase=None, forbidden_dir=None
        )


def test_encrypted_private_key_needs_its_passphrase(tmp_path):
    path = tmp_path / "enc.key"
    write_private_key(
        Ed25519PrivateKey.generate(), path, passphrase=b"correct horse", forbidden_dir=None
    )
    assert load_private_key(path, passphrase=b"correct horse")
    with pytest.raises((ValueError, TypeError)):
        load_private_key(path, passphrase=b"wrong")
    with pytest.raises(TypeError):
        load_private_key(path, passphrase=None)


@pytest.mark.skipif(os.name != "posix", reason="droits POSIX")
def test_private_key_permissions(keys):
    assert (keys[0].stat().st_mode & 0o777) == 0o600
    keys[0].chmod(0o644)
    with pytest.raises(PermissionError):
        load_private_key(keys[0], passphrase=None)


def test_keygen_command(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("PHISHGUARD_SIGNING_PASSPHRASE", raising=False)
    private, public = tmp_path / "k/priv.key", tmp_path / "k/pub.pem"
    assert (
        sign_script.main(["keygen", "--private-key", str(private), "--public-key", str(public)])
        == 0
    )
    captured = capsys.readouterr()
    assert "NON chiffrée" in captured.err
    assert "clé publique brute" in captured.out
    assert load_public_key(public) and load_private_key(private, passphrase=None)


# --------------------------------------------------------------------------- #
# Chargement par l'API
# --------------------------------------------------------------------------- #


def test_signed_models_load_from_verified_bytes(signed_dir, keys, monkeypatch):
    opened: list[object] = []
    import joblib

    real_load = joblib.load

    def spy(source, *args, **kwargs):
        opened.append(source)
        return real_load(source, *args, **kwargs)

    monkeypatch.setattr(joblib, "load", spy)
    analyzers = load_analyzers(signed_dir, public_key=load_public_key(keys[1]))
    assert analyzers.manifest is not None and analyzers.manifest.release == "2026.11.12"
    # Les modèles sont désérialisés depuis les octets vérifiés, jamais relus sur disque.
    assert opened and all(isinstance(s, io.BytesIO) for s in opened)


def test_model_outside_the_manifest_is_never_deserialized(signed_dir, keys, monkeypatch):
    manifest = json.loads((signed_dir / MANIFEST_NAME).read_bytes())
    manifest["artifacts"] = [a for a in manifest["artifacts"] if a["name"] != "text_v2.joblib"]
    write_signed_manifest(signed_dir, manifest, keys[2])
    import joblib

    monkeypatch.setattr(joblib, "load", lambda *a, **k: pytest.fail("pickle chargé"))
    with pytest.raises(IntegrityError, match="pas dans le manifeste"):
        load_analyzers(signed_dir, public_key=load_public_key(keys[1]))


def test_api_reports_the_verified_signature(signed_dir, keys, tmp_path):
    settings = settings_for(signed_dir, tmp_path, models_public_key=keys[1])
    with api_client(settings) as client:
        info = client.get("/v1/model").json()
    assert info["signature"]["release"] == "2026.11.12"
    assert len(info["signature"]["key_id"]) == 16


def test_api_refuses_to_start_on_a_tampered_model(signed_dir, keys, tmp_path, caplog):
    _flip(signed_dir / "url_v2.joblib", 100)
    settings = settings_for(signed_dir, tmp_path, models_public_key=keys[1])
    with pytest.raises(IntegrityError), api_client(settings):
        pass
    # La cause tient sur une ligne lisible : la trace, elle, est tronquée par le journal.
    assert any(
        "modèles refusés" in r.getMessage() and "url_v2.joblib" in r.getMessage()
        for r in caplog.records
    )


def test_production_requires_signed_models(api_models_dir, tmp_path, keys):
    with pytest.raises(ValueError, match="non signés"):
        settings_for(api_models_dir, tmp_path, environment="production")
    assert (
        settings_for(
            api_models_dir, tmp_path, environment="production", models_public_key=keys[1]
        ).models_public_key
        == keys[1]
    )
    assert settings_for(
        api_models_dir, tmp_path, environment="production", allow_unsigned_models=True
    ).allow_unsigned_models
