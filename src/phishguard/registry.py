"""Registre de modèles signé (étape 4.12) : manifeste, signature Ed25519, vérification.

Chaque publication de modèles a un ``manifest.json`` : version, date, empreinte SHA-256 et
taille de chaque fichier, métriques, version de l'extracteur de features. Le manifeste est
signé avec une clé **Ed25519** ; la signature est détachée (``manifest.json.sig``). L'API
(au démarrage) et l'extension (module 6, avant d'utiliser un modèle téléchargé) vérifient
la signature **puis** chaque empreinte, avant de lire le moindre modèle.

Pourquoi c'est indispensable ici : les modèles sont des fichiers **pickle**, que charger
revient à exécuter. Sans signature, quiconque peut écrire dans le dossier des modèles (ou
servir un faux téléchargement) exécute son code dans l'API. Avec elle, il lui faut la clé
privée, qui ne quitte jamais la machine de publication (jamais le dépôt, jamais la CI).

Choix de conception :

- **octets signés tels quels** : la signature porte sur les octets exacts du fichier,
  sans recanonicalisation à la vérification (aucune ambiguïté d'encodage JSON). Le
  manifeste est écrit une fois, en JSON canonique (clés triées, UTF-8, compact) ;
- **signature d'abord, contenu ensuite** : le manifeste n'est interprété qu'après
  vérification de la signature, et ses tailles sont bornées avant lecture ;
- **chemins plats** : un artefact est un nom de fichier du dossier (``url_v2.joblib``),
  jamais un chemin (``../../etc/x``) ni un lien symbolique ;
- **pas de TOCTOU** : :meth:`VerifiedManifest.read` lit le fichier **une fois**, vérifie
  l'empreinte de ces octets et les renvoie ; c'est eux que l'on désérialise. Un fichier
  remplacé entre la vérification et le chargement n'est donc jamais chargé ;
- **identifiant de clé** (``key_id``, 16 caractères hexadécimaux de l'empreinte de la clé
  publique) dans la signature : une rotation de clé se voit, et une signature produite
  par une autre clé est refusée avec un message clair ;
- **clé privée** chiffrée par phrase de passe (``PHISHGUARD_SIGNING_PASSPHRASE``, jamais en
  argument de ligne de commande, visible dans ``ps`` et l'historique), droits ``600``,
  refusée à l'intérieur du dépôt.

Hors périmètre, assumé : la protection contre le retour à une version antérieure signée
(*rollback*) relève de l'extension (module 6), qui connaît la dernière version acceptée ;
le manifeste porte pour cela ``release`` et ``created_at``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.json.sig"
MANIFEST_FORMAT = "phishguard-model-manifest"
MANIFEST_FORMAT_VERSION = 1
SIGNATURE_ALGORITHM = "ed25519"
# Nom de la variable d'environnement, pas une valeur : faux positif de bandit (B105).
PASSPHRASE_ENV = "PHISHGUARD_SIGNING_PASSPHRASE"  # nosec B105

# Bornes lues avant tout traitement : un manifeste ou une signature démesurés sont refusés.
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SIGNATURE_BYTES = 4096
MAX_KEY_BYTES = 4096
_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_HEX_CHARS = 16
_SIGNATURE_FIELDS = frozenset({"algorithm", "format_version", "key_id", "signature"})


class ManifestError(ValueError):
    """Manifeste absent, mal signé ou qui ne correspond pas aux fichiers."""


class SignatureError(ManifestError):
    """Signature absente, mal formée, d'une autre clé, ou invalide."""


class IntegrityError(ManifestError):
    """Un fichier ne correspond pas à son empreinte ou à sa taille signées."""


# --------------------------------------------------------------------------- #
# Clés
# --------------------------------------------------------------------------- #


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:KEY_ID_HEX_CHARS]


def public_key_raw_base64(public_key: Ed25519PublicKey) -> str:
    """Clé publique brute (32 octets) en base64 : forme importable par WebCrypto."""
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def write_private_key(
    key: Ed25519PrivateKey, path: Path, *, passphrase: bytes | None, forbidden_dir: Path | None
) -> None:
    """Écrit la clé privée (PKCS#8 PEM), créée en ``600``, sans écraser une clé existante."""
    path = Path(path)
    if forbidden_dir is not None and _inside(path, forbidden_dir):
        raise ValueError(f"{path} : la clé privée ne doit jamais être dans le dépôt")
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL : une clé existante n'est jamais écrasée (perdre la clé de publication oblige
    # à redistribuer la clé publique à toutes les extensions).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)


def load_private_key(path: Path, *, passphrase: bytes | None) -> Ed25519PrivateKey:
    path = Path(path)
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise PermissionError(f"{path} : clé privée lisible par d'autres (chmod 600)")
    data = _read_bounded(path, MAX_KEY_BYTES, "clé privée")
    key = serialization.load_pem_private_key(data, password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} : clé Ed25519 attendue")
    return key


def write_public_key(key: Ed25519PublicKey, path: Path) -> None:
    pem = key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(pem)


def load_public_key(path: Path) -> Ed25519PublicKey:
    data = _read_bounded(Path(path), MAX_KEY_BYTES, "clé publique")
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"{path} : clé publique Ed25519 attendue")
    return key


def passphrase_from_env() -> bytes | None:
    value = os.environ.get(PASSPHRASE_ENV)
    return value.encode("utf-8") if value else None


# --------------------------------------------------------------------------- #
# Manifeste
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Artifact:
    """Un fichier publié : nom plat dans le dossier des modèles, empreinte et taille."""

    name: str
    sha256: str
    size: int
    role: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "role": self.role, "sha256": self.sha256, "size": self.size}


def canonical_json(document: Mapping[str, Any]) -> bytes:
    """JSON canonique : clés triées, compact, UTF-8. Ce sont ces octets qui sont signés."""
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _check_name(name: str) -> str:
    if not isinstance(name, str) or not _ARTIFACT_NAME.fullmatch(name) or ".." in name:
        raise ManifestError(f"nom d'artefact refusé : {name!r} (nom de fichier plat attendu)")
    return name


def describe_artifact(directory: Path, name: str, role: str) -> Artifact:
    path = Path(directory) / _check_name(name)
    if path.is_symlink() or not path.is_file():
        raise ManifestError(f"{path} : fichier ordinaire attendu")
    data = path.read_bytes()
    return Artifact(name, hashlib.sha256(data).hexdigest(), len(data), role)


def build_manifest(
    directory: Path,
    artifacts: Iterable[tuple[str, str]],
    *,
    release: str,
    models: Mapping[str, Any],
    created_at: datetime | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Manifeste d'une publication. ``artifacts`` : paires (nom de fichier, rôle)."""
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}", release):
        raise ValueError(f"version de publication invalide : {release!r}")
    described = [describe_artifact(directory, name, role) for name, role in artifacts]
    names = [a.name for a in described]
    if len(set(names)) != len(names) or not names:
        raise ValueError("au moins un artefact, sans doublon")
    created = (created_at or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    return {
        "format": MANIFEST_FORMAT,
        "format_version": MANIFEST_FORMAT_VERSION,
        "release": release,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "models": dict(models),
        "artifacts": [a.to_dict() for a in sorted(described, key=lambda a: a.name)],
        **(dict(extra) if extra else {}),
    }


def sign_manifest(manifest_bytes: bytes, signing_key: Ed25519PrivateKey) -> bytes:
    """Document de signature détachée (JSON) pour ces octets exacts."""
    signature = signing_key.sign(manifest_bytes)
    return canonical_json(
        {
            "algorithm": SIGNATURE_ALGORITHM,
            "format_version": MANIFEST_FORMAT_VERSION,
            "key_id": key_id(signing_key.public_key()),
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    )


# gitleaks:allow ci-dessous : faux positif, le motif « clé suivie d'un jeton » vise un nom de type.
def write_signed_manifest(
    directory: Path,
    manifest: Mapping[str, Any],
    signing_key: Ed25519PrivateKey,  # gitleaks:allow
) -> tuple[Path, Path]:
    """Écrit ``manifest.json`` et sa signature, puis les revérifie avant de rendre la main."""
    directory = Path(directory)
    manifest_bytes = canonical_json(manifest)
    manifest_path, signature_path = directory / MANIFEST_NAME, directory / SIGNATURE_NAME
    manifest_path.write_bytes(manifest_bytes)
    signature_path.write_bytes(sign_manifest(manifest_bytes, signing_key))
    verify_manifest(directory, signing_key.public_key())  # jamais publier sans relire
    return manifest_path, signature_path


# --------------------------------------------------------------------------- #
# Vérification
# --------------------------------------------------------------------------- #


def _read_bounded(path: Path, limit: int, what: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ManifestError(f"{path} : {what} introuvable (fichier ordinaire attendu)")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ManifestError(f"{path} : {what} trop volumineux")
    return data


def _verify_signature(
    manifest_bytes: bytes, signature_bytes: bytes, public: Ed25519PublicKey
) -> str:
    try:
        document = json.loads(signature_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SignatureError("signature illisible") from None
    # Format strict : exactement ces champs. Un champ inconnu ou renommé n'est pas ignoré,
    # sinon deux fichiers de signature différents seraient acceptés pour le même manifeste.
    if not isinstance(document, dict) or set(document) != _SIGNATURE_FIELDS:
        raise SignatureError(
            "signature mal formée (champs attendus : " + ", ".join(sorted(_SIGNATURE_FIELDS)) + ")"
        )
    if document["algorithm"] != SIGNATURE_ALGORITHM:
        raise SignatureError(f"algorithme de signature {SIGNATURE_ALGORITHM} attendu")
    if document["format_version"] != MANIFEST_FORMAT_VERSION or isinstance(
        document["format_version"], bool
    ):
        raise SignatureError("version du format de signature inconnue")
    # Octets canoniques exigés : espaces, ordre des clés ou échappements différents
    # donneraient, eux aussi, un autre fichier pour la même signature.
    if canonical_json(document) != signature_bytes:
        raise SignatureError("signature mal formée (JSON non canonique)")
    expected_id = key_id(public)
    if document.get("key_id") != expected_id:
        raise SignatureError(
            f"manifeste signé par la clé {document.get('key_id')!r}, {expected_id!r} attendue"
        )
    encoded = str(document.get("signature", ""))
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise SignatureError("signature mal encodée (base64)") from None
    # Encodage canonique exigé : le dernier caractère de 88 caractères base64 porte des
    # bits inutilisés, qu'on pourrait changer sans changer les octets décodés. Sans ce
    # contrôle, un fichier de signature modifié resterait accepté (malléabilité).
    if base64.b64encode(signature).decode("ascii") != encoded:
        raise SignatureError("signature mal encodée (base64 non canonique)")
    if len(signature) != 64:
        raise SignatureError("signature Ed25519 de 64 octets attendue")
    try:
        public.verify(signature, manifest_bytes)
    except InvalidSignature:
        raise SignatureError("signature du manifeste invalide") from None
    return expected_id


def _parse_artifacts(manifest: Mapping[str, Any]) -> dict[str, Artifact]:
    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or not entries:
        raise ManifestError("manifeste sans artefact")
    artifacts: dict[str, Artifact] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ManifestError("artefact mal formé")
        name = _check_name(entry.get("name"))
        digest, size = entry.get("sha256"), entry.get("size")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ManifestError(f"{name} : empreinte SHA-256 invalide")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ManifestError(f"{name} : taille invalide")
        if name in artifacts:
            raise ManifestError(f"{name} : artefact en double")
        artifacts[name] = Artifact(name, digest, size, str(entry.get("role", "")))
    return artifacts


@dataclass(frozen=True)
class VerifiedManifest:
    """Manifeste dont la signature est valide. Les fichiers se lisent par :meth:`read`."""

    directory: Path
    manifest: Mapping[str, Any]
    artifacts: Mapping[str, Artifact]
    key_id: str
    sha256: str

    @property
    def release(self) -> str:
        return str(self.manifest["release"])

    def read(self, name: str) -> bytes:
        """Octets de ``name``, lus une fois et vérifiés (taille puis empreinte).

        Ce sont ces octets qu'il faut désérialiser, jamais le fichier relu ensuite.
        """
        artifact = self.artifacts.get(name)
        if artifact is None:
            raise IntegrityError(f"{name} n'est pas dans le manifeste signé")
        path = self.directory / artifact.name
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"{path} : fichier ordinaire attendu")
        with path.open("rb") as handle:
            data = handle.read(artifact.size + 1)
        if len(data) != artifact.size:
            raise IntegrityError(f"{name} : taille différente de celle signée")
        if hashlib.sha256(data).hexdigest() != artifact.sha256:
            raise IntegrityError(f"{name} : empreinte SHA-256 différente de celle signée")
        return data

    def verify_all(self) -> None:
        for name in self.artifacts:
            self.read(name)


def verify_manifest(directory: Path, public_key: Ed25519PublicKey) -> VerifiedManifest:
    """Vérifie la signature du manifeste de ``directory`` puis chaque artefact.

    Lève :class:`SignatureError` ou :class:`IntegrityError` (sous-classes de
    :class:`ManifestError`) ; ne renvoie qu'un manifeste entièrement vérifié.
    """
    directory = Path(directory)
    manifest_bytes = _read_bounded(directory / MANIFEST_NAME, MAX_MANIFEST_BYTES, "manifeste")
    signature_bytes = _read_bounded(directory / SIGNATURE_NAME, MAX_SIGNATURE_BYTES, "signature")
    signer = _verify_signature(manifest_bytes, signature_bytes, public_key)
    # Signature valide : le contenu vient du détenteur de la clé, on peut l'interpréter.
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ManifestError("manifeste signé mais illisible") from None
    if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT:
        raise ManifestError("format de manifeste inconnu")
    if manifest.get("format_version") != MANIFEST_FORMAT_VERSION:
        raise ManifestError(f"version de manifeste {manifest.get('format_version')!r} inconnue")
    verified = VerifiedManifest(
        directory=directory,
        manifest=manifest,
        artifacts=_parse_artifacts(manifest),
        key_id=signer,
        sha256=hashlib.sha256(manifest_bytes).hexdigest(),
    )
    verified.verify_all()
    return verified
