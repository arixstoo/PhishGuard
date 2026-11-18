"""Publication signée de test pour l'extension (étape 6.8).

Signe, avec une clé **éphémère** jetée ensuite, un petit manifeste au format de
`phishguard.registry`. L'extension (`extension/test/signed-model.test.ts`) vérifie que
ce que Python signe, le TypeScript l'accepte, et le refuse au moindre octet modifié.

    python scripts/make_signed_release_fixture.py

Aucune clé privée n'est écrite : seule la clé publique accompagne la fixture.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phishguard.registry import build_manifest, write_signed_manifest

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "extension" / "test" / "fixtures" / "signed-release"
REFERENCE = ROOT / "extension" / "src" / "generated" / "reference-data.json"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    extractor = json.loads(REFERENCE.read_text(encoding="utf-8"))["feature_extractor"]
    model = {"format": "phishguard-url-lightgbm", "note": "fixture : pas un vrai modèle"}
    # Octets explicites (LF) : la fixture doit avoir la même empreinte sur tout système.
    (OUT / "url_v9.json").write_bytes((json.dumps(model, sort_keys=True) + "\n").encode("utf-8"))

    key = Ed25519PrivateKey.generate()
    manifest = build_manifest(
        OUT,
        [("url_v9.json", "url-export")],
        release="2026.12.01",
        models={
            "url": {
                "version": "url_v9",
                "trained_at": None,
                "metrics": None,
                "feature_extractor": {
                    "version": extractor["version"],
                    "reference_data_sha256": extractor["reference_data_sha256"],
                    "features": [],
                },
            }
        },
        created_at=datetime(2026, 12, 1, 3, 0, tzinfo=UTC),
        extra={"normalization_version": extractor["normalization_version"]},
    )
    write_signed_manifest(OUT, manifest, key)
    (OUT / "public.pem").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    print(f"fixture écrite dans {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
