"""Tests du rapatriement des archives chiffrées (sans réseau ni gh)."""

import importlib.util
import io
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sync_feed_archives.py"
spec = importlib.util.spec_from_file_location("sync_feed_archives", SCRIPT)
sfa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sfa)


def add_file(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def make_archive(path: Path, members: dict[str, bytes], link: str | None = None) -> None:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            add_file(tar, name, data)
        if link:
            info = tarfile.TarInfo(link)
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)


def test_extract_only_raw_files_and_never_overwrite(tmp_path):
    archive = tmp_path / "a.tar.gz"
    make_archive(
        archive,
        {
            "raw/openphish_1.txt": b"https://a.example/\n",
            "raw/manifest_1.json": b"{}",
            "raw/../../evil.txt": b"x",
            "/abs.txt": b"x",
            "raw/sub/deep.txt": b"x",
            "raw/.synced_artifacts": b"x",
        },
        link="raw/link.txt",
    )
    out = tmp_path / "out"
    out.mkdir()
    (out / "manifest_1.json").write_bytes(b"original")

    added = sfa.extract_feeds(archive, out)

    assert added == ["openphish_1.txt"]
    assert (out / "manifest_1.json").read_bytes() == b"original"
    assert sorted(p.name for p in out.iterdir()) == ["manifest_1.json", "openphish_1.txt"]
    assert not (tmp_path / "evil.txt").exists()


def test_copy_plain_files_from_legacy_artifact(tmp_path):
    src = tmp_path / "artifact"
    src.mkdir()
    (src / "openphish_1.txt").write_text("new")
    (src / "manifest_1.json").write_text("new")
    (src / "subdir").mkdir()
    out = tmp_path / "out"
    out.mkdir()
    (out / "manifest_1.json").write_text("original")

    assert sfa.copy_plain_files(src, out) == ["openphish_1.txt"]
    assert (out / "manifest_1.json").read_text() == "original"


def test_decrypt_matches_workflow_encryption(tmp_path):
    try:
        openssl = sfa.find_openssl()
    except FileNotFoundError:
        pytest.skip("openssl indisponible")
    archive = tmp_path / "feeds.tar.gz"
    make_archive(archive, {"raw/tranco_X_3_1.csv": b"1,google.com\n"})
    encrypted = tmp_path / "feeds-1.tar.gz.enc"
    # Même commande que l'étape « Encrypt archive » de .github/workflows/fetch-feeds.yml
    subprocess.run(
        [openssl, "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt"]
        + ["-in", str(archive), "-out", str(encrypted), "-pass", "env:ARCHIVE_PASSPHRASE"],
        check=True,
        env={**os.environ, "ARCHIVE_PASSPHRASE": "test-pass"},
    )
    decrypted = tmp_path / "out.tar.gz"
    sfa.decrypt(encrypted, decrypted, "test-pass", openssl)
    assert sfa.extract_feeds(decrypted, tmp_path / "raw") == ["tranco_X_3_1.csv"]

    with pytest.raises(subprocess.CalledProcessError):
        sfa.decrypt(encrypted, tmp_path / "bad.tar.gz", "wrong-pass", openssl)
