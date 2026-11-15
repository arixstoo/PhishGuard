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


REPO_ID, WORKFLOW_ID = 1, 7
ORIGIN = {"repo_id": REPO_ID, "default_branch": "master", "workflow_id": WORKFLOW_ID}


def make_run(**overrides) -> dict:
    run = {
        "workflow_id": WORKFLOW_ID,
        "event": "schedule",
        "head_branch": "master",
        "head_repository": {"id": REPO_ID},
        "repository": {"id": REPO_ID},
    }
    return {**run, **overrides}


def make_artifact(name: str, run_id: int) -> dict:
    return {"name": name, "workflow_run": {"id": run_id}}


class FakeGitHub:
    """Simule `gh api` et `gh run download` (sans réseau)."""

    def __init__(self, monkeypatch, artifacts, runs, contents):
        self.runs, self.contents, self.downloaded = runs, contents, []
        monkeypatch.setattr(sfa, "list_artifacts", lambda repo: artifacts)
        monkeypatch.setattr(sfa, "gh_api", self.api)
        monkeypatch.setattr(sfa.subprocess, "run", self.run)

    def api(self, path: str) -> dict:
        if path == "repos/o/r":
            return {"id": REPO_ID, "default_branch": "master"}
        if path == "repos/o/r/actions/workflows/fetch-feeds.yml":
            return {"id": WORKFLOW_ID}
        return self.runs[int(path.rsplit("/", 1)[1])]

    def run(self, cmd, **kwargs):
        assert cmd[:3] == ["gh", "run", "download"]
        name, dest = cmd[cmd.index("-n") + 1], Path(cmd[cmd.index("-D") + 1])
        self.downloaded.append(name)
        for filename, data in self.contents[name].items():
            (dest / filename).write_bytes(data)
        return subprocess.CompletedProcess(cmd, 0)


@pytest.mark.parametrize(
    ("overrides", "trusted"),
    [
        ({}, True),
        ({"event": "workflow_dispatch"}, True),
        ({"event": "pull_request"}, False),
        ({"event": "pull_request_target"}, False),
        ({"event": "push"}, False),
        ({"workflow_id": 8}, False),
        ({"head_branch": "feature"}, False),
        ({"head_repository": {"id": 2}}, False),
        ({"head_repository": None}, False),
        ({"repository": {"id": 2}}, False),
    ],
)
def test_only_fetch_feeds_runs_on_default_branch_are_trusted(overrides, trusted):
    assert sfa.is_trusted_run(make_run(**overrides), ORIGIN) is trusted


def test_legacy_plain_artifact_imported_only_from_trusted_run(tmp_path, monkeypatch):
    fork_pr = make_run(event="pull_request", head_repository={"id": 99})
    gh = FakeGitHub(
        monkeypatch,
        [make_artifact("feeds-1", 1), make_artifact("feeds-2", 2), {"name": "feeds-3"}],
        {1: make_run(), 2: fork_pr},
        {"feeds-1": {"openphish_1.txt": b"legit"}, "feeds-2": {"openphish_2.txt": b"forged"}},
    )
    out = tmp_path / "raw"

    assert sfa.sync("o/r", out, "pass", "openssl") == 0

    assert gh.downloaded == ["feeds-1"]
    assert (out / "openphish_1.txt").read_bytes() == b"legit"
    assert not (out / "openphish_2.txt").exists()
    assert sfa.read_state(out) == {"feeds-1"}


def test_unreadable_archive_skipped_without_blocking_newer_ones(tmp_path, monkeypatch):
    good = tmp_path / "good.tar.gz"
    make_archive(good, {"raw/openphish_3.txt": b"ok"})
    FakeGitHub(
        monkeypatch,
        [make_artifact(f"feeds-{i}", i) for i in (1, 2, 3)],
        {1: make_run(), 2: make_run(), 3: make_run()},
        {
            "feeds-1": {"feeds-1.tar.gz.enc": b"wrong key"},
            "feeds-2": {"feeds-2.tar.gz.enc": b"not a tarball"},
            "feeds-3": {"feeds-3.tar.gz.enc": good.read_bytes()},
        },
    )

    def fake_decrypt(src, dest, passphrase, openssl):
        if src.read_bytes() == b"wrong key":
            raise subprocess.CalledProcessError(1, ["openssl"])
        dest.write_bytes(src.read_bytes())

    monkeypatch.setattr(sfa, "decrypt", fake_decrypt)
    out = tmp_path / "raw"

    assert sfa.sync("o/r", out, "pass", "openssl") == 1

    assert (out / "openphish_3.txt").read_bytes() == b"ok"
    assert sfa.read_state(out) == {"feeds-3"}


def test_invalid_api_response_is_a_clean_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARCHIVE_PASSPHRASE", "pass")
    monkeypatch.setenv("OPENSSL", "openssl")
    monkeypatch.setattr(sfa, "list_artifacts", lambda repo: [make_artifact("feeds-1", 1)])
    monkeypatch.setattr(
        sfa.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "<html>")
    )
    with pytest.raises(sfa.GitHubApiError):
        sfa.gh_api("repos/o/r")
    assert sfa.main(["--repo", "o/r", "--output-dir", str(tmp_path / "raw")]) == 1

    monkeypatch.setattr(sfa, "gh_api", lambda path: {"id": 1})
    with pytest.raises(sfa.GitHubApiError):
        sfa.trusted_origin("o/r")
    assert sfa.main(["--repo", "o/r", "--output-dir", str(tmp_path / "raw")]) == 1


def test_gh_api_decodes_utf8_whatever_the_locale(monkeypatch):
    body = '{"display_title": "❌ fix typo", "id": 7}'

    def fake_run(cmd, **kwargs):
        assert kwargs.get("encoding") == "utf-8"
        return subprocess.CompletedProcess(cmd, 0, body)

    monkeypatch.setattr(sfa.subprocess, "run", fake_run)
    assert sfa.gh_api("repos/o/r/actions/runs/7")["display_title"] == "❌ fix typo"


def test_nothing_pending_makes_no_api_call(tmp_path, monkeypatch):
    monkeypatch.setattr(sfa, "list_artifacts", lambda repo: [])

    def no_api(path):
        raise AssertionError("appel API inattendu")

    monkeypatch.setattr(sfa, "gh_api", no_api)
    assert sfa.sync("o/r", tmp_path, "pass", "openssl") == 0
