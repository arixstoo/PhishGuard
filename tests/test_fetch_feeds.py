"""Tests du collecteur de flux, sans réseau (httpx.MockTransport)."""

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fetch_feeds.py"
spec = importlib.util.spec_from_file_location("fetch_feeds", SCRIPT)
ff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ff)

NOW = datetime(2026, 10, 24, 4, 0, tzinfo=UTC)
URLHAUS_KEY = "secret-urlhaus-key"
URLHAUS_CSV = (
    "################\n# abuse.ch URLhaus\n#\n"
    "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    '"1","2026-10-23 10:00:00","http://a.example/x","online","","malware_download",'
    '"elf","https://urlhaus.abuse.ch/url/1/","r"\n'
    '"2","2026-10-23 11:00:00","http://b.example/y","offline","","malware_download",'
    '"exe","https://urlhaus.abuse.ch/url/2/","r"\n'
)
PHISHTANK_CSV = (
    "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
    '1,"https://evil.example/a\nb",http://x,2026,yes,2026,yes,Other\n'
    "2,https://evil.example/c,http://x,2026,yes,2026,yes,PayPal\n"
)


def make_handler(overrides=None, calls=None):
    """Faux serveur : chaque route peut être surchargée par une réponse ou une fonction."""
    overrides = overrides or {}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if calls is not None:
            calls.append(url)
        for prefix, resp in overrides.items():
            if url.startswith(prefix):
                return resp(request) if callable(resp) else resp
        if url == ff.OPENPHISH_URL:
            return httpx.Response(200, text="https://a.example/login\nhttps://b.example/\n\n")
        if url.startswith("https://data.phishtank.com/"):
            return httpx.Response(200, text=PHISHTANK_CSV)
        if url == ff.TRANCO_API_URL.format(day="2026-10-23"):
            return httpx.Response(200, json={"available": True, "list_id": "ABC12"})
        if url == ff.TRANCO_DOWNLOAD_URL.format(list_id="ABC12", top_n=3):
            return httpx.Response(200, text="1,google.com\n2,cloudflare.com\n3,facebook.com\n")
        if url == ff.URLHAUS_URL.format(key=URLHAUS_KEY):
            return httpx.Response(200, text=URLHAUS_CSV)
        return httpx.Response(404)

    return handler


def run_collector(tmp_path, handler, monkeypatch, urlhaus_key=URLHAUS_KEY):
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    monkeypatch.setattr(ff.time, "sleep", lambda _s: None)
    argv = ["--output-dir", str(tmp_path), "--tranco-top", "3"]
    if urlhaus_key:
        argv += ["--urlhaus-auth-key", urlhaus_key]
    args = ff.parse_args(argv)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        code = ff.run(args, client, now=NOW)
    manifest = json.loads((tmp_path / "manifest_20261024_040000.json").read_text("utf-8"))
    return code, manifest


def test_full_collection_writes_timestamped_files_and_manifest(tmp_path, monkeypatch):
    code, manifest = run_collector(tmp_path, make_handler(), monkeypatch)

    assert code == 0
    assert manifest["metadata"]["success"] is True
    feeds = manifest["feeds"]
    assert {name: f["status"] for name, f in feeds.items()} == dict.fromkeys(
        ["openphish", "phishtank", "tranco", "urlhaus"], "ok"
    )
    assert feeds["openphish"]["count"] == 2
    assert feeds["phishtank"]["count"] == 2  # champ multi-ligne compté une seule fois
    assert feeds["urlhaus"]["count"] == 2  # commentaires ignorés
    assert feeds["tranco"]["file"] == "tranco_ABC12_3_20261024_040000.csv"
    assert feeds["tranco"]["list_date"] == "2026-10-23"
    for entry in feeds.values():
        content = (tmp_path / entry["file"]).read_bytes()
        assert entry["sha256"] == ff.compute_sha256(content)


def test_tranco_content_matches_resolved_list_id(tmp_path, monkeypatch):
    """Le contenu doit venir de l'URL du list_id, pas de la dernière liste « daily »."""
    calls = []
    run_collector(tmp_path, make_handler(calls=calls), monkeypatch)
    assert ff.TRANCO_DOWNLOAD_URL.format(list_id="ABC12", top_n=3) in calls
    assert not any("download/daily" in url for url in calls)


def test_tranco_retries_on_rate_limit(tmp_path, monkeypatch):
    attempts = {"n": 0}

    def flaky(request):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return httpx.Response(200, json={"available": True, "list_id": "ABC12"})

    handler = make_handler({ff.TRANCO_API_URL.format(day="2026-10-23"): flaky})
    code, manifest = run_collector(tmp_path, handler, monkeypatch)
    assert code == 0
    assert attempts["n"] == 2
    assert manifest["feeds"]["tranco"]["list_id"] == "ABC12"


def test_tranco_without_list_id_fails_instead_of_guessing(tmp_path, monkeypatch):
    handler = make_handler({"https://tranco-list.eu/api/": httpx.Response(404)})
    code, manifest = run_collector(tmp_path, handler, monkeypatch)
    assert code == 1
    assert manifest["feeds"]["tranco"]["status"] == "error"
    assert not list(tmp_path.glob("tranco_*.csv"))


def test_secrets_never_reach_manifest_or_logs(tmp_path, monkeypatch, caplog):
    handler = make_handler({"https://urlhaus-api.abuse.ch/": httpx.Response(403)})
    with caplog.at_level("DEBUG"):
        code, manifest = run_collector(tmp_path, handler, monkeypatch)
    assert code == 0  # URLhaus en échec, mais Tranco + autres flux OK
    assert manifest["feeds"]["urlhaus"] == {
        "status": "error",
        "source_url": ff.URLHAUS_URL.format(key="***"),
        "error": "HTTP 403",
    }
    assert URLHAUS_KEY not in json.dumps(manifest)
    assert URLHAUS_KEY not in caplog.text


def test_urlhaus_skipped_without_key(tmp_path, monkeypatch):
    code, manifest = run_collector(tmp_path, make_handler(), monkeypatch, urlhaus_key=None)
    assert code == 0
    assert manifest["feeds"]["urlhaus"]["status"] == "skipped"


def test_no_phishing_feed_means_failure(tmp_path, monkeypatch):
    handler = make_handler(
        {
            ff.OPENPHISH_URL: httpx.Response(503),
            "https://data.phishtank.com/": httpx.Response(403),
        }
    )
    code, manifest = run_collector(tmp_path, handler, monkeypatch, urlhaus_key=None)
    assert code == 1
    assert manifest["metadata"]["success"] is False


def test_phishtank_app_key_goes_in_path():
    assert ff.PHISHTANK_URL.format(key_part="K/") == (
        "https://data.phishtank.com/data/K/online-valid.csv"
    )


@pytest.mark.parametrize("value", ["0", "1000001"])
def test_tranco_top_bounds(value):
    with pytest.raises(SystemExit):
        ff.parse_args(["--tranco-top", value])
