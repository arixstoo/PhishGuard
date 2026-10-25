"""Tests de la construction du jeu d'URLs (étape 1.2), sur de petits fichiers bruts factices."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pandas as pd
import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from phishguard.data import urls as U
from phishguard.data.integrity import DatasetIntegrityError

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_dataset.py"
spec = importlib.util.spec_from_file_location("build_dataset", SCRIPT)
build_script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_script)

TS1, TS2 = "20261022_091554", "20261023_091207"
OPENPHISH = "https://Evil-Demo.COM/login\nhttps://shared-demo.com/\n\nhttps://dup-demo.com/a\n"
PHISHTANK = (
    "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
    "1,https://dup-demo.com/a,x,2026-10-01T10:00:00+00:00,yes,x,yes,Other\n"
    "2,http://paypal.com@phish-demo.com/x,x,2026-10-02T10:00:00+00:00,yes,x,yes,PayPal\n"
    "3,https://bad url-demo.com/,x,2026-10-02T10:00:00+00:00,yes,x,yes,Other\n"
    "4,https://late-demo.com/,x,2099-01-01T00:00:00+00:00,yes,x,yes,Other\n"
)
URLHAUS = (
    "#####\n# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    '"1","2026-10-20 08:00:00","http://malware-demo.com/bin.sh","online","","malware_download",'
    '"elf,mirai","l","r"\n'
    '"2","2026-10-20 09:00:00","https://phish.urlhaus-demo.com/#victim@corp-demo.com","online","",'
    '"malware_download","Phishing","l","r"\n'
)
TRANCO = "1,google.com\n2,shared-demo.com\n3,github.io\n"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_run(raw: Path, ts: str, files: dict[str, tuple[str, str]], legacy: bool = False):
    """Écrit les fichiers d'une collecte et son manifeste (format 0.2.0 ou 0.1.0)."""
    feeds = {}
    for source, (name, content) in files.items():
        # Octets bruts, comme fetch_feeds.py (write_text ajouterait des \r sous Windows).
        (raw / name).write_bytes(content.encode("utf-8"))
        feeds[source] = {"file": name, "sha256": sha(content)}
        if not legacy:
            feeds[source]["status"] = "ok"
    metadata = {"timestamp_utc": ts}
    if not legacy:
        metadata["collected_at"] = pd.Timestamp(ts.replace("_", "T"), tz="UTC").isoformat()
    manifest = {"metadata": metadata, "feeds": feeds}
    (raw / f"manifest_{ts}.json").write_text(json.dumps(manifest), encoding="utf-8")


@pytest.fixture
def raw_dir(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_run(
        raw,
        TS1,
        {
            "openphish": (f"openphish_{TS1}.txt", OPENPHISH),
            "tranco": (f"tranco_AAA_3_{TS1}.csv", TRANCO),
        },
        legacy=True,
    )
    write_run(
        raw,
        TS2,
        {
            "phishtank": (f"phishtank_{TS2}.csv", PHISHTANK),
            "urlhaus": (f"urlhaus_recent_{TS2}.csv", URLHAUS),
            "tranco": (f"tranco_BBB_3_{TS2}.csv", TRANCO),
        },
    )
    return raw


def build(raw_dir, **kwargs):
    return U.build_url_dataset(U.discover_feeds(raw_dir).feeds, **kwargs)


# --------------------------------------------------------------------------- #
# normalize_url / registered_domain
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTPS://WWW.Example.COM", ("https://www.example.com/", "www.example.com")),
        ("  http://a-demo.com/Path?Q=1#Frag ", ("http://a-demo.com/Path?Q=1#Frag", "a-demo.com")),
        ("example.com/login", ("http://example.com/login", "example.com")),
        ("http://example.com./x", ("http://example.com./x", "example.com")),
        (
            "http://User:Pw@Bank-Demo.COM:8080/",
            ("http://User:Pw@bank-demo.com:8080/", "bank-demo.com"),
        ),
        ("http://[2001:DB8::1]/x", ("http://[2001:db8::1]/x", "2001:db8::1")),
    ],
)
def test_normalize_url(raw, expected):
    assert U.normalize_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "ftp://example.com/f",
        "http://",
        "http://a-demo.com/x y",
        "http://a-demo.com:99999/",
    ],
)
def test_normalize_url_rejects_invalid(raw):
    assert U.normalize_url(raw) is None


def test_normalize_url_does_not_treat_query_scheme_as_scheme():
    url, host = U.normalize_url("example.com/r?to=https://other-demo.com")
    assert host == "example.com"
    assert url == "http://example.com/r?to=https://other-demo.com"


@given(st.from_regex(r"https?://[a-zA-Z0-9.-]{1,20}\.[a-z]{2,5}(/[a-zA-Z0-9._~%-]*){0,3}"))
@example("http://0.aa%A")  # urlsplit garde la casse après « % » dans l'hôte
def test_normalize_url_is_idempotent(raw):
    first = U.normalize_url(raw)
    if first is not None:
        assert U.normalize_url(first[0]) == first


@pytest.fixture(scope="module")
def extractor():
    return U.make_domain_extractor()


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("login.secure.example.co.uk", "example.co.uk"),
        ("victim.github.io", "victim.github.io"),  # suffixe privé : un site par compte
        ("github.io", "github.io"),  # l'hôte est lui-même un suffixe privé
        ("s3.amazonaws.com", "s3.amazonaws.com"),
        ("192.0.2.10", "192.0.2.10"),
        ("2001:db8::1", "2001:db8::1"),
        ("localhost", None),
        ("co.uk", None),
    ],
)
def test_registered_domain(extractor, host, expected):
    assert U.registered_domain(host, extractor) == expected


# --------------------------------------------------------------------------- #
# Manifestes
# --------------------------------------------------------------------------- #


def test_parse_manifest_v0_flat_format():
    collected_at, entries = U.parse_manifest(
        {"timestamp_utc": TS1, "openphish": "openphish_x.txt", "urlhaus": None, "tranco": None}
    )
    assert collected_at == pd.Timestamp("2026-10-22T09:15:54", tz="UTC")
    assert entries == [{"source": "openphish", "file": "openphish_x.txt", "sha256": None}]


def test_parse_manifest_skips_failed_sources():
    _, entries = U.parse_manifest(
        {
            "metadata": {"timestamp_utc": TS2, "collected_at": "2026-10-23T09:12:07+00:00"},
            "feeds": {
                "openphish": {"status": "ok", "file": "a.txt", "sha256": "x"},
                "phishtank": {"status": "error", "source_url": "u", "error": "HTTP 403"},
                "urlhaus": {"status": "skipped", "source_url": "u", "error": "clé absente"},
            },
        }
    )
    assert [e["source"] for e in entries] == ["openphish"]


def test_discover_feeds_warns_about_missing_and_orphan_files(raw_dir):
    (raw_dir / f"tranco_AAA_3_{TS1}.csv").unlink()
    (raw_dir / "openphish_20990101_000000.txt").write_text("https://x-demo.com/\n", "utf-8")
    inventory = U.discover_feeds(raw_dir)
    assert len(inventory.feeds) == 4
    assert any("fichier absent" in w for w in inventory.warnings)
    assert any("sans manifeste" in w for w in inventory.warnings)


def test_discover_feeds_rejects_path_traversal(tmp_path):
    manifest = {
        "metadata": {"timestamp_utc": TS1},
        "feeds": {"openphish": {"file": "../secret.txt"}},
    }
    (tmp_path / f"manifest_{TS1}.json").write_text(json.dumps(manifest), "utf-8")
    with pytest.raises(ValueError, match="refusé"):
        U.discover_feeds(tmp_path)


def test_discover_feeds_rejects_unreadable_manifest(tmp_path):
    (tmp_path / f"manifest_{TS1}.json").write_text("{not json", "utf-8")
    with pytest.raises(ValueError, match="illisible"):
        U.discover_feeds(tmp_path)


def test_checksum_mismatch_is_fatal(raw_dir):
    (raw_dir / f"openphish_{TS1}.txt").write_text("https://tampered-demo.com/\n", "utf-8")
    with pytest.raises(DatasetIntegrityError):
        build(raw_dir)
    assert build(raw_dir, verify=False).steps["rows"] > 0


# --------------------------------------------------------------------------- #
# Construction du jeu
# --------------------------------------------------------------------------- #


def test_schema_and_types(raw_dir):
    dataset = build(raw_dir).dataset
    assert list(dataset.columns) == U.COLUMNS
    assert set(dataset["label"]) == {0, 1}
    assert str(dataset["first_seen"].dt.tz) == "UTC"
    assert dataset["url"].is_unique
    assert dataset["first_seen"].is_monotonic_increasing


def test_urlhaus_keeps_only_phishing_tags(raw_dir):
    result = build(raw_dir)
    from_urlhaus = result.dataset[result.dataset["source"] == "urlhaus"]
    assert from_urlhaus["url"].tolist() == ["https://phish.urlhaus-demo.com/#victim@corp-demo.com"]
    assert result.steps["urlhaus_malware_excluded"] == 1


def test_duplicates_keep_earliest_observation(raw_dir):
    dataset = build(raw_dir).dataset.set_index("url")
    # Vue par OpenPhish le 22/10, mais soumise à PhishTank le 01/10.
    row = dataset.loc["https://dup-demo.com/a"]
    assert row["source"] == "phishtank"
    assert row["first_seen"] == pd.Timestamp("2026-10-01T10:00:00", tz="UTC")
    # Tranco vue lors des deux collectes : date de la première.
    assert dataset.loc["https://google.com/", "first_seen"] == pd.Timestamp(
        "2026-10-22T09:15:54", tz="UTC"
    )


def test_first_seen_never_after_collection(raw_dir):
    dataset = build(raw_dir).dataset.set_index("url")
    assert dataset.loc["https://late-demo.com/", "first_seen"] == pd.Timestamp(
        "2026-10-23T09:12:07", tz="UTC"
    )


def test_label_conflicts_are_dropped(raw_dir):
    result = build(raw_dir)
    assert "https://shared-demo.com/" not in set(result.dataset["url"])
    assert result.steps["label_conflicts"] == 1


def test_invalid_urls_are_counted(raw_dir):
    result = build(raw_dir)
    assert result.steps["invalid_url"] == 1
    assert not result.dataset["url"].str.contains(" ").any()


def test_userinfo_trick_uses_real_host(raw_dir):
    row = build(raw_dir).dataset.set_index("url").loc["http://paypal.com@phish-demo.com/x"]
    assert row["host"] == "phish-demo.com"
    assert row["registered_domain"] == "phish-demo.com"


def test_steps_add_up(raw_dir):
    s = build(raw_dir).steps
    removed = s["invalid_url"] + s["unknown_suffix"] + s["duplicates_merged"]
    removed += s["capped_by_domain"]
    # Une URL en conflit est observée au moins deux fois (une par étiquette).
    assert s["observations"] - removed - s["rows"] >= 2 * s["label_conflicts"]


# --------------------------------------------------------------------------- #
# Limite par domaine
# --------------------------------------------------------------------------- #


def make_frame(n_phish: int, n_legit: int, domain: str = "big-demo.com") -> pd.DataFrame:
    rows = [(f"https://{domain}/p{i}", 1) for i in range(n_phish)]
    rows += [(f"https://{domain}/l{i}", 0) for i in range(n_legit)]
    df = pd.DataFrame(rows, columns=["url", "label"])
    df["registered_domain"] = domain
    return df


def test_cap_per_domain_limits_each_label_separately():
    capped = U.cap_per_domain(make_frame(20, 2), max_per_domain=5, seed=0)
    assert capped.groupby("label").size().to_dict() == {0: 2, 1: 5}


def test_cap_per_domain_is_deterministic_and_order_independent():
    df = make_frame(50, 0)
    first = set(U.cap_per_domain(df, 5, seed=1)["url"])
    shuffled = df.sample(frac=1.0, random_state=99)
    assert set(U.cap_per_domain(shuffled, 5, seed=1)["url"]) == first
    assert set(U.cap_per_domain(df, 5, seed=2)["url"]) != first


def test_cap_per_domain_rejects_zero():
    with pytest.raises(ValueError):
        U.cap_per_domain(make_frame(1, 0), 0, seed=0)


def test_summarize_counts_shared_domains():
    df = make_frame(3, 1)
    df["source"] = "x"
    df["first_seen"] = pd.Timestamp("2026-10-22", tz="UTC")
    summary = U.summarize(df)
    assert summary["rows_by_label"] == {"0": 1, "1": 3}
    assert summary["registered_domains_in_both_labels"] == 1


# --------------------------------------------------------------------------- #
# Script
# --------------------------------------------------------------------------- #


def test_script_writes_parquet_and_report(raw_dir, tmp_path, capsys):
    output, report = tmp_path / "out" / "urls.parquet", tmp_path / "metrics" / "report.json"
    argv = ["--raw-dir", str(raw_dir), "--output", str(output), "--report", str(report)]
    assert build_script.main(argv) == 0

    dataset = pd.read_parquet(output)
    assert list(dataset.columns) == U.COLUMNS
    content = json.loads(report.read_text("utf-8"))
    assert content["dataset"]["rows"] == len(dataset)
    assert content["metadata"]["params"]["max_per_domain"] == 5
    assert {i["file"] for i in content["inputs"]} >= {f"openphish_{TS1}.txt"}
    # Le rapport est versionné : il ne doit contenir aucune URL du jeu.
    assert not any(url in report.read_text("utf-8") for url in dataset["url"])
    assert "Domaines enregistrés distincts" in capsys.readouterr().out


def test_script_fails_without_feeds(tmp_path):
    argv = ["--raw-dir", str(tmp_path), "--output", str(tmp_path / "u.parquet")]
    assert build_script.main(argv + ["--report", str(tmp_path / "r.json")]) == 1


def test_script_rejects_invalid_cap():
    with pytest.raises(SystemExit):
        build_script.parse_args(["--max-per-domain", "0"])
