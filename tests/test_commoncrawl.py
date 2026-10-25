"""Tests de la collecte Common Crawl, sur un faux index servi par httpx.MockTransport."""

import gzip
import importlib.util
import json
import random
import sys
from pathlib import Path

import httpx
import pandas as pd
import pytest

from phishguard.data import commoncrawl as cc
from phishguard.data import urls as U

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fetch_commoncrawl.py"
spec = importlib.util.spec_from_file_location("fetch_commoncrawl", SCRIPT)
fetch_script = importlib.util.module_from_spec(spec)
# Enregistré avant exécution : @dataclass résout ses annotations via sys.modules.
sys.modules[spec.name] = fetch_script
spec.loader.exec_module(fetch_script)

CRAWL = "CC-MAIN-2026-43"


def cdx(url: str, ts: str = "20261010000000", status: str = "200", mime: str = "text/html"):
    """Une ligne CDX telle que publiée par Common Crawl."""
    host_and_path = url.split("://", 1)[1]
    host, _, path = host_and_path.partition("/")
    key = f"{cc.surt_host(host.removeprefix('www.'))})/{path}"
    fields = {"url": url, "mime": mime, "mime-detected": mime, "status": status}
    return key, f"{key} {ts} {json.dumps(fields)}"


def build_index(blocks: list[list[tuple[str, str]]], file: str = "cdx-00000.gz"):
    """Concatène des blocs gzip et produit ``(contenu du fichier, lignes de cluster.idx)``."""
    content, cluster, offset = b"", [], 0
    for seq, block in enumerate(blocks, start=1):
        block = sorted(block)
        data = gzip.compress("\n".join(line for _, line in block).encode("utf-8") + b"\n")
        first_key = block[0][1].split(" ", 2)
        cluster.append(f"{first_key[0]} {first_key[1]}\t{file}\t{offset}\t{len(data)}\t{seq}")
        content += data
        offset += len(data)
    return content, cluster


def range_transport(files: dict[str, bytes], cluster: list[str], log: list | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if log is not None:
            log.append(request)
        path = request.url.path
        if path.endswith("collinfo.json"):
            return httpx.Response(200, json=[{"id": CRAWL}, {"id": "CC-MAIN-2026-39"}])
        if path.endswith("cluster.idx"):
            return httpx.Response(200, content=("\n".join(cluster) + "\n").encode())
        name = path.rsplit("/", 1)[-1]
        if name in files:
            start, end = map(int, request.headers["Range"].removeprefix("bytes=").split("-"))
            return httpx.Response(206, content=files[name][start : end + 1])
        return httpx.Response(404)

    return httpx.MockTransport(handler)


# --------------------------------------------------------------------------- #
# SURT et index
# --------------------------------------------------------------------------- #


def test_surt_host_and_range():
    assert cc.surt_host("WWW.Example.co.uk.") == "uk,co,example,www"
    low, high = cc.surt_range("example.com")
    inside = ["com,example)/", "com,example)/a?b", "com,example,www)/x", "com,example,a,b)/"]
    outside = ["com,example-shop)/", "com,examplex)/", "com,exampl)/", "com,examplf)/"]
    assert all(low <= key < high for key in inside)
    assert not any(low <= key < high for key in outside)


def test_cluster_index_finds_every_block_of_a_domain():
    lines = [
        "com,aaa)/ 1\tcdx-00000.gz\t0\t10\t1",
        "com,example)/a 1\tcdx-00000.gz\t10\t10\t2",  # le domaine commence ici…
        "com,example,www)/z 1\tcdx-00000.gz\t20\t10\t3",
        "com,zzz)/ 1\tcdx-00000.gz\t30\t10\t4",  # … et finit avant ce bloc
    ]
    index = cc.ClusterIndex(lines)
    assert len(index) == 4
    # Le bloc précédent peut contenir le début du domaine : il est inclus.
    assert [b.offset for b in index.blocks_for("example.com")] == [0, 10, 20]
    assert [b.offset for b in index.blocks_for("aaa.com")] == [0]
    # Avant la première clé de l'index : le domaine ne peut pas y figurer.
    assert index.blocks_for("0.com") == []

    with pytest.raises(ValueError, match="trié"):
        cc.ClusterIndex(list(reversed(lines)))


# --------------------------------------------------------------------------- #
# Filtrage et tirage
# --------------------------------------------------------------------------- #


def test_parse_and_select_keep_only_first_party_html_pages():
    lines = [
        cdx("https://www.example.com/news/1", ts="20261012000000"),
        cdx("https://www.example.com/news/1", ts="20261008000000"),  # capture plus ancienne
        cdx("https://blog.example.com/post?id=2"),
        cdx("https://www.example.com/robots.txt", mime="text/plain"),
        cdx("https://www.example.com/redirect", status="301"),
        cdx("https://www.example.com/file.pdf", mime="application/pdf"),
        cdx("https://www.example.com/" + "a" * 3000),
        cdx("https://example-shop.com/other-domain"),
        cdx("https://user.example.com/third-party"),
    ]
    data = gzip.compress(
        (
            "\n".join(line for _, line in sorted(lines)) + "\nligne invalide\nk 1 {pas du json}\n"
        ).encode()
    )
    records = list(cc.parse_block(data))
    assert len(records) == len(lines)

    kept = cc.select_captures(records, "example.com", keep_url=lambda url: "user." not in url)
    assert kept == [
        cc.Capture("https://blog.example.com/post?id=2", "20261010000000"),
        cc.Capture("https://www.example.com/news/1", "20261008000000"),
    ]


def test_sample_prefers_deep_urls_and_is_deterministic():
    captures = [cc.Capture("https://a.com/", "1")] + [
        cc.Capture(f"https://a.com/p{i}", "1") for i in range(10)
    ]
    first = cc.sample_captures(captures, 3, cc.domain_rng(42, "a.com"))
    again = cc.sample_captures(captures, 3, cc.domain_rng(42, "a.com"))
    assert first == again and len(first) == 3
    assert all(c.url != "https://a.com/" for c in first)
    # Seule la page d'accueil est disponible : on la garde plutôt que rien.
    home = [cc.Capture("https://a.com/", "1")]
    assert cc.sample_captures(home, 5, random.Random(0)) == home


# --------------------------------------------------------------------------- #
# Réseau
# --------------------------------------------------------------------------- #


def test_fetch_block_uses_range_requests_and_checks_the_answer():
    content = b"0123456789abcdef"
    log: list[httpx.Request] = []
    client = httpx.Client(transport=range_transport({"cdx-00001.gz": content}, [], log))
    assert cc.fetch_block(client, CRAWL, cc.Block("cdx-00001.gz", 4, 6)) == b"456789"
    assert log[0].headers["Range"] == "bytes=4-9"
    assert log[0].headers["User-Agent"].startswith("PhishGuard")

    for block, message in [
        (cc.Block("../secret.gz", 0, 4), "refusé"),
        (cc.Block("cdx-00001.gz", 0, cc.MAX_BLOCK_BYTES + 1), "taille"),
    ]:
        with pytest.raises(ValueError, match=message):
            cc.fetch_block(client, CRAWL, block)

    full = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=content))
    )
    with pytest.raises(ValueError, match="partielle"):
        cc.fetch_block(full, CRAWL, cc.Block("cdx-00001.gz", 0, 4))


def test_get_with_retry_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr(cc.time, "sleep", lambda s: None)
    answers = iter([httpx.Response(503), httpx.Response(200, json=[{"id": CRAWL}])])
    client = httpx.Client(transport=httpx.MockTransport(lambda r: next(answers)))
    assert cc.latest_crawl(client) == CRAWL


def test_download_cluster_index_caches(tmp_path):
    log: list[httpx.Request] = []
    client = httpx.Client(transport=range_transport({}, ["k 1\tcdx-00000.gz\t0\t1\t1"], log))
    dest = tmp_path / CRAWL / "cluster.idx"
    assert (
        cc.download_cluster_index(client, CRAWL, dest).read_text() == "k 1\tcdx-00000.gz\t0\t1\t1\n"
    )
    cc.download_cluster_index(client, CRAWL, dest)
    assert len(log) == 1
    assert not dest.with_suffix(".part").exists()


# --------------------------------------------------------------------------- #
# Script et intégration au jeu d'URLs
# --------------------------------------------------------------------------- #


@pytest.fixture
def fake_crawl():
    blocks = [
        [cdx("https://www.alpha-demo.com/")]
        + [cdx(f"https://www.alpha-demo.com/doc/{i}") for i in range(3)],
        [cdx("https://beta-demo.com/login/help"), cdx("https://sites.beta-demo.com/x")],
        [cdx("https://zeta-demo.com/a", status="404")],
    ]
    content, cluster = build_index(blocks)
    return range_transport({"cdx-00000.gz": content}, cluster)


def write_tranco_run(raw: Path) -> None:
    ts = "20261024_084511"
    tranco = "1,alpha-demo.com\n2,beta-demo.com\n3,zeta-demo.com\n"
    (raw / f"tranco_X_3_{ts}.csv").write_bytes(tranco.encode())
    manifest = {
        "metadata": {"timestamp_utc": ts, "collected_at": "2026-10-24T08:45:11+00:00"},
        "feeds": {"tranco": {"status": "ok", "file": f"tranco_X_3_{ts}.csv", "sha256": None}},
    }
    phishing = "https://sites.beta-demo.com/fake-login\n"
    (raw / f"openphish_{ts}.txt").write_bytes(phishing.encode())
    manifest["feeds"]["openphish"] = {"status": "ok", "file": f"openphish_{ts}.txt", "sha256": None}
    (raw / f"manifest_{ts}.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_script_collects_and_build_dataset_reads_it(tmp_path, fake_crawl):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_tranco_run(raw)
    args = fetch_script.parse_args(
        ["--output-dir", str(raw), "--cache-dir", str(tmp_path / "cache"), "--per-domain", "2"]
    )
    now = pd.Timestamp("2026-10-24T19:00:00Z").to_pydatetime()
    assert fetch_script.run(args, httpx.Client(transport=fake_crawl), now) == 0

    csv_file = raw / f"commoncrawl_{CRAWL}_20261024_190000.csv"
    collected = pd.read_csv(csv_file, dtype=str)
    assert collected.groupby("domain").size().to_dict() == {"alpha-demo.com": 2, "beta-demo.com": 2}
    assert not collected["url"].str.endswith("alpha-demo.com/").any()  # page d'accueil évitée

    manifest = json.loads((raw / "manifest_20261024_190000.json").read_text(encoding="utf-8"))
    entry = manifest["feeds"]["commoncrawl"]
    assert entry["crawl"] == CRAWL and entry["tranco_top_requested"] == 3
    assert entry["domains_processed"] == 3 and entry["aborted"] is None
    assert entry["domains_with_urls"] == 2 and entry["block_errors"] == 0

    result = U.build_url_dataset(U.discover_feeds(raw).feeds)
    crawled = result.dataset[result.dataset["source"] == "commoncrawl"]
    assert set(crawled["label"]) == {U.LABEL_LEGITIMATE}
    assert crawled["first_seen"].eq(pd.Timestamp("2026-10-10", tz="UTC")).all()
    # beta-demo.com héberge du phishing : ses pages internes crawlées sont retirées,
    # sa page d'accueil Tranco est conservée.
    assert set(crawled["registered_domain"]) == {"alpha-demo.com"}
    assert result.steps["commoncrawl_on_phishing_domain"] == 2
    assert "https://beta-demo.com/" in set(result.dataset["url"])


def test_first_party_rejects_platform_customers():
    keep = fetch_script.first_party("amazonaws.com", U.make_domain_extractor())
    assert keep("https://aws.amazonaws.com/fr/")
    assert not keep("https://ec2-1-2-3-4.compute-1.amazonaws.com/shop")
    assert not keep("pas une url")


def test_script_requires_a_tranco_list(tmp_path, fake_crawl):
    args = fetch_script.parse_args(["--output-dir", str(tmp_path)])
    assert fetch_script.run(args, httpx.Client(transport=fake_crawl)) == 1


@pytest.mark.parametrize("argv", [["--per-domain", "0"], ["--workers", "20"]])
def test_script_rejects_bad_arguments(argv):
    with pytest.raises(SystemExit):
        fetch_script.parse_args(argv)


def test_rate_limiter_spaces_requests():
    clock = [0.0]
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    limiter = cc.RateLimiter(2.0, clock=lambda: clock[0], sleep=sleep)
    for _ in range(3):
        limiter.wait()
    assert sleeps == [0.5, 0.5]
    with pytest.raises(ValueError):
        cc.RateLimiter(0)


def test_http_403_stops_without_retry(monkeypatch):
    monkeypatch.setattr(cc.time, "sleep", lambda s: pytest.fail("pas de nouvel essai sur 403"))
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(403)))
    with pytest.raises(cc.AccessBlocked):
        cc.fetch_block(client, CRAWL, cc.Block("cdx-00000.gz", 0, 4))


def many_domains_crawl(n: int, blocked_from: int | None = None, failing_from: int | None = None):
    """Un domaine par bloc ; au-delà d'un rang, le CDN répond 403 ou 500."""
    names = [f"d{i:03d}-demo.com" for i in range(n)]
    content, cluster = build_index([[cdx(f"https://{name}/page")] for name in names])
    offsets = {int(line.split("\t")[2]): i for i, line in enumerate(cluster)}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("cluster.idx"):
            return httpx.Response(200, content=("\n".join(cluster) + "\n").encode())
        start, end = map(int, request.headers["Range"].removeprefix("bytes=").split("-"))
        rank = offsets[start]
        if blocked_from is not None and rank >= blocked_from:
            return httpx.Response(403)
        if failing_from is not None and rank >= failing_from:
            return httpx.Response(500)
        return httpx.Response(206, content=content[start : end + 1])

    return names, httpx.MockTransport(handler)


@pytest.mark.parametrize(
    ("blocked_from", "failing_from", "kept", "reason"),
    [(None, None, 30, None), (12, None, 12, "403"), (None, 20, 20, "d'affilée")],
)
def test_collection_keeps_a_clean_prefix(
    tmp_path, monkeypatch, blocked_from, failing_from, kept, reason
):
    monkeypatch.setattr(cc.time, "sleep", lambda s: None)
    names, transport = many_domains_crawl(30, blocked_from, failing_from)
    raw = tmp_path / "raw"
    raw.mkdir()
    tranco = raw / "tranco.csv"
    tranco.write_text("".join(f"{i + 1},{name}\n" for i, name in enumerate(names)), "utf-8")
    args = fetch_script.parse_args(
        [
            *["--output-dir", str(raw), "--cache-dir", str(tmp_path / "cache")],
            *["--tranco-file", str(tranco), "--crawl", CRAWL, "--rate", "5"],
            *["--workers", "3", "--max-consecutive-failures", "4"],
        ]
    )
    code = fetch_script.run(args, httpx.Client(transport=transport))

    assert code == (0 if reason is None else 1)
    manifest = json.loads(next(raw.glob("manifest_*.json")).read_text(encoding="utf-8"))
    entry = manifest["feeds"]["commoncrawl"]
    assert entry["domains_processed"] == kept
    assert manifest["metadata"]["success"] is (reason is None)
    assert (entry["aborted"] is None) if reason is None else (reason in entry["aborted"])
    collected = pd.read_csv(raw / entry["file"])
    # Préfixe propre : exactement les `kept` premiers domaines, sans trou.
    assert collected["tranco_rank"].tolist() == list(range(1, kept + 1))
