"""Collecte des URLs légitimes avec chemin depuis l'index de Common Crawl.

    python scripts/fetch_commoncrawl.py                   # dernier crawl, top 5 000 Tranco
    python scripts/fetch_commoncrawl.py --crawl CC-MAIN-2026-43 --tranco-top 20000

Corrige le biais de chemin mesuré à l'étape 1.3 (docs/data-bias.md) : pour chaque domaine
du haut de la liste Tranco, jusqu'à --per-domain pages internes réellement publiées.

Écrit dans data/raw/ :

- commoncrawl_<crawl>_<horodatage>.csv : url, timestamp (capture, UTC), domain, tranco_rank ;
- manifest_<horodatage>.json : même format que fetch_feeds.py, lu par build_dataset.py.

L'index du crawl (cluster.idx, ≈ 100 Mo) est mis en cache dans data/external/commoncrawl/.
Une nouvelle collecte n'a d'intérêt qu'à chaque nouveau crawl (environ une fois par mois).

Le CDN de Common Crawl bloque les clients trop rapides (HTTP 403) : le débit est limité
(--rate, 2 requêtes/s par défaut, soit ≈ 45 min pour 5 000 domaines) et la collecte
s'arrête au premier 403. Elle garde alors les domaines traités avant l'incident.

Code de sortie : 0 si tous les domaines ont été traités, 1 sinon.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import logging
import platform
import sys
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from phishguard.data import commoncrawl as cc
from phishguard.data.integrity import sha256_file
from phishguard.data.urls import (
    discover_feeds,
    make_domain_extractor,
    normalize_url,
    registered_domain,
)

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_VERSION = "0.3.0"
TIMEOUT = 60.0
MAX_RATE = 5.0  # requêtes par seconde

logger = logging.getLogger("fetch_commoncrawl")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--output-dir", type=Path, default=ROOT / "data/raw")
    p.add_argument("--cache-dir", type=Path, default=ROOT / "data/external/commoncrawl")
    p.add_argument(
        "--crawl", help="identifiant du crawl, ex. CC-MAIN-2026-43 (défaut : le dernier)"
    )
    p.add_argument(
        "--tranco-file",
        type=Path,
        help="liste Tranco à utiliser (défaut : la plus récente des manifestes de --output-dir)",
    )
    p.add_argument(
        "--tranco-top", type=int, default=5000, help="domaines interrogés (défaut : 5000)"
    )
    p.add_argument(
        "--per-domain", type=int, default=5, help="URLs gardées par domaine (défaut : 5)"
    )
    p.add_argument(
        "--blocks-per-domain",
        type=int,
        default=1,
        help="blocs d'index lus au plus par domaine (défaut : 1)",
    )
    p.add_argument("--seed", type=int, default=42)
    p.add_argument(
        "--rate",
        type=float,
        default=2.0,
        help=f"requêtes par seconde au plus, de 0,1 à {MAX_RATE:g} (défaut : 2)",
    )
    p.add_argument("--workers", type=int, default=2, help="requêtes simultanées (défaut : 2)")
    p.add_argument(
        "--max-consecutive-failures",
        type=int,
        default=10,
        help="domaines en erreur d'affilée avant l'arrêt (défaut : 10)",
    )
    args = p.parse_args(argv)
    for name in ("tranco_top", "per_domain", "blocks_per_domain", "max_consecutive_failures"):
        if getattr(args, name) < 1:
            p.error(f"--{name.replace('_', '-')} doit être >= 1")
    if not 1 <= args.workers <= 4:
        p.error("--workers doit être compris entre 1 et 4")
    if not 0.1 <= args.rate <= MAX_RATE:
        p.error(f"--rate doit être compris entre 0,1 et {MAX_RATE:g} (restons polis avec le CDN)")
    return args


def latest_tranco_file(raw_dir: Path) -> Path | None:
    """Fichier Tranco de la collecte la plus récente décrite par un manifeste."""
    feeds = [feed for feed in discover_feeds(raw_dir).feeds if feed.source == "tranco"]
    return max(feeds, key=lambda feed: feed.collected_at).path if feeds else None


def read_tranco(path: Path, top: int) -> list[tuple[int, str]]:
    """Les ``top`` premiers ``(rang, domaine)`` d'un CSV Tranco ``rang,domaine``."""
    domains: list[tuple[int, str]] = []
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) >= 2 and row[0].strip().isdigit() and row[1].strip():
                domains.append((int(row[0]), row[1].strip().lower()))
            if len(domains) >= top:
                break
    return domains


def first_party(domain: str, extractor) -> Callable[[str], bool]:
    """Vrai si l'URL appartient au domaine lui-même, pas à un client de sa plateforme.

    Sous ``amazonaws.com`` ou ``github.io`` (suffixes privés), un sous-domaine appartient à
    un tiers : ``ec2-1-2-3-4.compute.amazonaws.com`` n'est pas une page d'Amazon.
    """

    def keep(url: str) -> bool:
        normalized = normalize_url(url)
        return normalized is not None and registered_domain(normalized[1], extractor) == domain

    return keep


@dataclass
class DomainResult:
    captures: list[cc.Capture]
    block_errors: int = 0
    failed: bool = False  # tous les blocs lus ont échoué
    blocked: bool = False  # le CDN a répondu 403


def collect_domain(
    client: httpx.Client,
    crawl: str,
    index: cc.ClusterIndex,
    domain: str,
    args: argparse.Namespace,
    extractor,
    limiter: cc.RateLimiter,
    stop: threading.Event,
) -> DomainResult | None:
    """Captures retenues pour un domaine ; ``None`` si la collecte a été arrêtée avant."""
    if stop.is_set():
        return None
    rng = cc.domain_rng(args.seed, domain)
    blocks = index.sample_blocks(domain, args.blocks_per_domain, rng)
    errors = 0
    for block in blocks:
        try:
            data = cc.fetch_block(client, crawl, block, limiter)
        except cc.AccessBlocked:
            stop.set()
            return DomainResult([], errors + 1, failed=True, blocked=True)
        except (httpx.HTTPError, ValueError, OSError) as exc:
            errors += 1
            logger.warning("%s : bloc illisible (%s)", domain, type(exc).__name__)
            continue
        captures = cc.select_captures(cc.parse_block(data), domain, first_party(domain, extractor))
        if captures:
            return DomainResult(cc.sample_captures(captures, args.per_domain, rng), errors)
    return DomainResult([], errors, failed=bool(blocks) and errors == len(blocks))


def collect(
    client: httpx.Client,
    crawl: str,
    index: cc.ClusterIndex,
    domains: list[tuple[int, str]],
    args: argparse.Namespace,
) -> tuple[list[tuple[int, str, DomainResult]], str | None]:
    """Traite les domaines dans l'ordre du classement.

    Retourne les résultats du **préfixe propre** (les domaines traités avant le premier
    incident) et la raison de l'arrêt, ou ``None`` si tout a été traité. Garder un préfixe
    rend une collecte interrompue reproductible : c'est exactement ce que donnerait
    ``--tranco-top`` égal à sa longueur.
    """
    extractor = make_domain_extractor()
    extractor("example.com")  # charge la liste des suffixes avant les threads
    limiter = cc.RateLimiter(args.rate)
    stop = threading.Event()

    def task(item: tuple[int, str]) -> DomainResult | None:
        return collect_domain(client, crawl, index, item[1], args, extractor, limiter, stop)

    processed: list[tuple[int, str, DomainResult]] = []
    streak_start: int | None = None
    reason = None
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for (rank, domain), result in zip(domains, pool.map(task, domains), strict=True):
            if result is None or result.blocked:
                reason = "accès refusé par le CDN (HTTP 403)"
                break
            if result.failed:
                streak_start = len(processed) if streak_start is None else streak_start
                if len(processed) + 1 - streak_start >= args.max_consecutive_failures:
                    reason = f"{args.max_consecutive_failures} domaines en erreur d'affilée"
                    break
            else:
                streak_start = None
            processed.append((rank, domain, result))
            if len(processed) % 500 == 0:
                urls = sum(len(r.captures) for _, _, r in processed)
                logger.info("%d/%d domaines, %d URLs", len(processed), len(domains), urls)
        # Les tâches pas encore commencées s'arrêtent aussitôt.
        stop.set()
    if reason is not None and streak_start is not None:
        processed = processed[:streak_start]
    return processed, reason


def to_csv(rows: list[tuple[str, str, str, int]]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["url", "timestamp", "domain", "tranco_rank"])
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def run(args: argparse.Namespace, client: httpx.Client, now: datetime | None = None) -> int:
    logging.getLogger("httpx").setLevel(logging.WARNING)
    now = now or datetime.now(UTC)
    timestamp = now.strftime("%Y%m%d_%H%M%S")

    tranco_file = args.tranco_file or latest_tranco_file(args.output_dir)
    if tranco_file is None or not Path(tranco_file).is_file():
        logger.error("aucune liste Tranco : lancez d'abord scripts/fetch_feeds.py")
        return 1
    domains = read_tranco(Path(tranco_file), args.tranco_top)

    crawl = args.crawl or cc.latest_crawl(client)
    if not crawl.startswith("CC-MAIN-") or "/" in crawl:
        logger.error("identifiant de crawl refusé : %r", crawl)
        return 1
    logger.info(
        "Crawl %s, %d domaines Tranco (%s), %.1f requêtes/s au plus",
        crawl,
        len(domains),
        Path(tranco_file).name,
        args.rate,
    )
    index_path = cc.download_cluster_index(client, crawl, args.cache_dir / crawl / "cluster.idx")
    index = cc.ClusterIndex.from_file(index_path)
    logger.info("Index chargé : %d blocs", len(index))

    processed, reason = collect(client, crawl, index, domains, args)
    rows = [(c.url, c.timestamp, domain, rank) for rank, domain, r in processed for c in r.captures]
    if reason is not None:
        logger.error("Collecte interrompue : %s, après %d domaines", reason, len(processed))
    if not rows:
        logger.error("aucune URL collectée")
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)
    content = to_csv(rows)
    name = f"commoncrawl_{crawl}_{timestamp}.csv"
    (args.output_dir / name).write_bytes(content)
    entry = {
        # Les URLs d'un préfixe interrompu sont valides : la source reste lisible.
        "status": "ok",
        "file": name,
        "count": len(rows),
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "source_url": f"{cc.DATA_URL}/{cc.CLUSTER_PATH.format(crawl=crawl)}",
        "crawl": crawl,
        "cluster_idx_sha256": sha256_file(index_path),
        "tranco_file": Path(tranco_file).name,
        "tranco_sha256": sha256_file(Path(tranco_file)),
        "tranco_top_requested": len(domains),
        "domains_processed": len(processed),
        "domains_with_urls": sum(bool(r.captures) for _, _, r in processed),
        "per_domain": args.per_domain,
        "blocks_per_domain": args.blocks_per_domain,
        "seed": args.seed,
        "rate_per_second": args.rate,
        "block_errors": sum(r.block_errors for _, _, r in processed),
        "aborted": reason,
    }
    manifest = {
        "metadata": {
            "timestamp_utc": timestamp,
            "collected_at": now.isoformat(timespec="seconds"),
            "collector": "fetch_commoncrawl",
            "collector_version": COLLECTOR_VERSION,
            "python": platform.python_version(),
            "httpx": httpx.__version__,
            "success": reason is None,
        },
        "feeds": {"commoncrawl": entry},
    }
    manifest_path = args.output_dir / f"manifest_{timestamp}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(
        "Common Crawl %s : %s (%d URLs, %d/%d domaines traités, %d blocs en erreur)",
        "OK" if reason is None else "PARTIEL",
        name,
        len(rows),
        entry["domains_processed"],
        len(domains),
        entry["block_errors"],
    )
    return 0 if reason is None else 1


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    args = parse_args(argv)
    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
        return run(args, client)


if __name__ == "__main__":
    sys.exit(main())
