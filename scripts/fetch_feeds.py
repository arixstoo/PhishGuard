"""Script de collecte reproductible des flux de phishing et de domaines légitimes.

Chaque exécution écrit dans le dossier de sortie des fichiers horodatés (UTC) et un
manifeste JSON qui décrit ce qui a été collecté : statut par source, nombre de lignes,
SHA-256, URL d'origine (sans secret) et identifiant de la liste Tranco.

Usage:
    python scripts/fetch_feeds.py
    python scripts/fetch_feeds.py --output-dir data/raw --tranco-top 100000
    python scripts/fetch_feeds.py --urlhaus-auth-key VOTRE_CLE

Code de sortie : 0 si Tranco et au moins un flux de phishing ont été collectés, 1 sinon.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import logging
import os
import platform
import sys
import time
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("fetch_feeds")

COLLECTOR_VERSION = "0.2.0"
DEFAULT_UA = "PhishGuard-Collector/0.2 (+https://github.com/arixstoo/PhishGuard)"
PHISHTANK_UA = "phishtank/PhishGuard_research"
TIMEOUT = 60.0  # secondes
RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_RETRY_AFTER = 60.0  # secondes, plafond pour l'en-tête Retry-After

OPENPHISH_URL = "https://openphish.com/feed.txt"
PHISHTANK_URL = "https://data.phishtank.com/data/{key_part}online-valid.csv"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
TRANCO_API_URL = "https://tranco-list.eu/api/lists/date/{day}"
TRANCO_DOWNLOAD_URL = "https://tranco-list.eu/download/{list_id}/{top_n}"
TRANCO_MAX = 1_000_000

FeedResult = dict[str, Any]


def get_timestamp(now: datetime | None = None) -> str:
    """Retourne l'horodatage UTC au format YYYYMMDD_HHMMSS."""
    return (now or datetime.now(UTC)).strftime("%Y%m%d_%H%M%S")


def compute_sha256(content: bytes) -> str:
    """Calcule le hash SHA-256 du contenu binaire."""
    return hashlib.sha256(content).hexdigest()


def redact(text: str, secrets: list[str | None]) -> str:
    """Masque les secrets (clés d'API) dans un texte destiné aux logs ou au manifeste."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


def load_env_file(path: Path | None = None) -> None:
    """Charge les variables d'un fichier .env s'il existe (sans écraser l'environnement)."""
    target = path or Path(".env")
    if not target.exists():
        return
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def fetch(
    client: httpx.Client,
    url: str,
    headers: dict[str, str] | None = None,
    attempts: int = 3,
    backoff: float = 5.0,
    sleep: Callable[[float], None] | None = None,
) -> httpx.Response:
    """GET avec nouvelles tentatives sur erreurs réseau, 429 et 5xx.

    Respecte l'en-tête Retry-After (plafonné). Lève httpx.HTTPError après le dernier essai.
    """
    for attempt in range(1, attempts + 1):
        try:
            response = client.get(url, headers=headers)
            if response.status_code not in RETRY_STATUSES or attempt == attempts:
                response.raise_for_status()
                return response
            retry_after = response.headers.get("Retry-After", "")
            delay = float(retry_after) if retry_after.isdigit() else backoff * attempt
            reason = f"HTTP {response.status_code}"
        except httpx.TransportError as exc:
            if attempt == attempts:
                raise
            delay = backoff * attempt
            reason = type(exc).__name__
        delay = min(delay, MAX_RETRY_AFTER)
        logger.info("Nouvel essai %d/%d dans %.0f s (%s)", attempt + 1, attempts, delay, reason)
        (sleep or time.sleep)(delay)
    raise AssertionError("inatteignable")  # pragma: no cover


def describe_error(exc: Exception, secrets: list[str | None]) -> str:
    """Message d'erreur court, sans URL complète ni secret."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    return redact(f"{type(exc).__name__}: {exc}", secrets)


def count_csv_rows(text: str, skip_comments: bool = False, has_header: bool = False) -> int:
    """Compte les lignes de données d'un CSV (gère les champs entre guillemets multi-lignes)."""
    lines = text.splitlines()
    if skip_comments:
        lines = [line for line in lines if not line.startswith("#")]
    rows = sum(1 for row in csv.reader(io.StringIO("\n".join(lines))) if row)
    return max(0, rows - 1) if has_header else rows


def save(dest: Path, content: bytes, count: int, source_url: str) -> FeedResult:
    """Écrit le contenu brut tel que reçu et retourne l'entrée de manifeste."""
    dest.write_bytes(content)
    return {
        "status": "ok",
        "file": dest.name,
        "count": count,
        "bytes": len(content),
        "sha256": compute_sha256(content),
        "source_url": source_url,
    }


def failure(status: str, source_url: str, error: str) -> FeedResult:
    return {"status": status, "source_url": source_url, "error": error}


def download_openphish(client: httpx.Client, output_dir: Path, timestamp: str) -> FeedResult:
    """Télécharge le flux communautaire OpenPhish (une URL par ligne)."""
    logger.info("OpenPhish : %s", OPENPHISH_URL)
    try:
        response = fetch(client, OPENPHISH_URL, headers={"User-Agent": DEFAULT_UA})
    except httpx.HTTPError as exc:
        error = describe_error(exc, [])
        logger.error("OpenPhish en échec : %s", error)
        return failure("error", OPENPHISH_URL, error)
    count = sum(1 for line in response.text.splitlines() if line.strip())
    result = save(output_dir / f"openphish_{timestamp}.txt", response.content, count, OPENPHISH_URL)
    logger.info("OpenPhish OK : %s (%d URLs)", result["file"], count)
    return result


def download_phishtank(
    client: httpx.Client, output_dir: Path, timestamp: str, app_key: str | None = None
) -> FeedResult:
    """Télécharge les URLs vérifiées et en ligne de PhishTank.

    PhishTank exige un User-Agent commençant par 'phishtank/'. La clé d'application,
    facultative, se place dans le chemin : /data/<clé>/online-valid.csv.
    """
    url = PHISHTANK_URL.format(key_part=f"{app_key}/" if app_key else "")
    public_url = PHISHTANK_URL.format(key_part="***/" if app_key else "")
    logger.info("PhishTank : %s", public_url)
    try:
        response = fetch(client, url, headers={"User-Agent": PHISHTANK_UA})
    except httpx.HTTPError as exc:
        error = describe_error(exc, [app_key])
        logger.warning("PhishTank indisponible (blocage Cloudflare ou quota) : %s", error)
        return failure("error", public_url, error)
    count = count_csv_rows(response.text, has_header=True)
    result = save(output_dir / f"phishtank_{timestamp}.csv", response.content, count, public_url)
    logger.info("PhishTank OK : %s (%d URLs)", result["file"], count)
    return result


def resolve_tranco_list(
    client: httpx.Client, today: date, max_days_back: int = 3
) -> dict[str, str] | None:
    """Trouve la liste Tranco quotidienne la plus récente et son identifiant permanent.

    La liste du jour J est publiée vers 22 h UTC : on commence par la veille.
    """
    for days_back in range(1, max_days_back + 1):
        day = (today - timedelta(days=days_back)).isoformat()
        try:
            data = fetch(client, TRANCO_API_URL.format(day=day), {"User-Agent": DEFAULT_UA}).json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.info("Pas de liste Tranco pour %s : %s", day, describe_error(exc, []))
            continue
        if data.get("available") and data.get("list_id"):
            return {"list_id": str(data["list_id"]), "list_date": day}
    return None


def download_tranco(
    client: httpx.Client,
    output_dir: Path,
    timestamp: str,
    top_n: int = 100_000,
    today: date | None = None,
) -> FeedResult:
    """Télécharge le top N d'une liste Tranco identifiée par son list_id.

    Le contenu est téléchargé via l'identifiant résolu : le fichier correspond exactement
    à la liste https://tranco-list.eu/list/<list_id>, ce qui rend l'expérience reproductible.
    """
    info = resolve_tranco_list(client, today or datetime.now(UTC).date())
    if info is None:
        logger.error("Tranco en échec : impossible d'identifier une liste datée")
        return failure("error", TRANCO_API_URL.format(day="..."), "list_id introuvable")

    url = TRANCO_DOWNLOAD_URL.format(list_id=info["list_id"], top_n=top_n)
    logger.info(
        "Tranco : list_id=%s (liste du %s), top %d", info["list_id"], info["list_date"], top_n
    )
    try:
        response = fetch(client, url, headers={"User-Agent": DEFAULT_UA})
    except httpx.HTTPError as exc:
        error = describe_error(exc, [])
        logger.error("Tranco en échec : %s", error)
        return {**failure("error", url, error), **info}

    count = sum(1 for line in response.text.splitlines() if line.strip())
    if count == 0 or "," not in response.text.split("\n", 1)[0]:
        logger.error("Tranco en échec : réponse inattendue (pas un CSV rang,domaine)")
        return {**failure("error", url, "réponse inattendue"), **info}
    dest = output_dir / f"tranco_{info['list_id']}_{top_n}_{timestamp}.csv"
    result = {**save(dest, response.content, count, url), **info}
    logger.info("Tranco OK : %s (%d domaines)", result["file"], count)
    return result


def download_urlhaus(
    client: httpx.Client, output_dir: Path, timestamp: str, auth_key: str | None = None
) -> FeedResult:
    """Télécharge l'export « recent » d'URLhaus (URLs ajoutées ces 30 derniers jours).

    abuse.ch exige une Auth-Key gratuite (https://auth.abuse.ch/).
    """
    key = auth_key or os.environ.get("URLHAUS_AUTH_KEY")
    public_url = URLHAUS_URL.format(key="***")
    if not key:
        logger.warning(
            "URLhaus ignoré : Auth-Key absente. Créez-la sur https://auth.abuse.ch/ puis "
            "passez-la via --urlhaus-auth-key ou la variable URLHAUS_AUTH_KEY."
        )
        return failure("skipped", public_url, "Auth-Key absente")

    logger.info("URLhaus : %s", public_url)
    try:
        response = fetch(
            client,
            URLHAUS_URL.format(key=key),
            headers={"User-Agent": DEFAULT_UA, "Auth-Key": key},
        )
    except httpx.HTTPError as exc:
        error = describe_error(exc, [key])
        logger.error("URLhaus en échec : %s", error)
        return failure("error", public_url, error)
    count = count_csv_rows(response.text, skip_comments=True)
    result = save(
        output_dir / f"urlhaus_recent_{timestamp}.csv", response.content, count, public_url
    )
    logger.info("URLhaus OK : %s (%d URLs)", result["file"], count)
    return result


def collection_succeeded(feeds: dict[str, FeedResult]) -> bool:
    """Succès si Tranco et au moins une source de phishing sont présents."""
    phishing_ok = any(
        feeds.get(name, {}).get("status") == "ok" for name in ("openphish", "phishtank", "urlhaus")
    )
    return phishing_ok and feeds.get("tranco", {}).get("status") == "ok"


def run(args: argparse.Namespace, client: httpx.Client, now: datetime | None = None) -> int:
    # httpx journalise chaque URL en INFO : on le fait taire pour ne pas exposer les clés.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    now = now or datetime.now(UTC)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = get_timestamp(now)
    logger.info("=== Collecte des flux (%s UTC) ===", timestamp)

    feeds: dict[str, FeedResult] = {
        "openphish": download_openphish(client, output_dir, timestamp),
        "phishtank": download_phishtank(client, output_dir, timestamp, args.phishtank_key),
        "tranco": download_tranco(client, output_dir, timestamp, args.tranco_top, now.date()),
        "urlhaus": download_urlhaus(client, output_dir, timestamp, args.urlhaus_auth_key),
    }
    ok = collection_succeeded(feeds)
    manifest = {
        "metadata": {
            "timestamp_utc": timestamp,
            "collected_at": now.isoformat(timespec="seconds"),
            "collector_version": COLLECTOR_VERSION,
            "python": platform.python_version(),
            "httpx": httpx.__version__,
            "tranco_top": args.tranco_top,
            "success": ok,
        },
        "feeds": feeds,
    }
    manifest_file = output_dir / f"manifest_{timestamp}.json"
    manifest_file.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Manifeste : %s", manifest_file)

    summary = ", ".join(f"{name}={res['status']}" for name, res in feeds.items())
    if ok:
        logger.info("=== Collecte terminée : %s ===", summary)
        return 0
    logger.error("=== Collecte incomplète : %s ===", summary)
    return 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collecteur reproductible de flux PhishGuard.")
    parser.add_argument("--output-dir", default="data/raw", help="Dossier de destination")
    parser.add_argument(
        "--tranco-top",
        type=int,
        default=100_000,
        help=f"Nombre de domaines Tranco, de 1 à {TRANCO_MAX:_} (défaut : 100_000)",
    )
    parser.add_argument(
        "--phishtank-key",
        default=os.environ.get("PHISHTANK_APP_KEY"),
        help="Clé d'application PhishTank (facultative, ou variable PHISHTANK_APP_KEY)",
    )
    parser.add_argument(
        "--urlhaus-auth-key",
        default=None,
        help="Auth-Key abuse.ch (ou variable URLHAUS_AUTH_KEY)",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.tranco_top <= TRANCO_MAX:
        parser.error(f"--tranco-top doit être compris entre 1 et {TRANCO_MAX}")
    return args


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    load_env_file()
    args = parse_args(argv)
    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
        return run(args, client)


if __name__ == "__main__":
    sys.exit(main())
