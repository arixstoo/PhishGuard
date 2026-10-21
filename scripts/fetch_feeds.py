"""Script de collecte reproductible des flux de phishing et de domaines légitimes.

Usage:
    python scripts/fetch_feeds.py
    python scripts/fetch_feeds.py --output-dir data/raw --tranco-top 100000
    python scripts/fetch_feeds.py --urlhaus-auth-key VOTRE_CLE
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import logging
import os
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("fetch_feeds")

DEFAULT_UA = "PhishGuard-Collector/0.1 (+https://github.com/arixstoo/PhishGuard)"
PHISHTANK_UA = "phishtank/PhishGuard_research"
TIMEOUT = 30.0  # secondes


def get_timestamp() -> str:
    """Retourne l'horodatage UTC au format YYYYMMDD_HHMMSS."""
    return datetime.now(UTC).strftime("%Y%m%d_%H%M%S")


def compute_sha256(content: bytes) -> str:
    """Calcule le hash SHA-256 du contenu binaire."""
    return hashlib.sha256(content).hexdigest()


def load_env_file(path: Path | None = None) -> None:
    """Charge automatiquement les variables d'un fichier .env s'il existe."""
    target = path or Path(".env")
    if not target.exists():
        return
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def download_openphish(
    output_dir: Path, timestamp: str, client: httpx.Client
) -> tuple[Path | None, int]:
    """Télécharge le flux communautaire OpenPhish."""
    url = "https://openphish.com/feed.txt"
    dest = output_dir / f"openphish_{timestamp}.txt"
    logger.info("Téléchargement OpenPhish : %s", url)

    try:
        response = client.get(url, headers={"User-Agent": DEFAULT_UA})
        response.raise_for_status()
        dest.write_text(response.text, encoding="utf-8")
        lines = [line.strip() for line in response.text.splitlines() if line.strip()]
        count = len(lines)
        logger.info("OpenPhish OK : %s (%d URLs sauvegardées)", dest.name, count)
        return dest, count
    except (httpx.HTTPError, OSError) as exc:
        logger.error("Échec du téléchargement OpenPhish : %s", exc)
        return None, 0


def download_phishtank(
    output_dir: Path,
    timestamp: str,
    client: httpx.Client,
    app_key: str | None = None,
) -> tuple[Path | None, int]:
    """Télécharge la base d'URLs vérifiées de PhishTank.

    PhishTank exige impérativement un User-Agent débutant par 'phishtank/'.
    """
    base_url = "http://data.phishtank.com/data/online-valid.csv"
    url = f"{base_url}?app_key={app_key}" if app_key else base_url
    dest = output_dir / f"phishtank_{timestamp}.csv"
    logger.info("Téléchargement PhishTank : %s (User-Agent: %s)", base_url, PHISHTANK_UA)

    try:
        response = client.get(url, headers={"User-Agent": PHISHTANK_UA}, follow_redirects=True)
        response.raise_for_status()
        dest.write_bytes(response.content)
        lines = [line for line in response.text.splitlines() if line.strip()]
        count = max(0, len(lines) - 1)  # moins la ligne d'en-tête CSV
        logger.info("PhishTank OK : %s (%d URLs actives sauvegardées)", dest.name, count)
        return dest, count
    except (httpx.HTTPError, OSError) as exc:
        logger.warning(
            "PhishTank non disponible (rate limit ou maintenance Cloudflare) : %s",
            exc,
        )
        return None, 0


def download_tranco(
    output_dir: Path,
    timestamp: str,
    client: httpx.Client,
    top_n: int = 100_000,
) -> tuple[Path | None, int, str]:
    """Télécharge la liste Tranco journalière officielle et extrait le top N domaines."""
    logger.info("Récupération de la liste Tranco officielle...")
    list_id = "daily"

    # Tentative d'identification de la liste officielle récente via l'API
    for days_back in range(1, 4):
        date_str = (datetime.now(UTC) - timedelta(days=days_back)).strftime("%Y-%m-%d")
        try:
            r = client.get(
                f"https://tranco-list.eu/api/lists/date/{date_str}",
                headers={"User-Agent": DEFAULT_UA},
                timeout=5.0,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("available") and data.get("list_id"):
                    list_id = data["list_id"]
                    logger.info(
                        "Tranco version identifiée : list_id=%s (date=%s)", list_id, date_str
                    )
                    break
        except (httpx.HTTPError, OSError) as exc:
            logger.debug("API Tranco non disponible pour la date %s : %s", date_str, exc)
            continue

    dest = output_dir / f"tranco_{list_id}_{top_n}_{timestamp}.csv"
    zip_url = "https://tranco-list.eu/download/daily/top-1m.csv.zip"
    logger.info("Téléchargement de l'archive Tranco : %s", zip_url)

    try:
        response = client.get(zip_url, headers={"User-Agent": DEFAULT_UA}, follow_redirects=True)
        response.raise_for_status()

        # Extraction en mémoire du fichier top-1m.csv
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            csv_name = z.namelist()[0]
            with z.open(csv_name) as zf:
                lines = []
                for idx, line in enumerate(zf):
                    if idx >= top_n:
                        break
                    lines.append(line.decode("utf-8"))

        dest.write_text("".join(lines), encoding="utf-8")
        logger.info("Tranco OK : %s (%d domaines sauvegardés)", dest.name, len(lines))
        return dest, len(lines), list_id
    except (httpx.HTTPError, OSError, zipfile.BadZipFile) as exc:
        logger.error("Échec du téléchargement Tranco : %s", exc)
        return None, 0, list_id


def download_urlhaus(
    output_dir: Path,
    timestamp: str,
    client: httpx.Client,
    auth_key: str | None = None,
) -> tuple[Path | None, int]:
    """Télécharge le dump récent d'URLhaus.

    Depuis 2024, abuse.ch exige un Auth-Key (gratuit sur https://auth.abuse.ch/).
    """
    key = auth_key or os.environ.get("URLHAUS_AUTH_KEY")
    if not key:
        logger.warning(
            "URLhaus ignoré : abuse.ch exige désormais un Auth-Key gratuit. "
            "Créez votre clé sur https://auth.abuse.ch/ et passez-la via --urlhaus-auth-key "
            "ou la variable d'environnement URLHAUS_AUTH_KEY."
        )
        return None, 0

    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
    dest = output_dir / f"urlhaus_recent_{timestamp}.csv"
    logger.info("Téléchargement URLhaus avec Auth-Key...")

    try:
        response = client.get(
            url,
            headers={"User-Agent": DEFAULT_UA, "Auth-Key": key},
            follow_redirects=True,
        )
        response.raise_for_status()
        dest.write_bytes(response.content)
        lines = [
            line for line in response.text.splitlines() if line.strip() and not line.startswith("#")
        ]
        count = len(lines)
        logger.info("URLhaus OK : %s (%d URLs sauvegardées)", dest.name, count)
        return dest, count
    except (httpx.HTTPError, OSError) as exc:
        logger.error("Échec du téléchargement URLhaus : %s", exc)
        return None, 0


def main() -> int:
    load_env_file()
    parser = argparse.ArgumentParser(
        description="Collecteur reproductible de flux pour PhishGuard."
    )
    parser.add_argument(
        "--output-dir", default="data/raw", help="Dossier de destination (défaut: data/raw)"
    )
    parser.add_argument(
        "--tranco-top",
        type=int,
        default=100_000,
        help="Nombre de domaines Tranco (défaut: 100 000)",
    )
    parser.add_argument("--phishtank-key", default=None, help="Clé d'API PhishTank (optionnelle)")
    parser.add_argument(
        "--urlhaus-auth-key",
        default=None,
        help="Clé d'authentification abuse.ch URLhaus (optionnelle)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = get_timestamp()

    logger.info("=== Lancement de la collecte des flux (%s UTC) ===", timestamp)

    manifest: dict[str, dict] = {
        "metadata": {
            "timestamp_utc": timestamp,
            "collector_version": "0.1.0",
        },
        "feeds": {},
    }

    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
        # 1. OpenPhish
        op_path, op_count = download_openphish(output_dir, timestamp, client)
        if op_path:
            manifest["feeds"]["openphish"] = {
                "file": op_path.name,
                "count": op_count,
                "sha256": compute_sha256(op_path.read_bytes()),
            }

        # 2. PhishTank (fonctionne avec le User-Agent phishtank/ sans clé requise)
        pt_path, pt_count = download_phishtank(
            output_dir, timestamp, client, app_key=args.phishtank_key
        )
        if pt_path:
            manifest["feeds"]["phishtank"] = {
                "file": pt_path.name,
                "count": pt_count,
                "sha256": compute_sha256(pt_path.read_bytes()),
            }

        # 3. Tranco (extraction rapide du top N domaines de l'archive officielle)
        tr_path, tr_count, tr_id = download_tranco(
            output_dir, timestamp, client, top_n=args.tranco_top
        )
        if tr_path:
            manifest["feeds"]["tranco"] = {
                "file": tr_path.name,
                "count": tr_count,
                "list_id": tr_id,
                "sha256": compute_sha256(tr_path.read_bytes()),
            }

        # 4. URLhaus (avec clé optionnelle)
        uh_path, uh_count = download_urlhaus(
            output_dir, timestamp, client, auth_key=args.urlhaus_auth_key
        )
        if uh_path:
            manifest["feeds"]["urlhaus"] = {
                "file": uh_path.name,
                "count": uh_count,
                "sha256": compute_sha256(uh_path.read_bytes()),
            }

    # Sauvegarde du manifeste d'exécution
    manifest_file = output_dir / f"manifest_{timestamp}.json"
    manifest_file.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Manifeste de collecte créé : %s", manifest_file)
    logger.info("=== Collecte terminée avec succès ===")

    return 0


if __name__ == "__main__":
    sys.exit(main())
