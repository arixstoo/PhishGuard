"""URLs légitimes avec chemin, échantillonnées dans l'index de Common Crawl.

Pourquoi : Tranco ne publie que des domaines. Toutes les URLs légitimes du jeu sont donc
des pages d'accueil, ce qui crée le raccourci « URL avec chemin = phishing » mesuré à
l'étape 1.3 (``docs/data-bias.md``). Common Crawl fournit de vraies pages internes de ces
mêmes domaines.

Méthode, sans passer par le serveur de requêtes ``index.commoncrawl.org`` (lent et
souvent en erreur 504 sous la charge) :

1. ``cluster.idx`` (≈ 100 Mo par crawl, mis en cache) liste la première clé SURT de
   chaque bloc de l'index CDX, trié ;
2. pour chaque domaine Tranco, une recherche dichotomique donne les blocs qui couvrent
   le domaine et ses sous-domaines ; un bloc est tiré au hasard (graine fixe) ;
3. ce bloc (≈ 250 Ko compressés, ≈ 3 000 captures) est lu par une requête HTTP partielle
   sur ``data.commoncrawl.org`` ;
4. on ne garde que les pages HTML en statut 200 du domaine, puis au plus ``per_domain``
   URLs distinctes, tirées avec la même graine.

Seules des chaînes de caractères sont manipulées : aucune page n'est visitée.
"""

from __future__ import annotations

import bisect
import gzip
import json
import random
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx

DATA_URL = "https://data.commoncrawl.org"
COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
CLUSTER_PATH = "cc-index/collections/{crawl}/indexes/cluster.idx"
INDEX_PATH = "cc-index/collections/{crawl}/indexes/{file}"
USER_AGENT = "PhishGuard-Collector/0.3 (+https://github.com/arixstoo/PhishGuard)"
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

# Bornes de sécurité : un bloc fait ≈ 250 Ko, cluster.idx ≈ 100 Mo.
MAX_BLOCK_BYTES = 5 * 1024 * 1024
MAX_CLUSTER_BYTES = 512 * 1024 * 1024
MAX_URL_LENGTH = 2048
HTML_MIMES = frozenset({"text/html", "application/xhtml+xml"})


@dataclass(frozen=True)
class Block:
    """Un bloc compressé de l'index CDX : ``length`` octets à ``offset`` dans ``file``."""

    file: str
    offset: int
    length: int


@dataclass(frozen=True)
class Capture:
    url: str
    timestamp: str  # AAAAMMJJhhmmss, UTC


# --------------------------------------------------------------------------- #
# SURT et index des blocs
# --------------------------------------------------------------------------- #


def surt_host(domain: str) -> str:
    """Hôte au format SURT : ``www.Example.com`` -> ``com,example,www``."""
    labels = domain.strip().rstrip(".").lower().split(".")
    return ",".join(reversed(labels))


def surt_range(domain: str) -> tuple[str, str]:
    """Intervalle ``[début, fin)`` des clés SURT d'un domaine **et** de ses sous-domaines.

    Les clés commencent par ``com,example)`` (le domaine) ou ``com,example,`` (ses
    sous-domaines). Dans l'ordre ASCII, ``)`` < ``*`` < ``+`` < ``,`` < ``-`` : toutes
    ces clés sont dans ``[com,example), com,example-)``, et aucune autre, puisque ``*`` et
    ``+`` ne peuvent pas figurer dans un nom d'hôte.
    """
    host = surt_host(domain)
    return f"{host})", f"{host}-"


class ClusterIndex:
    """``cluster.idx`` chargé en mémoire : première clé et position de chaque bloc."""

    def __init__(self, lines: Iterable[str]):
        self._keys: list[str] = []
        self._blocks: list[Block] = []
        for line in lines:
            if not line.strip():
                continue
            key, file, offset, length, *_ = line.rstrip("\n").split("\t")
            self._keys.append(key)
            self._blocks.append(Block(file, int(offset), int(length)))
        if self._keys != sorted(self._keys):
            raise ValueError("cluster.idx n'est pas trié")

    @classmethod
    def from_file(cls, path: Path) -> ClusterIndex:
        with Path(path).open(encoding="utf-8") as handle:
            return cls(handle)

    def __len__(self) -> int:
        return len(self._blocks)

    def blocks_for(self, domain: str) -> list[Block]:
        """Blocs qui peuvent contenir des captures du domaine ou de ses sous-domaines.

        Le bloc ``i`` couvre les clés de ``keys[i]`` (inclus) à ``keys[i + 1]`` (exclu) :
        on part du dernier bloc qui commence avant le début de l'intervalle.
        """
        first, _, end = self._span(domain)
        return self._blocks[first:end]

    def sample_blocks(self, domain: str, k: int, rng: random.Random) -> list[Block]:
        """Jusqu'à ``k`` blocs à lire pour un domaine, tirés avec ``rng``.

        On tire parmi les blocs qui **commencent** dans l'intervalle du domaine : ils ne
        contiennent que lui. Le bloc précédent n'en contient qu'une partie, parfois rien : il
        ne sert que pour un petit domaine qui tient entièrement dedans.
        """
        first, inner_start, end = self._span(domain)
        inner = self._blocks[inner_start:end]
        if inner:
            return rng.sample(inner, min(k, len(inner)))
        return self._blocks[first:end]

    def _span(self, domain: str) -> tuple[int, int, int]:
        """``(bloc précédent, premier bloc intérieur, fin)`` en positions dans l'index.

        Aucune clé n'est égale à la borne basse (elle se termine par ``)`` sans chemin) :
        ``bisect_right`` donne donc le premier bloc qui commence dans l'intervalle.
        """
        low, high = surt_range(domain)
        inner_start = bisect.bisect_right(self._keys, low)
        end = bisect.bisect_left(self._keys, high)
        return max(inner_start - 1, 0), inner_start, end


# --------------------------------------------------------------------------- #
# Lecture et filtrage d'un bloc
# --------------------------------------------------------------------------- #


def parse_block(data: bytes) -> Iterator[tuple[str, str, dict]]:
    """Décompresse un bloc et produit ``(clé SURT, horodatage, champs JSON)``."""
    for line in gzip.decompress(data).decode("utf-8", errors="replace").splitlines():
        parts = line.split(" ", 2)
        if len(parts) != 3:
            continue
        try:
            fields = json.loads(parts[2])
        except json.JSONDecodeError:
            continue
        if isinstance(fields, dict):
            yield parts[0], parts[1], fields


def select_captures(
    records: Iterable[tuple[str, str, dict]],
    domain: str,
    keep_url: Callable[[str], bool] | None = None,
) -> list[Capture]:
    """Pages HTML en statut 200 du domaine (ou d'un sous-domaine), une par URL.

    Sont écartés : les autres domaines du bloc, ``robots.txt``, les redirections et
    erreurs, les contenus non HTML, les URLs trop longues, et les URLs refusées par
    ``keep_url``. Pour une URL capturée plusieurs fois, on garde la plus ancienne capture.
    """
    low, high = surt_range(domain)
    earliest: dict[str, str] = {}
    for key, timestamp, fields in records:
        if not low <= key < high or key.endswith(")/robots.txt"):
            continue
        mime = fields.get("mime-detected") or fields.get("mime") or ""
        url = fields.get("url") or ""
        if fields.get("status") != "200" or mime not in HTML_MIMES:
            continue
        if not url.startswith(("http://", "https://")) or len(url) > MAX_URL_LENGTH:
            continue
        if keep_url is not None and not keep_url(url):
            continue
        if url not in earliest or timestamp < earliest[url]:
            earliest[url] = timestamp
    return [Capture(url, ts) for url, ts in sorted(earliest.items())]


def domain_rng(seed: int, domain: str) -> random.Random:
    """Générateur propre à un domaine : le tirage ne dépend pas de l'ordre de traitement."""
    return random.Random(f"{seed}:{domain}")


def sample_captures(captures: list[Capture], k: int, rng: random.Random) -> list[Capture]:
    """Au plus ``k`` captures, en privilégiant les URLs avec chemin ou paramètres.

    La page d'accueil est déjà fournie par Tranco : on la garde seulement s'il ne reste
    rien d'autre.
    """
    deep = [c for c in captures if c.url.split("://", 1)[1].partition("/")[2]]
    pool = deep or captures
    return sorted(rng.sample(pool, min(k, len(pool))), key=lambda c: c.url)


# --------------------------------------------------------------------------- #
# Accès réseau
# --------------------------------------------------------------------------- #


class AccessBlocked(RuntimeError):
    """Le CDN refuse nos requêtes (HTTP 403) : il faut s'arrêter, pas insister."""


class RateLimiter:
    """Débit maximal partagé entre threads : au plus ``rate`` requêtes par seconde.

    Le CDN de Common Crawl bloque (HTTP 403) les clients trop rapides : à environ
    20 requêtes par seconde, notre adresse a été bloquée après quelques minutes.
    """

    def __init__(self, rate: float, clock=time.monotonic, sleep=time.sleep):
        if rate <= 0:
            raise ValueError("le débit doit être > 0")
        self._interval = 1.0 / rate
        self._next = 0.0
        self._lock = threading.Lock()
        self._clock = clock
        self._sleep = sleep

    def wait(self) -> None:
        with self._lock:
            now = self._clock()
            start = max(now, self._next)
            self._next = start + self._interval
        if start > now:
            self._sleep(start - now)


def get_with_retry(
    client: httpx.Client,
    url: str,
    headers: dict[str, str] | None = None,
    attempts: int = 4,
    backoff: float = 2.0,
    limiter: RateLimiter | None = None,
) -> httpx.Response:
    """GET avec nouvelles tentatives (erreurs réseau, 429 et 5xx), délai croissant.

    Lève :class:`AccessBlocked` sur un HTTP 403, sans nouvel essai.
    """
    headers = {"User-Agent": USER_AGENT, **(headers or {})}
    for attempt in range(1, attempts + 1):
        if limiter is not None:
            limiter.wait()
        try:
            response = client.get(url, headers=headers)
            if response.status_code == 403:
                raise AccessBlocked(f"HTTP 403 sur {url} : accès refusé par le CDN")
            if response.status_code not in RETRY_STATUSES or attempt == attempts:
                response.raise_for_status()
                return response
        except httpx.TransportError:
            if attempt == attempts:
                raise
        time.sleep(backoff * 2 ** (attempt - 1))
    raise AssertionError("inatteignable")  # pragma: no cover


def latest_crawl(client: httpx.Client) -> str:
    """Identifiant du crawl le plus récent (``CC-MAIN-AAAA-SS``)."""
    crawls = get_with_retry(client, COLLINFO_URL).json()
    return str(crawls[0]["id"])


def download_cluster_index(client: httpx.Client, crawl: str, dest: Path) -> Path:
    """Télécharge ``cluster.idx`` en flux (taille bornée) ; réutilise le cache s'il existe.

    Le fichier est écrit sous un nom temporaire puis renommé : un téléchargement
    interrompu ne laisse pas d'index tronqué en cache.
    """
    dest = Path(dest)
    if dest.is_file() and dest.stat().st_size > 0:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(".part")
    url = f"{DATA_URL}/{CLUSTER_PATH.format(crawl=crawl)}"
    size = 0
    with client.stream("GET", url, headers={"User-Agent": USER_AGENT}) as response:
        response.raise_for_status()
        with partial.open("wb") as handle:
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_CLUSTER_BYTES:
                    raise ValueError("cluster.idx anormalement volumineux")
                handle.write(chunk)
    expected = response.headers.get("Content-Length")
    if expected is not None and int(expected) != size:
        partial.unlink()
        raise ValueError(f"cluster.idx tronqué : {size} octets sur {expected}")
    partial.replace(dest)
    return dest


def fetch_block(
    client: httpx.Client, crawl: str, block: Block, limiter: RateLimiter | None = None
) -> bytes:
    """Lit un bloc par requête partielle (en-tête ``Range``)."""
    if not 0 < block.length <= MAX_BLOCK_BYTES:
        raise ValueError(f"taille de bloc refusée : {block.length}")
    if "/" in block.file or not block.file.endswith(".gz"):
        raise ValueError(f"nom de fichier d'index refusé : {block.file!r}")
    url = f"{DATA_URL}/{INDEX_PATH.format(crawl=crawl, file=block.file)}"
    end = block.offset + block.length - 1
    response = get_with_retry(
        client, url, headers={"Range": f"bytes={block.offset}-{end}"}, limiter=limiter
    )
    if response.status_code != 206 or len(response.content) != block.length:
        raise ValueError(f"réponse partielle inattendue pour {block.file}")
    return response.content
