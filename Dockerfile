# Image durcie de l'API PhishGuard (étape 4.9, docs/docker.md).
#
#   docker compose up --build        # API sur 127.0.0.1:8000, modèles montés en lecture seule
#   make docker-build docker-scan    # image seule, puis analyse trivy
#
# Principes :
# - deux étapes : uv et la construction restent dans `build`, l'image finale ne contient
#   que l'interpréteur, l'environnement virtuel et une bibliothèque système (libgomp) ;
# - dépendances installées depuis uv.lock (versions et empreintes SHA-256 vérifiées) ;
# - images de base épinglées par empreinte (Dependabot les met à jour), jamais par une
#   étiquette mobile ;
# - utilisateur sans privilège (UID 10001), sans shell de connexion ni répertoire personnel ;
# - aucun secret ni modèle dans l'image : clés et configuration par l'environnement au
#   lancement, modèles montés en lecture seule (fichiers pickle, voir docs/docker.md).

ARG PYTHON_IMAGE=python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

# --------------------------------------------------------------------------- #
# Construction : environnement virtuel /opt/venv, depuis uv.lock
# --------------------------------------------------------------------------- #
FROM ${PYTHON_IMAGE} AS build

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3.12 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_NO_CACHE=1

COPY --from=uv /uv /usr/local/bin/uv

WORKDIR /src

# Dépendances d'abord (couche réutilisée tant que uv.lock ne change pas), puis le paquet.
# --locked : échoue si uv.lock ne correspond plus à pyproject.toml. Aucun extra : ni les
# outils de développement, ni shap, ni sentence-transformers.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-install-project --no-editable

COPY src ./src
RUN uv sync --locked --no-editable \
    && /opt/venv/bin/python -c "import phishguard.api.main"

# --------------------------------------------------------------------------- #
# Exécution
# --------------------------------------------------------------------------- #
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="phishguard-api" \
      org.opencontainers.image.description="API de détection de phishing explicable (PhishGuard)" \
      org.opencontainers.image.source="https://github.com/arixstoo/PhishGuard" \
      org.opencontainers.image.licenses="MIT"

# Correctifs de sécurité Debian publiés après l'image de base (upgrade) : l'empreinte
# épinglée fixe le point de départ, pas l'absence de correctifs. trivy l'a montré :
# zlib1g corrigé (CVE-2026-76844, CVE-2026-85091) avant la publication d'une nouvelle
# image python. libgomp1 : OpenMP, requis par LightGBM. pip est retiré : l'image
# n'installe rien après sa construction, et chaque outil en moins est une faille de moins.
RUN apt-get update \
    && apt-get upgrade --yes --no-install-recommends \
    && apt-get install --yes --no-install-recommends libgomp1 \
    && apt-get purge --yes --auto-remove \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt/* /var/log/dpkg.log \
    && python -m pip uninstall --yes --quiet pip \
    && groupadd --system --gid 10001 phishguard \
    && useradd --system --uid 10001 --gid phishguard --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin phishguard \
    && install --directory --owner=root --group=root --mode=0755 /app /app/models \
    && install --directory --owner=phishguard --group=phishguard --mode=0700 /data

COPY --from=build /opt/venv /opt/venv

# Production par défaut : documentation fermée, HSTS, journal JSON. Chemins de l'image :
# modèles en lecture seule, base SQLite dans le volume /data.
# OMP_NUM_THREADS=1 (étape 4.13, docs/load-test.md) : chaque requête prédit une seule
# ligne ; OpenMP y lançait une équipe de threads par appel, en concurrence avec les autres
# requêtes du pool sur 2 CPU. Mesuré à 50 req/s : p95 de 263 à 117 ms, médiane inchangée.
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=1 \
    PHISHGUARD_API_ENVIRONMENT=production \
    PHISHGUARD_API_MODELS_DIR=/app/models \
    PHISHGUARD_API_DATABASE_PATH=/data/phishguard.sqlite3

WORKDIR /app
USER 10001:10001
EXPOSE 8000

# Sonde sans dépendance (ni curl ni wget dans l'image) ; /v1/health est hors limite de
# débit et n'expose rien du déploiement.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/v1/health', timeout=3)"]

# python -m phishguard.api plutôt qu'uvicorn directement : pas de réécriture de l'IP par
# uvicorn, pas d'en-tête Server, connexions bornées (docs/api.md). Forme exec : Python
# reçoit SIGTERM et arrête proprement les requêtes en cours.
ENTRYPOINT ["python", "-m", "phishguard.api", "--host", "0.0.0.0", "--port", "8000"]
