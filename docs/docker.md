# Image Docker durcie (étape 4.9)

L'API tourne dans une image minimale, sans privilège, sans secret ni modèle embarqué, et
dont le démarrage est vérifié par la CI sur une machine propre.

```bash
make docker-up            # docker compose up --build --wait, puis test de démarrage
curl -s http://127.0.0.1:8000/v1/health
docker compose exec api python -m phishguard.api.keys create --name extension-dev
make docker-down          # la base (volume phishguard-data) est conservée
make docker-build docker-scan   # image seule, puis trivy comme la CI
```

Prérequis : les modèles déployés dans `./models` (`url_v2`, `text_v2` et leurs
calibrations, voir `phishguard.deployment`), produits par `make train train-adversarial`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `Dockerfile` | deux étapes : `build` (uv, `uv.lock`) et `runtime` (image finale) |
| `.dockerignore` | **liste blanche** : `pyproject.toml`, `uv.lock`, `README.md`, `LICENSE`, `src/` |
| `docker-compose.yml` | API, modèles en lecture seule, volume SQLite, durcissement à l'exécution |
| `scripts/docker_smoke.sh` | test de démarrage : santé, en-têtes de production, analyse, base inscriptible |
| `scripts/smoke_models.py` | petits modèles synthétiques pour ce test sur une machine sans modèles |

## Construction

- **Deux étapes.** `uv` et les fichiers de construction restent dans `build`. L'image
  finale ne contient que l'interpréteur, l'environnement virtuel `/opt/venv` et
  `libgomp1` (OpenMP, requis par LightGBM).
- **Dépendances verrouillées.** `uv sync --locked --no-editable` installe exactement
  `uv.lock`, empreintes SHA-256 vérifiées, et échoue si le verrou est périmé. Aucun extra :
  ni les outils de développement, ni `shap`, ni `sentence-transformers` (plusieurs Go).
- **Images de base épinglées par empreinte** (`python:3.12-slim-trixie@sha256:…`,
  `ghcr.io/astral-sh/uv:0.12.13@sha256:…`). Une étiquette peut être republiée vers un
  autre contenu ; une empreinte, non. Dependabot (écosystème `docker`) propose chaque
  semaine la nouvelle empreinte, étiquette comprise.
- **`pip` retiré** de l'image finale : rien ne s'installe après la construction, et
  chaque outil absent est une faille de moins à suivre. Ni `curl` ni `wget` : la sonde de
  santé est écrite en Python standard.
- **Contexte en liste blanche.** `.dockerignore` exclut tout puis réadmet les seuls
  fichiers du paquet : un `.env`, une base `data/`, un modèle ou l'historique `.git` ne
  peuvent pas entrer dans une couche, même ajoutés au dépôt plus tard.

## Exécution

| Mesure | Où | Effet |
|---|---|---|
| utilisateur `10001:10001`, sans shell ni répertoire personnel | `Dockerfile` | une faille de l'API ne donne pas root dans le conteneur |
| `PHISHGUARD_API_ENVIRONMENT=production` | `Dockerfile` | documentation fermée, HSTS, journal JSON, origines `http://` refusées |
| `python -m phishguard.api` en forme exec | `Dockerfile` | pas de réécriture de l'IP par uvicorn, pas d'en-tête `Server`, connexions bornées ; SIGTERM reçu par Python |
| `read_only: true`, `/tmp` en mémoire `noexec` | compose | rien ne s'écrit hors du volume `/data` ; aucun binaire déposé ne s'exécute depuis `/tmp` |
| `cap_drop: [ALL]`, `no-new-privileges` | compose | aucune capacité Linux, aucun setuid |
| `pids_limit`, `mem_limit`, `cpus` | compose | une rafale ou une fuite mémoire ne fait pas tomber l'hôte |
| port publié sur `127.0.0.1` | compose | l'exposer passe par un proxy inverse TLS (`PHISHGUARD_API_TRUSTED_PROXIES`) |
| `init: true` | compose | tini en PID 1 : signaux relayés, processus orphelins récupérés |
| journal `json-file` borné (3 × 10 Mo) | compose | le disque de l'hôte ne se remplit pas |
| `HEALTHCHECK` sur `/v1/health` | `Dockerfile` | `docker compose up --wait` attend un service qui répond vraiment |

### Secrets

**Aucun secret dans l'image** : ni `ENV`, ni `ARG`, ni fichier. Les clés des sources de
Threat Intelligence (étape 2.1) arrivent au lancement, par `.env.docker` (facultatif,
ignoré par git et refusé par le hook pre-commit) :

```bash
# .env.docker : les seules clés dont l'API a besoin
GSB_API_KEY=...
VT_API_KEY=...
PHISHGUARD_API_THREAT_INTEL_ENABLED=true
```

Pas le `.env` complet : il contient aussi des secrets que l'API n'utilise pas
(phrase de passe des archives, clés de collecte). Moindre privilège, y compris pour les
secrets. `trivy image --scanners secret` vérifie en CI qu'aucune couche n'en contient.

### Modèles

Les modèles ne sont **pas** dans l'image : `./models` est monté en **lecture seule** sur
`/app/models` (`PHISHGUARD_MODELS_HOST_DIR` pour un autre dossier). Trois raisons :

1. ce sont des fichiers pickle : les charger exécute du code. Le montage en lecture seule
   empêche une API compromise de remplacer le modèle qui sera chargé au redémarrage ;
2. une nouvelle version du modèle ne demande pas de reconstruire l'image, et une
   nouvelle image ne change pas de modèle par surprise ;
3. ils ne sont pas versionnés : une image construite par la CI n'en aurait pas.

**Signés (étape 4.12).** Le compose monte aussi `keys/model-signing.pub` en lecture
seule et renseigne `PHISHGUARD_API_MODELS_PUBLIC_KEY` : l'API vérifie le manifeste signé
avant de lire le moindre modèle et refuse de démarrer sinon. Avant le premier
`docker compose up` : `make keygen` (une fois), puis `make export sign`
([model-registry.md](model-registry.md)). Une clé publique absente est une erreur claire
(`create_host_path: false`), pas un dossier vide monté à sa place.

### Base SQLite

Volume nommé `phishguard-data` sur `/data` (droits `700`, propriétaire `10001`) : seul
emplacement inscriptible. Il contient les empreintes des clés d'API et les retours en
quarantaine, et survit à `docker compose down` (`down --volumes` le supprime).
SQLite en mode WAL écrit ses fichiers `-wal` et `-shm` à côté de la base, dans le volume.

## CI : job `image` de `security.yml`

Bloquant, à chaque push et chaque lundi :

1. construction de l'image ;
2. **`trivy image`** (0.76.2, épinglé par empreinte) : échoue sur toute vulnérabilité
   `HIGH` ou `CRITICAL` **qui a un correctif**, dans les paquets Debian comme dans les
   paquets Python, et sur tout secret présent dans une couche ;
3. rapport complet (`MEDIUM` et plus, correctifs ou non), non bloquant ;
4. **`trivy config`** : mauvaises configurations du `Dockerfile` (trivy n'analyse pas
   le compose : son durcissement est vérifié sur le conteneur lancé, `docker inspect`
   de `ReadonlyRootfs`, `CapDrop`, `no-new-privileges` et du montage des modèles) ;
5. propriétés de l'image : UID 10001, pas de `pip`, ni `uv`, ni `curl`, ni `wget`, aucun
   modèle ni `.env` ;
6. **`docker compose up --wait`** avec des modèles synthétiques **signés par une clé
   éphémère** créée puis effacée dans le job (la clé de publication n'approche jamais
   la CI), puis
   `scripts/docker_smoke.sh` : la CI est la « machine propre » du critère de fin.

**Pourquoi `--ignore-unfixed` dans le contrôle bloquant.** Une faille sans correctif
publié n'a aucune action possible : bloquer dessus bloquerait toutes les PR jusqu'à ce
que Debian publie un paquet, et pousserait à désactiver le contrôle. Elles restent
visibles dans le rapport complet, et le contrôle hebdomadaire échoue dès qu'un correctif
existe.

## Vérification

Mesuré le 12 novembre 2026, Docker Desktop 29.1 (WSL2), trivy 0.76.2.

**`trivy image`, premier passage : échec voulu.** Deux failles HIGH de `zlib1g`
(CVE-2026-76844, CVE-2026-85091), corrigées par Debian (`1:1.3.dfsg+really1.3.1-1+deb13u1`)
mais pas encore dans l'image `python:3.12-slim-trixie`. Le contrôle a fait son travail :
l'étape `runtime` applique désormais les correctifs de sécurité Debian
(`apt-get upgrade`) au-dessus de l'image de base épinglée.

**Second passage :**

| Contrôle | Résultat |
|---|---|
| vulnérabilités `HIGH`/`CRITICAL` avec correctif (bloquant) | **0** |
| secrets dans les couches (bloquant) | **0** |
| vulnérabilités `CRITICAL`, avec ou sans correctif | **0** |
| dépendances Python (`/opt/venv`, `uv.lock`) | **0** vulnérabilité |
| `trivy config` (Dockerfile) | **0** mauvaise configuration |
| paquets Debian sans correctif publié (`affected`, `fix_deferred`) | 47 `HIGH`, 79 `MEDIUM` |

Les failles restantes sont toutes dans des paquets du système de base (`util-linux`,
`ncurses`, `systemd` en bibliothèques, `login`, `libsqlite3-0`…) que l'API n'appelle pas,
hormis SQLite, sans correctif publié par Debian. Elles sont suivies par le rapport complet
et le passage hebdomadaire. Une image *distroless* ou construite sur une base plus réduite
en retirerait la plupart ; c'est la piste d'amélioration suivante, au prix d'une image
sans shell (débogage plus difficile, `docker compose exec` impossible).

**`docker compose up --wait`** : conteneur `healthy` en une vingtaine de secondes
(chargement de `url_v2` et `text_v2`), puis `scripts/docker_smoke.sh` :

```console
$ make docker-up
 Container phishguard-api-1  Healthy
image : santé, en-têtes, documentation fermée, analyse et base SQLite vérifiés
$ docker compose exec api python -c "import os; print(os.getuid(), os.getgid())"
10001 10001
$ docker compose exec api touch /app/models/x
touch: cannot touch '/app/models/x': Read-only file system
```

Même résultat avec les modèles synthétiques de `scripts/smoke_models.py`, comme sur la CI.
Taille de l'image : environ 1 Go décompressée, presque entièrement les bibliothèques
scientifiques (`scikit-learn`, `scipy`, `pandas`, `pyarrow`, `lightgbm`).
