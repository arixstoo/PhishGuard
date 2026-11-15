# API HTTP (module 4)

L'API expose le pipeline principal (`phishguard.analysis`, étape 3.12) en HTTP. Elle ne
contient aucune logique d'analyse propre : elle valide, authentifie, limite le débit, puis
délègue à la couche service. Toutes les analyses renvoient le contrat figé de l'étape
2.11 bis ([response-schema.md](response-schema.md)).

Étapes couvertes ici : 4.1 (squelette), 4.2 (entrées), 4.3 (service et endpoints), 4.4
(authentification et limites), 4.5 (durcissement HTTP), 4.6 (journalisation). Les exemples `curl`, la politique de confidentialité et
les mesures de charge arrivent à l'étape 4.13.

## Lancement

```bash
make api                          # python -m phishguard.api : 127.0.0.1:8000
uvicorn phishguard.api.main:app --reload   # développement
```

`python -m phishguard.api` est préféré en production : il désactive la réécriture de
l'IP du client par uvicorn (`proxy_headers=False`, voir [Proxy inverse](#proxy-inverse))
et l'en-tête `Server`. Il n'écoute que sur `127.0.0.1` par défaut.

Les modèles déployés (`url_v2`, `text_v2`, règles email, voir `phishguard.deployment`)
sont chargés **une seule fois au démarrage** (`lifespan`). Un modèle manquant fait échouer
le démarrage, avec la commande qui le produit.

Documentation interactive : `/docs` (Swagger), `/redoc`, `/openapi.json`, en
développement seulement. `PHISHGUARD_API_ENVIRONMENT=production` la ferme, et l'API
refuse de démarrer si on tente de la forcer (voir [Durcissement HTTP](#durcissement-http-étape-45)).

## Configuration

Variables préfixées `PHISHGUARD_API_`, puis `.env` (`phishguard.api.settings`). Une valeur
invalide empêche le démarrage.

| Variable | Défaut | Rôle |
|---|---|---|
| `PHISHGUARD_API_MODELS_DIR` | `models` | dossier des modèles déployés |
| `PHISHGUARD_API_DATABASE_PATH` | `data/api/phishguard.sqlite3` | base SQLite |
| `PHISHGUARD_API_ENVIRONMENT` | `development` | `production` : documentation fermée, HSTS, origines `http://` refusées |
| `PHISHGUARD_API_DOCS_ENABLED` | selon l'environnement | `/docs`, `/redoc`, `/openapi.json` ; `true` refusé en production |
| `PHISHGUARD_API_CORS_ALLOWED_ORIGINS` | vide | origines exactes autorisées depuis un navigateur |
| `PHISHGUARD_API_CORS_MAX_AGE_SECONDS` | `600` | mise en cache des pré-vérifications CORS |
| `PHISHGUARD_API_REQUEST_TIMEOUT_SECONDS` | `30` | durée maximale d'une requête, corps compris |
| `PHISHGUARD_API_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `PHISHGUARD_API_LOG_FORMAT` | selon l'environnement | `json` (production) ou `console` (développement) |
| `PHISHGUARD_API_MAX_EMAIL_BYTES` | 1 Mio | taille maximale d'un email |
| `PHISHGUARD_API_MAX_JSON_BYTES` | 64 Kio | taille maximale d'un corps JSON |
| `PHISHGUARD_API_THREAT_INTEL_ENABLED` | `false` | autoriser l'enrichissement à la demande du client |
| `PHISHGUARD_API_RATE_LIMIT_ENABLED` | `true` | limites de débit |
| `PHISHGUARD_API_RATE_LIMIT_ANONYMOUS` | `30/minute` | quota sans clé, par IP |
| `PHISHGUARD_API_RATE_LIMIT_AUTHENTICATED` | `300/minute` | quota par clé |
| `PHISHGUARD_API_RATE_LIMIT_REJECTED` | `10/minute` | quota des clés refusées, par IP |
| `PHISHGUARD_API_RATE_LIMIT_STORAGE_URI` | `memory://` | stockage des compteurs |
| `PHISHGUARD_API_TRUSTED_PROXIES` | vide | réseaux dont `X-Forwarded-For` est cru |

## Routes

| Méthode | Route | Entrée | Réponse |
|---|---|---|---|
| GET | `/v1/health` | — | `{"status": "ok"}`, sans clé ni limite de débit |
| GET | `/v1/model` | — | versions, date d'entraînement, SHA-256 des fichiers chargés |
| POST | `/v1/analyze/url` | JSON `UrlRequest` | `AnalysisResponse` |
| POST | `/v1/analyze/text` | JSON `TextRequest` | `AnalysisResponse` |
| POST | `/v1/analyze/email` | multipart : `file` (`.eml`), `language`, `analyst` | `AnalysisResponse` |
| POST | `/v1/feedback` | JSON `FeedbackRequest` | 202, retour mis en quarantaine |

Options communes aux analyses : `language` (`fr`, `en`, `ar` ; défaut `fr`) et `analyst`
(vue « Détails techniques », défaut `false`). `use_threat_intel` (URL, défaut `false`)
n'envoie l'URL à des tiers que si le serveur l'a aussi activé
(`PHISHGUARD_API_THREAT_INTEL_ENABLED`) et jamais pour une URL interne.

`GET /v1/model` donne l'empreinte SHA-256 de chaque fichier de modèle et de calibration
**effectivement chargé**, calculée au démarrage : on peut ainsi vérifier quel artefact
répond. La signature des modèles arrive à l'étape 4.12.

## Entrées (étape 4.2)

Toute entrée est hostile ; les bornes sont dans les schémas (`phishguard.api.schemas`),
avant toute analyse.

| Entrée | Contraintes |
|---|---|
| URL | 4 à 2 048 caractères ; aucun caractère de contrôle (C0, DEL, C1) |
| Texte | 1 à 5 000 caractères, pas seulement des espaces ; tabulation et fins de ligne admises |
| Email | 1 Mio au plus ; type `message/rfc822`, `application/octet-stream` ou `text/plain` |
| Domaine (retour) | nom de domaine seulement, ramené en ASCII (IDNA) ; ni URL, ni IP |
| Corps JSON | 64 Kio au plus, `Content-Type: application/json` obligatoire |

- **Mode strict** : `"true"` n'est pas un booléen, `123` n'est pas une chaîne.
- **Aucun champ inconnu** : `use_threat_intell` (faute de frappe) est une erreur, pas une
  option silencieusement ignorée.
- **Demi-codets UTF-16 isolés refusés** (`"\ud800"`) : JSON valide, mais impossible à
  encoder en UTF-8 ; ils feraient échouer plus loin le journal ou le hachage.
- **Caractères invisibles de format admis** (largeur nulle, U+202E) : ce sont des
  évasions que la normalisation (étape 3.8) retire et compte, et un indice en soi.
- **Taille avant lecture** : un `Content-Length` trop grand est refusé (413) sans lire le
  corps ; sans `Content-Length` (envoi par morceaux), la lecture est coupée à la limite.
- **`application/json` exigé** : sans ce contrôle, un autre site pourrait envoyer depuis
  le navigateur d'un visiteur une requête `text/plain` contenant du JSON, sans
  pré-vérification CORS.

## Erreurs

Une seule enveloppe, un `code` stable :

```json
{"error": {"code": "validation_error", "message": "…", "details": [{"loc": ["body", "url"], "type": "string_too_long", "msg": "…"}]}}
```

| Statut | `code` | Cas |
|---|---|---|
| 400 | `invalid_input` | URL bien formée mais inanalysable (schéma `ftp:`, hôte vide) |
| 401 | `invalid_api_key` | clé inconnue, révoquée, mal formée ou présentée deux fois |
| 404 / 405 | `not_found` / `method_not_allowed` | route ou méthode inconnue |
| 408 | `request_timeout` | corps reçu trop lentement (délai par requête) |
| 413 | `payload_too_large` | corps ou fichier trop gros |
| 415 | `unsupported_media_type` | corps non JSON, fichier qui n'est pas un email |
| 422 | `validation_error` | entrée hors schéma (taille, type, caractère, JSON malformé) |
| 429 | `rate_limited` | limite de débit atteinte (`Retry-After`) |
| 500 | `internal_error` | défaut du serveur, sans aucun détail |
| 503 | `service_unavailable` | base des clés indisponible |
| 503 | `timeout` | traitement plus long que le délai par requête (`Retry-After`) |

**L'entrée n'est jamais renvoyée** : FastAPI recopie par défaut la valeur fautive
(`input`) dans ses erreurs de validation, ce qui réfléchirait une URL de 100 000
caractères ou un jeton contenu dans une URL. Seuls l'emplacement, le type et le message
de chaque erreur sont gardés. De même, le message d'une URL inanalysable est fixe.

## Authentification (étape 4.4)

En-tête `X-API-Key`, facultatif :

- **absent** : client anonyme, limité par IP ;
- **valide** : client authentifié, limité par clé, quota plus élevé ;
- **invalide ou révoqué** : **401**, jamais un retour silencieux au niveau anonyme (qui
  masquerait une erreur de configuration et laisserait chercher des clés sans bruit).

```bash
make api-key NAME=extension-dev                # affichée une seule fois
python -m phishguard.api.keys list             # sans les secrets
python -m phishguard.api.keys revoke <key_id>
```

Une clé est un secret aléatoire de 256 bits (`pg_` + 43 caractères base64url). La base
SQLite (`data/api/phishguard.sqlite3`, droits `600`) n'en garde que **l'empreinte
SHA-256** : une fuite de la base ne donne aucune clé utilisable. Un hachage lent (bcrypt,
Argon2) protège des mots de passe humains devinables ; il n'apporte rien contre un secret
de 256 bits et coûterait des dizaines de millisecondes par requête. Une valeur qui n'a
pas le format d'une clé est refusée sans requête en base.

## Limites de débit (étape 4.4)

| Client | Compteur | Défaut | Variable |
|---|---|---|---|
| anonyme | IP (/64 en IPv6) | 30/minute | `PHISHGUARD_API_RATE_LIMIT_ANONYMOUS` |
| clé valide | clé | 300/minute | `PHISHGUARD_API_RATE_LIMIT_AUTHENTICATED` |
| clé refusée | IP (/64 en IPv6) | 10/minute | `PHISHGUARD_API_RATE_LIMIT_REJECTED` |

- Un compteur **par route**, fenêtre glissante. Réponses : `X-RateLimit-Limit`,
  `X-RateLimit-Remaining`, `X-RateLimit-Reset` ; au-delà, 429 et `Retry-After`.
- Le limiteur passe **avant la lecture du corps** : une rafale de requêtes malformées
  consomme le quota comme des requêtes valides.
- **IPv6 regroupée par /64** : un abonné en reçoit un entier ; compter par adresse ne
  limiterait rien.
- Les chemins inconnus partagent un compteur : des URLs aléatoires ne créent pas autant
  d'entrées en mémoire.
- `memory://` (défaut) compte par processus. Avec plusieurs workers, utiliser un stockage
  partagé (`PHISHGUARD_API_RATE_LIMIT_STORAGE_URI=redis://…`).
- Stockage indisponible : la requête passe, l'incident est journalisé. La limite protège
  la capacité, elle n'est pas un contrôle d'accès.

**Pourquoi `limits` et pas `slowapi`.** Le cahier des charges proposait slowapi. Ses
limites dynamiques (une limite par niveau de client) rangent la requête courante dans un
objet partagé par toutes les requêtes : deux requêtes concurrentes peuvent se voir
appliquer la limite l'une de l'autre, et, par son middleware, la limite n'était pas
appliquée du tout (slowapi 0.1.10). L'API utilise donc directement `limits`, le moteur de
slowapi, en mode asynchrone, dans un middleware ASGI d'une centaine de lignes, testé.

## Durcissement HTTP (étape 4.5)

Trois couches à l'extérieur de toutes les autres (`phishguard.api.hardening`), pour que
**toute** réponse en profite, y compris un 429, un 413 ou un 500.

### En-têtes de sécurité

| En-tête | Valeur | Raison |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | le navigateur ne réinterprète jamais le JSON |
| `Cache-Control` | `no-store` | les réponses parlent des messages des utilisateurs |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` | l'API ne sert que du JSON |
| `X-Frame-Options` | `DENY` | anciens navigateurs (doublon de `frame-ancestors`) |
| `Referrer-Policy` | `no-referrer` | |
| `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` | `same-origin` | isolation |
| `Permissions-Policy` | API sensibles coupées | |
| `Strict-Transport-Security` | `max-age=31536000` | production seulement (derrière TLS) |

Aucun en-tête `Server` (`python -m phishguard.api`). La documentation interactive, en
développement seulement, a sa propre politique de contenu : Swagger et ReDoc chargent
leurs scripts depuis jsDelivr.

```console
$ PHISHGUARD_API_ENVIRONMENT=production make api
$ curl -sI http://127.0.0.1:8000/v1/health
HTTP/1.1 200 OK
content-type: application/json
x-content-type-options: nosniff
cache-control: no-store
x-frame-options: DENY
referrer-policy: no-referrer
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
permissions-policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
x-permitted-cross-domain-policies: none
strict-transport-security: max-age=31536000
content-security-policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'
```

### CORS

Une **liste explicite** d'origines (`PHISHGUARD_API_CORS_ALLOWED_ORIGINS`), vide par
défaut : sans elle, aucune réponse ne porte d'en-tête CORS et les navigateurs bloquent
tout appel venu d'un autre site.

```bash
PHISHGUARD_API_CORS_ALLOWED_ORIGINS=chrome-extension://<identifiant>,https://phishguard.example
```

- `*` est refusé au démarrage, comme `null` (origine des iframes isolées et des fichiers
  locaux, qu'un attaquant obtient à volonté), un joker, un chemin ou une barre finale.
- En production, une origine `http://` n'est admise que pour la boucle locale.
- Méthodes `GET` et `POST`, en-têtes `Content-Type` et `X-API-Key` seulement ;
  `Retry-After` et `X-RateLimit-*` lisibles par le client, même sur un 429.
- **Pas d'identifiants de navigateur** (`allow_credentials=False`) : l'API ne connaît
  aucun cookie, la clé est un en-tête que le client envoie lui-même.
- `application/json` reste exigé (étape 4.2) : un autre site ne peut pas contourner la
  pré-vérification avec une requête « simple » `text/plain`.

### Délais et bornes

- Délai par requête, **lecture du corps comprise** (`PHISHGUARD_API_REQUEST_TIMEOUT_SECONDS`,
  30 s) : un client qui envoie son corps octet par octet reçoit 408 ; un traitement trop
  long, 503 avec `Retry-After`. Le calcul ML d'un thread ne peut pas être interrompu : il
  va à son terme et sa réponse tardive est jetée. Garder le thread est voulu : le pool
  reste borné, alors qu'abandonner les threads laisserait un attaquant en empiler.
- `python -m phishguard.api` : 100 connexions simultanées au plus (`--limit-concurrency`,
  503 au-delà), connexions inactives fermées après 5 s (`--timeout-keep-alive`),
  en-têtes bornés à 16 Kio.
- Taille du corps bornée avant lecture (étape 4.2).

### Erreurs et débogage

- Jamais de trace de pile : `debug=False` explicite, et toute exception non prévue
  devient un 500 sans détail. Ce filet est un middleware : le 500 de Starlette est produit
  *à l'extérieur* des middlewares de l'application et perdrait les en-têtes de sécurité.
- En production, `/docs`, `/redoc` et `/openapi.json` répondent 404 ; les forcer
  (`PHISHGUARD_API_DOCS_ENABLED=true`) empêche le démarrage.

## Journalisation (étape 4.6)

`structlog`, une ligne par requête (`phishguard.api.logs`), en JSON en production :

```json
{"method": "POST", "route": "/v1/analyze/url", "status": 200, "duration_ms": 108.09, "client": "anonymous", "key_id": null, "channel": "url", "verdict": "phishing", "score": 90, "model_version": "url_v2", "threat_intel": false, "event": "request", "request_id": "d61882ad1a934936ac7f8834d2d65592", "level": "info", "logger": "phishguard.api.access", "timestamp": "2026-11-12T16:17:46.861674Z"}
```

(Ligne réelle, pour `https://paypa1-secure.example/reset?token=SUPERSECRET123` : ni l'URL,
ni son hôte, ni le jeton.)

- **Journalisé** : identifiant de requête, méthode, **modèle** de la route, statut,
  latence, niveau du client, identifiant public de la clé, canal, verdict, score, version
  du modèle.
- **Jamais journalisé** : le contenu des messages et des emails, les URLs (ni complètes,
  ni leur hôte), les clés d'API, l'adresse IP, les en-têtes, la chaîne de requête. Un
  chemin inconnu est écrit `_unmatched` : un jeton glissé dans le chemin n'est pas écrit.
- `X-Request-ID` : tiré par le serveur à chaque requête et renvoyé au client (lisible en
  CORS), pour retrouver une ligne sans rien journaliser d'autre. Une valeur envoyée par
  le client est ignorée : elle permettrait de brouiller la corrélation ou d'injecter du
  texte. Les journaux écrits pendant la requête, y compris depuis le pool de threads,
  portent le même identifiant.

La règle tient par construction, à trois niveaux :

1. **liste blanche** : les routes ne peuvent ajouter à leur ligne que `channel`,
   `verdict`, `score`, `model_version` et `threat_intel` (`annotate`, toute autre clé
   lève une erreur) ;
2. **exceptions sans message** : une trace ne garde que les types et les emplacements
   (`exc_summary`). Les messages recopient souvent l'entrée : `InvalidUrlError` cite
   l'URL, une erreur `httpx` l'URL de la source appelée, clé de Safe Browsing comprise ;
3. **caviardage de tous les journaux**, ceux des bibliothèques compris : URLs, emails et
   clés d'API remplacés (`[url]`, `[email]`, `[api-key]`), champs sensibles masqués,
   caractères de contrôle neutralisés (pas de fausses lignes injectées), chaînes
   tronquées. Effet de bord assumé : « Uvicorn running on [url] ».

Le journal d'accès d'uvicorn est coupé (`access_log=False`) : il écrit le chemin brut, la
chaîne de requête et l'IP du client. Les tests (`tests/test_api_logging.py`) analysent
une URL, un message et un email contenant un jeton secret, au niveau DEBUG, et vérifient
qu'il n'apparaît dans aucune ligne, y compris sur les chemins d'erreur (URL invalide,
validation, 500, chemin inconnu, clé refusée).

## Proxy inverse

Derrière un proxy, l'API voit l'IP du proxy ; le proxy ajoute celle du client dans
`X-Forwarded-For`. Mais un client peut écrire cet en-tête lui-même : le croire sans
condition, c'est laisser chacun choisir son IP, donc sa limite.

1. L'en-tête n'est lu que si la connexion vient d'un réseau de
   `PHISHGUARD_API_TRUSTED_PROXIES` (vide par défaut : toujours ignoré).
2. Il est lu de droite à gauche : la première adresse qui n'est pas un proxy de confiance
   est le client ; ce qui est à sa gauche a pu être inventé.
3. Une valeur illisible arrête la lecture.

```bash
PHISHGUARD_API_TRUSTED_PROXIES=127.0.0.1 python -m phishguard.api   # nginx sur la machine
```

Côté proxy, **remplacer** l'en-tête plutôt que l'allonger quand il est le premier saut
(nginx : `proxy_set_header X-Forwarded-For $remote_addr;`).

## Exécution

Le calcul ML (features, LightGBM, TF-IDF, SHAP, parseur d'email) est synchrone : il
tourne dans le pool de threads de Starlette (`run_in_threadpool`), jamais sur la boucle
asynchrone. L'enrichissement par la Threat Intelligence reste sur la boucle, propriétaire
du client HTTP partagé ; `UrlAnalyzer.analyze(run_sync=...)` sépare les deux.

Ordre des couches, de l'extérieur vers l'intérieur : en-têtes de sécurité, journal de la
requête, CORS, délai et
filet d'erreurs, limite de débit, taille du corps, routage, authentification, validation,
service.
