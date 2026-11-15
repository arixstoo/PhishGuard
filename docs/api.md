# API HTTP (module 4)

L'API expose le pipeline principal (`phishguard.analysis`, étape 3.12) en HTTP. Elle ne
contient aucune logique d'analyse propre : elle valide, authentifie, limite le débit, puis
délègue à la couche service. Toutes les analyses renvoient le contrat figé de l'étape
2.11 bis ([response-schema.md](response-schema.md)).

Étapes couvertes ici : 4.1 (squelette), 4.2 (entrées), 4.3 (service et endpoints), 4.4
(authentification et limites). Les exemples `curl`, la politique de confidentialité et
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

Documentation interactive : `/docs` (Swagger), `/redoc`, `/openapi.json`. Désactivable
par `PHISHGUARD_API_DOCS_ENABLED=false` (l'étape 4.5 le fera en production).

## Configuration

Variables préfixées `PHISHGUARD_API_`, puis `.env` (`phishguard.api.settings`). Une valeur
invalide empêche le démarrage.

| Variable | Défaut | Rôle |
|---|---|---|
| `PHISHGUARD_API_MODELS_DIR` | `models` | dossier des modèles déployés |
| `PHISHGUARD_API_DATABASE_PATH` | `data/api/phishguard.sqlite3` | base SQLite |
| `PHISHGUARD_API_DOCS_ENABLED` | `true` | `/docs`, `/redoc`, `/openapi.json` |
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
| 413 | `payload_too_large` | corps ou fichier trop gros |
| 415 | `unsupported_media_type` | corps non JSON, fichier qui n'est pas un email |
| 422 | `validation_error` | entrée hors schéma (taille, type, caractère, JSON malformé) |
| 429 | `rate_limited` | limite de débit atteinte (`Retry-After`) |
| 500 | `internal_error` | défaut du serveur, sans aucun détail |
| 503 | `service_unavailable` | base des clés indisponible |

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

Ordre des couches, de l'extérieur vers l'intérieur : limite de débit, taille du corps,
routage, authentification, validation, service.
