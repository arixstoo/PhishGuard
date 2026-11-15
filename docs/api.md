# API HTTP (module 4)

L'API expose le pipeline principal (`phishguard.analysis`, étape 3.12) en HTTP. Elle ne
contiendra aucune logique d'analyse propre : elle validera, authentifiera, limitera le
débit, puis déléguera à une couche service. Les analyses renverront le contrat figé de
l'étape 2.11 bis ([response-schema.md](response-schema.md)).

Étapes couvertes ici : 4.1 (squelette) et 4.2 (entrées). Les routes d'analyse (4.3),
l'authentification et les limites de débit (4.4) suivent.

## Lancement

```bash
make api                          # python -m phishguard.api : 127.0.0.1:8000
uvicorn phishguard.api.main:app --reload   # développement
```

`python -m phishguard.api` est préféré en production : il désactive la réécriture de
l'IP du client par uvicorn d'après `X-Forwarded-For` (`proxy_headers=False`), un en-tête
que le client peut écrire lui-même, et l'en-tête `Server`. Il n'écoute que sur
`127.0.0.1` par défaut.

Les modèles déployés (`url_v2`, `text_v2`, règles email, voir `phishguard.deployment`)
sont chargés **une seule fois au démarrage** (`lifespan`), hors de la boucle asynchrone.
Un modèle manquant fait échouer le démarrage, avec la commande qui le produit.

Documentation interactive : `/docs` (Swagger), `/redoc`, `/openapi.json`. Désactivable
par `PHISHGUARD_API_DOCS_ENABLED=false` (l'étape 4.5 le fera en production).

## Configuration

Variables préfixées `PHISHGUARD_API_`, puis `.env` (`phishguard.api.settings`). Une valeur
invalide empêche le démarrage.

| Variable | Défaut | Rôle |
|---|---|---|
| `PHISHGUARD_API_MODELS_DIR` | `models` | dossier des modèles déployés |
| `PHISHGUARD_API_DOCS_ENABLED` | `true` | `/docs`, `/redoc`, `/openapi.json` |
| `PHISHGUARD_API_MAX_EMAIL_BYTES` | 1 Mio | taille maximale d'un email |
| `PHISHGUARD_API_MAX_JSON_BYTES` | 64 Kio | taille maximale d'un corps JSON |
| `PHISHGUARD_API_THREAT_INTEL_ENABLED` | `false` | autoriser l'enrichissement à la demande du client |

## Routes

| Méthode | Route | Réponse |
|---|---|---|
| GET | `/v1/health` | `{"status": "ok"}` |

## Entrées (étape 4.2)

Toute entrée est hostile ; les bornes sont dans les schémas (`phishguard.api.schemas`),
avant toute analyse.

| Entrée | Contraintes |
|---|---|
| URL | 4 à 2 048 caractères ; aucun caractère de contrôle (C0, DEL, C1) |
| Texte | 1 à 5 000 caractères, pas seulement des espaces ; tabulation et fins de ligne admises |
| Email | 1 Mio au plus, appliqué au corps de la requête et au parseur |
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
| 404 / 405 | `not_found` / `method_not_allowed` | route ou méthode inconnue |
| 413 | `payload_too_large` | corps trop gros |
| 415 | `unsupported_media_type` | corps non JSON |
| 422 | `validation_error` | entrée hors schéma (taille, type, caractère, JSON malformé) |
| 500 | `internal_error` | défaut du serveur, sans aucun détail |

**L'entrée n'est jamais renvoyée** : FastAPI recopie par défaut la valeur fautive
(`input`) dans ses erreurs de validation, ce qui réfléchirait une URL de 100 000
caractères ou un jeton contenu dans une URL. Seuls l'emplacement, le type et le message
de chaque erreur sont gardés.
