# API HTTP (module 4)

L'API expose le pipeline principal (`phishguard.analysis`, étape 3.12) en HTTP. Elle ne
contiendra aucune logique d'analyse propre : elle validera, authentifiera, limitera le
débit, puis déléguera à une couche service. Les analyses renverront le contrat figé de
l'étape 2.11 bis ([response-schema.md](response-schema.md)).

Étape couverte ici : 4.1 (squelette). Les entrées (4.2), les routes d'analyse (4.3),
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
| `PHISHGUARD_API_THREAT_INTEL_ENABLED` | `false` | autoriser l'enrichissement à la demande du client |

## Routes

| Méthode | Route | Réponse |
|---|---|---|
| GET | `/v1/health` | `{"status": "ok"}` |

## Erreurs

Une seule enveloppe, un `code` stable :

```json
{"error": {"code": "not_found", "message": "Not Found"}}
```

Une erreur interne renvoie 500, code `internal_error`, sans aucun détail : la trace reste
dans le journal du serveur.
