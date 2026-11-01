# Clés d'API et gestion des secrets

*Étape 2.1 du cahier des charges. Code : `src/phishguard/config.py`.*

Le module 2 enrichit le verdict avec des sources de Threat Intelligence. Quatre d'entre elles demandent une clé d'API. Cette page dit où créer chaque clé, comment le projet la charge, et quoi faire si elle fuit.

## Principe : sans clé, rien ne casse

Chaque clé est **facultative**. Une clé absente désactive la source correspondante, elle ne fait pas échouer le démarrage. Sans aucune clé, PhishGuard reste entièrement local : modèles URL, SMS et email, sans aucune requête vers un tiers. C'est le comportement par défaut et celui de la CI.

| Source | Variable | Où créer la clé | Restrictions à appliquer |
| --- | --- | --- | --- |
| Google Safe Browsing | `GSB_API_KEY` | Google Cloud Console : créer un projet, activer l'API Safe Browsing, puis *Identifiants > Créer une clé API* | Restreindre la clé à la seule API Safe Browsing |
| VirusTotal | `VT_API_KEY` | Profil du compte, rubrique *API Key* | Palier public : quota réduit et usage non commercial seulement, voir les conditions |
| urlscan.io | `URLSCAN_API_KEY` | *Settings > API Keys* | Scans soumis en visibilité `unlisted` ou `private` (étape 2.6) |
| AbuseIPDB (facultatif) | `ABUSEIPDB_API_KEY` | *Account > API* | Réputation d'adresses IP seulement |

Les quotas et les conditions d'usage changent : relis-les sur le site de chaque service avant d'activer une source. Les enrichisseurs RDAP, DNS et Certificate Transparency (étape 2.7) n'ont pas besoin de clé.

## Configuration

```bash
cp .env.example .env      # puis remplir les valeurs voulues
python -m phishguard.config
```

`python -m phishguard.config` affiche l'état de chaque source, sans jamais afficher de clé :

```
google_safe_browsing   GSB_API_KEY          désactivée (clé absente)
virustotal             VT_API_KEY           activée
urlscan                URLSCAN_API_KEY      désactivée (clé absente)
abuseipdb              ABUSEIPDB_API_KEY    désactivée (clé absente)
```

Règles de chargement (`pydantic-settings`) :

- ordre de priorité : variable d'environnement, puis fichier `.env` du **répertoire courant** ;
- une valeur vide ou faite d'espaces compte comme absente : une copie brute de `.env.example` n'active rien ;
- les espaces autour d'une clé sont retirés (erreur fréquente lors d'un copier-coller) ;
- la configuration est lue une fois par processus (`get_settings()`), puis figée.

Dans le code, une clé est toujours lue au dernier moment, par la source qui en a besoin :

```python
from phishguard.config import get_settings

settings = get_settings()
if settings.is_enabled("virustotal"):
    key = settings.api_key("virustotal")  # en clair, à passer dans l'en-tête x-apikey
```

Les clés sont gardées en `SecretStr` : elles sont masquées dans `repr()`, `str()`, `model_dump_json()` et les erreurs de validation. Ne les journalise jamais, même tronquées.

Plus tard, chaque utilisateur pourra fournir **sa propre clé** (extension, module 5) : on ne dépend pas des quotas du projet, et aucune clé n'est partagée.

## Ce qui empêche une clé d'arriver dans Git

Trois protections, de la plus simple à la plus sûre :

1. **`.gitignore`** ignore `.env` et toutes ses variantes (`.env.local`, `.env.prod`…), sauf `.env.example`.
2. **Hook `forbid-env-files`** (pre-commit) : refuse un fichier `.env*` même ajouté de force avec `git add -f`.
3. **Hook gitleaks** (étape 0.4) : cherche les secrets dans chaque fichier commité, quel que soit son nom.

Vérification faite pour cette étape, dans un dépôt jetable avec des clés aléatoires aux formats réels : gitleaks bloque une clé VirusTotal (64 caractères hexadécimaux, règle `generic-api-key`), une clé Google (`AIza…`, règle `gcp-api-key`) et une clé urlscan (UUID, `generic-api-key`), y compris dans un fichier Python (`vt_key = "…"`). Le hook `forbid-env-files` refuse `.env`, `.env.local` et `config/.env.prod`, et laisse passer `.env.example`.

Pour refaire cette vérification après une mise à jour de gitleaks :

```bash
pre-commit run --all-files    # doit passer sur le dépôt
```

puis, dans un dépôt de test, ajouter une fausse clé et vérifier que `pre-commit run gitleaks` échoue. N'utilise jamais une vraie clé pour ce test.

`.env.example` est lui-même protégé par un test (`tests/test_config.py`) : il doit déclarer chaque variable et ne contenir **aucune** valeur.

## Si une clé fuit

Supprimer le commit **ne suffit pas** : l'historique a pu être cloné, mis en cache ou indexé en quelques minutes. Une clé poussée est une clé compromise.

1. **Révoque** la clé immédiatement sur le site du service, puis génère-en une nouvelle.
2. Mets la nouvelle clé dans `.env`, jamais dans le code.
3. Regarde l'historique d'usage de l'ancienne clé côté service (requêtes inattendues, quota consommé).
4. Seulement ensuite, nettoie l'historique si nécessaire (`git filter-repo`), en sachant que cela ne rend pas la clé à nouveau sûre.

Pour une vulnérabilité du projet lui-même, voir [SECURITY.md](../SECURITY.md).
