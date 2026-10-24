# Sources de données pour PhishGuard

Ce document décrit les sources de flux (feeds) de phishing et de domaines légitimes utilisées pour l'entraînement et l'évaluation des modèles de PhishGuard, leurs licences, fréquences de mise à jour, limites techniques et conditions d'utilisation.

---

## Vue d'ensemble

| Source | Type | Format | Licence / Coût | Fréquence | Auth / Clé |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **OpenPhish Community** | Phishing (URLs actives) | TXT (1 URL / ligne) | Gratuit pour usage non-commercial / recherche | Toutes les 12 h | Aucune |
| **PhishTank** | Phishing (signalements validés) | CSV / JSON | Données libres pour recherche / non-commercial (Cisco) | Toutes les 1–4 h | `User-Agent` `phishtank/...` obligatoire, App Key facultative |
| **URLhaus (abuse.ch)** | Malwares / Phishing (IOCs) | CSV / JSON | CC0 1.0 (Domaine public) | Toutes les 5 min | `Auth-Key` gratuite (auth.abuse.ch) |
| **Tranco List** | Légitime (Top sites) | CSV / ZIP | Données de recherche ouvertes (Le Pochat et al.) | Quotidienne (22h UTC) | Aucune (identifiant permanent) |
| **UCI PhiUSIIL** | Comparaison externe (phishing + légitime) | CSV dans un ZIP | CC BY 4.0 | Figé (version du 04/03/2024) | Aucune |

---

## 1. OpenPhish (Flux Communautaire)

- **URL du flux** : `https://openphish.com/feed.txt` (redirige vers `raw.githubusercontent.com/openphish/public_feed`, dépôt dont le README précise : mise à jour toutes les 12 h, usage non commercial uniquement, [conditions d'utilisation](https://openphish.com/terms.html))
- **Site officiel** : [openphish.com](https://openphish.com/)
- **Description** : Détection automatisée d'URLs de phishing actives à travers le web. Le flux gratuit communautaire contient un échantillon des détections récentes.
- **Format** : Fichier texte brut, une URL par ligne.
- **Conditions d'utilisation & Licence** :
  - Gratuit pour une utilisation personnelle, académique ou de recherche de sécurité non-commerciale.
  - L'intégration directe dans un produit commercial ou la redistribution publique du flux complet nécessite l'offre commerciale premium.
- **Fréquence de mise à jour** : Toutes les 12 heures (environ 300 URLs par instantané).
- **Limites & Bonnes pratiques** :
  - Pas de quota d'appels formellement publié pour le flux public, mais il est recommandé de ne pas requêter plus d'une fois toutes les 6 heures pour ménager l'infrastructure.
- **Spécificités & Pièges** :
  - Les URLs sont très éphémères : la majorité des sites sont suspendus par les hébergeurs ou registrars en quelques heures ou jours. L'archivage horodaté quotidien est impératif pour conserver l'historique et permettre un split temporel réaliste.

---

## 2. PhishTank

- **URL du flux** : `https://data.phishtank.com/data/online-valid.csv` (ou `.json`, `.csv.gz`, `.csv.bz2`) ; avec une clé : `https://data.phishtank.com/data/<app_key>/online-valid.csv` (la clé va dans le **chemin**, pas en paramètre `?app_key=`). Le serveur redirige vers un lien signé `cdn.phishtank.com`.
- **Site officiel** : [phishtank.org](https://phishtank.org/)
- **Description** : Système participatif et collaboratif de signalement et de validation d'URLs de phishing, opéré par Cisco Talos / OpenDNS.
- **Format** : Fichier CSV avec les colonnes :
  - `phish_id` : Identifiant numérique unique.
  - `url` : URL signalée.
  - `phish_detail_url` : Lien vers la page de vérification PhishTank.
  - `submission_time` : Horodatage ISO de soumission.
  - `verified` : Booléen (`yes`/`no`) confirmant la validation par la communauté.
  - `verification_time` : Horodatage ISO de validation.
  - `online` : Booléen indiquant si l'URL répondait lors de la dernière vérification.
  - `target` : Marque ou entité ciblée (ex. *PayPal*, *Microsoft*, *Google*).
- **Conditions d'utilisation & Licence** :
  - Données fournies sous licence d'usage de recherche et communautaire avec demande explicite d'attribution à PhishTank.
  - Usage commercial soumis à accord préalable avec Cisco.
- **Limites & Authentification** :
  - **User-Agent obligatoire** : PhishTank applique un filtre strict sur le `User-Agent` (ex. `phishtank/PhishGuard_<contact>`). Les requêtes avec User-Agent par défaut (comme `python-requests` ou `curl`) reçoivent fréquemment des codes `403 Forbidden` ou `503 Service Unavailable`.
  - **Clé API / App Key** : Une clé applicative facultative permet d'éviter les blocages de débit (HTTP 429). Elle se passe via `--phishtank-key` ou la variable `PHISHTANK_APP_KEY`.
  - Note : Les inscriptions de nouvelles clés sont parfois temporairement suspendues sur le portail ; le script de collecte gère le cas avec un `User-Agent` conforme et une dégradation élégante en cas d'erreur de débit.

---

## 3. URLhaus (abuse.ch)

- **URL du portail** : `https://urlhaus.abuse.ch/`
- **URL de téléchargement** : `https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv`
- **Description** : Projet géré par abuse.ch dédié au partage d'indicateurs de compromission (IoCs) concernant des sites malveillants.
- **Format** : Fichier CSV avec en-têtes précédées de commentaires `#` :
  - `id`, `dateadded`, `url`, `url_status`, `last_online`, `threat`, `tags`, `urlhaus_link`, `reporter`.
- **Conditions d'utilisation & Licence** :
  - Les données d'abuse.ch sont publiées sous licence **Creative Commons Zero 1.0 (CC0 / Domaine Public)**.
  - Utilisation libre tant pour les projets open source que commerciaux.
- **Authentification (`Auth-Key`)** :
  - Depuis fin 2023 / début 2024, abuse.ch exige une `Auth-Key` personnelle gratuite pour accéder aux exports et à l'API afin de prévenir les abus de scraping non maîtrisés.
  - L'obtention de la clé est immédiate et gratuite sur [auth.abuse.ch](https://auth.abuse.ch/) (connexion via compte GitHub, Google ou Twitter).
  - La clé peut être transmise à `fetch_feeds.py` via la variable d'environnement `URLHAUS_AUTH_KEY` ou l'option `--urlhaus-auth-key`.
- **Piège majeur & Précaution d'analyse (Attention)** :
  - **Nature des données** : URLhaus recense principalement des URLs de distribution de logiciels malveillants (*malware download*, botnets, scripts malveillants, ransomwares) et non du vol d'identifiants (*credential phishing*).
  - **Stratégie PhishGuard** : Conserver ces URLs avec un marquage explicite ou filtrer via les tags (`phishing`, `fake-update`, etc.). Depuis l'étape 1.2, `build_dataset.py` ne garde que les URLs étiquetées `phishing` ou `pdf-link-phishing` (une poignée par export) et écarte les téléchargements de malwares, comptés dans le rapport (voir [`url-dataset.md`](url-dataset.md)).

---

## 4. Tranco List (Domaines Légitimes)

- **URL du portail** : `https://tranco-list.eu/`
- **API de résolution** : `https://tranco-list.eu/api/lists/date/{YYYY-MM-DD}`
- **Téléchargement direct** : `https://tranco-list.eu/download/{list_id}/{count}` (CSV `rang,domaine`, `count` ≤ 1 000 000)
- **Quota** : l'API renvoie souvent `429 Too Many Requests` ; le script réessaie en respectant `Retry-After`.
- **Description** : Classement de popularité des sites web conçu spécifiquement pour la recherche académique en sécurité informatique (Le Pochat et al., NDSS 2019). Il combine et stabilise les signaux issus de plusieurs classements réputés (Alexa, Cisco Umbrella, Majestic, Cloudflare Radar) via la méthode de vote Borda/Dowdall pour éliminer le bruit et les manipulations de trafic éphémères.
- **Format** : CSV sans en-tête avec deux colonnes :
  - `rank` (entier, rang 1 à 1 000 000)
  - `domain` (nom de domaine apex/FQDN, ex. `google.com`, `wikipedia.org`)
- **Conditions d'utilisation & Licence** :
  - Données ouvertes pour la recherche et l'industrie. Citation requise des auteurs du papier de recherche NDSS 2019.
- **Reproductibilité scientifique (Identifiant de liste)** :
  - Contrairement à d'autres tops mouvants, Tranco attribue un **identifiant unique immuable** (ex. `V929N` pour le 1er janvier 2024) à chaque instantané journalier.
  - Le script `fetch_feeds.py` résout l'ID de la liste de la veille (publiée vers 22 h UTC) via l'API, puis télécharge **ce list_id précis** (`/download/{list_id}/{N}`). Le fichier `tranco_{list_id}_{N}_{horodatage}.csv` contient donc exactement la liste visible sur `https://tranco-list.eu/list/{list_id}`. Si aucun ID n'est résolu, la source est marquée en échec au lieu d'enregistrer une liste non identifiée.
  - Pour citer la liste dans un rapport : « Tranco list `{list_id}` generated on `{list_date}` », valeurs reprises du manifeste.
- **Piège structural (Biais de chemin / Path bias)** :
  - La liste Tranco ne fournit que des **domaines racines** (ex. `example.com`), sans chemin d'accès (`/login.php`, `/account/verify`).
  - À l'inverse, les URLs de phishing comportent quasi systématiquement des sous-chemins profonds et des paramètres de requête.
  - Un modèle naïf entraîné sans précaution apprendrait le raccourci fallacieux : « présence d'un chemin = phishing ». Ce biais est mesuré à l'étape 1.3 ([`data-bias.md`](data-bias.md)). PhiUSIIL, envisagé comme remède, **ne le corrige pas** : ses URLs légitimes n'ont pas de chemin non plus (voir section 5).

---

## 5. UCI PhiUSIIL (comparaison externe)

- **Page** : https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- **Fichier** : `PhiUSIIL_Phishing_URL_Dataset.csv`, extrait du ZIP de l'UCI ; 235 795 URLs, 134 850 légitimes et 100 945 phishing. Empreinte SHA-256 du CSV figée dans `src/phishguard/data/phiusiil.py` : le téléchargement est refusé si elle change.
- **Licence** : CC BY 4.0. Citation : Prasad, A. et Chandra, S. (2024), *PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning*, Computers & Security, 136.
- **Usage dans PhishGuard** : point de comparaison pour l'audit des biais (`scripts/audit_bias.py`), jamais pour l'entraînement. Téléchargé dans `data/external/` (non versionné).
- **Pièges** :
  - l'étiquette est **inversée** par rapport à la convention du projet : `label = 1` y désigne une URL légitime. Le chargeur la convertit (1 = phishing) ;
  - aucune URL légitime n'a de chemin, de paramètre ni de schéma `http`, et toutes commencent par `www.` : le jeu reproduit le biais de chemin de Tranco et en ajoute un (`www.`) ;
  - pas de date par URL : inutilisable pour un split temporel ;
  - ses URLs de phishing (2023) recoupent PhishTank : les domaines déjà présents dans notre jeu sont exclus de la comparaison.

---

## Stratégie d'Archivage et de Reproductibilité

1. **Nommage horodaté (UTC, `YYYYMMDD_HHMMSS`)** : une exécution produit dans `data/raw/` :
   - `openphish_<horodatage>.txt`
   - `phishtank_<horodatage>.csv`
   - `urlhaus_recent_<horodatage>.csv`
   - `tranco_<list_id>_<N>_<horodatage>.csv`
   - `manifest_<horodatage>.json`

   Les fichiers sont enregistrés **octet pour octet** tels que reçus (pas de nettoyage à cette étape, voir [`url-dataset.md`](url-dataset.md)).

2. **Manifeste** : pour chaque source, `status` (`ok`, `error` ou `skipped`), `file`, `count`, `bytes`, `sha256`, `source_url` (clés masquées par `***`) et `error` le cas échéant ; pour Tranco, `list_id` et `list_date`. Les métadonnées donnent la date ISO de collecte, les versions du collecteur, de Python et de httpx, et `success`.

3. **Code de sortie** : `0` si Tranco **et** au moins une source de phishing ont été collectés, `1` sinon. Une source isolée en échec (par ex. PhishTank bloqué par Cloudflare) ne fait pas échouer la collecte, mais apparaît dans le manifeste.

4. **Secrets** : les clés URLhaus et PhishTank ne sont jamais écrites dans les logs ni dans le manifeste (le logger `httpx`, qui affiche les URLs complètes, est réduit au niveau WARNING).

5. **Split temporel sans fuite** : les sites de phishing disparaissent vite et les attaquants changent de technique. Une validation croisée aléatoire (*k-fold*) crée une fuite temporelle et surestime le modèle. L'archivage daté permet de découper :
   - Entraînement : collectes les plus anciennes ($T_0 	o T_1$).
   - Test : collectes les plus récentes ($T_1 	o T_2$), sans aucun `registered_domain` commun aux deux blocs.

6. **Collecte quotidienne, deux filets de sécurité** :
   - **En local (archive principale)** : `powershell -ExecutionPolicy Bypass -File scripts
egister_daily_fetch.ps1` programme la tâche Windows `PhishGuard-FetchFeeds` chaque jour à 06:00 (lancée au réveil si le PC était éteint). Logs : `data/logs/fetch_feeds.log`.
   - **Sur GitHub Actions (secours)** : `.github/workflows/fetch-feeds.yml` s'exécute à 04:00 UTC (et à la demande), y compris en cas de collecte partielle. Secrets du dépôt : `ARCHIVE_PASSPHRASE` (obligatoire), `URLHAUS_AUTH_KEY` (recommandé), `PHISHTANK_APP_KEY` (facultatif).

7. **Archive GitHub chiffrée** : le dépôt est public et tout compte GitHub connecté peut télécharger ses artefacts. Les conditions d'OpenPhish interdisant la redistribution du flux, le workflow ne dépose que `feeds-<run_id>.tar.gz.enc` (AES-256-CBC, PBKDF2 200 000 itérations, clé `ARCHIVE_PASSPHRASE`). Sans ce secret, il refuse de déposer quoi que ce soit en clair. Ne jamais publier les fichiers bruts dans le dépôt ni dans une release.

8. **Rapatriement avant expiration (90 jours)** : `python scripts/sync_feed_archives.py` liste les artefacts encore disponibles, télécharge ceux qui ne sont pas encore récupérés (suivi dans `data/raw/.synced_artifacts`), les déchiffre avec `ARCHIVE_PASSPHRASE` (lue dans `.env`) et copie leurs fichiers dans `data/raw/` sans jamais écraser un fichier existant. Les artefacts antérieurs au chiffrement (fichiers en clair) sont aussi récupérés. Il faut `gh` connecté et `openssl` (fourni par Git for Windows). À lancer au moins une fois par mois.

9. **Surveillance** : les IP des runners GitHub sont parfois bloquées par Cloudflare (PhishTank) ; vérifier le champ `status` de chaque source dans les manifestes.

10. **Historique** : les fichiers Tranco des premières collectes de test (21/10/2026), enregistrés sous un `list_id` erroné par la v0.1.0 du collecteur, ont été supprimés. Les manifestes de ces collectes y font encore référence.
