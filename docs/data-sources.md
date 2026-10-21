# Sources de données pour PhishGuard

Ce document décrit les sources de flux (feeds) de phishing et de domaines légitimes utilisées pour l'entraînement et l'évaluation des modèles de PhishGuard, leurs licences, fréquences de mise à jour, limites techniques et conditions d'utilisation.

---

## Vue d'ensemble

| Source | Type | Format | Licence / Coût | Fréquence | Auth / Clé |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **OpenPhish Community** | Phishing (URLs actives) | TXT (1 URL / ligne) | Gratuit pour usage non-commercial / recherche | Toutes les 6–12 h | Aucune |
| **PhishTank** | Phishing (signalements validés) | CSV / JSON | Données libres pour recherche / non-commercial (Cisco) | Toutes les 1–4 h | Recommande `User-Agent` & App Key |
| **URLhaus (abuse.ch)** | Malwares / Phishing (IOCs) | CSV / JSON | CC0 1.0 (Domaine public) | Toutes les 5 min | `Auth-Key` gratuite (auth.abuse.ch) |
| **Tranco List** | Légitime (Top sites) | CSV / ZIP | Données de recherche ouvertes (Le Pochat et al.) | Quotidienne (22h UTC) | Aucune (identifiant permanent) |

---

## 1. OpenPhish (Flux Communautaire)

- **URL du flux** : `https://openphish.com/feed.txt`
- **Site officiel** : [openphish.com](https://openphish.com/)
- **Description** : Détection automatisée d'URLs de phishing actives à travers le web. Le flux gratuit communautaire contient un échantillon des détections récentes.
- **Format** : Fichier texte brut, une URL par ligne.
- **Conditions d'utilisation & Licence** :
  - Gratuit pour une utilisation personnelle, académique ou de recherche de sécurité non-commerciale.
  - L'intégration directe dans un produit commercial ou la redistribution publique du flux complet nécessite l'offre commerciale premium.
- **Fréquence de mise à jour** : Approximativement toutes les 6 à 12 heures.
- **Limites & Bonnes pratiques** :
  - Pas de quota d'appels formellement publié pour le flux public, mais il est recommandé de ne pas requêter plus d'une fois toutes les 6 heures pour ménager l'infrastructure.
- **Spécificités & Pièges** :
  - Les URLs sont très éphémères : la majorité des sites sont suspendus par les hébergeurs ou registrars en quelques heures ou jours. L'archivage horodaté quotidien est impératif pour conserver l'historique et permettre un split temporel réaliste.

---

## 2. PhishTank

- **URL du flux** : `http://data.phishtank.com/data/online-valid.csv` (ou format `.json`)
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
  - **Clé API / App Key** : Une clé applicative facultative (`?app_key=...`) permet d'éviter les blocages de débit (rate limiting HTTP 429).
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
  - **Stratégie PhishGuard** : Conserver ces URLs avec un marquage explicite ou filtrer via les tags (`phishing`, `fake-update`, etc.). Dans l'Étape 1.2, ces URLs sont isolées ou annotées afin de ne pas induire en erreur un modèle de détection spécialisé dans les formulaires d'hameçonnage.

---

## 4. Tranco List (Domaines Légitimes)

- **URL du portail** : `https://tranco-list.eu/`
- **API de résolution** : `https://tranco-list.eu/api/lists/date/{YYYY-MM-DD}`
- **Téléchargement direct** : `https://tranco-list.eu/download/{list_id}/{count}` ou `https://tranco-list.eu/download_path/{list_id}`
- **Description** : Classement de popularité des sites web conçu spécifiquement pour la recherche académique en sécurité informatique (Le Pochat et al., NDSS 2019). Il combine et stabilise les signaux issus de plusieurs classements réputés (Alexa, Cisco Umbrella, Majestic, Cloudflare Radar) via la méthode de vote Borda/Dowdall pour éliminer le bruit et les manipulations de trafic éphémères.
- **Format** : CSV sans en-tête avec deux colonnes :
  - `rank` (entier, rang 1 à 1 000 000)
  - `domain` (nom de domaine apex/FQDN, ex. `google.com`, `wikipedia.org`)
- **Conditions d'utilisation & Licence** :
  - Données ouvertes pour la recherche et l'industrie. Citation requise des auteurs du papier de recherche NDSS 2019.
- **Reproductibilité scientifique (Identifiant de liste)** :
  - Contrairement à d'autres tops mouvants, Tranco attribue un **identifiant unique immuable** (ex. `V929N` pour le 1er janvier 2024) à chaque instantané journalier.
  - Le script `fetch_feeds.py` interroge l'API Tranco pour récupérer l'ID exact de la liste correspondant à la date demandée et enregistre le fichier sous `data/raw/{date}_tranco_{list_id}.csv.zip`, garantissant une reproductibilité stricte de toute expérience future.
- **Piège structural (Biais de chemin / Path bias)** :
  - La liste Tranco ne fournit que des **domaines racines** (ex. `example.com`), sans chemin d'accès (`/login.php`, `/account/verify`).
  - À l'inverse, les URLs de phishing comportent quasi systématiquement des sous-chemins profonds et des paramètres de requête.
  - Un modèle naïf entraîné sans précaution apprendrait le raccourci fallacieux : « présence d'un chemin = phishing ». Ce biais est documenté et adressé lors des étapes 1.2 et 1.3 avec l'intégration de jeux légitimes avec chemins complets (comme le corpus PhiUSIIL).

---

## Stratégie d'Archivage et de Reproductibilité

1. **Nommage horodaté standardisé** :
   Chaque fichier téléchargé dans `data/raw/` respecte le schéma :
   - `data/raw/YYYY-MM-DD_openphish.txt`
   - `data/raw/YYYY-MM-DD_phishtank.csv`
   - `data/raw/YYYY-MM-DD_urlhaus.csv`
   - `data/raw/YYYY-MM-DD_tranco_<list_id>.csv.zip` (ou `.csv`)
   - `data/raw/YYYY-MM-DD_manifest.json` (métadonnées, hashes SHA-256, compteurs d'URLs, statuts de collecte)

2. **Temporal Split sans fuite de données** :
   Les sites de phishing disparaissant rapidement et les attaquants adaptant constamment leurs techniques d'évasion (domaines DGA, nouveaux TLDs, contournement d'hébergeurs), une validation croisée aléatoire (*k-fold*) crée une fuite temporelle massive et surestime l'efficacité du modèle. L'archivage daté permet de découper rigoureusement :
   - Entraînement : données collectées sur les dates passées ($T_0 \to T_1$).
   - Test : données collectées sur les dates les plus récentes ($T_1 \to T_2$), en s'assurant qu'aucun domaine enregistré (`registered_domain`) n'apparaît dans les deux sous-ensembles.

3. **Automatisation quotidienne** :
   Un workflow GitHub Actions planifié (`.github/workflows/daily_feed_fetch.yaml`) s'exécute chaque nuit à 04:00 UTC pour archiver les flux et sauvegarder les artefacts.
