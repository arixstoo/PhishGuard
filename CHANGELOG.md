# Journal des versions

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Versions : une par module du [cahier des charges](PhishGuard%20%E2%80%94%20Cahier%20des%20charges%20et%20plan%20de%20r%C3%A9alisation.md).

## [Non publié] : module 2, Threat Intelligence et fusion des signaux

### Configuration

- Clés d'API facultatives (Google Safe Browsing, VirusTotal, urlscan.io, AbuseIPDB) chargées par `pydantic-settings` depuis l'environnement ou `.env` ; une clé absente désactive sa source sans bloquer le démarrage. `python -m phishguard.config` affiche les sources actives sans afficher les clés (étape 2.1, [docs/secrets.md](docs/secrets.md)).
- `.gitignore` et un hook pre-commit refusent toutes les variantes de `.env` ; gitleaks vérifié sur des clés aux formats réels (2.1).

### Sécurité

- Garde-fou réseau anti-SSRF `phishguard.security.netguard` : schémas et ports autorisés, IPv4 ambiguës décodées (`0x7f000001`, `2130706433`, `127.1`), résolution DNS contrôlée avec refus de toute adresse non publique (IPv4 cachées dans l'IPv6 comprises), connexion à l'IP validée contre le *DNS rebinding*, redirections revalidées, délais et taille de réponse bornés. Décision documentée : le serveur ne visite jamais l'URL analysée (étape 2.3, [docs/ssrf.md](docs/ssrf.md)).

### Enrichisseurs

- Contrat commun `Signal` / `Enricher` : un enrichisseur ne lève jamais d'exception vers l'appelant, une panne devient un signal `error` ou `timeout` de risque nul. La règle est appliquée par la classe de base, pas par chaque source ; l'annulation (`CancelledError`) passe, et le message des exceptions n'est jamais recopié pour ne pas faire fuiter de clé (étape 2.2, [docs/enrichers.md](docs/enrichers.md)).
- Google Safe Browsing (API v5 `urls:search`) : une correspondance est une règle dure (`risk = 1.0`). Clé dans un en-tête, cache selon la durée donnée par Google, fragment et identifiants retirés de l'URL avant l'envoi. `scripts/check_enrichers.py` interroge les vraies sources avec ses propres clés (étape 2.4).
- VirusTotal (API v3) : rapport de l'URL, puis du domaine si l'URL est inconnue, sans jamais soumettre d'analyse ; risque `min(1, (malicious + 0,5 × suspicious) / 5)`. Limiteur local (4 par minute, 500 par jour) qui renvoie `skipped` au lieu de dépasser le quota, cache de 6 h (étape 2.5).
- urlscan.io : recherche des scans existants par domaine seulement (IP, pays, marques imitées, verdict, capture), cache d'une heure. Soumission d'un scan derrière `URLSCAN_SUBMIT`, désactivée par défaut, en visibilité `unlisted` ou `private`, jamais `public` (étape 2.6).

## [0.1.0] : module 1, données et détection (URL, SMS, email)

Premiers détecteurs, évalués avec une méthode qui cherche les biais avant les scores. Rien n'est encore exposé à l'utilisateur : l'API, l'extension et le bot arrivent aux modules 4 et 5.

### Données

- Collecte quotidienne et reproductible : OpenPhish, PhishTank, URLhaus, Tranco, archivage chiffré (étape 1.1) ; pages internes légitimes Common Crawl (1.3 bis).
- Jeu d'URLs normalisé et dédoublonné, au plus 5 URLs par domaine (1.2) ; audit des biais (1.3) ; split temporel et groupé par domaine, sans fuite (1.4).

### URL

- 26 features lexicales hors ligne : marques, typosquatting, homographes, TLD, raccourcisseurs (1.5).
- Modèle `url_v1` : LightGBM, choisi sur la validation parmi régression logistique, Random Forest et LightGBM (1.6).
- Évaluation à prévalence réaliste, seuil de décision par règle écrite (1.7), analyse des erreurs par catégorie (1.8).
- Résultat sur le test : PR-AUC 0,939, rappel de 73,9 % au seuil de décision, 47 % de précision quand 1 % des URLs sont du phishing ([model card](docs/model-card-url.md)).

### SMS

- Six approches comparées (mots, caractères, SVM, features smishing FR/EN/AR), split groupé par gabarit, jeu de test français / arabe rédigé à la main (1.9).
- Modèle `text_v1` : n-grammes de caractères et SVM linéaire. Test UCI (anglais) : PR-AUC 0,975, rappel 94,8 % pour 1,5 % de faux positifs ; sur le jeu FR/AR rédigé, 40 à 43 % des messages légitimes signalés ([model card](docs/model-card-text.md)).

### Email

- Parseur défensif `.eml` : SPF, DKIM, DMARC (y compris les en-têtes Exchange Online), expéditeurs, liens trompeurs (liens réécrits par les passerelles de sécurité déballés), pièces jointes à risque, texte masqué. Taille **et temps** d'analyse bornés : en-têtes, parties MIME et balises HTML limités avant l'analyse (1.10).
- Score par règles transparentes et modèle appris, avec le modèle URL appliqué aux liens (1.11). Règles sur le test : 47 % du phishing signalé pour 0,8 % de faux positifs ; le modèle appris reste expérimental ([model card](docs/model-card-email.md)).

### Documentation

- Model cards [URL](docs/model-card-url.md), [SMS](docs/model-card-text.md), [email](docs/model-card-email.md), générées depuis `docs/metrics/` ; `make data`, `make train`, `make test` (1.12).

### Limites connues

- Biais de chemin et de popularité du modèle URL : 6,4 % de faux positifs sur les pages internes légitimes au seuil de décision.
- Modèle SMS entraîné sur de l'anglais : pas prêt pour le français et l'arabe.
- Corpus d'emails publics d'époques différentes (légitime de 2002, phishing de 2020 à 2026) : le modèle email appris sépare surtout les époques, et le verdict vient des règles. Sur du phishing récent (Phishing Pot), les règles jugent encore 64 % des emails « sûrs ».

## [0.0.1] : module 0, fondations

- Structure du dépôt, CI (ruff, pytest), pre-commit avec détection de secrets, fichiers de communauté.
- Baseline SMS reproductible avec métriques honnêtes (doublons retirés avant le split).
- Phishing 101, planification des issues et jalons.
