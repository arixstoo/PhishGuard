# Journal des versions

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Versions : une par module du [cahier des charges](PhishGuard%20%E2%80%94%20Cahier%20des%20charges%20et%20plan%20de%20r%C3%A9alisation.md).

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
