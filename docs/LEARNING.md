# Journal d'apprentissage

Trois lignes par étape : ce que j'ai fait, ce que j'ai appris, ce qui m'a bloqué. C'est la matière première de l'article de lancement et des réponses en entretien.

> Les entrées des modules 0 et 1.1 à 1.2 ont été reconstituées à partir de l'historique git, des PR et des documents du dépôt. À compléter avec mes propres souvenirs quand ils diffèrent.

## Module 0 — Fondations

### 0.1 à 0.3 — Ancien projet, arborescence, environnement
- **Fait** : conservé le détecteur de spam SMS de 2022 sous le tag `v0-legacy` et dans `notebooks/legacy/`, posé l'arborescence `src/phishguard`, `scripts`, `tests`, `docs`, et décrit le projet dans `pyproject.toml` (paquet installable, dépendances `dev` séparées).
- **Appris** : un dépôt réutilisable met le code dans un paquet importable (`src/`) et garde les scripts minces. Il faut garder l'ancien projet plutôt que le supprimer : il montre d'où l'on part.
- **Bloqué** : la règle `data/` du `.gitignore` ignorait aussi `src/phishguard/data/`. Corrigé en `/data/`, qui ne vise que le dossier à la racine.

### 0.4 et 0.5 — Qualité de code et intégration continue
- **Fait** : ruff (lint et format) en hook pre-commit avec détection de secrets, et un workflow GitHub Actions qui lance ruff et pytest avec couverture à chaque push.
- **Appris** : un outil non épinglé n'est pas reproductible. La CI installait la dernière version de ruff, aux règles différentes de celle du hook local : même code, verdicts différents.
- **Bloqué** : CI rouge alors que tout passait en local. Corrigé en épinglant `ruff==0.17.1` aux deux endroits et en excluant le code legacy du lint.

### 0.6 — Fichiers de communauté
- **Fait** : README réécrit, licence MIT, `SECURITY.md`, `CONTRIBUTING.md`, code de conduite, modèles d'issues (dont faux positif / faux négatif) et de PR.
- **Appris** : pour un outil de sécurité, `SECURITY.md` (comment signaler une faille) et un modèle « faux positif » font partie du produit, pas de la décoration.
- **Bloqué** : le badge CI pointait vers `ci.yml` alors que le workflow s'appelle `ci.yaml`.

### 0.7 — Baseline SMS rigoureux
- **Fait** : TF-IDF + régression logistique sur l'UCI SMS Spam Collection, téléchargement vérifié par SHA-256, dédoublonnage avant le split, métriques PR-AUC et rappel à 1 % de faux positifs.
- **Appris** : le corpus contient 414 doublons. Avec un split aléatoire, 139 messages du test avaient déjà été vus à l'entraînement : la précision était gonflée et le nombre de faux positifs divisé par deux. Les « 96 % d'accuracy » de 2022 ne voulaient pas dire grand-chose sur un corpus à 87 % légitime.
- **Bloqué** : accepter que le « vrai » score soit moins bon (F1 0,912 au lieu de 0,942), et que le taux de faux positifs (1,7 %) dépasse encore l'objectif de 1 %.

### 0.8 — Phishing 101
- **Fait** : `docs/phishing-101.md`, comment fonctionne le phishing et comment le repérer.
- **Appris** : on ne choisit de bonnes features qu'après avoir compris les techniques des attaquants (typosquatting, homographes, raccourcisseurs, usurpation de l'expéditeur).
- **Bloqué** : rien de noté.

### 0.9 — Planifier le travail
- **Fait** : `scripts/bootstrap_github.py` crée les labels, les jalons et une issue par étape du cahier des charges, de façon idempotente.
- **Appris** : un script idempotent peut être relancé sans créer de doublons. C'est la même exigence que pour une collecte de données.
- **Bloqué** : rien de noté.

## Module 1 — Données et détection

### 1.1 — Scripts de collecte reproductibles
- **Fait** : `scripts/fetch_feeds.py` collecte OpenPhish, PhishTank, URLhaus et Tranco dans des fichiers horodatés, avec un manifeste (statut, SHA-256, identifiant de la liste Tranco). Collecte quotidienne par GitHub Actions, archive chiffrée, rapatriement local (`sync_feed_archives.py`).
- **Appris** : les flux de phishing sont éphémères, donc ce qui n'est pas archivé le jour même est perdu. Un dépôt public expose ses artefacts : il faut les chiffrer, parce que les conditions d'OpenPhish interdisent la redistribution.
- **Bloqué** : le fichier Tranco ne correspondait pas à l'identifiant noté (le script téléchargeait la dernière liste au lieu du `list_id` résolu). Il a aussi fallu masquer les clés d'API dans les logs, et rapatrier les artefacts produits avant le chiffrement.

### 1.2 — Schéma commun et nettoyage
- **Fait** : `scripts/build_dataset.py` produit `urls.parquet` : SHA-256 vérifié, URLhaus réduit au phishing, URLs normalisées, domaine enregistré avec `tldextract` hors ligne, doublons fusionnés, 5 URLs au plus par domaine. Résultat : 128 588 URLs.
- **Appris** : les suffixes privés comptent (`a.github.io` et `b.github.io` sont deux propriétaires différents). URLhaus est surtout du malware, pas du phishing. Une URL vue avec les deux étiquettes doit sortir du jeu.
- **Bloqué** : trois formats de manifeste coexistaient dans les archives. Les dates PhishTank remontent à 2011 alors que le légitime ne couvre que nos jours de collecte, ce qui a été noté pour 1.3 et 1.4.

### 1.3 — Repérer les biais avant d'entraîner
- **Fait** : `scripts/audit_bias.py`, un modèle sonde (n-grammes de caractères + régression logistique) qui mesure les raccourcis. On compare ses scores selon la partie de l'URL qu'il voit, le split (aléatoire ou groupé par domaine) et les sources vues à l'entraînement, puis on le valide sur PhiUSIIL. Les constats sont dans `docs/data-bias.md`.
- **Appris** : la longueur de l'URL seule sépare les classes (ROC-AUC 0,96). Environ 20 points de rappel à 1 % FPR viennent de la forme de l'URL, pas du domaine. Sans PhishTank à l'entraînement, le rappel passe de 0,92 à 0,63. Un raccourci se démontre en changeant la distribution : sur PhiUSIIL, la sonde tombe au hasard dès qu'elle ne voit que l'hôte, parce que toutes ses URLs légitimes commencent par `www.`.
- **Bloqué** : le remède du plan (PhiUSIIL) ne marche pas, ses URLs légitimes n'ont aucun chemin. Leçon : vérifier une source avant de la croire, même quand le plan la recommande.

### 1.3 bis — Source d'URLs légitimes avec chemin (Common Crawl)
- **Fait** : `scripts/fetch_commoncrawl.py` échantillonne des pages internes des 5 000 premiers domaines Tranco dans l'index de Common Crawl (13 934 URLs, 11 332 gardées dans le jeu). L'audit mesure désormais le taux de faux positifs sur des pages internes légitimes jamais vues.
- **Appris** : un modèle validé à « 1 % de faux positifs » sur des pages d'accueil en signalait **89 %** sur des liens profonds légitimes ; avec les pages internes, 27 %. La métrique hors ligne n'a de sens que si le légitime du test ressemble à celui du terrain. Retirer un raccourci fait apparaître d'autres biais : sans « chemin = phishing », le biais de source est plus fort qu'on ne le croyait (rappel sans PhishTank 0,84 → 0,42).
- **Bloqué** : un premier essai sans limite de débit a fait bloquer mon adresse IP par le CDN de Common Crawl (HTTP 403), et le script affichait quand même « OK ». Corrigé : 2 requêtes par seconde, arrêt au premier 403, manifeste honnête sur une collecte partielle. Une coupure réseau a ensuite interrompu une collecte : le garde-fou a gardé le préfixe propre, et la relance (même graine) a retrouvé 99,6 % des mêmes URLs.

### 1.4 — Split temporel et groupé
- **Fait** : `src/phishguard/data/split.py` et `scripts/split_dataset.py` découpent le jeu en 70 / 15 / 15. Aucun domaine enregistré n'est dans deux blocs (vérifié avant écriture et par un test Hypothesis), et chaque source est découpée dans le temps séparément. Voir `docs/split.md`.
- **Appris** : « trier par date » suppose que toutes les dates suivent la même horloge. Ici, ce n'est pas le cas : un tri global laissait 0,2 % de phishing en validation, contre 20 % dans chaque bloc avec un découpage par source. Un split doit aussi être déterministe : toutes les URLs Tranco ont la même date, et sans départage par hachage, l'ordre du fichier aurait décidé du bloc.
- **Bloqué** : mon premier indicateur d'« ordre temporel » comptait 30 000 lignes hors ordre à cause d'une seule URL récente placée tôt. Je l'ai remplacé par une mesure exacte : les lignes placées par une strate plus petite (83 lignes PhishTank, soit 0,3 %).

### 1.5 — Extracteur de features URL
- **Fait** : `src/phishguard/urls/` calcule 26 features sans réseau, rangées par groupe (schéma, hôte, chemin, longueur) et par famille (base, marques, homographes, TLD, raccourcisseurs). 172 marques et 33 raccourcisseurs en JSON, réutilisables par l'extension. 84 tests, dont des valeurs de référence pour le portage TypeScript. `scripts/evaluate_url_features.py` mesure l'apport de chaque famille sur la validation. Voir `docs/url-features.md`.
- **Appris** : une feature qui sépare très bien les classes peut mesurer la collecte plutôt que le phishing. `is_https` vaut 100 % sur Tranco parce que l'étape 1.2 fabrique ces URLs en `https://`, et `host_len` (ROC-AUC 0,91 à elle seule) mesure surtout la popularité des domaines Tranco. Le TLD apporte le plus (+5 points de rappel à 1 % FPR), mais c'est aussi la feature la plus exposée à ce biais. Les marques et les homographes n'apportent rien de mesurable ici : le jeu n'a presque pas de cas où elles se déclenchent, et on les garde pour l'explication et pour une attaque rare mais grave.
- **Bloqué** : les premières règles de marque signalaient `maps.google.co.th` comme une usurpation de Google, et `cloud.com` comme un typosquat d'`icloud`. Corrigé par les domaines nationaux (`any_cctld`, sauf `.co`, `.io`…) et par la règle « un mot contenu dans une marque n'est pas un typosquat » : 187 → 92 faux typosquats légitimes. Un test sur la liste a trouvé `gov.uk`, un suffixe public qui ne pouvait jamais être reconnu comme domaine officiel.
