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

### 1.6 — Entraîner et comparer les modèles URL
- **Fait** : `scripts/train_url.py` (ou `make train-url`) entraîne régression logistique standardisée, Random Forest et LightGBM, pour chaque réglage d'une petite grille et chaque jeu de features (avec et sans schéma, chemin, longueur). Choix sur la validation au rappel à 1 % FPR, test jamais chargé. Le modèle retenu est enregistré avec ses features, sa table des TLD et ses seuils (`UrlModel`, `models/url_v1.joblib`) ; les tableaux de `docs/url-models.md` sont générés par le script.
- **Appris** : un modèle, ce n'est pas que l'estimateur. Sans la table des TLD et la liste ordonnée des features, on ne peut pas le rejouer. Le test d'aller-retour l'a montré : la table était arrondie à 6 décimales à l'enregistrement, donc le modèle rechargé ne voyait pas exactement les features de l'entraînement. Autre constat : pour une seule URL, la latence vient surtout du coût fixe d'un appel `predict_proba` (quelques millisecondes), pas de la taille du modèle.
- **Bloqué** : le code a été écrit sans accès au jeu de données (`data/` n'est pas versionné), donc sans pouvoir lire un seul résultat. Les tableaux étant générés par le script, ils sont justes dès la première exécution locale ; mais la lecture des résultats et la durée annoncée de l'entraînement ont dû être reprises après coup. Constat de cette lecture : au seuil de 1 % FPR, le modèle signale 6,8 % des pages internes légitimes contre 0,3 % des pages d'accueil, le biais de chemin de l'étape 1.3 est toujours là.

### 1.7 — Évaluation réaliste
- **Fait** : `scripts/evaluate_url.py` (ou `make evaluate-url`) mesure le modèle sur le test, une seule fois : rappel et FPR de chaque seuil réglé sur la validation (avec intervalles de Wilson), séparément pour les pages d'accueil et les pages internes ; précision à 1 % et 0,1 % de phishing, par la formule et par rééchantillonnage bootstrap ; rappel par source ; FPR par rang Tranco. Le seuil de décision est choisi sur la validation par une règle écrite à l'avance. Voir `docs/evaluation.md`.
- **Appris** : la précision dépend de la prévalence, pas le rappel ni le FPR. Avec 85 % de rappel et 1 % de faux positifs, on obtient 96 % de précision sur un test à 20 % de phishing, mais 8 % à 0,1 % de prévalence : douze fausses alertes pour une vraie. Un seuil se choisit donc avec une prévalence et un coût des fausses alertes en tête, jamais à 0,5 par défaut. Et un intervalle de confiance compte autant que le chiffre : à 0,1 %, un échantillon ne contient qu'environ 17 URLs de phishing.
- **Bloqué** : écrit sans accès aux données, le script prenait « la liste Tranco la plus récente » de `data/raw/`, selon la date de modification des fichiers. Or la collecte quotidienne en ajoute une chaque jour, et le jeu avait été construit avec cinq listes : 191 pages d'accueil du test se retrouvaient « hors liste », et le tableau aurait changé à chaque relance. Le script lit maintenant les listes du jeu dans `docs/metrics/urls_dataset.json` et vérifie leur empreinte. Autre surprise : le seuil de décision atteint la cible sur la validation (61,8 % de précision à 1 %) mais pas sur le test (47,3 %), parce que les faux positifs sur les pages internes doublent d'un bloc à l'autre. On ne retouche pas le seuil après avoir lu le test, on le documente.

### 1.8 — Analyse d'erreurs
- **Fait** : `scripts/analyze_url_errors.py` (ou `make errors-url`) extrait les 50 pires faux positifs et faux négatifs de la validation au seuil de décision, et les range par des règles explicites et ordonnées : nom proche d'une marque, plateforme d'hébergement, long paramètre, page profonde, domaine peu connu, TLD risqué ; côté phishing : plateforme réputée, raccourcisseur, IP, site compromis, domaine neuf d'apparence honnête. Chaque catégorie a sa piste d'amélioration. Seuls des agrégats et des exemples défangés sont versionnés ; les URLs complètes restent dans `data/reports/`. Voir `docs/error-analysis-url.md`.
- **Appris** : l'analyse d'erreurs se fait sur la validation, pas sur le test, sinon on règle le modèle sur le test sans le dire. Une partie du phishing n'a aucune trace dans le texte de l'URL : une page sur `docs.google.com` ou `*.web.app`, un sous-dossier d'un vieux site compromis. Aucune feature lexicale ne la verra, c'est ce qui justifie la Threat Intelligence du module 2. Publier des exemples demande aussi des précautions : défanger, retirer la requête (identifiants, adresse de la victime) et respecter la licence de chaque flux.
- **Bloqué** : les règles, écrites sans avoir vu une seule erreur réelle, rangeaient 43 des 50 pires faux négatifs dans « domaine d'apparence honnête », y compris `santandder[.]net`, que `is_typosquat` reconnaît pourtant. Il manquait une catégorie « le signal est là mais le modèle l'ignore » et une autre pour les noms composés trompeurs (`info-vitale[.]fr`). Deuxième leçon : les 50 pires erreurs ne ressemblent pas à l'ensemble. Le « site compromis » en est absent, mais il représente 21 % des 837 faux négatifs. Le script compte maintenant toutes les erreurs à côté des pires. Enfin, plusieurs « faux positifs » Tranco ressemblent à du phishing (`chat-whaptsap[.]app`) : la liste mesure le trafic, pas l'honnêteté.

### 1.9 — Modèle de texte (SMS)
- **Fait** : `scripts/train_text.py` (ou `make train-text`) compare TF-IDF mots et caractères, régression logistique et SVM linéaire, 13 features smishing écrites à la main (FR, EN, AR), leur combinaison avec les caractères, et en option des embeddings multilingues. Split 70 / 15 / 15 groupé par gabarit de message, réglage sur la validation, test lu une fois, plus un jeu de 100 SMS français et arabes rédigés à la main comme test hors distribution (`datasets/sms_fr_ar.csv`). Voir `docs/text-models.md`.
- **Appris** : le dédoublonnage exact ne suffit pas, une campagne envoie le même texte avec un autre numéro. Il faut grouper par gabarit. Sur le corpus anglais, toutes les approches à n-grammes se valent (PR-AUC de validation au-dessus de 0,99), et la différence n'apparaît que hors distribution : les n-grammes de caractères signalent plus de la moitié des SMS légitimes français, parce qu'ils ont appris « pas de l'anglais = suspect ». Un modèle choisi sur la validation anglaise n'est pas forcément le bon pour des utilisateurs francophones et arabophones, et il ne faut pas pour autant choisir sur le jeu de test FR/AR.
- **Bloqué** : le corpus UCI n'était pas téléchargeable depuis l'environnement de développement. La copie de `notebooks/legacy/` contient les mêmes 5 160 messages après dédoublonnage mais n'a pas l'empreinte du fichier officiel : elle a servi à vérifier le code, pas à publier des chiffres. Les tests ont aussi trouvé deux bugs : les groupes d'un numéro espacé (`+44 7700 900123`) comptaient comme numéros courts, et `split_sms` arrondissait en silence des parts qui n'étaient pas des multiples de 5 %.

### 1.10 — Parseur d'emails
- **Fait** : `src/phishguard/email/` analyse un `.eml` avec la bibliothèque standard `email` et BeautifulSoup (`html.parser`), sans rien rendre ni télécharger, avec des limites partout (taille, parties, profondeur, liens, texte). Il extrait SPF, DKIM et DMARC, la cohérence `From` / `Reply-To` / `Return-Path`, le nom affiché trompeur, les liens dont le texte diffère de la cible, les formulaires, les pièces jointes à risque (double extension, RTLO) et le texte masqué. 13 emails de test rédigés à la main, un test Hypothesis sur des octets aléatoires et sur des emails corrompus, `scripts/parse_email.py` pour inspecter un message. Voir `docs/email-parser.md`.
- **Appris** : seul l'en-tête `Authentication-Results` ajouté par le dernier serveur est fiable, car l'expéditeur peut écrire les autres lui-même. Les signaux se comparent au niveau du domaine enregistré, et seulement pour des domaines au suffixe public connu. Le texte masqué n'est pas une preuve : les newsletters légitimes cachent une ligne d'aperçu. Une licence se vérifie avant de versionner des données, même de test : Phishing Pot est CC BY-NC, donc ses emails restent dans `data/`.
- **Bloqué** : les corpus Nazario et SpamAssassin n'étaient pas accessibles depuis l'environnement de développement. La vérification s'est faite sur 200 emails de Phishing Pot et les 47 emails de test de CPython. Elle a trouvé deux bugs que mes emails rédigés ne montraient pas : un `From: "Service", _ <x@y>` (virgule hors des guillemets) faisait perdre l'expéditeur, et des liens relatifs étaient lus comme des noms de domaine.
