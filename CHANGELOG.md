# Journal des versions

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Versions : une par module du [cahier des charges](PhishGuard%20%E2%80%94%20Cahier%20des%20charges%20et%20plan%20de%20r%C3%A9alisation.md).

## [Non publié] : module 4, API et backend sécurisés

Le moteur devient un service HTTP : trois routes d'analyse au contrat figé, des entrées bornées dès le schéma, des clés d'API stockées en empreinte seulement et des limites de débit par niveau de client, appliquées avant la lecture du corps ([docs/api.md](docs/api.md)).

### API

- Squelette FastAPI (`phishguard.api`) : `create_app()`, routeurs séparés (`analyze`, `feedback`, `meta`), configuration `pydantic-settings` préfixée `PHISHGUARD_API_` aux valeurs par défaut sûres (aucun proxy cru, Threat Intelligence désactivée, limites actives) ; une valeur invalide empêche le démarrage. Les modèles déployés sont chargés **une seule fois**, au démarrage (`lifespan`, hors de la boucle) ; un modèle manquant fait échouer le démarrage. `GET /v1/health` (sans clé ni limite) et documentation interactive `/docs`, désactivable. `python -m phishguard.api` (`make api`) lance uvicorn sur `127.0.0.1`, sans réécriture de l'IP par uvicorn ni en-tête `Server` (étape 4.1).
- Schémas d'entrée stricts (`phishguard.api.schemas`) : URL de 4 à 2 048 caractères, texte de 1 à 5 000, email d'1 Mio au plus et de type attendu ; mode strict, aucun champ inconnu, caractères de contrôle C0/C1 et demi-codets UTF-16 isolés refusés, caractères invisibles de format admis (évasions comptées par la normalisation). Taille du corps bornée avant lecture, y compris sans `Content-Length` ; `application/json` exigé (pas de requête inter-sites `text/plain` sans pré-vérification CORS). Une enveloppe d'erreur unique, **sans jamais recopier l'entrée** (FastAPI renvoie par défaut la valeur fautive) ni trace de pile (étape 4.2).
- Couche service (`phishguard.api.service`) et endpoints `POST /v1/analyze/url`, `/text`, `/email` (téléversement `.eml`), `GET /v1/model` (version, date d'entraînement, SHA-256 des fichiers chargés), `POST /v1/feedback` (domaine seulement, horodaté par le serveur, rangé en quarantaine, sans effet sur le modèle). Le calcul ML tourne dans le pool de threads ; `UrlAnalyzer.analyze(run_sync=...)` sépare le calcul local de l'enrichissement, qui reste sur la boucle. Une URL inanalysable donne 400 avec un message fixe : celui de l'analyseur recopiait l'URL (étape 4.3).
- Authentification et limites de débit (étape 4.4) :
  - clé d'API dans `X-API-Key`, secret de 256 bits dont seule l'empreinte SHA-256 est stockée (SQLite, droits `600`) ; `python -m phishguard.api.keys create|list|revoke` (`make api-key`). Une clé invalide ou révoquée est refusée (401), jamais rétrogradée en anonyme ;
  - trois niveaux : anonyme (30/min par IP), clé (300/min), clé refusée (10/min par IP, contre la recherche de clés). IPv6 regroupée par /64, un compteur par route, fenêtre glissante, `Retry-After` et `X-RateLimit-*`. Le limiteur passe avant la lecture du corps ;
  - `X-Forwarded-For` lu de droite à gauche et seulement depuis un proxy déclaré (`PHISHGUARD_API_TRUSTED_PROXIES`, vide par défaut) : un en-tête falsifié ne change pas le compteur ;
  - **`limits` au lieu de `slowapi`** : les limites dynamiques de slowapi 0.1.10 partagent la requête courante entre requêtes concurrentes, et son middleware ne les appliquait pas. Écart au cahier des charges documenté dans [docs/api.md](docs/api.md).
- Durcissement HTTP (`phishguard.api.hardening`, étape 4.5) :
  - en-têtes de sécurité sur **toute** réponse, y compris 429, 413 et 500 : `nosniff`, `Cache-Control: no-store`, politique de contenu `default-src 'none'`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-*-Policy`, `Permissions-Policy`, HSTS en production ;
  - CORS à liste explicite (`PHISHGUARD_API_CORS_ALLOWED_ORIGINS`, vide par défaut) : `*`, `null`, joker et chemin refusés au démarrage, `http://` refusé en production hors boucle locale, aucun identifiant de navigateur ;
  - délai par requête, lecture du corps comprise : 408 pour un client lent, 503 pour un traitement trop long, réponse tardive jetée. `python -m phishguard.api` borne les connexions (100 simultanées, 5 s d'inactivité, en-têtes de 16 Kio) ;
  - filet d'erreurs en middleware : le 500 de Starlette contournait les en-têtes de sécurité. `debug=False` explicite ;
  - `PHISHGUARD_API_ENVIRONMENT=production` ferme `/docs`, `/redoc` et `/openapi.json`, et refuse de démarrer si on les force. `HEAD /v1/health` pour `curl -I`.
- 127 tests (`tests/test_api_*.py`) sur de petits modèles chargés par le vrai chemin de démarrage : URL de 100 000 caractères, texte vide, JSON malformé, octet nul, demi-codet, corps envoyé par morceaux, email trop gros ou d'un autre type, contrat de réponse relu par `AnalysisResponse`, exécution dans le pool de threads, 100 requêtes rapides puis 429, clé révoquée, `X-Forwarded-For` falsifié.

## [0.3.0] : module 3, explicabilité et robustesse adversariale

Le moteur explique maintenant chaque verdict, en trois phrases pour l'utilisateur et en valeurs SHAP pour l'analyste, et il a été attaqué méthodiquement : dix techniques d'évasion mesurées sur les vrais jeux de test, deux défenses (normalisation, entraînement adversarial) mesurées avant et après, et un test sur du phishing rédigé par un LLM qui montre honnêtement où le texte seul ne suffit plus. Les modèles robustes (`url_v2`, `text_v2`) sont déployés, et les trois canaux (URL, message, email) passent par le même pipeline et le même contrat de réponse. Rien n'est encore exposé à l'utilisateur : l'API arrive au module 4.

### Explicabilité

- Valeurs SHAP du modèle URL (`phishguard.explain.shap_url`) : contribution exacte de chaque feature, calculée par le TreeSHAP natif de LightGBM (identique à la bibliothèque `shap`, vérifié par les tests), avec repli sur `shap.TreeExplainer` pour les autres modèles d'arbres. Les quatre formes de sortie possibles (liste par classe, tableau 3D, matrice, colonne de base) sont normalisées, les autres refusées. `scripts/explain_url.py` (`make explain-url`) produit le graphique global, l'importance de chaque feature et 10 URLs de phishing expliquées par leurs 3 raisons principales ; la lecture montre que la longueur de l'hôte et le TLD portent 60 % de l'importance, reflet des biais connus du jeu (étape 3.1, [docs/explain-url.md](docs/explain-url.md)).
- Raisons en langage simple (`phishguard.explain.reasons`) : au plus trois phrases par verdict, classées par poids, et toujours un conseil d'action selon le canal et le verdict. Seules les features compréhensibles ont une phrase (16, dont la marque imitée, l'adresse IP, le TLD à risque) ; la part du modèle est répartie selon les valeurs SHAP, les indices de forme passent après les indices précis, et un constat net sans effet sur le score (raccourcisseur) est cité à 0 point. Gabarits YAML en français, anglais et arabe, mêmes clés et mêmes variables vérifiées par les tests, y compris pour les 24 règles du score email. Tout fragment de l'entrée est nettoyé (caractères invisibles et d'inversion de sens, balisage, adresses désarmées) et les gabarits ne peuvent lire que des valeurs (étape 3.2, [docs/reasons.md](docs/reasons.md)).
- Explications du modèle SMS (`phishguard.explain.text`) : contribution exacte de chaque mot (`coefficient × tfidf` des n-grammes, ramenée aux mots sans rien perdre : la somme redonne la marge du SVM), et catégories de leurre repérées dans le message (urgence, argent, lien, code, compte ; un lien ne compte que comme lien). Raisons `text.*` : les catégories d'abord, puis les trois mots les plus influents pour un verdict suspect ou phishing ; jamais un lien, un nombre ou un mot-outil recopié. `TextAnalyzer` analyse un SMS ou un message sans aucun appel réseau, sans conserver le texte, et remplit le schéma de réponse (`AnalysisResponse.from_text_analysis`). Calibration du score SMS sur la validation (`scripts/calibrate_text.py`, `make calibrate-text`) : Platt retenue, ECE de 0,034 à 0,003 (étape 3.3, [docs/explain-text.md](docs/explain-text.md)).
- Schéma de réponse **1.2.0** : deux niveaux de sortie. `reasons` et `advice` pour l'utilisateur, `analyst` pour les détails techniques : sortie brute et calibrée du modèle, ses seuils, son explication (toutes les valeurs SHAP de l'URL, ou les dix mots les plus influents dans chaque sens pour le texte, nettoyés), le détail de la fusion (contributions, seuils, règle dure, sources ignorées) et les versions (schéma, modèle, fusion, gabarits, méthode). Facultatif (`to_response(analyst=False)`) ; une vue analyste qui décrit un autre modèle ou une autre fusion que la réponse est refusée. Les clients ne l'affichent que sous « Détails techniques » (étape 3.4).
- Schéma de réponse **1.1.0** : raisons rédigées dans la langue demandée avec leurs variables (`params`), au plus trois ; nouveaux champs `language` et `advice`. `UrlAnalysis` porte son explication SHAP, calculée sur les mêmes features que le score ; une explication impossible ne fait jamais échouer l'analyse ([docs/response-schema.md](docs/response-schema.md)).

### Robustesse adversariale

- Catalogue des techniques d'évasion ([docs/evasion-catalog.md](docs/evasion-catalog.md)) : 21 techniques (9 sur l'URL, 7 sur le texte, 5 sur l'email), chacune avec son vecteur, la feature de PhishGuard qu'elle contourne, la contre-mesure en place ou prévue (avec son étape) et ses références MITRE ATLAS (AML.T0015 *Evade AI Model*, AML.T0043) et ATT&CK, vérifiées contre ATT&CK v20.1 et ATLAS 5.6.0. Modèle de menace : attaquant en boîte noire qui garde l'effet du leurre. Trois techniques restent non couvertes (message en image, QR code) ou hors de portée du modèle lexical (domaine de confiance détourné), et le catalogue le dit (étape 3.5).
- Bibliothèque de perturbations (`phishguard.adversarial.perturb`), réservée à l'évaluation et au renforcement des détecteurs : dix perturbations qui reproduisent dix techniques du catalogue. Côté texte : largeur nulle, homoglyphes, leetspeak, mots coupés, dilution. Côté URL : sous-domaines, chemin bénin, long paramètre, majuscules dans l'hôte, homographe de l'hôte. Toutes sont déterministes, avec une graine par échantillon tirée d'un CRC32, stable d'un processus à l'autre. Elles gardent le sens : une URL perturbée reste valide et garde son domaine enregistré, sauf l'homographe, qui en désigne volontairement un autre, et un message se relit à l'identique. Une entrée où la technique ne s'applique pas ressort inchangée et est comptée à part. Vérifié sur 3 000 URLs du test : aucune URL invalide (étape 3.6).
- Banc d'essai de robustesse (`phishguard.adversarial.benchmark`, `scripts/robustness_benchmark.py`, `make robustness`). Chaque perturbation est appliquée aux blocs de test, phishing **et** légitime, et le banc mesure au seuil de décision : le rappel et le FPR avant et après (avec intervalles de Wilson), les phishing qui échappent et le décalage moyen du score. Rien n'est réglé sur le test. Premier rapport, avant défenses ([docs/robustness-report.md](docs/robustness-report.md)) :
  - URL : les sous-domaines ajoutés coûtent 12,5 points de rappel, et un long paramètre de suivi fait signaler 49 % des URLs légitimes ;
  - SMS : les n-grammes de caractères résistent aux homoglyphes et à la largeur nulle modérés, mais pas à leur intensité maximale (−16,7 points), ni à la dilution (−32,3 points avec 50 mots) ;
  - SMS français / arabe : déjà 42 % de faux positifs sans aucune perturbation.

  Trois variantes à intensité maximale ont été ajoutées aux perturbations (étape 3.7).
- Normalisation défensive (`phishguard.security.normalize`), à l'entraînement comme à l'inférence ([docs/normalization.md](docs/normalization.md)) :
  - NFKC, puis retrait des caractères de format (Cf) et de contrôle (Cc) ;
  - repli des homoglyphes vers le latin, limité aux mots qui imitent l'écriture latine : un texte russe, grec ou arabe reste intact ;
  - règle d'alerte forte pour un hôte qui imite des lettres latines (`host_script_alert`, y compris un label entièrement cyrillique). Les hôtes ne sont jamais repliés, sans quoi `аpple.com` deviendrait `apple.com` ;
  - journalisation des entrées modifiées, avec des comptes seulement.

  Où elle s'applique :
  - `TextNormalizer` est le prétraitement des vectoriseurs TF-IDF : même texte pour l'entraînement, le score et les explications. `text_v1` est réentraîné, avec les mêmes chiffres sur le test propre ;
  - les mots-clés smishing replient aussi les homoglyphes ;
  - `parse_url` normalise le texte brut avant les features ;
  - `UrlAnalysis.host_alert` porte l'alerte, que l'étape 3.12 branchera sur la fusion.

  Banc d'essai relancé : sous homoglyphes et largeur nulle, le rappel SMS revient exactement à celui du texte propre (`zero_width_dense` : de 78,1 % à 94,8 %). Les homographes d'hôte sont signalés à 99,4 % au lieu de 75,1 %. Le FPR sur les données propres est inchangé (URL 0,83 %, SMS 1,47 %). Les évasions de forme (sous-domaines, dilution) restent entières, comme prévu. Coût : 0,53 → 1,25 ms par SMS (étape 3.8).
- Entraînement adversarial (`phishguard.adversarial.augment`, `scripts/train_adversarial.py`, `make train-adversarial`) : une copie perturbée de chaque échantillon d'entraînement, avec la même étiquette, puis réentraînement de la configuration déjà retenue de chaque modèle. Seule la donnée change. Le générateur d'entraînement est distinct de celui du banc : vocabulaires disjoints (vérifié par les tests), autres séparateurs, autre table leet, intensités tirées dans une plage et autre graine. Ni la validation ni le test ne sont augmentés. Les deux classes sont perturbées, un choix fait avant la mesure ; l'ablation « phishing seul » montre qu'il apprend au modèle que toute forme ajoutée signale le phishing (94 % de FPR sous long paramètre). Résultats (`url_v2`, `text_v2`) :
  - URL : FPR sous long paramètre de 49,1 % à 0,77 %, sous chemin bénin de 11,3 % à 0,71 %, sous sous-domaines de 5,6 % à 0,96 % ; rappel sous sous-domaines de 61,4 % à 66,9 %. Prix : 10,3 points de rappel sur les URLs propres (73,9 % → 63,6 %), le raccourci de forme retiré étant en partie un biais du jeu ;
  - SMS : rappel propre identique (94,8 %), FPR propre de 1,47 % à 1,18 %, FPR sous leetspeak de 10,2 % à 5,2 %. La dilution résiste (−29,2 points avec 50 mots).

  Le banc ajoute un résumé, une ligne par défense (rappel et FPR propres, moyenne et pire cas sous perturbation). `leetspeak` et `add_long_param` acceptent leur table et leurs noms de paramètres (étape 3.9).
- Phishing rédigé par un LLM (`phishguard.data.llm_phishing`, `scripts/evaluate_llm_phishing.py`, `make llm-phishing`, [docs/llm-phishing.md](docs/llm-phishing.md)). Le jeu est défensif et local, jamais versionné : 150 phishing et 150 courriers légitimes d'entreprise, sans faute, rédigés par un LLM, plus 40 messages légitimes de contrôle avec lien. Le chargeur refuse tout fichier qui cite un domaine non réservé, une vraie adresse ou un numéro de téléphone. Résultats :
  - le rappel tient (90 à 91 %), mais **57 à 63 % des courriers légitimes sont signalés** (1,2 à 1,5 % sur le SMS) et la ROC-AUC passe de 0,99 à 0,71. Le modèle a appris « registre commercial = spam » ;
  - la règle « lien + demande de code ou de compte » paraît précise sur le jeu principal, mais le contrôle montre qu'elle signale 52,5 % des messages légitimes avec lien : elle ne sera pas ajoutée à la fusion ;
  - un domaine récent sur le lien ferait passer le rappel de l'analyse de 76 % à 92 % (scénario), mais ne réduit aucun faux positif.

  Conclusion : face à des messages bien écrits, le texte seul ne distingue plus un leurre d'un vrai courrier ; les signaux d'infrastructure et d'authentification deviennent l'essentiel (étape 3.10).
- Rapport de robustesse final ([docs/robustness-report.md](docs/robustness-report.md)) : résumé « en bref », puis modèle de menace, méthodologie, jeux de données, résultats avant défenses, défenses, résultats après défenses, phishing rédigé par un LLM, limites et pistes futures ; tableaux détaillés par passage en annexe. Graphique du rappel et du FPR par technique, un passage par couleur (`scripts/plot_robustness.py`, `make plot-robustness`, palette catégorielle validée pour les daltonismes). Les limites qualifient les chiffres de borne optimiste, faute d'attaque automatisée ou combinée (étape 3.11).

### Intégration

- Normalisation et explications dans le pipeline principal, pour les trois canaux (étape 3.12, [docs/analysis.md](docs/analysis.md)) :
  - règle dure **`lookalike_host`** dans la fusion (configuration **1.1.0**) : un hôte qui imite des lettres latines, dans l'URL analysée ou dans un lien d'un email, donne le verdict phishing, avant la liste blanche comme Safe Browsing. Sa raison est traduite en trois langues (gabarits version 2), et l'imitation est un constat ATT&CK (T1583.001) ;
  - `analysis.normalization` (URL, message, email) : ce que la normalisation a changé, en comptes seulement, journalisé et exposé dans la vue analyste ;
  - **`EmailAnalyzer`** : email brut (`.eml`) → règles de l'étape 1.11 avec la règle `url_model` → fusion → raisons et techniques ATT&CK, entièrement local, résumé sans contenu.
- Schéma de réponse **1.3.0** : `analyst.normalization` (facultatif), réponses du canal `email` (`AnalysisResponse.from_email_analysis`), raison `hard_rule.lookalike_host`.
- Modèles déployés (`phishguard.deployment`, `load_analyzers`) : `url_v2` et `text_v2`, issus de l'entraînement adversarial, et les règles email. Le choix de `url_v2` est un compromis assumé et documenté : −10,3 points de rappel sur un test biaisé, contre la fin d'une évasion gratuite par sous-domaines et de 49 % de faux positifs sous long paramètre de suivi. Calibrations et évaluation de test de `url_v2` et `text_v2` dans `docs/metrics/`.
- 29 tests de bout en bout (`tests/test_pipeline_e2e.py`) : homographe d'hôte, liste blanche, IDN légitime, caractères invisibles dans une URL et dans un message, les 13 emails de test, chargement des modèles déployés.

## [0.2.0] : module 2, Threat Intelligence et fusion des signaux

Le moteur enrichit maintenant un indicateur comme le ferait un analyste avant de conclure : six sources de Threat Intelligence interrogées en parallèle, fusionnées avec le modèle local calibré en un score, un verdict, ses raisons et ses techniques MITRE ATT&CK, dans un schéma de réponse figé. L'enrichissement reste **désactivé par défaut** : sans opt-in, rien ne quitte la machine, et une URL interne n'est jamais envoyée. Vérifié contre les vraies API (Safe Browsing, VirusTotal, urlscan.io, RDAP, DNS) et, pour l'âge des domaines, contre les registres eux-mêmes. Rien n'est encore exposé à l'utilisateur : l'API arrive au module 4.

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
- RDAP (âge du domaine, registraire) par l'amorçage IANA et le serveur du registre, barème de risque selon l'âge ; DNS (`dnspython` : A, AAAA, MX, NS, fournisseur de DNS gratuit, allure de *fast flux*, absence de MX) ; Certificate Transparency par crt.sh, en option. Un signal manquant donne toujours `risk = 0` (étape 2.7).
- Robustesse réseau commune à toutes les sources : client `httpx` partagé (connexion 2 s, lecture 3 s), nouvelles tentatives avec `tenacity` sur les seules erreurs temporaires (5xx, 429 avec un délai court, échecs de connexion ; un `POST` seulement si la requête n'est pas partie), disjoncteur par source (5 échecs consécutifs : pause de 60 s, puis une requête d'essai), cache `cachetools` à durée de vie par entrée (étape 2.8).
- Orchestrateur : toutes les sources en parallèle sous un budget global de 2,5 s ; les sources trop lentes sont annulées et marquées `timeout`, l'analyse se dégrade sans jamais échouer. Aucune source appelée si l'utilisateur n'a pas activé l'enrichissement. `scripts/check_enrichers.py` passe par l'orchestrateur (étape 2.9).

### Fusion du score

- Calibration des probabilités du modèle URL sur la validation (isotone ou Platt, choisie en validation croisée), enregistrée en JSON sans pickle ; `scripts/calibrate_url.py`, `make calibrate-url`. Sur `url_v1`, la régression isotone est retenue : ECE de 0,011 à 0,003 en validation croisée (`docs/metrics/url_calibration.json`).
- Fusion pure et versionnée (`fusion/fusion.json`) : règles dures (liste noire, Safe Browsing avant liste blanche), « OU probabiliste » pondéré des signaux utilisables, seuils sûr < 30 ≤ suspect ≤ 70 < phishing, contribution de chaque source. Résultat indépendant de l'ordre des signaux, même si une source répond deux fois. 18 cas de table de vérité et des tests de propriétés (étape 2.10, [docs/fusion.md](docs/fusion.md)).
- Correspondance MITRE ATT&CK : chaque verdict suspect ou phishing est relié à ses techniques (T1566.001/.002/.003, T1204.001/.002, T1598.001/.002/.003, T1583.001), au moins une pour tout phishing. Catalogue vérifié contre les données officielles d'ATT&CK v20.1 par `scripts/verify_mitre.py` (étape 2.11, [docs/mitre-attack.md](docs/mitre-attack.md)).
- Schéma de réponse figé, version 1.0.0 (`phishguard.schema.AnalysisResponse`) : `verdict`, `score`, `confidence`, `reasons`, `signals`, `mitre`, `model_version`, `enrichment`, `latency_ms`, plus `schema_version`, `channel` et `fusion_version`. Réponses incohérentes refusées (phishing sans technique ATT&CK, sûr avec techniques, signaux sans enrichissement). Schéma JSON versionné dans `docs/schema/`, régénéré par `make schema` et vérifié par les tests (étape 2.11 bis, [docs/response-schema.md](docs/response-schema.md)).

### Analyse de bout en bout et tests de vie privée

- `UrlAnalyzer` (`phishguard.analysis`) : modèle local, calibration, enrichissement **seulement sur opt-in**, fusion et techniques ATT&CK, en un appel ; point d'entrée de l'API du module 4. Une URL interne (IP privée ou de bouclage, hôte sans suffixe public) n'est jamais envoyée aux sources, même avec l'opt-in.
- Tests de vie privée : sans enrichissement, aucun accès réseau (HTTP, DNS, socket) ; avec, ni identifiants, ni fragment, ni clé dans une URL, et le domaine seul pour urlscan, RDAP, DNS et crt.sh. Tests de dégradation : toutes les sources en panne ou trop lentes, le verdict du modèle est renvoyé dans le délai. Contrat commun des six sources face à neuf formes de panne, et liste des hôtes que chacune peut contacter (étape 2.12, [docs/analysis.md](docs/analysis.md)).

### Pièces jointes

- Inspection du **contenu** des pièces jointes, en mémoire et sans rien exécuter ni extraire : vrai type par signature et nom qui ment, macros VBA (OLE avec `olefile`, OOXML, ODF), modèle distant, objets OLE dans un RTF, archives ZIP listées sans décompression (chiffrées, ou contenant un programme), PDF actifs (y compris noms obfusqués), page HTML qui demande un mot de passe. Cinq nouvelles règles du score email ; `dangerous_attachment` tient compte du contenu (étape 2.13, [docs/attachments.md](docs/attachments.md)).

### Documentation

- Évaluation d'outils externes ([docs/external-tools.md](docs/external-tools.md)). EML Analyzer : idée reprise (contenu des pièces jointes), outil non intégré. Format `.msg` : plus tard. DeHashed : écarté (pas de valeur de détection, données personnelles de tiers). PhishTool : référence de comparaison pour les tests utilisateurs de l'étape 5.13, avec son protocole.

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
