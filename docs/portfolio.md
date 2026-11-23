# Mettre le projet en valeur (étape 6.14)

Ce document prépare le CV, les entretiens et la démonstration. Tout ce qui y est dit est
vérifiable dans le dépôt : chaque chiffre renvoie à sa source. Les passages entre crochets
attendent des données qui n'existent pas encore (utilisateurs réels, tests utilisateurs).

Rôles visés : analyste SOC N1/N2, Threat Intelligence, AppSec / DevSecOps, sécurité de l'IA.

## 1. Le haut du README

Fait : le problème en trois phrases, une vraie capture de l'extension (en attendant le GIF,
[launch/demo.md](launch/demo.md)), les trois chiffres clés générés depuis
`docs/metrics/url_v2_test.json` par `make cards` (aucun chiffre recopié à la main), la
latence, le lien d'installation dès la publication, et les trois documents phares.

## 2. Les trois documents phares

À épingler (README, profil GitHub, section « Sélection » de LinkedIn) :

1. **[Modèle de menace](threat-model.md)** : biens, attaquants, menaces, parades, risques
   résiduels. Montre la démarche de sécurité.
2. **[Rapport de robustesse](robustness-report.md)** : 21 techniques d'évasion cataloguées,
   banc d'essai, défenses et leur coût mesuré, phishing rédigé par un LLM. Montre la
   rigueur ML et l'honnêteté sur les limites.
3. **[Article de lancement](launch/article.md)** : ce que j'ai appris, avec les vrais
   chiffres. Montre la communication technique.

## 3. CV : trois puces chiffrées

> **PhishGuard**, détecteur de phishing open source (extension Chrome, API, bot Telegram),
> conçu, développé et déployé seul. *github.com/arixstoo/PhishGuard*
>
> - Modèle LightGBM évalué sur un **split temporel groupé par domaine** (21 004 URLs les
>   plus récentes) : **66,8 % de rappel à 1 % de faux positifs**, PR-AUC 0,91 ; fuite de
>   données découverte et corrigée dans le protocole initial (12,5 % du test déjà vus à
>   l'entraînement) ; banc de **21 techniques d'évasion**, détection des homographes portée
>   de **75 % à 99 %**.
> - Sécurité applicative : API FastAPI durcie (garde-fou **SSRF** contre le *DNS rebinding*
>   et les IPv4 obfusquées, limitation de débit, fuzzing Hypothesis), **modèles signés
>   Ed25519** vérifiés par l'extension, provenance **Sigstore**, scans trivy, pip-audit,
>   gitleaks en CI ; extension MV3 à trois permissions et **zéro requête réseau par défaut,
>   vérifié par 39 tests Playwright**.
> - *[Adoption : N utilisateurs actifs hebdomadaires, N retours traités, taux de faux
>   positifs signalés de N %, à remplir avec le rapport hebdomadaire
>   ([measure.md](measure.md)).]*

Version anglaise :

> - LightGBM model evaluated on a **temporal, domain-grouped split** (21,004 most recent
>   URLs): **66.8% recall at 1% FPR**, PR-AUC 0.91; found and fixed a data leak in the
>   initial protocol (12.5% of the test set seen in training); **21-technique evasion
>   benchmark**, homograph detection raised from **75% to 99%**.
> - AppSec: hardened FastAPI service (**SSRF** guard against DNS rebinding and obfuscated
>   IPv4, rate limiting, Hypothesis fuzzing), **Ed25519-signed models** verified by the
>   extension, **Sigstore** provenance, trivy, pip-audit and gitleaks in CI; MV3 extension
>   with three permissions and **zero network requests by default, enforced by 39
>   Playwright tests**.
> - *[Adoption: N weekly active users, N reports handled.]*

Sources : `docs/metrics/url_v2_test.json`, README (fuite : 139 / 1 115), 
[evasion-catalog.md](evasion-catalog.md), [robustness-report.md](robustness-report.md),
[ssrf.md](ssrf.md), [model-registry.md](model-registry.md),
[extension-privacy.md](extension-privacy.md).

## 4. Cinq histoires d'entretien (situation, action, résultat)

Chacune tient en deux minutes. Finir par ce que l'on ferait autrement : c'est souvent la
question suivante.

### 1. La fuite de données dans un split aléatoire

- **Situation** : mon détecteur de spam de 2022 annonçait 96 % d'accuracy.
- **Action** : en reconstruisant la référence, j'ai cherché les doublons : 414 messages en
  double, et **139 des 1 115 messages du test déjà vus à l'entraînement**. J'ai dédupliqué
  avant de découper ; pour les URLs, j'ai imposé un découpage temporel et groupé par
  domaine, vérifié par un test Hypothesis.
- **Résultat** : précision 0,952 → 0,889, faux positifs réels deux fois plus nombreux.
  Les chiffres publiés sont plus bas, mais vrais.
- **Leçon** : sur un jeu à 87 % légitime, l'accuracy ne dit rien ; on rapporte le rappel à
  un taux de faux positifs fixé.

### 2. La faille SSRF que j'ai testée

- **Situation** : l'API reçoit des URLs choisies par n'importe qui ; un service qui les
  visiterait pourrait être retourné contre le réseau interne.
- **Action** : d'abord ne pas faire la requête (le serveur interroge des services de
  réputation *au sujet* de l'URL). Puis un garde-fou pour le jour où il le faudra : DNS
  résolu par nous, connexion à l'IP validée (nom dans `Host` et SNI), redirections
  revalidées. 112 tests sans réseau, dont une propriété Hypothesis.
- **Résultat** : en testant, `0x7f000001`, `2130706433` et `127.1` passaient un contrôle
  fondé sur `ipaddress` alors que le résolveur système les lit comme `127.0.0.1`. Corrigé en
  appliquant la règle des navigateurs (standard URL du WHATWG).
- **Leçon** : valider le nom ne suffit pas, il faut se connecter à ce qu'on a validé
  (*DNS rebinding*).

### 3. L'évasion qui a fait chuter le rappel, et la défense

- **Situation** : banc d'essai de 10 perturbations sur le modèle URL.
- **Action** : la pire n'était pas l'homographe mais **deux sous-domaines ajoutés**
  (−12,5 points de rappel). Défenses : normalisation (NFKC, caractères invisibles,
  homoglyphes) et entraînement adversarial, sur **les deux classes** : ma première version,
  qui ne perturbait que le phishing, rendait suspectes 94 % des URLs légitimes à paramètre
  de suivi.
- **Résultat** : homographes détectés à 99,4 % au lieu de 75,1 % ; coût publié : −10,3
  points de rappel sur les URLs propres, en partie parce que le modèle a perdu un raccourci
  que le test récompensait.
- **Leçon** : mesurer le FPR sous attaque, pas seulement le rappel ; une défense qui
  signale toute forme inhabituelle rend l'outil inutilisable.

### 4. La décision de vie privée sur l'accès à Gmail

- **Situation** : analyser les emails est la fonction la plus utile, et la plus intrusive :
  Chrome affiche « Lire et modifier vos données sur mail.google.com ».
- **Action** : seul le message **ouvert** est lu, sur l'appareil ; rien n'est gardé, même en
  mémoire de session ; jamais d'analyse en ligne pour Gmail, même si l'option est activée ;
  bannière dans un Shadow DOM fermé, liens jamais modifiés ; option pour couper. Chaque
  autre permission est optionnelle et demandée au moment de l'activation.
- **Résultat** : un seul avertissement à l'installation, justifié en une phrase dans la
  fiche du store ; des tests vérifient que rien n'est stocké ni envoyé depuis Gmail.
- **Leçon** : une permission est une question posée à l'utilisateur au pire moment ; on ne
  la demande pas « pour plus tard ».

### 5. Ce que les testeurs non techniques ont mal compris

*[À écrire après les séances de tests utilisateurs ([user-tests.md](user-tests.md)) :
situation (protocole, nombre de participants, score SUS), ce qui a été mal compris (mot,
couleur, bouton), ce qui a changé, et le score du groupe suivant.]*

En attendant, une histoire voisine et réelle : un faux positif que seul un vrai navigateur
a trouvé. Dans la maquette Gmail, un expéditeur affiché « impots.gouv.fr » écrivait depuis
`dgfip.finances.gouv.fr`, domaine légitime de la même administration. La règle « nom
affiché ≠ domaine de l'expéditeur » est devenue graduée, comme dans le score de l'API.

## 5. Démonstration en direct (5 minutes)

Préparer : profil Chrome avec l'extension, la maquette Gmail ou un message de test envoyé à
soi-même, un terminal avec l'API locale (`make api`), le Wi-Fi prêt à être coupé.

| Minute | Montrer | Dire |
|---|---|---|
| 0:00 | Le problème : un message « Votre compte est limité » | « Le lien affiché dit paypal.com. » |
| 0:30 | Ouvrir le message : la bannière | « Analyse sur l'appareil, seul ce message est lu. » |
| 1:15 | Clic droit sur le lien → verdict, raisons, conseil | « Un verdict en mots, pas seulement en couleur. » |
| 2:00 | « Détails techniques » : score, règle, domaine | « Les raisons viennent des contributions SHAP du modèle. » |
| 2:45 | **Mode avion**, nouvelle analyse | « Le modèle est dans l'extension : pas de réseau, pas de fuite. » |
| 3:30 | Homographe `xn--pple-43d.com` : « Phishing probable » | « Normalisation : des lettres cyrilliques qui imitent le latin. » |
| 4:15 | Terminal : `curl` sur l'API, réponse JSON avec techniques ATT&CK | « Même décision côté serveur, contrat de réponse figé. » |
| 4:45 | Conclure : chiffres, limites, ce qui vient | « 67 % de rappel à 1 % de faux positifs : honnête, et la suite est mesurée. » |

Plan B si la démo casse : les captures de `make store-assets` et la vidéo de 90 secondes.

## 6. Questions difficiles à préparer

- « Pourquoi LightGBM et pas un réseau de neurones ? » : 25 features tabulaires,
  inférence de 2 à 4 ms dans un navigateur, modèle exportable en JSON et explicable
  exactement (TreeSHAP) ; comparaison dans [url-models.md](url-models.md).
- « Votre rappel est loin de l'objectif. » : oui, et pourquoi (phishing sur plateformes
  réputées, invisible aux features lexicales), ce qui a été choisi (seuil prudent), et la
  suite ([roadmap.md](roadmap.md)).
- « Comment savez-vous que le modèle ne régresse pas ? » : test figé, test récent, 106 sites
  légitimes courants ; l'ancien modèle a été refusé alors qu'il avait un meilleur rappel
  ([model-updates.md](model-updates.md)).
- « Que se passe-t-il si votre compte GitHub est compromis ? » : un modèle doit porter la
  signature de la clé hors ligne ; l'extension refuse le reste
  ([model-registry.md](model-registry.md)).
