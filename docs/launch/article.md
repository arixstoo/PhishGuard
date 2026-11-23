# Ce que j'ai appris en construisant un détecteur de phishing open source

*Brouillon de l'article de lancement (étape 6.11). À publier sur dev.to, Medium ou
LinkedIn le jour J. Chaque chiffre renvoie à sa source dans le dépôt (section
« Chiffres » à la fin) : les revérifier avant publication.*

---

En 2022, j'ai écrit un détecteur de spam SMS qui affichait « 96 % de précision ». Il
était faux, et je ne le savais pas. Quatre ans plus tard, PhishGuard est une extension
Chrome (Firefox à venir), une API et un bot Telegram qui préviennent au moment où l'on va
cliquer sur un lien de phishing, avec une explication en une phrase, en français, en
anglais et en arabe. Voici ce que j'ai appris en route, avec les vrais chiffres, y compris
ceux qui ne m'arrangent pas.

## 1. Mon premier résultat était une fuite de données

Le corpus SMS que j'utilisais contient 414 messages en double. Avec un découpage aléatoire
entre entraînement et test, **139 messages du test sur 1 115 avaient déjà été vus pendant
l'entraînement**. Le modèle était noté sur des questions dont il connaissait les réponses :
précision gonflée, nombre de faux positifs divisé par deux.

Après déduplication, la précision passe de 0,952 à 0,889. Et « 96 % d'accuracy » ne
voulait presque rien dire sur un jeu où 87 % des messages sont légitimes : un modèle qui
répond toujours « légitime » fait 87 %.

Pour les URLs, j'ai donc fait l'inverse du réflexe : un découpage **temporel** (le test est
fait des URLs les plus récentes) et **groupé par domaine** (aucun domaine dans deux blocs).
C'est plus dur, donc plus honnête : le phishing de demain ne ressemble pas à celui d'hier.

## 2. Le modèle avait appris un raccourci, et le test le récompensait

Les explications SHAP du modèle URL m'ont montré quelque chose de gênant : il avait appris
que « pas de chemin dans l'URL » voulait dire « légitime ». Normal : mes URLs légitimes
venaient de listes de sites populaires (des pages d'accueil), mes URLs de phishing de flux
de signalement (des pages profondes). Résultat : les pages internes légitimes recevaient
**20 fois plus de faux positifs** que les pages d'accueil.

J'ai ajouté des pages internes légitimes, et je rapporte désormais le taux de faux
positifs séparément pour les deux. Leçon : un jeu de données porte ses biais jusque dans le
jeu de test, et un test biaisé note mieux le modèle qui exploite le biais.

## 3. Un attaquant n'a besoin que de deux sous-domaines

J'ai écrit un banc d'essai d'évasion : homoglyphes (`раypal` en cyrillique), caractères
invisibles, sous-domaines ajoutés, chemins anodins, dilution par des mots inoffensifs. La
technique la plus efficace contre le premier modèle était la plus bête : **ajouter deux
sous-domaines** (`support.`, `fr.`) faisait perdre 12,5 points de rappel. L'attaquant les
crée gratuitement sur son propre domaine.

Les défenses :

- une **normalisation** à l'entraînement et à l'inférence (NFKC, retrait des caractères
  invisibles, repli des homoglyphes). Un homographe d'hôte comme `аpple.com` est signalé
  dans **99,4 %** des cas au lieu de 75,1 %. Sous une largeur nulle entre chaque lettre, le
  rappel SMS remonte de 78,1 % à 94,8 % ;
- un **entraînement adversarial** sur les deux classes. Perturber seulement le phishing,
  comme je l'avais d'abord fait, apprend au modèle que la perturbation *est* l'indice : 94 %
  des URLs légitimes avec un paramètre de suivi devenaient suspectes.

La robustesse a un prix, et je le publie : le modèle robuste perd **10 points de rappel**
sur les URLs propres, en partie parce qu'il a perdu le raccourci de la section 2.

## 4. Contre un phishing bien écrit, le texte seul ne suffit plus

J'ai fait rédiger par un LLM des messages de phishing soignés et des courriers
d'entreprise légitimes. Le rappel tient (90 %), mais **57 à 63 % des courriers légitimes
d'entreprise sont signalés**. Ce qui reste discriminant ne dépend pas de la rédaction :
l'âge du domaine, la concordance du lien, l'authentification de l'expéditeur. C'est la
première piste de la feuille de route.

## 5. Les chiffres, sans arrondi flatteur

Modèle URL déployé (`url_v2`, LightGBM sur 25 features lexicales, calculées sans réseau),
mesuré une fois sur les 21 004 URLs les plus récentes :

| Mesure | Valeur |
|---|---:|
| PR-AUC | 0,910 |
| Rappel à 1 % de faux positifs | 66,8 % |
| Au seuil de décision : rappel | 63,6 % |
| Au seuil de décision : faux positifs (pages d'accueil / pages internes) | 0,3 % / 4,0 % |
| Précision si 1 % des URLs visitées sont du phishing | environ 48 % |
| Latence de l'API (médiane, 50 requêtes/s) | 12 ms |
| Analyse dans l'extension | 2 à 4 ms |

Mon objectif de départ était **95 % de rappel à 1 % de faux positifs. Il n'est pas
atteint.** Des features lexicales seules ne voient pas un phishing hébergé sur une
plateforme réputée : il faut la réputation de l'URL et le contenu de la page. J'ai préféré
un seuil prudent (moins d'alertes, plus fiables) à un rappel affiché plus haut. Un
détecteur qui crie au loup tous les jours est désinstallé au bout d'une semaine.

## 6. La vie privée se vérifie, elle ne se promet pas

« Par défaut, rien ne quitte votre appareil » est la promesse principale de l'extension.
Elle est vérifiée, pas seulement écrite :

- le modèle tourne **dans le navigateur** : je l'ai porté de Python en TypeScript, et les
  200 vecteurs de référence donnent les mêmes features et les mêmes scores à 10⁻⁶ près ;
- 39 parcours Playwright en CI échouent si **une seule requête** sort du paquet de
  l'extension avec les réglages par défaut ;
- chaque permission a une phrase de justification, et un test échoue si le manifeste en
  ajoute une sans la justifier ;
- la politique de confidentialité est liée au code : chaque valeur chiffrée (durées,
  limites) est vérifiée par un test. En l'écrivant, j'ai trouvé un écart : la rétention des
  signalements n'était qu'une recommandation. Elle est maintenant appliquée par l'API.

Même les mesures d'adoption suivent la règle : pas de télémétrie dans l'extension, seulement
des totaux sans identifiant côté serveur.

## 7. La sécurité de la chaîne, pas seulement du code

- **SSRF** : la meilleure protection est de ne pas faire la requête. Le serveur interroge
  des services de réputation *au sujet* de l'URL, il ne la visite jamais. Pour le jour où il
  le faudrait, j'ai écrit un garde-fou qui résout le DNS lui-même et se connecte à l'adresse
  vérifiée : `0x7f000001`, `2130706433` et `127.1` sont tous `127.0.0.1`, et une seconde
  réponse DNS peut changer la destination.
- **Mises à jour du modèle signées** : l'extension n'accepte un nouveau modèle que si sa
  signature Ed25519 correspond à la clé intégrée. Un octet modifié est rejeté (testé octet
  par octet). La clé privée ne va jamais sur la CI : la CI produit et prouve la provenance,
  l'humain vérifie et signe.
- **Garde-fou de non-régression** : un modèle n'est publié que si son rappel ne baisse pas
  *et* s'il ne signale pas plus de sites légitimes courants. Essai réel : l'ancien modèle,
  soumis comme candidat, avait un **meilleur rappel** (75,5 % contre 66,8 %) mais signalait
  **28 pages de connexion légitimes sur 106, contre 3**. Le rappel seul l'aurait publié.

## 8. Ce que les tests automatisés ne voient pas

Un vrai Chromium avec la maquette de Gmail a trouvé un faux positif qu'aucun test unitaire
n'aurait vu : un expéditeur affiché « impots.gouv.fr » qui écrivait depuis
`dgfip.finances.gouv.fr`, un domaine légitime de la même administration. La règle est
devenue graduée.

*[À compléter après les tests utilisateurs : ce que les testeurs non techniques ont mal
compris, et ce qui a changé dans l'interface.]*

## Essayer, vérifier, contribuer

- Extension : *[lien du Chrome Web Store]*
- Code (licence MIT), rapport de robustesse, modèle de menace, model cards :
  https://github.com/arixstoo/PhishGuard
- Documentation : https://arixstoo.github.io/PhishGuard/

Les signalements de faux positifs sont la contribution la plus utile : ils sont relus à
la main, et ne modifient jamais le modèle automatiquement.

---

## Chiffres (pour la relecture, ne pas publier)

| Affirmation | Source |
|---|---|
| 414 doublons, 139 / 1 115 messages déjà vus, précision 0,952 → 0,889 | `docs/metrics/sms_baseline.json`, README |
| 20 fois plus de faux positifs sur les pages internes | `docs/model-card-url.md` (biais connus) |
| −12,5 points de rappel avec deux sous-domaines | `docs/robustness-report.md`, section 4 |
| homographe 75,1 % → 99,4 % ; largeur nulle 78,1 % → 94,8 % | `docs/robustness-report.md`, « En bref » |
| 94 % des URLs légitimes avec paramètre de suivi suspectes (phishing seul perturbé) | `docs/LEARNING.md`, étape 3.9 |
| −10 points de rappel du modèle robuste | `docs/robustness-report.md`, « En bref » (10,3) |
| LLM : rappel 90 %, 57 à 63 % de FPR | `docs/robustness-report.md`, section 7 |
| PR-AUC, rappel à 1 % de FPR, seuil de décision, 21 004 URLs | `docs/metrics/url_v2_test.json` (`test`) |
| précision à 1 % de prévalence ≈ 48 % | calcul : 0,636 × 0,01 / (0,636 × 0,01 + 0,00684 × 0,99) = 0,484 |
| 12 ms médiane à 50 req/s | `docs/load-test.md` |
| 2 à 4 ms par analyse dans l'extension | `docs/extension-design.md`, CHANGELOG 0.5.0-beta.1 |
| 200 vecteurs, 10⁻⁶ ; 39 parcours Playwright | CHANGELOG 0.5.0-beta.1, `docs/LEARNING.md` 5.10 |
| 75,5 % contre 66,8 %, 28 contre 3 sur 106 sites | `docs/model-updates.md`, CHANGELOG (étape 6.8) |
| faux positif `impots.gouv.fr` corrigé | CHANGELOG 0.5.0-beta.1 (étape 5.6) |
