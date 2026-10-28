# Score email : règles puis modèle (étape 1.11)

Le parseur de l'étape 1.10 ([`email-parser.md`](email-parser.md)) extrait les signaux d'un email. Ce document les transforme en score de deux façons : des **règles transparentes**, dont chaque point a une raison lisible, et des **modèles appris** sur des corpus publics. Les deux sont comparés sur le même test.

```bash
make email-corpora          # = python scripts/fetch_email_corpora.py (SpamAssassin + Nazario)
make train-email            # = python scripts/train_email.py
python -m pytest tests/test_email_score.py
```

```python
from phishguard.email import parse_eml
from phishguard.email.score import score_email

result = score_email(parse_eml(raw))  # url_model=UrlModel.load(...) en option
result.score, result.verdict, result.reasons  # 85, "phishing", ["Un lien affiche une adresse…", …]
```

| Sortie | Contenu | Versionné |
| :--- | :--- | :--- |
| `models/email_v1.joblib` | Modèle déployé, ses features, son seuil | Non |
| `docs/metrics/email_v1.json` | Effectifs, déclenchement des règles, essais, résultats par source | Oui : aucun contenu d'email |
| Bloc généré de ce document | Tableaux de la section [Résultats](#résultats) | Oui |

| Fichier | Rôle |
| :--- | :--- |
| `src/phishguard/email/score.py` | Features, règles et verdict |
| `src/phishguard/email/model.py` | Split groupé par expéditeur, modèles, recherche, `EmailModel` |
| `src/phishguard/email/corpus.py` | Lecture des dossiers, mbox et archives tar, sans extraction |
| `src/phishguard/evaluation/splits.py` | Split stratifié et groupé, commun aux SMS et aux emails |
| `scripts/fetch_email_corpora.py`, `scripts/train_email.py` | Téléchargement des corpus, comparaison |

## Les règles

Chaque règle déclenchée ajoute ses points, et le score est plafonné à 100. **Verdict : sûr sous 30, suspect de 30 à 70, phishing au-delà de 70**, les seuils prévus pour la fusion (étape 2.10).

| Règle | Points | Ce qu'elle dit à l'utilisateur |
| :--- | ---: | :--- |
| `dangerous_attachment` | 40 | Une pièce jointe peut exécuter du code ou ouvrir une fausse page de connexion. |
| `disguised_attachment` | 40 | Le nom d'une pièce jointe cache sa vraie extension (facture.pdf.exe). |
| `mismatched_link` | 35 | Un lien affiche une adresse mais mène vers un autre site. |
| `url_model` | 35 | Un lien ressemble aux liens de phishing appris par le modèle URL. |
| `dmarc_fail` | 30 | Le domaine de l'expéditeur n'a pas autorisé cet envoi (DMARC en échec). |
| `non_web_link` | 30 | Un lien exécute du code (javascript:, data:) au lieu d'ouvrir une page. |
| `display_name_spoof` | 25 | Le nom affiché imite une autre adresse que l'adresse réelle de l'expéditeur. |
| `reply_to_differs` | 20 | Votre réponse partirait vers un autre domaine que celui de l'expéditeur. |
| `form` | 20 | L'email contient un formulaire : un service légitime vous renvoie vers son site. |
| `spf_fail` | 15 | Le serveur d'envoi n'est pas autorisé par le domaine (SPF en échec). |
| `ip_link` | 15 | Un lien pointe vers une adresse IP plutôt qu'un nom de site. |
| `dkim_fail` | 10 | La signature DKIM de l'email est invalide. |
| `shortener_link` | 10 | Un lien passe par un raccourcisseur qui masque sa destination. |
| `archive_attachment` | 10 | Une archive est jointe : son contenu n'est pas vérifiable sans l'ouvrir. |
| `hidden_text` | 10 | L'email contient du texte caché (50 caractères ou plus). |
| `zero_width_chars` | 10 | Des caractères invisibles coupent les mots (3 ou plus). |
| `urgent_account_request` | 10 | Le message presse d'agir sur un compte, une carte ou un colis. |
| `spf_softfail` | 5 | Le serveur d'envoi n'est probablement pas autorisé. |
| `return_path_differs` | 5 | L'adresse de retour est sur un autre domaine (fréquent pour les envois en masse). |

**Comment les poids ont été fixés** : à la main, **avant** toute mesure, d'après la gravité du signal et sa rareté dans un email légitime. Un seul signal fort (40, 35) suffit pour « suspect ». Deux signaux forts, ou un fort et deux moyens, donnent « phishing ». Les signaux faibles (texte caché, raccourcisseur, `Return-Path`) ne déclenchent rien seuls, parce qu'ils sont courants dans les newsletters. Ces poids ne sont **pas réglés sur le test**. La ligne « règles, seuil réglé » des résultats montre ce que donnerait un seuil choisi sur la validation.

Détails de mise en œuvre :
- un lien `javascript:` qui affiche une adresse compte dans `non_web_link`, pas aussi dans `mismatched_link` (pas de double compte) ;
- les caractères invisibles sont retirés avant de chercher les mots d'urgence (`bloqu<U+200B>é` reste « bloqué »). Cette normalisation est partagée avec les SMS ;
- `reply_to_differs` ne compte pas pour une **liste de diffusion déclarée** (en-tête `List-Id` ou `List-Post`) : une liste renvoie les réponses à la liste, c'est son rôle. Sur SpamAssassin, 615 des 766 emails légitimes au `Reply-To` différent sont des listes, contre 4 phishing sur 133. Un attaquant peut ajouter ces en-têtes : il ne perd alors que les 20 points de cette règle.

**Ces deux derniers réglages (listes de diffusion, seuil du modèle URL) ont été faits après une première mesure**, qui donnait aux règles 13,7 % de faux positifs (score ≥ 30) pour 66 % de rappel : `url_model` se déclenchait sur 17 % des emails légitimes, `reply_to_differs` sur 18,5 %. Chacun corrige un défaut de principe, pas un chiffre, mais la mesure des règles n'est plus tout à fait « à l'aveugle ».

## Le modèle

### Données

- **Légitime** : SpamAssassin public corpus, parties « ham » (easy_ham, easy_ham_2, hard_ham), 2002-2003.
- **Phishing** : corpus de Jose Nazario (mbox annuels) et, si présent, Phishing Pot ([`data-sources.md`](data-sources.md)).

Les corpus sont lus sans extraction (les archives tar en mémoire), dédoublonnés par SHA-256, puis chaque email passe par `parse_eml`.

### Le biais d'époque

DMARC date de 2012, la généralisation de DKIM aussi : **les emails légitimes de SpamAssassin n'ont aucun en-tête d'authentification**, alors que le phishing récent en a. Un modèle entraîné sur ces corpus apprend « pas d'en-tête = légitime ». C'est l'inverse de la réalité, et l'équivalent du `is_https` des URLs (étape 1.5). Le même biais touche le reste du contenu : le HTML, les raccourcisseurs et les formulaires étaient rares en 2002.

Mesuré sur le jeu réel, le biais n'est pas seulement dans l'authentification. **`has_html` sépare à elle seule les deux corpus** (AUC 0,97) : 5 % des emails légitimes de SpamAssassin sont en HTML, contre 98 % du phishing. `auth_missing` fait presque aussi bien, dans l'autre sens (AUC 0,05 : tous les légitimes en manquent, 10 % du phishing seulement). Un modèle « sans authentification » qui garde `has_html` est en pratique un détecteur de HTML : la première version déployée donnait 0,9998 à la newsletter légitime des emails de test, et 0,29 à la même sans son HTML.

Conséquences :
1. Chaque modèle est entraîné sur trois jeux de features : toutes, **sans le groupe `auth`**, et **sans `auth` ni `has_html`** (`robust`, `ERA_BIASED_FEATURES` dans `model.py`).
2. **Le modèle déployé utilise le jeu `robust`** (`--deploy-feature-set` pour changer). Les règles, elles, gardent DMARC, SPF et DKIM, qui sont de vrais signaux sur des emails d'aujourd'hui. La fusion de l'étape 2.10 combinera les deux.
3. Les scores du test **ne disent pas ce que vaudrait le modèle sur la boîte d'un utilisateur** : ils mesurent la séparation de deux corpus d'époques différentes. Même le jeu `robust` garde des features d'époque (longueur du texte, nombre de liens, `Return-Path`, voir [Lecture](#lecture)).

### Méthode

- **Au plus 50 emails par domaine d'expéditeur** (`--max-per-sender`), choisis par empreinte SHA-256, donc sans regarder le contenu. Sans cette limite, une seule passerelle RSS de SpamAssassin (`rssfeeds@spamassassin.taint.org`, 623 résumés presque identiques) tombait en entier dans le test et en faisait les deux tiers des emails légitimes : le test mesurait surtout ce flux RSS (36 % de faux positifs au seuil réglé pour 1 % sur la validation). 872 emails sont retirés ainsi.
- **Split** 70 / 15 / 15, stratifié et **groupé par domaine enregistré de l'expéditeur** : une campagne envoyée d'un même domaine ne peut pas être apprise puis « reconnue » au test. Un email sans expéditeur lisible forme son propre groupe.
- **Modèles** : régression logistique standardisée (`C` ∈ {0,1 ; 1 ; 10}) et LightGBM (100 ou 300 arbres, 7 ou 31 feuilles), classes pondérées.
- **Sélection** sur la PR-AUC de validation ; seuil d'un modèle à 1 % de faux positifs sur la validation ; test lu une fois.
- **Modèle URL** (option) : si `models/url_v1.joblib` existe, le lien le plus suspect de chaque email est scoré par le modèle de l'étape 1.6, sur sa vraie cible quand une passerelle de sécurité l'a réécrit. Deux features (`max_link_url_score`, `link_flagged_by_url_model`) et la règle `url_model` s'ajoutent, et le modèle déployé passe au jeu `robust_with_url_model`. La règle utilise le seuil du modèle URL à **0,1 %** de faux positifs par lien, pas 1 % : elle juge le pire lien d'un email qui en a souvent des dizaines, et le taux de faux positifs par email croît avec le nombre de liens.

## Résultats

<!-- generated:train-email:start -->
*Généré par `scripts/train_email.py` le 2026-10-27 (test : 720 emails dont 225 de phishing). Seuil des modèles et ligne « règles, seuil réglé » : 1 % de faux positifs sur la validation. Chiffres complets : [`metrics/email_v1.json`](metrics/email_v1.json).*

### Règles contre modèles (test)

| Approche | PR-AUC | R@1%FPR | Rappel | FPR | Précision |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Règles, score ≥ 30 (suspect ou phishing) | 0,748 | 0,467 | 0,467 | 0,81 % | 0,963 |
| Règles, score > 70 (phishing) | 0,748 | 0,467 | 0,053 | 0,00 % | 1,000 |
| Règles, seuil réglé | 0,748 | 0,467 | 0,431 | 0,81 % | 0,960 |
| Régression logistique, toutes | 0,999 | 0,996 | 0,987 | 0,61 % | 0,987 |
| Régression logistique, sans authentification | 0,996 | 0,991 | 0,898 | 0,61 % | 0,985 |
| Régression logistique, sans authentification ni HTML | 0,949 | 0,742 | 0,662 | 0,20 % | 0,993 |
| Régression logistique, toutes + modèle URL | 1,000 | 0,996 | 0,996 | 0,40 % | 0,991 |
| Régression logistique, sans authentification + modèle URL | 0,998 | 0,982 | 0,920 | 0,61 % | 0,986 |
| Régression logistique, sans authentification ni HTML + modèle URL | 0,975 | 0,840 | 0,742 | 0,40 % | 0,988 |
| LightGBM, toutes | 0,997 | 0,991 | 0,991 | 0,81 % | 0,982 |
| LightGBM, sans authentification | 0,997 | 0,987 | 0,973 | 0,61 % | 0,987 |
| LightGBM, sans authentification ni HTML | 0,983 | 0,836 | 0,640 | 0,00 % | 1,000 |
| LightGBM, toutes + modèle URL | 0,997 | 0,991 | 0,991 | 0,40 % | 0,991 |
| LightGBM, sans authentification + modèle URL | 0,999 | 0,987 | 0,969 | 0,61 % | 0,986 |
| LightGBM, sans authentification ni HTML + modèle URL **(déployé)** | 0,989 | 0,889 | 0,742 | 0,20 % | 0,994 |

### Déclenchement des règles

Part des emails de chaque classe (tout le jeu) sur lesquels la règle s'applique.

| Règle | Points | Légitime | Phishing |
| :--- | ---: | ---: | ---: |
| `dmarc_fail` | 30 | 0,0 % | 3,1 % |
| `spf_fail` | 15 | 0,0 % | 6,9 % |
| `spf_softfail` | 5 | 0,0 % | 8,7 % |
| `dkim_fail` | 10 | 0,0 % | 2,5 % |
| `reply_to_differs` | 20 | 4,3 % | 8,6 % |
| `display_name_spoof` | 25 | 0,9 % | 22,2 % |
| `return_path_differs` | 5 | 81,2 % | 18,7 % |
| `mismatched_link` | 35 | 0,5 % | 5,0 % |
| `non_web_link` | 30 | 0,1 % | 0,5 % |
| `form` | 20 | 2,0 % | 0,3 % |
| `ip_link` | 15 | 0,2 % | 0,3 % |
| `url_model` | 35 | 0,4 % | 27,4 % |
| `shortener_link` | 10 | 0,1 % | 8,3 % |
| `dangerous_attachment` | 40 | 0,1 % | 5,4 % |
| `disguised_attachment` | 40 | 0,0 % | 0,5 % |
| `archive_attachment` | 10 | 0,0 % | 0,3 % |
| `hidden_text` | 10 | 0,0 % | 11,4 % |
| `zero_width_chars` | 10 | 0,1 % | 2,8 % |
| `urgent_account_request` | 10 | 1,6 % | 22,5 % |

### Par source (test, modèle déployé)

| Source | Classe | Emails | Rappel ou FPR |
| :--- | :--- | ---: | ---: |
| `nazario` | phishing | 210 | 75,7 % |
| `phishing_pot` | phishing | 15 | 53,3 % |
| `spamassassin` | légitime | 495 | 0,2 % |
<!-- generated:train-email:end -->

## Lecture

Constats de l'exécution du bloc généré : 4 150 emails légitimes SpamAssassin, 1 327 de phishing Nazario (2020 à 2024) et 200 de Phishing Pot, ramenés à 4 805 par la limite de 50 emails par expéditeur.

### Règles

- **Sur le test, les règles signalent 47 % du phishing pour 0,8 % de faux positifs** (score ≥ 30), avec une précision de 96 %. Le verdict « phishing » (score > 70) est sûr mais rare : 5 % du phishing, aucun légitime.
- **Ce qui détecte** : le modèle URL appliqué aux liens (27 % du phishing, 0,4 % des légitimes), le nom affiché trompeur (22 %), l'urgence sur un compte (22 %), le texte caché (11 %). Les signaux « classiques » sont rares dans le phishing réel : lien au texte trompeur 5 %, DMARC en échec 3 %, pièce jointe dangereuse 5 %.
- **Sur les 200 emails Phishing Pot**, le phishing le plus récent : sans modèle URL, 80 % sont jugés « sûrs » et 20 % « suspects ». Avec le modèle URL, 64 % « sûrs », 34 % « suspects », 2 % « phishing ». Les attaquants envoient depuis leurs propres domaines, avec SPF et DKIM souvent valides, et montrent un bouton ou l'URL brute plutôt qu'une fausse adresse. **Le signal décisif d'un email de phishing actuel est le lien lui-même**, d'où la règle `url_model` et la Threat Intelligence du module 2 (réputation, âge du domaine).
- `return_path_differs` est **plus fréquent chez les légitimes** (81 %, des listes de diffusion) que dans le phishing (19 %) : à 5 points, il ne déclenche jamais rien seul, mais il ne devrait pas compter dans le sens du phishing.

### Modèles

- **Les modèles séparent presque parfaitement les deux corpus** (PR-AUC de 0,997 à 1,000 avec toutes les features), et c'est justement le problème : ils apprennent l'époque. Avec toutes les features ou sans `auth`, l'écart est minime (0,999 contre 0,996) parce que `has_html` suffit à tout séparer.
- **Le jeu `robust` (sans `auth` ni `has_html`) perd la moitié de l'avance** : PR-AUC 0,983 (LightGBM), 0,989 avec le modèle URL. Le modèle déployé (LightGBM, `robust_with_url_model`) signale 74 % du phishing du test pour 0,2 % de faux positifs : mieux que les règles sur ce test.
- **Mais il n'est pas utilisable tel quel.** Sur les emails rédigés pour les tests, il signale la newsletter légitime moderne (0,993). Les features qui restent sont encore des marqueurs d'époque : longueur du texte, nombre de liens et de domaines, `Return-Path`. Seul un corpus d'emails légitimes **récents** permettra de savoir ce que vaut un modèle appris.
- **Recommandation** : le verdict montré à l'utilisateur vient des **règles**, dont chaque point s'explique et dont aucun poids n'a été appris sur ces corpus. Le modèle appris reste expérimental jusqu'à l'arrivée d'emails légitimes récents (boîtes de volontaires, avec consentement), et ne sera fusionné qu'avec un poids faible (étape 2.10).

## Limites

- **Représentativité** : SpamAssassin date de 2002-2003, Nazario de 2020 à 2024, Phishing Pot est récent : près de vingt ans séparent les deux classes, et tout ce qui a changé entre-temps (HTML, longueur, liens, authentification) sépare les corpus sans rien dire du phishing. Aucun corpus public ne fournit des emails légitimes **d'aujourd'hui**, avec leurs newsletters HTML, leurs liens de suivi et leurs en-têtes d'authentification. Les faux positifs réels seront plus nombreux que sur ce test.
- Le contenu des pièces jointes n'est pas analysé, et les feuilles de style non plus (voir [`email-parser.md`](email-parser.md#limites)).
- Les poids des règles sont un jugement : ils seront revus avec des retours utilisateurs (faux positifs signalés) et recalibrés lors de la fusion (étape 2.10).
- `models/email_v1.joblib` est un fichier pickle : ne jamais le charger depuis une source non fiable.
