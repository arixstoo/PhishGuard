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

result = score_email(parse_eml(raw))          # url_model=UrlModel.load(...) en option
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

Deux détails de mise en œuvre :
- un lien `javascript:` qui affiche une adresse compte dans `non_web_link`, pas aussi dans `mismatched_link` (pas de double compte) ;
- les caractères invisibles sont retirés avant de chercher les mots d'urgence (`bloqu<U+200B>é` reste « bloqué »). Cette normalisation est partagée avec les SMS.

## Le modèle

### Données

- **Légitime** : SpamAssassin public corpus, parties « ham » (easy_ham, easy_ham_2, hard_ham), 2002-2003.
- **Phishing** : corpus de Jose Nazario (mbox annuels) et, si présent, Phishing Pot ([`data-sources.md`](data-sources.md)).

Les corpus sont lus sans extraction (les archives tar en mémoire), dédoublonnés par SHA-256, puis chaque email passe par `parse_eml`.

### Le biais d'époque

DMARC date de 2012, la généralisation de DKIM aussi : **les emails légitimes de SpamAssassin n'ont aucun en-tête d'authentification**, alors que le phishing récent en a. Un modèle entraîné sur ces corpus apprend « pas d'en-tête = légitime ». C'est l'inverse de la réalité, et l'équivalent du `is_https` des URLs (étape 1.5). Le même biais touche le reste du contenu : le HTML, les raccourcisseurs et les formulaires étaient rares en 2002.

Conséquences :
1. Chaque modèle est entraîné avec toutes les features **et sans le groupe `auth`**.
2. **Le modèle déployé n'utilise pas le groupe `auth`** (`--deploy-feature-set` pour changer). Les règles, elles, gardent DMARC, SPF et DKIM, qui sont de vrais signaux sur des emails d'aujourd'hui. La fusion de l'étape 2.10 combinera les deux.
3. Les scores du test **ne disent pas ce que vaudrait le modèle sur la boîte d'un utilisateur** : ils mesurent la séparation de deux corpus d'époques différentes.

### Méthode

- **Split** 70 / 15 / 15, stratifié et **groupé par domaine enregistré de l'expéditeur** : une campagne envoyée d'un même domaine ne peut pas être apprise puis « reconnue » au test. Un email sans expéditeur lisible forme son propre groupe.
- **Modèles** : régression logistique standardisée (`C` ∈ {0,1 ; 1 ; 10}) et LightGBM (100 ou 300 arbres, 7 ou 31 feuilles), classes pondérées.
- **Sélection** sur la PR-AUC de validation ; seuil d'un modèle à 1 % de faux positifs sur la validation ; test lu une fois.
- **Modèle URL** (option) : si `models/url_v1.joblib` existe, le lien le plus suspect de chaque email est scoré par le modèle de l'étape 1.6. Deux features (`max_link_url_score`, `link_flagged_by_url_model`) et la règle `url_model` s'ajoutent, et le modèle déployé passe au jeu « sans authentification + modèle URL ».

## Résultats

<!-- generated:train-email:start -->
*Pas encore généré : lancez `make email-corpora` puis `make train-email`. Ce bloc est réécrit à chaque exécution.*
<!-- generated:train-email:end -->

## Lecture

### Ce qu'a montré la vérification sur du phishing réel

Pendant le développement, les règles seules (sans modèle URL) ont été appliquées aux **200 emails de phishing réels** de Phishing Pot, la seule source accessible depuis l'environnement de développement :

- **71 % sont jugés « sûrs »**, 28,5 % « suspects », un seul « phishing ». Les règles détectent mal le phishing actuel.
- Pourquoi : les attaquants envoient depuis **leurs propres domaines**, avec SPF et DKIM valides (DMARC n'échoue que sur 10 % des emails). Leurs liens montrent l'URL brute ou un bouton (« Vérifier mon compte ») plutôt qu'une fausse adresse : le piège « le lien affiché n'est pas le lien réel » ne se déclenche que sur 2 % d'entre eux.
- Les signaux les plus fréquents sont **faibles** : texte caché (47,5 %), SPF en échec (37,5 %), `Return-Path` différent (26,5 %).

**Conséquence** : le signal décisif d'un email de phishing actuel est **le lien lui-même**. D'où la règle et les features `url_model`, qui appliquent aux liens le modèle de l'étape 1.6, et la Threat Intelligence du module 2 (réputation, âge du domaine). Sans ces signaux, le score email reste un filet de sécurité pour les attaques grossières (pièces jointes, liens déguisés, usurpation de nom).

### À compléter après `make train-email`

- Écart entre « toutes » et « sans authentification » : il mesure le biais d'époque. Un écart important confirme que le groupe `auth` apprend l'année, pas le phishing.
- Taux de faux positifs des règles sur SpamAssassin, à comparer au rappel : ce sont les deux seules mesures des règles qui ne dépendent pas d'un apprentissage.
- Gain du modèle URL sur le rappel.

## Limites

- **Représentativité** : SpamAssassin date de 2002-2003, Nazario couvre des années plus récentes. Aucun corpus public ne fournit des emails légitimes **d'aujourd'hui**, avec leurs newsletters HTML, leurs liens de suivi et leurs en-têtes d'authentification. Les faux positifs réels seront plus nombreux que sur ce test.
- Le contenu des pièces jointes n'est pas analysé, et les feuilles de style non plus (voir [`email-parser.md`](email-parser.md#limites)).
- Les poids des règles sont un jugement : ils seront revus avec des retours utilisateurs (faux positifs signalés) et recalibrés lors de la fusion (étape 2.10).
- `models/email_v1.joblib` est un fichier pickle : ne jamais le charger depuis une source non fiable.
