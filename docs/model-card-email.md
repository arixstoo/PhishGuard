# Model card : score email `email_v1`

Fiche d'identité du score de phishing des emails : des règles transparentes et un modèle appris sur les signaux du parseur. Les chiffres sont générés depuis `docs/metrics/` par `make cards`. Détails : [`email-parser.md`](email-parser.md), [`email-score.md`](email-score.md).

## En bref

| | |
| :--- | :--- |
| Tâche | Risque de phishing d'un email brut (`.eml`) |
| Méthode | 19 règles à points (score de 0 à 100, verdict sûr / suspect / phishing) et un modèle appris sur 21 features, sans les features d'authentification |
| Entrée | L'email brut : en-têtes, corps, noms des pièces jointes. Rien n'est rendu ni téléchargé |
| Sortie | Score des règles avec leurs raisons ; score du modèle et décision au seuil de 1 % FPR de validation |
| Version | `email_v1`, module 1 de PhishGuard, licence MIT |

## Usage prévu

- Bandeau d'avertissement dans Gmail (extension, module 5) et analyse d'un `.eml` par l'API : les **raisons** des règles sont montrées à l'utilisateur (« Votre réponse partirait vers un autre domaine… »).
- Les règles restent la référence lisible. Le modèle appris est un signal de plus pour la fusion (étape 2.10), pas un verdict seul.

## Ce que le score ne fait pas

- Il n'ouvre aucune pièce jointe et n'analyse pas leur contenu : il lit leur nom, leur type et leur taille.
- Il ne suit aucun lien. Le lien le plus suspect peut être scoré par le modèle URL s'il est fourni (règle `url_model`).
- Il ne vérifie pas lui-même SPF, DKIM ni DMARC : il lit le résultat écrit par le serveur de réception de l'utilisateur.
- Il ne lit pas les feuilles de style : un texte caché par une classe CSS n'est pas vu.

## Données

- **Légitime** : SpamAssassin public corpus (parties « ham »), 2002-2003.
- **Phishing** : corpus de Jose Nazario (années récentes) et Phishing Pot (CC BY-NC, non versionné).
- Split 70 / 15 / 15 groupé par domaine enregistré de l'expéditeur, doublons exacts retirés.

## Chiffres

<!-- generated:card-email:start -->
*Pas encore généré : lancez `make email-corpora && make train-email`, puis `make cards`.*
<!-- generated:card-email:end -->

## Biais connus et limites

- **Époque** : les emails légitimes de SpamAssassin sont antérieurs à DMARC et n'ont aucun en-tête d'authentification. Un modèle appris dessus prend « pas d'en-tête » pour un signe de légitimité : le modèle déployé n'utilise donc pas ces features. Les mêmes corpus anciens ont peu de HTML, de liens de suivi et de formulaires : **les scores du test surestiment ce que le modèle vaudra sur une boîte de réception actuelle.**
- **Règles sur du phishing réel** : sur 200 emails de Phishing Pot, les règles seules en jugent 71 % « sûrs ». Les attaquants envoient depuis leurs propres domaines, avec SPF et DKIM valides, et montrent l'URL brute. Sans le modèle URL ni la Threat Intelligence, le score email n'arrête que les attaques grossières.
- Les poids des règles sont fixés à la main ; ils seront revus avec les retours utilisateurs (étape 4.10) et lors de la fusion (étape 2.10).
- `models/email_v1.joblib` est un fichier pickle : ne jamais le charger depuis une source non fiable.

## Reproduire

```bash
make email-corpora train-email cards
```
