# Model card : score email `email_v1`

Fiche d'identité du score de phishing des emails : des règles transparentes et un modèle appris sur les signaux du parseur. Les chiffres sont générés depuis `docs/metrics/` par `make cards`. Détails : [`email-parser.md`](email-parser.md), [`email-score.md`](email-score.md).

## En bref

| | |
| :--- | :--- |
| Tâche | Risque de phishing d'un email brut (`.eml`) |
| Méthode | 19 règles à points (score de 0 à 100, verdict sûr / suspect / phishing) et, à titre expérimental, un modèle LightGBM sur 22 features : 20 signaux du parseur sans l'authentification ni `has_html`, et 2 du modèle URL |
| Entrée | L'email brut : en-têtes, corps, noms des pièces jointes. Rien n'est rendu ni téléchargé |
| Sortie | Score des règles avec leurs raisons ; score du modèle et décision au seuil de 1 % FPR de validation |
| Version | `email_v1`, module 1 de PhishGuard, licence MIT |

## Usage prévu

- Bandeau d'avertissement dans Gmail (extension, module 5) et analyse d'un `.eml` par l'API : les **raisons** des règles sont montrées à l'utilisateur (« Votre réponse partirait vers un autre domaine… »).
- **Le verdict montré à l'utilisateur vient des règles**, dont chaque point s'explique et dont aucun poids n'a été appris sur ces corpus.
- **Le modèle appris est expérimental** : il bat les règles sur le test, mais ce test oppose des emails légitimes de 2002 à du phishing de 2020 à 2026, et le modèle signale une newsletter légitime moderne (voir [Biais connus](#biais-connus-et-limites)). Il ne doit pas produire de verdict seul, et n'entrera dans la fusion (étape 2.10) qu'avec un poids faible, jusqu'à disposer d'emails légitimes récents.

## Ce que le score ne fait pas

- Il n'ouvre aucune pièce jointe et n'analyse pas leur contenu : il lit leur nom, leur type et leur taille.
- Il ne suit aucun lien. Le lien le plus suspect peut être scoré par le modèle URL s'il est fourni (règle `url_model`).
- Il ne vérifie pas lui-même SPF, DKIM ni DMARC : il lit le résultat écrit par le serveur de réception de l'utilisateur.
- Il ne lit pas les feuilles de style : un texte caché par une classe CSS n'est pas vu.

## Données

- **Légitime** : SpamAssassin public corpus (parties « ham »), 2002-2003 : 4 150 emails.
- **Phishing** : corpus de Jose Nazario, 2020 à 2024 (1 327 emails), et 200 emails Phishing Pot récents (CC BY-NC, non versionnés).
- Doublons exacts retirés, **au plus 50 emails par domaine d'expéditeur** (une passerelle RSS de SpamAssassin en envoyait 623), soit 4 805 emails. Split 70 / 15 / 15 stratifié et groupé par domaine enregistré de l'expéditeur.

## Chiffres

<!-- generated:card-email:start -->
*Généré par `scripts/model_cards.py` depuis [`metrics/email_v1.json`](metrics/email_v1.json).*

**Modèle déployé** : `lightgbm`, jeu `robust_with_url_model`, seuil 0,9441 (1 % FPR sur la validation). Test : 720 emails dont 225 de phishing.

| Approche | PR-AUC | Rappel | FPR |
| :--- | ---: | ---: | ---: |
| Règles, score ≥ 30 | 0,748 | 0,467 | 0,81 % |
| Modèle déployé | 0,989 | 0,742 | 0,20 % |
<!-- generated:card-email:end -->

## Biais connus et limites

- **Époque** : les emails légitimes de SpamAssassin sont antérieurs à DMARC (aucun en-tête d'authentification) et presque tous en texte brut (5 % de HTML, contre 98 % du phishing). `has_html` sépare à elle seule les deux corpus (AUC 0,97) : le modèle déployé n'utilise donc ni l'authentification ni `has_html`. Il garde pourtant d'autres marqueurs d'époque (longueur du texte, nombre de liens, `Return-Path`) et donne 0,993 à la newsletter légitime des emails de test. **Les scores du test mesurent la séparation de deux époques, pas ce que le modèle vaudra sur une boîte de réception actuelle.**
- **Règles sur du phishing récent** : sur les 200 emails de Phishing Pot, les règles en jugent 80 % « sûrs » sans le modèle URL, 64 % avec. Les attaquants envoient depuis leurs propres domaines, avec SPF et DKIM souvent valides, et montrent un bouton ou l'URL brute. Sans le modèle URL ni la Threat Intelligence, le score email n'arrête que les attaques grossières.
- **Deux réglages faits après une première mesure** : le seuil du modèle URL dans la règle `url_model` (0,1 % de faux positifs par lien au lieu de 1 %) et l'exception des listes de diffusion pour `reply_to_differs`. Avant, les règles signalaient 13,7 % des emails légitimes ; chaque réglage corrige un défaut de principe ([`email-score.md`](email-score.md#les-règles)), mais la mesure des règles n'est plus tout à fait à l'aveugle.
- `return_path_differs` est plus fréquent chez les légitimes (81 %, listes de diffusion) que dans le phishing (19 %) : à 5 points il ne décide jamais seul, mais il est à revoir.
- Les poids des règles sont fixés à la main ; ils seront revus avec les retours utilisateurs (étape 4.10) et lors de la fusion (étape 2.10).
- `models/email_v1.joblib` est un fichier pickle : ne jamais le charger depuis une source non fiable.

## Reproduire

```bash
make email-corpora email-samples train-email cards   # SpamAssassin, Nazario, 200 emails Phishing Pot
```
