# Model card : modèle de texte SMS `text_v1`

Fiche d'identité du modèle de détection de spam et de smishing dans les SMS. Les chiffres sont générés depuis `docs/metrics/` par `make cards`. Détails : [`text-models.md`](text-models.md), [`datasets/README.md`](../datasets/README.md).

## En bref

| | |
| :--- | :--- |
| Tâche | Score de risque d'un SMS ou d'un message court : spam ou smishing contre légitime |
| Modèle | Choisi par `make train-text` parmi six approches (TF-IDF mots ou caractères, régression logistique ou SVM, features smishing), sur la PR-AUC de validation |
| Entrée | Le texte du message, sans métadonnées (ni expéditeur, ni date) |
| Sortie | Un score, et une décision au seuil qui donne 1 % de faux positifs sur la validation |
| Version | `text_v1`, module 1 de PhishGuard, licence MIT |
| Fichier | `models/text_v1.joblib`, régénéré par `make train-text` (non publié) |

## Usage prévu

- Score d'un message collé dans le bot Telegram ou la page « coller et analyser » (module 5), **en anglais d'abord**.
- Les features smishing (lien, numéro court, montant, urgence…) servent aussi à **expliquer** le verdict (module 3).
- En français et en arabe, le modèle n'est **pas prêt** (voir [Chiffres](#chiffres) et [Limites](#limites)) : il ne doit pas produire d'alerte seul dans ces langues.

## Ce que le modèle ne fait pas

- Il ne suit pas les liens du message : un lien est un signal, pas une page analysée. Le modèle URL et le module 2 s'en chargent.
- Il ne connaît pas l'expéditeur (numéro, nom affiché), ni l'historique de la conversation.
- Il ne distingue pas le spam commercial du smishing : le corpus d'entraînement les mélange.
- Il n'est pas destiné à filtrer automatiquement les messages d'un utilisateur.

## Données

- **Entraînement, validation, test** : UCI SMS Spam Collection (CC BY 4.0), 5 574 messages en anglais collectés en 2011-2012, 13 % de spam. Téléchargement vérifié par SHA-256, 414 doublons exacts retirés (5 160 messages), puis split 70 / 15 / 15 **groupé par gabarit** : un même texte de campagne avec un autre numéro reste dans un seul bloc.
- **Test hors distribution** : 100 SMS français et arabes **rédigés à la main** sur le modèle des arnaques signalées publiquement, anonymisés (domaines `.example`, numéros fictifs). Ils ne servent à aucun réglage.

## Chiffres

<!-- generated:card-text:start -->
*Pas encore généré : lancez `make train-text`, puis `make cards`.*

En attendant, le **baseline de l'étape 0.7** (TF-IDF mots + régression logistique, seuil 0,5, corpus dédoublonné, [`metrics/sms_baseline.json`](metrics/sms_baseline.json)) : précision 0,889, rappel 0,938, PR-AUC 0,971, FPR 1,7 %.
<!-- generated:card-text:end -->

## Biais connus

- **Langue** : entraîné sur de l'anglais. Pendant le développement, les n-grammes de caractères signalaient plus de la moitié des SMS légitimes français : ils ont appris « pas de l'anglais = suspect ». Les features smishing, indépendantes de la langue, réduisent ce biais sans le supprimer.
- **Époque** : 2011-2012. Le smishing actuel (colis, administration, banque, « maman, nouveau numéro ») y est rare, le spam par numéros surtaxés y domine.
- **Validation saturée** : en anglais, toutes les approches à n-grammes dépassent 0,99 de PR-AUC de validation, avec 96 spams. Le choix entre elles y est presque aléatoire, alors qu'elles diffèrent beaucoup hors distribution.

## Limites

- Le jeu FR/AR est petit (100 messages) et rédigé, donc biaisé par son auteur : il donne un ordre de grandeur, pas une performance. Il ne couvre ni la darija ni l'arabizi.
- Choisir le modèle déployé pour des utilisateurs francophones et arabophones demande un **jeu de validation FR/AR distinct** de ce jeu de test. C'est la priorité avant tout usage dans ces langues.
- Validation et test comptent 774 messages chacun : le taux de faux positifs du test peut s'écarter du 1 % visé.
- `models/text_v1.joblib` est un fichier pickle : ne jamais le charger depuis une source non fiable.

## Reproduire

```bash
make train-text cards     # télécharge le corpus UCI (SHA-256 vérifié) si besoin
```

Le corpus UCI est figé et vérifié par son empreinte : mêmes versions de bibliothèques, mêmes chiffres.
