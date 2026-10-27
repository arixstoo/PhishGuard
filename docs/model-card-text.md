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
*Généré par `scripts/model_cards.py` depuis [`metrics/text_v1.json`](metrics/text_v1.json).*

**Modèle** : approche `char_svm` (`C=0.1`), seuil -0,2538 (1 % FPR sur la validation), SHA-256 `d583ba3f3e3a`, corpus `7d039a24a608`.

| Jeu | Messages | Précision | Rappel | FPR | PR-AUC |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Test UCI (anglais) | 774 | 0,901 | 0,948 | 1,47 % | 0,975 |
| Jeu français rédigé (hors distribution) | 60 | 0,629 | 0,733 | 43 % | 0,769 |
| Jeu arabe rédigé (hors distribution) | 40 | 0,619 | 0,650 | 40 % | 0,731 |

Taille 386 Kio, latence p50 0,53 ms par message.
<!-- generated:card-text:end -->

## Biais connus

- **Langue** : entraîné sur de l'anglais. Le modèle retenu (n-grammes de caractères) signale **43 % des SMS légitimes français et 40 % des arabes** du jeu rédigé : il a appris « pas de l'anglais = suspect ». Les n-grammes de mots, eux, ne détectent que 10 à 17 % du smishing FR/AR. Les features smishing, indépendantes de la langue, transfèrent mieux (90 à 95 % du smishing détecté, seules ou avec les caractères) mais signalent encore 30 à 37 % des messages légitimes ([`text-models.md`](text-models.md#lecture)).
- **Époque** : 2011-2012. Le smishing actuel (colis, administration, banque, « maman, nouveau numéro ») y est rare, le spam par numéros surtaxés y domine.
- **La validation anglaise départage mal** : toutes les approches à n-grammes y sont entre 0,984 et 0,993 de PR-AUC, avec 96 spams. Le SVM sur caractères est retenu pour 0,0007 de PR-AUC devant la régression logistique sur caractères, alors que les approches diffèrent beaucoup hors distribution. Le meilleur modèle pour l'anglais (caractères seuls) n'est pas le meilleur en français et en arabe (caractères + features smishing), et ajouter les features coûte sur l'anglais (PR-AUC du test 0,943 contre 0,975).

## Limites

- Le jeu FR/AR est petit (100 messages) et rédigé, donc biaisé par son auteur : il donne un ordre de grandeur, pas une performance. Il ne couvre ni la darija ni l'arabizi.
- Choisir le modèle déployé pour des utilisateurs francophones et arabophones demande un **jeu de validation FR/AR distinct** de ce jeu de test. C'est la priorité avant tout usage dans ces langues.
- Validation et test comptent 774 messages chacun : le taux de faux positifs du test peut s'écarter du 1 % visé.
- Les embeddings multilingues (approche optionnelle) n'ont pas été mesurés.
- `models/text_v1.joblib` est un fichier pickle : ne jamais le charger depuis une source non fiable.

## Reproduire

```bash
make train-text cards     # télécharge le corpus UCI (SHA-256 vérifié) si besoin
```

Le corpus UCI est figé et vérifié par son empreinte : mêmes versions de bibliothèques, mêmes chiffres.
