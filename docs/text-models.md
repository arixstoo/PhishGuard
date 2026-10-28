# Modèles de texte pour les SMS (étape 1.9)

`scripts/train_text.py` compare six approches de détection du spam et du smishing par SMS (sept avec les embeddings), puis enregistre la meilleure. Pour chacune, il mesure la qualité sur le corpus UCI (anglais), la généralisation à un jeu français / arabe jamais vu, la taille et la latence. Il prend la suite du baseline de l'étape 0.7 ([`metrics/sms_baseline.json`](metrics/sms_baseline.json)).

```bash
make train-text                          # = python scripts/train_text.py
python scripts/train_text.py --embeddings   # + embeddings multilingues (pip install -e '.[embeddings]')
python scripts/train_text.py --quick        # un seul réglage par approche
python -m pytest tests/test_smishing_features.py tests/test_text_models.py
```

| Sortie | Contenu | Versionné |
| :--- | :--- | :--- |
| `models/text_v1.joblib` | Approche retenue, son seuil, ses métadonnées | Non |
| `docs/metrics/text_v1.json` | Split, essais, résultats sur la validation, le test et le jeu FR/AR, coûts | Oui : aucun texte de message |
| Bloc généré de ce document | Tableaux de la section [Résultats](#résultats) | Oui |

| Fichier | Rôle |
| :--- | :--- |
| `src/phishguard/text/smishing.py` | 13 features smishing pures, en anglais, français et arabe |
| `src/phishguard/text/models.py` | Approches, recherche sur la validation, seuil, coût, `TextModel` |
| `src/phishguard/data/sms.py` | Corpus UCI, split groupé par gabarit, jeu FR/AR |
| `datasets/sms_fr_ar.csv`, [`datasets/README.md`](../datasets/README.md) | 100 messages FR/AR rédigés à la main, et leurs limites |

## Méthode

### Split : groupé par gabarit

Le baseline 0.7 retirait les doublons exacts (414 messages). Mais une campagne de spam envoie le même texte avec un numéro, un montant ou un code différent : ces quasi-doublons restent, et un split aléatoire en place une partie des deux côtés. `template_key` réduit chaque message à son **gabarit** (minuscules, nombres remplacés par `0`, espaces réduits). Le split 70 / 15 / 15 est stratifié par classe et **groupé par gabarit** (`StratifiedGroupKFold`) : aucun gabarit n'est dans deux blocs, et le script le vérifie avant d'entraîner. Le corpus UCI n'est pas daté : le split ne peut pas être temporel.

### Les approches

| Approche | Représentation | Classifieur | Grille (`C`) |
| :--- | :--- | :--- | :--- |
| Mots + régression logistique | TF-IDF mots, 1-2 grammes, accents retirés | régression logistique | 0,3 ; 1 ; 3 ; 10 |
| Mots + SVM linéaire | idem | `LinearSVC` | 0,03 ; 0,1 ; 0,3 ; 1 |
| Caractères + régression logistique | TF-IDF `char_wb`, 2 à 5 caractères | régression logistique | 0,3 ; 1 ; 3 ; 10 |
| Caractères + SVM linéaire | idem | `LinearSVC` | 0,03 ; 0,1 ; 0,3 ; 1 |
| Features smishing | 13 features ([ci-dessous](#features-smishing)), standardisées | régression logistique | 0,3 ; 1 ; 3 ; 10 |
| Caractères + features smishing | les deux, concaténées | régression logistique | 0,3 ; 1 ; 3 ; 10 |
| Embeddings (option) | `paraphrase-multilingual-MiniLM-L12-v2`, vecteurs normalisés | régression logistique | 0,3 ; 1 ; 3 ; 10 |

Toutes les classes sont pondérées (`class_weight="balanced"`) : le corpus ne compte que 12 % de spam. Le SVM ne donne pas de probabilité : son score est la marge, ce qui suffit pour classer et fixer un seuil. Il faudra le calibrer avant de fusionner les scores (étape 2.10).

### Sélection et seuil

1. Pour chaque approche, le réglage de `C` qui maximise la **PR-AUC de validation** (rappel à 1 % FPR pour départager). Ce n'est pas le critère des modèles URL (rappel à 1 % FPR) : la validation SMS ne compte qu'environ 680 messages légitimes, 1 % FPR y représente 7 messages, trop peu pour choisir sur ce seul chiffre.
2. L'approche retenue est celle qui a la meilleure PR-AUC de validation.
3. Le seuil de chaque approche est celui qui donne **1 % de faux positifs sur la validation**. Précision, rappel et F1 du test sont mesurés à ce seuil, réglé ailleurs. Le seuil de 0,5 du baseline n'a pas de sens pour un SVM, et pas davantage pour une régression pondérée.
4. Le test n'est lu qu'une fois, pour le tableau final. Le jeu français / arabe ne sert à aucun réglage.

### Features smishing

Les features smishing servent deux fois : comme modèle explicable, et pour donner les raisons d'un verdict (module 3). Ce sont des fonctions pures, à porter dans l'extension et le bot (module 5).

| Feature | Définition |
| :--- | :--- |
| `has_url`, `n_urls` | liens : schéma, `www.` ou domaine nu (`suivi-colis.fr/x`) |
| `has_shortener` | lien vers un raccourcisseur de `shorteners.json` (liste partagée avec les URLs) |
| `has_short_code` | nombre isolé de 4 à 6 chiffres : numéro court (`text WIN to 87121`) ou code à usage unique |
| `has_phone` | numéro de téléphone (9 à 15 chiffres) |
| `has_amount` | montant avec une devise (`£`, `€`, `$`, `DA`, `دج`…) |
| `urgency_hits` | mots d'urgence ou de menace distincts (`urgent`, `suspendu`, `عاجل`…) |
| `reward_hits` | mots de gain (`won`, `gagné`, `مبروك`…) |
| `account_hits` | mots de compte, d'identifiant ou de livraison (`verify`, `colis`, `حساب`…) |
| `upper_ratio`, `digit_ratio`, `n_exclamations`, `length` | forme du message |

Les mots-clés sont cherchés après normalisation (minuscules, accents latins et diacritiques arabes retirés, formes de l'alif unifiées, chiffres arabes orientaux convertis). Les chiffres des liens ne comptent ni comme numéro ni comme montant.

### Coût

- **Taille** : estimateur sérialisé (joblib, compression 3). Pour les embeddings, l'encodeur n'est pas dans le fichier. Il se télécharge à part et se mesure si `--embedding-model` désigne un dossier local.
- **Latence** : un message à la fois sur 200 messages du test (p50), représentation comprise, comme une requête du bot ou de l'API.

## Résultats

<!-- generated:train-text:start -->
*Pas encore généré : lancez `make train-text`. Ce bloc est réécrit à chaque exécution.*
<!-- generated:train-text:end -->

## Lecture

Constats d'une première exécution de vérification, faite pendant le développement sur la copie du corpus conservée dans `notebooks/legacy/`. Elle compte les mêmes 5 160 messages après dédoublonnage, mais ce n'est pas le fichier publié par l'UCI à l'octet près (empreinte différente). Les chiffres de référence sont ceux du bloc généré ; ces constats sont à confirmer après `make train-text`.

- **Les caractères battent les mots**, comme prévu par le plan : sur l'anglais, la PR-AUC du test passe d'environ 0,98 à 0,99, avec moins de faux positifs au même seuil.
- **La validation anglaise est saturée.** Toutes les approches à n-grammes y dépassent 0,99 de PR-AUC, avec 96 spams : un ou deux messages départagent la première place. Elle ne permet pas de choisir entre caractères seuls et caractères + features.
- **La vraie différence est hors distribution.** Sur le jeu français / arabe, les n-grammes de mots ne détectent presque rien : le vocabulaire anglais ne transfère pas. Les n-grammes de caractères détectent davantage, mais signalent **plus de la moitié des messages légitimes français** : ils ont appris « pas de l'anglais = suspect ». Les features smishing, indépendantes de la langue d'entraînement, limitent ces fausses alertes. La combinaison caractères + features a le meilleur rappel et la meilleure PR-AUC sur le français comme sur l'arabe, mais signale encore un message légitime sur trois en français, deux fois plus que les features seules. Aucune approche n'est utilisable telle quelle en français ou en arabe.
- **Conséquence pour la suite.** La règle automatique retient l'approche qui gagne sur la validation anglaise. Pour un produit destiné à des utilisateurs francophones et arabophones, le choix final (model card, étape 1.12) devra se faire sur un **jeu de validation FR/AR distinct** de ce jeu de test, sous peine de régler le modèle sur son propre test. En attendant, `--approaches char_smishing_logreg` permet de n'entraîner que cette approche.
- **Coût** : toutes les approches TF-IDF tiennent en moins de 400 Kio et répondent en moins de 3 ms par message. Les embeddings multilingues ajoutent un encodeur de plusieurs centaines de Mo : il faudra un gain net sur le FR/AR pour les justifier.

## Limites

- Le corpus UCI date de 2011-2012, est en anglais, et mélange spam commercial et smishing. Le smishing actuel (colis, administration, banque) y est rare.
- Le jeu français / arabe est petit (100 messages) et rédigé à la main (voir [`datasets/README.md`](../datasets/README.md)) : un écart de 10 points de rappel y représente 2 à 3 messages. Il mesure un ordre de grandeur, pas une performance.
- Validation et test sont petits (774 messages chacun) : le FPR du test peut s'écarter du 1 % visé sur la validation.
- `models/text_v1.joblib` est un fichier pickle : ne jamais le charger depuis une source non fiable.
