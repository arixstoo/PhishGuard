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

Les mots-clés sont cherchés après normalisation (minuscules, accents latins et diacritiques arabes retirés, formes de l'alif unifiées, chiffres arabes orientaux convertis). Les chiffres des liens ne comptent ni comme numéro ni comme montant. Deux pièges vus sur le corpus réel : les SMS collent des phrases sans espace (`pain.it will`, `reply.Be`), donc un domaine nu sans chemin ne compte que pour une liste de TLD sans `it`, `be` ni `me` (une adresse email n'est pas un lien) ; et `da` (dinar) est aussi de l'argot anglais (`2 da report`), donc `da`, `dh` et `mad` demandent un nombre d'au moins deux chiffres.

### Coût

- **Taille** : estimateur sérialisé (joblib, compression 3). Pour les embeddings, l'encodeur n'est pas dans le fichier. Il se télécharge à part et se mesure si `--embedding-model` désigne un dossier local.
- **Latence** : un message à la fois sur 200 messages du test (p50), représentation comprise, comme une requête du bot ou de l'API.

## Résultats

<!-- generated:train-text:start -->
*Généré par `scripts/train_text.py` le 2026-10-27 (corpus `7d039a24a608`, 5 160 messages après dédoublonnage ; test : 774 messages dont 96 spams). Seuil de chaque approche : 1 % de faux positifs sur la validation. Chiffres complets : [`metrics/text_v1.json`](metrics/text_v1.json).*

### Test (UCI, anglais)

| Approche | Réglage | Précision | Rappel | F1 | FPR | PR-AUC | R@1%FPR | Taille | Latence p50 |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Mots + régression logistique | `C=10.0` | 0,898 | 0,917 | 0,907 | 1,47 % | 0,964 | 0,896 | 136 Kio | 0,42 ms |
| Mots + SVM linéaire | `C=0.1` | 0,889 | 0,917 | 0,903 | 1,62 % | 0,957 | 0,885 | 135 Kio | 0,43 ms |
| Caractères + régression logistique | `C=1.0` | 0,902 | 0,958 | 0,929 | 1,47 % | 0,975 | 0,938 | 387 Kio | 0,53 ms |
| Caractères + SVM linéaire **(retenu)** | `C=0.1` | 0,901 | 0,948 | 0,924 | 1,47 % | 0,975 | 0,938 | 386 Kio | 0,53 ms |
| Features smishing + régression logistique | `C=1.0` | 0,827 | 0,896 | 0,860 | 2,65 % | 0,905 | 0,833 | 1 Kio | 0,74 ms |
| Caractères + features smishing + régression logistique | `C=10.0` | 0,846 | 0,969 | 0,903 | 2,51 % | 0,943 | 0,927 | 388 Kio | 1,68 ms |

### Hors distribution : jeu français / arabe

100 messages rédigés à la main (voir [`../datasets/README.md`](../datasets/README.md)), jamais vus à l'entraînement, même seuil qu'au-dessus. Rappel = part du smishing détectée, FPR = part du légitime signalée.

| Approche | Rappel français | FPR français | PR-AUC français | Rappel arabe | FPR arabe | PR-AUC arabe |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Mots + régression logistique | 0,167 | 7 % | 0,595 | 0,150 | 10 % | 0,559 |
| Mots + SVM linéaire | 0,167 | 3 % | 0,596 | 0,100 | 10 % | 0,549 |
| Caractères + régression logistique | 0,700 | 47 % | 0,779 | 0,650 | 35 % | 0,732 |
| Caractères + SVM linéaire | 0,733 | 43 % | 0,769 | 0,650 | 40 % | 0,731 |
| Features smishing + régression logistique | 0,933 | 33 % | 0,901 | 0,900 | 30 % | 0,876 |
| Caractères + features smishing + régression logistique | 0,933 | 37 % | 0,940 | 0,950 | 30 % | 0,927 |

**Approche retenue** (meilleure PR-AUC de validation) : Caractères + SVM linéaire (`C=0.1`), seuil -0,2538.
<!-- generated:train-text:end -->

## Lecture

Constats de l'exécution du bloc généré, sur le fichier officiel de l'UCI (empreinte vérifiée). Le jeu français / arabe est petit : un point de rappel y vaut un tiers à la moitié d'un message, les écarts de quelques points ne disent rien.

- **Les caractères battent les mots**, comme prévu par le plan : sur le test anglais, la PR-AUC passe de 0,957-0,964 à 0,975, et le rappel à 1 % FPR de 0,885-0,896 à 0,938, pour le même taux de faux positifs au seuil (1,5 %).
- **La validation anglaise départage mal.** Toutes les approches à n-grammes y sont entre 0,984 et 0,993 de PR-AUC, avec 96 spams. Le SVM sur caractères est retenu devant la régression logistique sur caractères pour 0,0007 de PR-AUC : c'est du bruit, les deux sont identiques sur le test.
- **La vraie différence est hors distribution.** Sur le jeu français / arabe, les n-grammes de mots ne détectent que 10 à 17 % du smishing : le vocabulaire anglais ne transfère pas. Les n-grammes de caractères en détectent 65 à 73 %, mais signalent aussi **35 à 47 % des messages légitimes** : ils ont appris « pas de l'anglais = suspect ». Les features smishing seules, indépendantes de la langue d'entraînement, détectent 90 à 93 % du smishing avec 30 à 33 % de fausses alertes. La combinaison caractères + features a la meilleure PR-AUC (0,940 en français, 0,927 en arabe) mais autant de fausses alertes : un message légitime sur trois. Aucune approche n'est utilisable telle quelle en français ou en arabe.
- **Les features coûtent sur l'anglais.** Ajoutées aux caractères, elles font baisser la PR-AUC du test de 0,975 à 0,943 et montent le FPR du test à 2,5 %. Explication probable : sur le corpus UCI, des messages légitimes ont aussi des montants (`£6 to get in`), des chiffres et des points d'exclamation, et ces 13 features standardisées pèsent plus lourd que chacun des milliers de n-grammes, qui ont de petites valeurs. Le meilleur modèle pour l'anglais n'est pas le meilleur hors de l'anglais.
- **Le FPR du test dépasse le 1 % visé** (1,5 % à 2,7 % selon l'approche) : sur la validation, 1 % FPR, c'est 7 messages légitimes sur 678, et le seuil est donc imprécis.
- **Conséquence pour la suite.** La règle automatique retient l'approche qui gagne sur la validation anglaise. Pour un produit destiné à des utilisateurs francophones et arabophones, le choix final (model card, étape 1.12) devra se faire sur un **jeu de validation FR/AR distinct** de ce jeu de test, sous peine de régler le modèle sur son propre test. En attendant, `--approaches char_smishing_logreg` permet de n'entraîner que cette approche.
- **Coût** : toutes les approches TF-IDF tiennent en moins de 400 Kio. Un message prend de 0,4 à 0,8 ms, et 1,7 ms pour la combinaison, qui calcule les deux représentations. Les features seules tiennent en 1 Kio mais ne sont pas plus rapides que les n-grammes : ce sont des expressions régulières en Python. Les embeddings multilingues n'ont pas encore été mesurés (`pip install -e '.[embeddings]'`, puis `--embeddings`) ; ils ajoutent un encodeur de plusieurs centaines de Mo, et il leur faudra un gain net sur le FR/AR pour les justifier.

## Limites

- Le corpus UCI date de 2011-2012, est en anglais, et mélange spam commercial et smishing. Le smishing actuel (colis, administration, banque) y est rare.
- Le jeu français / arabe est petit (100 messages) et rédigé à la main (voir [`datasets/README.md`](../datasets/README.md)) : un écart de 10 points de rappel y représente 2 à 3 messages. Il mesure un ordre de grandeur, pas une performance.
- Validation et test sont petits (774 messages chacun) : le FPR du test peut s'écarter du 1 % visé sur la validation.
- `models/text_v1.joblib` est un fichier pickle : ne jamais le charger depuis une source non fiable.
