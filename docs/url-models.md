# Modèles URL (étape 1.6)

`scripts/train_url.py` entraîne trois modèles sur les features de l'étape 1.5 ([`url-features.md`](url-features.md)), les compare sur la validation et enregistre le meilleur. Le bloc de test n'est pas chargé : il sert une seule fois, à l'évaluation finale ([`evaluation.md`](evaluation.md), étape 1.7).

```bash
make train-url                         # = python scripts/train_url.py
python scripts/train_url.py --quick    # grilles réduites, pour vérifier le pipeline en une minute
python -m pytest tests/test_url_training.py tests/test_url_model.py
```

La grille complète (3 modèles × 6 jeux de features × 4 à 8 réglages, soit 96 entraînements) prend environ 3 minutes sur les 119 000 URLs d'entraînement et de validation (mesuré le 27/10/2026 sur un poste à 20 cœurs logiques, dont un peu plus de 2 minutes d'entraînement). Deux exécutions sur le même jeu donnent les 96 mêmes essais au chiffre près ; seule l'empreinte de `models/url_v1.joblib` change, car le fichier contient sa date d'entraînement.

| Sortie | Contenu | Versionné |
| :--- | :--- | :--- |
| `models/url_v1.joblib` | Modèle retenu, liste de ses features, table des TLD, seuils réglés sur la validation | Non (régénéré par `make train-url`) |
| `docs/metrics/url_v1.json` | Tous les essais (modèle × jeu de features × hyperparamètres), le choix final, l'empreinte SHA-256 du jeu et du modèle | Oui : aucune URL ni aucun domaine |
| Bloc généré de ce document | Tableaux de la section [Résultats](#résultats) | Oui |

Le cahier des charges nomme le modèle `models/url_lgbm_v1.joblib`. Le fichier s'appelle `url_v1.joblib` parce que la famille de modèle n'est pas fixée à l'avance : c'est la recherche qui la choisit (LightGBM sur le jeu actuel), et elle est enregistrée dans les métadonnées du fichier.

```python
from phishguard.urls.model import UrlModel

model = UrlModel.load("models/url_v1.joblib")  # fichier de confiance uniquement (pickle)
model.score(["http://paypa1-secure.com/login"])  # probabilité de phishing
model.predict(["http://paypa1-secure.com/login"], threshold="fpr_1pct")
```

| Fichier | Rôle |
| :--- | :--- |
| `src/phishguard/urls/training.py` | Modèles, grilles d'hyperparamètres, jeux de features, recherche, mesure de latence |
| `src/phishguard/urls/model.py` | `UrlModel` : de l'URL brute au score, avec les mêmes features qu'à l'entraînement |
| `src/phishguard/evaluation/metrics.py` | `recall_at_fpr`, `threshold_at_fpr`, `binary_report` |
| `src/phishguard/reporting.py` | Tableaux Markdown et réécriture du bloc généré de ce document |
| `scripts/train_url.py`, `Makefile` | Commande unique `make train-url` |

## Méthode

### Les trois modèles

| Modèle | Pourquoi | Grille (validation) |
| :--- | :--- | :--- |
| Régression logistique, après standardisation | Référence linéaire : rapide, petite, chaque poids se lit | `C` ∈ {0,01 ; 0,1 ; 1 ; 10} |
| Random Forest | Interactions entre features sans réglage fin | 300 arbres, `max_depth` ∈ {aucune, 16}, `min_samples_leaf` ∈ {1, 5} |
| LightGBM | Gradient boosting, en général le plus fort sur des features tabulaires | `n_estimators` ∈ {300, 800}, `learning_rate` ∈ {0,05 ; 0,1}, `num_leaves` ∈ {15, 63} |

Les grilles sont volontairement petites : avec 26 features, l'écart entre deux réglages raisonnables est faible devant l'écart entre jeux de features ou entre sources. Toutes les graines sont fixées et LightGBM tourne en mode déterministe : deux exécutions sur le même jeu donnent les mêmes essais.

### Jeux de features

Chaque modèle est entraîné sur les six jeux de l'ablation de l'étape 1.5 : toutes les features, puis sans les groupes `scheme`, `path`, `length`, sans chemin ni longueur, et « hôte seul » comme référence la moins exposée aux biais de collecte. C'était la décision n° 2 de [`url-features.md`](url-features.md#ce-quon-en-fait). Le taux de faux positifs sur les **pages internes légitimes** (Common Crawl) est rapporté pour chaque essai : c'est là que le biais de chemin se voit.

**Le modèle enregistré utilise le jeu « sans schéma »** (25 features). `is_https` n'est pas un signal mais un artefact de construction : les URLs Tranco sont fabriquées en `https://<domaine>/` à l'étape 1.2. On le sait par construction, sans avoir besoin d'une mesure ; le garder ferait apprendre « http = phishing » sur des données où le légitime ne peut pas être en http. Le choix se change avec `--deploy-feature-set`.

### Sélection

1. Chaque combinaison est entraînée sur le bloc d'entraînement (98 031 URLs dans l'instantané du 25/10/2026) et mesurée sur la validation (21 007 URLs).
2. **Critère : le rappel à 1 % de faux positifs** (R@1%FPR), puis la PR-AUC en cas d'égalité. C'est la question qui compte pour un outil grand public : combien de phishing détecte-t-on quand on s'interdit de déranger l'utilisateur plus d'une fois sur cent ?
3. Le rappel à 0,1 % FPR est rapporté, pas utilisé pour choisir : 0,1 % du légitime de validation, c'est environ 17 URLs, et une ou deux URLs suffisent à le déplacer de plusieurs points.
4. Le modèle retenu **n'est pas réentraîné** sur entraînement + validation : ses seuils sont réglés sur la validation, il faut qu'il ne l'ait pas vue.

Le seuil enregistré `fpr_1pct` est le plus petit score qui laisse au plus 1 % des URLs légitimes de validation au-dessus ; une URL est signalée si son score le dépasse strictement. Le seuil de décision définitif, choisi selon la prévalence réelle du phishing, est justifié à l'étape 1.7.

### Coût à l'inférence

Mesuré sur un seul fil, comme en production (une requête = une URL) :

- **latence p50 / p95** : une URL brute à la fois, extraction des features comprise, sur 200 URLs de validation ;
- **modèle seul (lot)** : temps de l'estimateur par URL sur toute la validation, features déjà extraites ;
- **taille** : estimateur sérialisé (joblib, compression 3). Le modèle sera porté dans l'extension (module 5) : un modèle de plusieurs dizaines de Mo n'y a pas sa place.

## Résultats

<!-- generated:train-url:start -->
*Généré par `scripts/train_url.py` le 2026-10-27 (jeu `0310e419432c`, validation : 21 007 URLs dont 4 198 de phishing). Chiffres complets : [`metrics/url_v1.json`](metrics/url_v1.json).*

### Les trois modèles (jeu de features « sans schéma »)

| Modèle | Hyperparamètres retenus | PR-AUC | R@1%FPR | R@0,1%FPR | FPR pages internes | Latence p50 (1 URL) | Modèle seul (lot) | Taille |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Régression logistique | `C=0.1` | 0,893 | 0,681 | 0,353 | 6,4 % | 2,06 ms | 0,2 µs | 2 Kio |
| Random Forest | `n_estimators=300, max_depth=None, min_samples_leaf=5` | 0,954 | 0,831 | 0,661 | 6,2 % | 13,47 ms | 23,1 µs | 14 072 Kio |
| LightGBM **(retenu)** | `n_estimators=300, learning_rate=0.05, num_leaves=63, min_child_samples=20` | 0,956 | 0,841 | 0,671 | 6,8 % | 1,89 ms | 18,7 µs | 852 Kio |

### Rappel à 1 % FPR selon le jeu de features

Meilleur réglage de chaque modèle pour chaque jeu ; entre parenthèses, le taux de faux positifs sur les pages internes légitimes au même seuil.

| Jeu de features | Régression logistique | Random Forest | LightGBM |
| :--- | ---: | ---: | ---: |
| toutes | 0,686 (6,9 %) | 0,852 (6,3 %) | 0,861 (7,0 %) |
| sans schéma | 0,681 (6,4 %) | 0,831 (6,2 %) | 0,841 (6,8 %) |
| sans chemin | 0,691 (5,1 %) | 0,846 (6,3 %) | 0,852 (7,3 %) |
| sans longueur | 0,654 (6,1 %) | 0,825 (7,0 %) | 0,831 (6,6 %) |
| sans chemin ni longueur | 0,659 (3,9 %) | 0,721 (4,6 %) | 0,727 (3,5 %) |
| hôte seul | 0,650 (2,9 %) | 0,703 (4,0 %) | 0,706 (4,3 %) |

**Modèle retenu** : LightGBM (`n_estimators=300, learning_rate=0.05, num_leaves=63, min_child_samples=20`), 25 features. Seuil à 1 % FPR sur la validation : 0,6960 ; à 0,1 % : 0,9719.
<!-- generated:train-url:end -->

## Lecture

Lecture de l'exécution du 25/10/2026 (jeu `0310e419432c`), chiffres de validation.

**Le gain de LightGBM sur la régression logistique justifie-t-il sa taille et sa latence ?** Oui. À 1 % FPR, LightGBM détecte 84 % du phishing contre 68 % pour la régression logistique (+16 points), et à 0,1 % FPR l'écart double (67 % contre 35 %) : un modèle linéaire ne sait pas combiner les features (un TLD risqué *et* un sous-domaine long, par exemple). Le coût est acceptable : 852 Kio au lieu de 2 Kio, et une latence d'une URL identique (1,8 ms contre 2,1 ms), parce qu'elle vient surtout de l'extraction des features et du coût fixe d'un appel `predict_proba`, pas de l'estimateur. Random Forest atteint presque la même qualité (83 %), mais pour 14 Mo et 13 ms par URL : il n'a pas sa place dans l'extension.

**Le classement des modèles est-il le même pour chaque jeu de features ?** Oui : LightGBM ≥ Random Forest > régression logistique sur les six jeux. Mais l'écart entre LightGBM et Random Forest ne dépasse jamais un point de rappel, ce qui n'est pas significatif avec une seule graine (voir [Limites](#limites)). Ce qui départage vraiment les deux, c'est la taille et la latence.

**Que coûte de retirer chemin et longueur, et que gagne-t-on sur les pages internes ?** Pour LightGBM, retirer le chemin seul ne coûte rien (85 % de rappel), car les features de longueur (`url_len`…) mesurent encore le chemin. Retirer chemin **et** longueur fait perdre 11 points (84 % → 73 %) et divise par deux les faux positifs sur les pages internes légitimes (6,8 % → 3,5 %). C'est la mesure directe du biais de chemin de l'étape 1.3 : au seuil qui donne 1 % de faux positifs au global, le modèle retenu en donne 0,3 % sur les pages d'accueil mais 6,8 % sur les pages internes, vingt fois plus. Une bonne partie de ce que le modèle appelle « phishing » est donc « a un chemin ».

**Décision pour `url_v1`.** On garde le jeu « sans schéma » : retirer `is_https` coûte 2 points de rappel (86 % → 84 %), mais ces 2 points venaient d'un artefact de construction, pas du phishing. On ne retire pas chemin et longueur à ce stade : sans eux, le modèle ne fait guère mieux que la référence « hôte seul » (73 % contre 71 % de rappel), et une partie du signal du chemin est réelle (mots-clés, imitation de pages de connexion), même si ces données ne permettent pas de la séparer du biais. Le taux de faux positifs sur les pages internes est le chiffre à surveiller : il est mesuré sur le test à l'étape 1.7, et le remède durable est d'ajouter davantage de pages internes légitimes à l'entraînement, pas de retirer les features.

**Vérification de la table des TLD.** `tld_phish_rate` est appris sur l'entraînement puis appliqué à ces mêmes lignes, ce qui peut faire surestimer la feature au modèle. Contrôle fait le 27/10/2026 : en remplaçant, pour l'entraînement seulement, la table par un encodage hors-pli (5 plis groupés par domaine enregistré), le rappel à 1 % FPR de LightGBM sur la validation passe de 0,841 à 0,834, et celui des deux autres modèles bouge de moins d'un point. Le lissage (m = 20) suffit : l'encodage simple est conservé.

## Limites

- Une seule graine et un seul split : un écart de moins d'un point de rappel entre deux modèles n'est pas significatif.
- Sélection et seuils viennent de la même validation : les scores de validation du modèle retenu sont légèrement optimistes. Le test (étape 1.7) donne le chiffre à citer.
- Les biais de collecte de l'étape 1.5 (popularité via `host_len`, TLD) restent dans les jeux « toutes » et « sans schéma » ; ils sont mesurés à l'étape 1.7.
- `models/url_v1.joblib` est un fichier pickle : il ne doit jamais être chargé depuis une source non fiable. Registre de modèles signé : étape 4.12.
