# Modèles URL (étape 1.6)

`scripts/train_url.py` entraîne trois modèles sur les features de l'étape 1.5 ([`url-features.md`](url-features.md)), les compare sur la validation et enregistre le meilleur. Le bloc de test n'est pas chargé : il sert une seule fois, à l'évaluation finale ([`evaluation.md`](evaluation.md), étape 1.7).

```bash
make train-url                         # = python scripts/train_url.py
python scripts/train_url.py --quick    # grilles réduites, pour vérifier le pipeline en une minute
python -m pytest tests/test_url_training.py tests/test_url_model.py
```

La grille complète (3 modèles × 6 jeux de features × 4 à 8 réglages, soit 96 entraînements) prend environ 4 minutes pour 140 000 URLs sur 4 cœurs.

| Sortie | Contenu | Versionné |
| :--- | :--- | :--- |
| `models/url_v1.joblib` | Modèle retenu, liste de ses features, table des TLD, seuils réglés sur la validation | Non (régénéré par `make train-url`) |
| `docs/metrics/url_v1.json` | Tous les essais (modèle × jeu de features × hyperparamètres), le choix final, l'empreinte SHA-256 du jeu et du modèle | Oui : aucune URL ni aucun domaine |
| Bloc généré de ce document | Tableaux de la section [Résultats](#résultats) | Oui |

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
*Pas encore généré : lancez `make train-url` sur le jeu de l'étape 1.4. Ce bloc est réécrit à chaque exécution.*
<!-- generated:train-url:end -->

## Lecture

*À rédiger après la première exécution sur le jeu réel*, en répondant à ces questions :

- Le gain de LightGBM sur la régression logistique justifie-t-il sa taille et sa latence ?
- Le classement des modèles est-il le même pour chaque jeu de features ?
- Que coûte, en rappel, de retirer chemin et longueur, et que gagne-t-on en faux positifs sur les pages internes ?

## Limites

- Une seule graine et un seul split : un écart de moins d'un point de rappel entre deux modèles n'est pas significatif.
- Sélection et seuils viennent de la même validation : les scores de validation du modèle retenu sont légèrement optimistes. Le test (étape 1.7) donne le chiffre à citer.
- Les biais de collecte de l'étape 1.5 (popularité via `host_len`, TLD) restent dans les jeux « toutes » et « sans schéma » ; ils sont mesurés à l'étape 1.7.
- `models/url_v1.joblib` est un fichier pickle : il ne doit jamais être chargé depuis une source non fiable. Registre de modèles signé : étape 4.12.
