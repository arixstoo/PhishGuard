# Export du modèle URL pour l'extension (étape 4.11)

L'extension (module 5) analysera les URLs **localement** : l'URL d'une page ne quitte pas
le navigateur. Elle doit donc reproduire exactement le score Python, sans Python.

```bash
make export      # models/url_v2.json et tests/golden/url_vectors.json
```

## Format : arbres LightGBM en JSON, pas ONNX

Pour un modèle LightGBM, l'export le plus simple et le plus robuste en première version
n'est pas ONNX mais les arbres eux-mêmes (`Booster.dump_model()`). En TypeScript, la
prédiction est une boucle d'une vingtaine de lignes (étape 5.3), sans dépendance de
plusieurs Mo (`onnxruntime-web`, WebAssembly), et le fichier est du **JSON pur** : rien
d'exécutable, contrairement au pickle (`.joblib`). ONNX (`onnxmltools`) reste une option
pour d'autres types de modèles.

`models/url_v2.json` (`phishguard.urls.export.export_url_model`) :

| Champ | Contenu |
|---|---|
| `format`, `format_version` | `phishguard-url-lightgbm`, 1 |
| `model_version`, `trained_at` | `url_v2`, date d'entraînement |
| `feature_names` | ordre exact des 25 colonnes attendues par les arbres |
| `feature_extractor` | `version` de l'extracteur, `reference_data_sha256`, `normalization_version` |
| `objective` | `{"name": "binary", "sigmoid": 1.0}` : probabilité = 1 / (1 + e^(−sigmoid × score brut)) |
| `thresholds`, `decision_rule` | seuils de décision (`fpr_1pct`…), règle `score > threshold` |
| `calibration` | fonction score → probabilité (isotonique, étape 2.10), déjà en JSON |
| `tld_table` | table de risque des TLD (`null` : `url_v2` n'utilise pas `tld_phish_rate`) |
| `booster` | les 300 arbres, réduits aux champs de l'inférence |

`dump_model()` garde aussi, par nœud, le gain de la coupure, le poids et l'effectif
d'entraînement : inutiles pour prédire, ils doublaient la taille. Après réduction :
**3,3 Mio** (357 Kio compressé), contre 6,6 Mio.

Les seuils sont écrits avec 17 chiffres significatifs : la relecture JSON en double
précision est exacte, aucune coupure ne bascule par arrondi.

### Refusé à l'export, pas en production

`UnsupportedModelError` si le modèle ne peut pas être reproduit par la boucle de
l'extension : estimateur autre que LightGBM, multiclasse, coupure catégorielle, valeur de
`missing_type` inconnue, ou **ordre des colonnes du booster différent de celui du modèle**
(l'erreur la plus silencieuse : tout fonctionne, les scores sont faux).

## Implémentation de référence en Python pur

`predict_raw` parcourt les arbres en ne lisant que le JSON, sans LightGBM. Elle reprend
à l'identique `Tree::NumericalDecision` de LightGBM :

```text
si valeur est NaN et missing_type ≠ "NaN" : valeur = 0
si (missing_type = "Zero" et |valeur| ≤ 1e-35) ou (missing_type = "NaN" et valeur est NaN) :
    aller du côté default_left
sinon : gauche si valeur ≤ threshold, droite sinon
score brut = somme des feuilles atteintes
```

C'est la spécification de l'implémentation TypeScript : elle n'a qu'à traduire ces
lignes. `scripts/export_model.py` refuse d'écrire quoi que ce soit si la référence
s'écarte de LightGBM de plus de 1e-12 sur une des 200 URLs ; les tests la confrontent
aussi à LightGBM sur des données avec valeurs manquantes et nulles
(`zero_as_missing`), branches que les features d'URL n'exercent pas.

## Vecteurs de référence communs

`tests/golden/url_vectors.json`, **versionné** : 200 URLs avec, pour chacune, les 25
valeurs de features, le score brut, la probabilité et la probabilité calibrée calculés par
Python. Les tests TypeScript devront retrouver ces valeurs à **1e-6** près (champ
`tolerance`) : features d'abord (l'extracteur, la partie la plus fragile), puis scores.
Sans ce garde-fou, les deux implémentations divergeraient en silence.

Le fichier porte aussi `model_export_sha256` (l'export dont viennent les scores) et
`feature_extractor` (version, empreinte des listes de référence).

**URLs synthétiques et déterministes**, jamais tirées des flux de phishing : une URL de
phishing réelle contient souvent l'adresse email ou l'identifiant de sa victime, et ce
fichier est public. 40 cas choisis à la main, chacun pour une branche de l'extracteur
(IDN et punycode, homographes cyrilliques, IP décimale, hexadécimale et IPv6, port,
identifiants, URL imbriquée, encodage pourcent, espace de largeur nulle, inversion de
sens U+202E, raccourcisseurs, sous-domaines profonds, suffixes privés `github.io`),
complétés par 160 combinaisons tirées avec une graine fixe (marques et typosquats,
mots-clés, chiffres, IP de documentation).

### Ce qui empêche la dérive

| Changement | Détecté par |
|---|---|
| calcul d'une feature modifié côté Python | `test_committed_golden_vectors_match_the_python_extractor` |
| `brands.json`, `shorteners.json`, mots-clés ou version de `tldextract` modifiés | `reference_data_sha256` différent (même test, message explicite) |
| export JSON insuffisant pour reproduire LightGBM | `test_reference_implementation_matches_lightgbm`, et le script lui-même |
| implémentation TypeScript divergente | tests de l'extension contre ces vecteurs (étape 5.3) |

`FEATURE_EXTRACTOR_VERSION` (`phishguard.urls.features`) s'incrémente à toute
modification d'une feature ; l'extension refusera un modèle exporté pour un autre
extracteur que le sien.

**Liste des suffixes publics.** `host_n_subdomains` et le domaine enregistré dépendent de
la liste embarquée par `tldextract` : l'extension devra embarquer **la même**. Sa version
entre dans `reference_data_sha256`.

## Distribution

`models/url_v2.json` n'est pas versionné, comme les autres modèles. Il est signé avec eux
(rôle `url-export` du manifeste, étape 4.12) : l'extension vérifiera la signature avant de
l'utiliser (module 6).
