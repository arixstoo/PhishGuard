# Modèles de texte SMS (étape 1.9)

Reproduire : `python scripts/train_text_models.py` (ajouter `--embeddings` pour l'approche optionnelle, après `pip install -e '.[embeddings]'`). Sortie complète : [`docs/metrics/text_models.json`](metrics/text_models.json).

## Approches comparées

| nom | représentation | classifieur |
|---|---|---|
| `word_logreg` | TF-IDF mots | régression logistique (baseline de l'étape 0.7) |
| `word_svc` | TF-IDF mots | `LinearSVC` |
| `char_logreg` | TF-IDF caractères (`char_wb`, 2 à 5) | régression logistique |
| `char_svc` | TF-IDF caractères (`char_wb`, 2 à 5) | `LinearSVC` |
| `char_smishing_logreg` | TF-IDF caractères + 9 features smishing | régression logistique |
| `embeddings_logreg` (optionnel) | `paraphrase-multilingual-MiniLM-L12-v2` | régression logistique |

Les **features smishing** (`src/phishguard/text/smishing.py`) sont des fonctions pures, multilingues (anglais, français, arabe) : présence d'un lien, d'un numéro court, d'un numéro de téléphone, d'un montant, nombre de mots d'urgence, part de majuscules, part de chiffres, points d'exclamation, longueur. Elles sont explicables (« contient un lien et deux mots d'urgence ») et portables en TypeScript pour l'extension.

## Protocole

1. Dédoublonnage de la UCI SMS Spam Collection **avant** tout split (414 doublons, voir l'étape 0.7).
2. Split stratifié 60 / 20 / 20 (entraînement / validation / test), graine 42.
3. `C` choisi parmi {0,1 ; 1 ; 10} sur la **validation** (critère : PR-AUC). Le test n'est utilisé qu'une fois.
4. Réentraînement sur entraînement + validation, puis évaluation sur le test UCI.
5. Évaluation **hors distribution** sur le [jeu français / arabe](sms-fr-ar.md), jamais vu à l'entraînement.

Seuils de décision : 0,5 sur la probabilité (régression logistique), 0 sur la marge (`LinearSVC`). La PR-AUC et le rappel à 1 % de FPR ne dépendent pas du seuil. La latence est mesurée message par message (cas de l'extension), sur CPU, sur 200 messages du test. La taille est celle du pipeline sérialisé avec joblib. Pour les embeddings, elle n'inclut pas l'encodeur, qui est rapporté à part (`encoder_size_bytes_fp32`).

## Résultats

> **À compléter** : la première exécution complète n'a pas encore eu lieu (le corpus UCI n'était pas téléchargeable depuis l'environnement de développement). Le tableau sera généré par `scripts/train_text_models.py` et collé ici, sans retouche.

## Lecture attendue (à confirmer par les chiffres)

- Le TF-IDF **caractères** devrait mieux résister aux variantes d'écriture (`FR33`, `c1ick`) et beaucoup mieux généraliser au français et à l'arabe que le TF-IDF mots, dont le vocabulaire anglais ne recouvre presque rien.
- Les **embeddings multilingues** devraient être les meilleurs hors distribution, au prix d'un encodeur de plusieurs centaines de Mo et d'une latence bien plus élevée : un coût difficile à justifier dans une extension de navigateur.
- Le gain des **features smishing** sur le jeu FR/AR est probablement surestimé (même auteur pour la liste de mots et les messages, voir les limites du jeu).
