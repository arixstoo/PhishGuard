# Split temporel et groupé (étape 1.4)

`scripts/split_dataset.py` découpe `data/processed/urls.parquet` (voir [`url-dataset.md`](url-dataset.md)) en trois blocs : **entraînement** (70 %), **validation** (15 %) et **test** (15 %). Tous les modèles URL des étapes suivantes s'entraînent et s'évaluent sur ces blocs : les hyperparamètres et le seuil se règlent sur la validation, le test ne sert qu'au rapport final.

```bash
python scripts/split_dataset.py                           # 70 / 15 / 15, graine 42
python scripts/split_dataset.py --validation 0.1 --test 0.2
```

| Sortie | Contenu | Versionné |
| :--- | :--- | :--- |
| `data/processed/urls_split.parquet` | Le jeu avec une colonne `split` (`train`, `validation`, `test`) | Non, comme `urls.parquet` |
| `docs/metrics/urls_split.json` | Paramètres, effectifs et dates par bloc et par strate, empreinte du jeu découpé | Oui : aucune URL ni aucun domaine |

La logique est dans `src/phishguard/data/split.py`, testée par `tests/test_split.py`.

## Deux garanties

1. **Groupé.** Un domaine enregistré n'appartient qu'à un seul bloc, toutes classes et sources confondues. Le test mesure la détection de sites **jamais vus**, pas la mémoire des domaines (fuite mesurée à l'étape 1.3, voir [`data-bias.md`](data-bias.md#3-fuite-par-domaine)). Un domaine présent dans les deux classes (hébergeur, raccourcisseur) reste d'un seul côté, ses deux classes ensemble.
2. **Temporel.** Dans chaque source, les domaines apparus les premiers vont à l'entraînement et les plus récents au test : le modèle est jugé sur des attaques postérieures à celles qu'il a apprises, comme en production.

`split_dataset.py` vérifie la première garantie avant d'écrire quoi que ce soit (`assert_no_domain_leakage`), et un test par propriétés (Hypothesis) la vérifie sur des jeux aléatoires.

## Pourquoi découper chaque source séparément

Le plan propose de trier tout le jeu par `first_seen`. Sur nos données, c'est inutilisable : les sources ne suivent pas la même horloge (date de signalement PhishTank depuis 2011, date de capture Common Crawl, date de collecte Tranco ; voir [`url-dataset.md`](url-dataset.md#sens-de-first_seen)). 89 % du phishing est antérieur à la première URL légitime, et le tri global donnerait :

| Bloc | Tri global (naïf) : part de phishing | **Par source** : part de phishing |
| :--- | ---: | ---: |
| entraînement | 27,3 % | **20,0 %** |
| validation | **0,2 %** | **20,0 %** |
| test | 5,6 % | **20,0 %** |

Avec 0,2 % de phishing en validation, on ne pourrait ni régler un seuil ni mesurer un rappel. Le découpage par strate (étiquette × source) a un second avantage : chaque bloc garde **la même composition de sources** (72 % Tranco, 19 % PhishTank, 8 % Common Crawl, 1 % OpenPhish). Un écart de score entre validation et test ne peut donc pas venir d'un changement de source, biais mesuré à l'étape 1.3.

Les pages internes légitimes (Common Crawl, étape 1.3 bis) sont présentes dans chaque bloc : 7 754 / 1 659 / 1 623. C'était une condition de [`data-bias.md`](data-bias.md) pour régler le seuil sur un légitime réaliste.

## Algorithme

1. Chaque domaine est daté par sa **première** URL dans la strate : un domaine connu au moment de l'entraînement y reste, même si de nouvelles URLs y apparaissent ensuite.
2. Les strates sont traitées de la plus petite à la plus grande. Un domaine déjà placé par une strate précédente garde son bloc, et ses lignes comptent dans les quotas de la strate courante.
3. Les autres domaines remplissent, dans l'ordre chronologique, ce qui reste du quota de l'entraînement, puis de la validation, puis du test. Un domaine n'est jamais coupé : il va dans le bloc où tombe sa première ligne.
4. Les ex aequo sont départagés par un hachage (BLAKE2b) du domaine et de la graine. Toutes les URLs d'une collecte Tranco ont la même date : sans ce départage, l'ordre du fichier déciderait. Le split ne dépend donc pas de l'ordre des lignes (vérifié par un test).

## Instantané du 25/10/2026

140 042 URLs, 124 195 domaines enregistrés, **0 domaine dans plusieurs blocs**.

| Bloc | URLs | Part | Domaines | Phishing | Pages internes légitimes |
| :--- | ---: | ---: | ---: | ---: | ---: |
| entraînement | 98 031 | 70,0 % | 87 023 | 20,0 % | 7 754 |
| validation | 21 007 | 15,0 % | 18 551 | 20,0 % | 1 659 |
| test | 21 004 | 15,0 % | 18 621 | 20,0 % | 1 623 |

Première apparition des domaines, par source (date médiane) :

| Source | Entraînement | Validation | Test |
| :--- | :--- | :--- | :--- |
| PhishTank | 29/09/2025 (depuis 2011) | 02/08/2026 | 04/10/2026 |
| OpenPhish | 22/10/2026 | 24/10/2026 | 25/10/2026 |
| Common Crawl | 09/10/2026 | 11/10/2026 | 15/10/2026 |
| Tranco | 22/10/2026 (date unique) | idem | idem |

**Écarts à l'ordre temporel.** Seules les lignes d'un domaine déjà placé par une strate plus petite peuvent sortir de l'ordre (`rows_placed_by_smaller_stratum` dans le rapport) : 83 lignes PhishTank (0,3 %), partagées avec OpenPhish, et 2 980 lignes Tranco (3 %), surtout les pages d'accueil de domaines dont les pages internes Common Crawl ont fixé le bloc. Pour Tranco, l'écart est sans effet : toutes ses URLs ont la même date.

## Limites

- **Le temps ne porte vraiment que sur le phishing.** Le légitime ne couvre que trois semaines (captures Common Crawl comprises) : le split ne mesure pas la dérive du web légitime. La collecte quotidienne de Tranco atténuera cette limite.
- **OpenPhish ne couvre que quatre jours** : son test est le phishing du 25/10, son entraînement celui du 21 au 24/10. L'écart temporel est réel mais court.
- **Le test PhishTank est récent, pas lointain** : il couvre surtout l'été et l'automne 2026. Pour mesurer la dérive sur plusieurs mois, il faudra attendre que la collecte quotidienne accumule des données.
- **Les parts visées ne sont qu'approchées** pour les très petites strates (URLhaus : 6 URLs, aucune en validation).
- **Le split dépend du jeu** : toute reconstruction de `urls.parquet` (nouvelle collecte) déplace les blocs. `urls_split.json` conserve l'empreinte SHA-256 du jeu découpé ; relancer `split_dataset.py` après chaque `build_dataset.py`.
