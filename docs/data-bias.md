# Biais du jeu d'URLs (étapes 1.3 et 1.3 bis)

Un jeu de données peut contenir des **raccourcis** : des indices qui séparent les classes dans le jeu, mais pas dans la réalité. Un modèle qui les apprend obtient d'excellents scores hors ligne et échoue en production. Ce document recense les raccourcis mesurés dans `data/processed/urls.parquet` (étape 1.2, voir [`url-dataset.md`](url-dataset.md)) et ce que le projet fait pour les neutraliser.

Deux instantanés sont comparés :

- **avant** (24/10, étape 1.3) : 128 588 URLs, le légitime n'est fait que de pages d'accueil Tranco ;
- **après** (25/10, étape 1.3 bis) : 140 042 URLs, dont **11 332 pages internes légitimes** tirées de Common Crawl pour les 5 000 premiers domaines Tranco (voir [`data-sources.md`](data-sources.md#6-common-crawl-urls-légitimes-avec-chemin)).

Les tableaux donnent les deux valeurs sous la forme « avant → après ».

```bash
python scripts/audit_bias.py                # audit complet (≈ 6 min), avec PhiUSIIL
python scripts/audit_bias.py --no-external  # sans téléchargement
```

| Sortie | Contenu | Versionné |
| :--- | :--- | :--- |
| `docs/metrics/data_bias.json` | Tous les chiffres de ce document, l'empreinte du jeu audité et les versions des bibliothèques | Oui : aucune URL ni aucun domaine |
| `data/external/PhiUSIIL_Phishing_URL_Dataset.csv` | Jeu de comparaison, empreinte SHA-256 vérifiée | Non |

Le code est dans `src/phishguard/data/bias.py` et `src/phishguard/data/phiusiil.py`, testé par `tests/test_data_bias.py`.

## Méthode : un modèle sonde

On n'a pas encore de modèle (étapes 1.5 et 1.6). L'audit utilise donc un **modèle sonde** volontairement simple : n-grammes de caractères (3 à 5) TF-IDF et régression logistique à classes équilibrées. Il ne sert pas à détecter le phishing mais à détecter les raccourcis. On compare ses scores selon :

- **ce qu'il voit de l'URL** (« représentation ») : l'URL complète, l'origine (`schéma://hôte/`), l'hôte seul, le domaine enregistré seul ;
- **le protocole de découpage** : aléatoire ou groupé par domaine enregistré ;
- **les sources** vues à l'entraînement.

Sauf mention contraire : split groupé par domaine enregistré, 20 % des domaines en test, graine 42, environ 22 % de phishing dans le test avant, 19 % après. Métriques : PR-AUC et rappel à 1 % de faux positifs (R@1%FPR), qui comptent davantage que l'accuracy (voir `src/phishguard/evaluation/metrics.py`).

## Synthèse

| Biais | Mesure clé | Gravité | Traitement |
| :--- | :--- | :--- | :--- |
| Structure (chemin, schéma, sous-domaine, longueur) | Pages internes légitimes signalées à tort : **89 % → 27 %**. Longueur de l'URL seule : ROC-AUC 0,96 → 0,89 | Élevée → moyenne | Pages internes Common Crawl ajoutées (1.3 bis) ; scores rapportés pour chaque représentation ; features groupées ; FPR sur pages internes mesuré à chaque modèle |
| Source | R@1%FPR sans PhishTank à l'entraînement : 0,92 → 0,63 **avant**, 0,84 → 0,42 **après** | Élevée | Évaluation croisée entre sources dans chaque rapport ; collecte quotidienne poursuivie |
| Fuite par domaine | Test aléatoire partageant un domaine avec l'entraînement : 5,5 % → 15,2 % | Faible ici | Split groupé obligatoire : fait (étape 1.4, [`split.md`](split.md)) |
| Temps | Phishing antérieur à la première URL légitime : 96 % → 89 % | Bloquant pour un split temporel naïf | Split temporel par source : fait (étape 1.4), 20 % de phishing dans chaque bloc |
| PhiUSIIL comme remède | Ses URLs légitimes n'ont **aucun** chemin | — | Remède du plan écarté ; jeu gardé comme comparaison externe |

## 1. Biais de structure (« biais de chemin »)

**En deux phrases.** Tranco ne publie que des domaines : toutes les URLs légitimes du jeu sont des pages d'accueil courtes en `https`, sans sous-domaine, alors que le phishing a souvent un chemin, un sous-domaine ou `http`. Un modèle apprend alors « URL longue ou avec chemin = phishing » et signalera n'importe quel lien profond d'un site légitime.

### Constat avant correction (24/10)

| Part des URLs | Légitime (Tranco) | Phishing |
| :--- | ---: | ---: |
| avec un chemin | **0 %** | 44 % |
| en `http` | **0 %** | 16 % |
| avec un sous-domaine | **0 %** | 30 % |
| longueur médiane | 21 | 41 (PhishTank), 45 (OpenPhish) |

Le biais est pire que prévu : ce n'est pas seulement le chemin. **Un seul trait, la longueur de l'URL, sépare les classes avec une ROC-AUC de 0,960** (chemin seul : 0,72 ; sous-domaine seul : 0,65). Une régression logistique sur les 12 traits structurels, sans voir un seul caractère, atteint une PR-AUC de 0,960.

### Après ajout des pages internes Common Crawl (25/10)

| Part des URLs | Tranco | Common Crawl | Légitime (total) | Phishing |
| :--- | ---: | ---: | ---: | ---: |
| avec un chemin | 0 % | 95 % | 0 % → **10 %** | 44 % |
| en `http` | 0 % | 6 % | 0 % → **0,6 %** | 16 % |
| avec un sous-domaine | 0 % | 88 % (dont `www.` 26 %) | 0 % → **9 %** | 30 % |
| longueur médiane | 21 | 68 | 21 → 22 | 41 |

ROC-AUC d'un seul trait : longueur de l'URL 0,960 → **0,886**, chemin 0,72 → 0,67, sous-domaine 0,65 → 0,61. Les pages internes ne forment que 10 % du légitime : le raccourci est affaibli, pas supprimé.

### Ablation du modèle sonde

Même protocole, 25 719 URLs de test avant, 27 888 après :

| Représentation vue | PR-AUC | ROC-AUC | R@1%FPR |
| :--- | ---: | ---: | ---: |
| URL complète | 0,978 → 0,957 | 0,986 → 0,982 | 0,931 → 0,837 |
| origine (`schéma://hôte/`) | 0,939 → 0,917 | 0,961 → 0,956 | 0,823 → 0,766 |
| hôte | 0,915 → 0,899 | 0,949 → 0,948 | 0,772 → 0,743 |
| **domaine enregistré** (référence) | **0,878 → 0,875** | **0,923 → 0,929** | **0,715 → 0,720** |
| traits structurels seuls | 0,960 → **0,645** | 0,982 → 0,909 | 0,852 → **0,076** |

Le domaine enregistré est la seule représentation qui a la même forme dans les deux classes : son score ne bouge pas, ce qui confirme que la référence était saine. Avant, **environ 22 points de rappel à 1 % FPR (0,93 contre 0,72) venaient de la forme de l'URL** ; il en reste 12 (0,84 contre 0,72). Le modèle qui ne voit que les traits structurels s'effondre (R@1%FPR 0,85 → 0,08) : sans le raccourci, la forme de l'URL seule ne suffit plus à trouver le phishing.

La baisse du score de l'URL complète n'est pas une régression : c'est la part du score qui ne tenait qu'au raccourci. Le test contient maintenant des URLs légitimes avec chemin, donc il est plus difficile et plus proche de la réalité.

### Faux positifs sur les pages internes légitimes

C'est la mesure qui compte pour l'utilisateur : combien de liens profonds de sites légitimes un modèle signalerait-il ? Sur un même split groupé par domaine, deux sondes (URL complète) sont comparées :

- **sans pages internes** à l'entraînement, comme avant l'étape 1.3 bis ;
- **avec** les pages internes.

Le seuil de chaque sonde est réglé pour 1 % de faux positifs sur les pages d'accueil du test, comme on l'aurait validé avec Tranco seul. On mesure alors la part des **2 276 pages internes du test**, de domaines jamais vus à l'entraînement, signalées à tort.

| Sonde entraînée | FPR pages d'accueil | **FPR pages internes** | Rappel du phishing |
| :--- | ---: | ---: | ---: |
| sans pages internes (avant) | 1,0 % | **89,2 %** | 0,928 |
| avec pages internes (après) | 1,0 % | **26,8 %** | 0,907 |

(Au seuil 0,5 : 86,7 % puis 22,3 % de pages internes signalées.)

Lecture :

- **avant, un modèle validé à « 1 % de faux positifs » en signalait en réalité 89 % sur les liens profonds légitimes**. Le score hors ligne était trompeur, et le modèle aurait été inutilisable dans un navigateur ;
- l'ajout des pages internes divise ces faux positifs par plus de trois, pour 2 points de rappel perdus ;
- 27 % reste très loin de l'objectif de 1 %. Le seuil est encore réglé sur des pages d'accueil, faciles à reconnaître comme légitimes, et les pages internes ne pèsent que 10 % du légitime à l'entraînement.

### Le remède prévu (PhiUSIIL) ne fonctionne pas

Le plan proposait de comparer avec PhiUSIIL, censé contenir des URLs légitimes avec chemin. Vérification faite, c'est faux : ses 134 849 URLs légitimes n'ont **aucun** chemin, aucun paramètre, aucun `http`, et **toutes** commencent par `www.`. PhiUSIIL a le même biais de chemin que Tranco, plus un biais `www.` qui lui est propre.

Validation externe : la sonde, entraînée sur notre jeu, est testée sur PhiUSIIL (202 976 URLs avant, 202 952 après, une fois exclues celles dont le domaine figure déjà chez nous) :

| Représentation vue | PR-AUC | ROC-AUC | R@1%FPR |
| :--- | ---: | ---: | ---: |
| URL complète | 0,918 → 0,969 | 0,887 → 0,962 | 0,787 → 0,879 |
| origine | 0,814 → 0,921 | 0,744 → 0,899 | 0,593 → 0,744 |
| hôte | 0,515 → 0,701 | **0,500 → 0,689** | 0,072 → 0,278 |
| domaine enregistré | 0,776 → 0,776 | 0,778 → 0,778 | 0,368 → 0,370 |

Lecture :

- le bon score sur l'URL complète **ne prouve pas** que la sonde généralise : les deux jeux partagent le raccourci du chemin, donc elle y retrouve ce qu'elle a appris. Sa hausse après correction ne prouve rien non plus, PhiUSIIL n'ayant toujours aucune URL légitime avec chemin ;
- avant, sur l'hôte, la sonde tombait au **hasard** (ROC-AUC 0,50). Elle avait appris chez nous « sous-domaine = phishing » ; dans PhiUSIIL, 100 % des URLs légitimes ont un sous-domaine (`www.`). C'est la démonstration directe qu'un raccourci du jeu d'entraînement casse dès que la distribution change. Après correction, 88 % des pages internes ont un sous-domaine (26 % en `www.`) : la sonde n'associe plus aussi fortement sous-domaine et phishing, et remonte à 0,69 ;
- sur le domaine enregistré, sans raccourci de forme, rien ne change (le rappel à 1 % FPR reste à 0,37), comme attendu. Les domaines de phishing de 2023 ne ressemblent pas à ceux de 2026 : premier signe de dérive temporelle.

### Ce qu'on fait

1. **Chaque évaluation de modèle URL rapportera l'ablation par représentation** (étapes 1.6 et 1.7), avec le domaine enregistré comme référence. Un gain qui n'existe que sur l'URL complète est considéré comme suspect.
2. **Chaque évaluation rapportera aussi le FPR sur les pages internes légitimes**, séparément du FPR global, et le seuil de décision sera réglé sur un légitime qui contient des pages internes (étape 1.4 : les pages internes doivent être présentes dans la validation).
3. **Les features URL seront rangées en groupes** (hôte, chemin, schéma, longueur) à l'étape 1.5, pour entraîner et comparer les modèles avec et sans les groupes de chemin et de longueur, comme le demande le plan.
4. **La longueur sera mesurée par composant** (longueur de l'hôte, longueur du chemin) plutôt que sur l'URL entière, qui mélange les deux.
5. **Remède de données : fait (étape 1.3 bis)**, avec des pages internes réelles tirées de l'index de Common Crawl, premier parti uniquement, et sans les domaines qui hébergent du phishing (`sites.google.com`, `weebly.com`…). Pistes pour aller plus loin : interroger davantage de domaines Tranco (`--tranco-top`) et plus de pages par domaine, pour rapprocher la part de pages internes de celle du phishing avec chemin (44 %).
6. **Écarté** : fabriquer des URLs légitimes avec chemin en ajoutant `www.` ou un chemin inventé aux domaines Tranco. On remplacerait un raccourci par un autre, puisque ces chemins ne ressembleraient à rien de réel.

## 2. Biais de source

**En deux phrases.** 96 % du phishing vient de PhishTank et chaque source a un style reconnaissable (OpenPhish : 42 % de `http`, PhishTank : 15 %), tandis que tout le légitime vient de Tranco. Le modèle risque d'apprendre « ressemble à PhishTank » au lieu de « ressemble à du phishing », et de rater le phishing d'une autre origine.

### Constat

Pour chaque source cible, un même jeu de test départage deux modèles : l'un a vu la source cible à l'entraînement, l'autre jamais. Aucun domaine du test n'apparaît à l'entraînement.

| Source testée | Modèle | PR-AUC | ROC-AUC | R@1%FPR |
| :--- | :--- | ---: | ---: | ---: |
| PhishTank | a vu PhishTank | 0,975 → 0,954 | 0,984 → 0,979 | 0,924 → 0,839 |
| PhishTank | **n'a vu qu'OpenPhish** | 0,895 → 0,801 | 0,949 → 0,924 | **0,633 → 0,416** |
| OpenPhish | a vu OpenPhish | 0,946 → 0,810 | 0,987 → 0,984 | 0,949 → 0,852 |
| OpenPhish | n'a vu que PhishTank | 0,911 → 0,770 | 0,979 → 0,978 | 0,904 → 0,808 |

- Sans PhishTank, le rappel à 1 % FPR perdait 29 points ; il en perd **42** après correction. Le raccourci de structure masquait une partie du biais de source : le modèle entraîné sur OpenPhish seul s'appuyait sur « chemin = phishing », qui marchait aussi sur PhishTank. Sans ce raccourci, il ne lui reste que ce qu'il a appris d'OpenPhish, et cela se transfère mal.
- Avant : sans PhishTank, le rappel à 1 % FPR perd 29 points. Une partie de l'écart vient de la taille (il ne reste qu'environ 1 000 URLs de phishing, toutes d'OpenPhish), mais pas tout : la PR-AUC chute aussi.
- OpenPhish est bien détecté par un modèle qui ne l'a jamais vu (−4,5 points de rappel) : ce qui est appris sur PhishTank se transfère en grande partie. Ce test ne contient qu'environ 200 URLs de phishing (1 % du test) : son rappel est imprécis, et sa PR-AUC ne se compare pas à celle de PhishTank (22 % de phishing).
- Un modèle qui devine la source d'une URL de phishing atteint une **ROC-AUC de 0,937** (0,939 après) : les sources sont très reconnaissables.
- URLhaus (6 URLs) est trop petit pour être évalué séparément.
- Avant, le légitime n'avait qu'une source : « source = Tranco » et « légitime » étaient confondus. Common Crawl est une seconde source légitime, mais petite (10 % du légitime) et d'un style propre (pages internes de grands sites) : la confusion est réduite, pas levée.

### Ce qu'on fait

1. **L'évaluation croisée entre sources fera partie du rapport de chaque modèle** (étape 1.7), en plus du score global.
2. **La collecte quotidienne continue** (étape 1.1) : OpenPhish ne publie que ~300 URLs par jour, sa part augmentera avec le temps.
3. La source n'est **jamais** une feature, et `first_seen` non plus.

## 3. Fuite par domaine

**En deux phrases.** Avec un split aléatoire, un même domaine enregistré peut se trouver à l'entraînement et au test : le modèle reconnaît alors le domaine au lieu de juger l'URL. On découpe donc par domaine enregistré, pour que le score mesure la détection de sites jamais vus.

### Constat

| Split | Test partageant un domaine avec l'entraînement | PR-AUC | R@1%FPR | R@0,1%FPR |
| :--- | ---: | ---: | ---: | ---: |
| aléatoire | 1 428 → 4 265 URLs (5,5 % → 15,2 %) | 0,984 → 0,965 | 0,949 → 0,855 | 0,884 → 0,712 |
| groupé par domaine | **0** | 0,978 → 0,957 | 0,931 → 0,837 | 0,869 → 0,708 |

L'écart est modeste (2 points de rappel) parce que l'étape 1.2 limite déjà chaque domaine à 5 URLs. Sans cette limite, `google.com` aurait plus de 6 000 URLs de phishing, et l'écart serait bien plus grand. La part du test aléatoire qui partage un domaine avec l'entraînement a triplé : un domaine Tranco a maintenant jusqu'à 5 URLs légitimes (sa page d'accueil et ses pages internes), qu'un split aléatoire disperse. Le split groupé devient d'autant plus nécessaire. Par ailleurs, 517 domaines (1 867 URLs) sont présents dans les deux classes : surtout des hébergeurs et des raccourcisseurs.

### Ce qu'on fait

1. **Split groupé par `registered_domain` obligatoire** pour tout modèle URL, avec un test unitaire qui vérifie l'absence de recouvrement. **Fait (étape 1.4)** : `temporal_group_split`, testé par propriétés (Hypothesis), voir [`split.md`](split.md).
2. Un domaine présent dans les deux classes est placé d'un seul côté du split, ses deux classes ensemble.

## 4. Biais temporel

**En deux phrases.** Les dates PhishTank remontent à 2011, alors que le légitime date de nos collectes (22 au 25/10/2026) et des captures Common Crawl (à partir du 05/10/2026) : 89 % du phishing est antérieur à la première URL légitime (96 % avant Common Crawl). Un split temporel naïf mettrait donc presque tout le phishing à l'entraînement et presque rien au test.

### Constat

Split naïf : tri global par `first_seen`, puis découpage 70 / 15 / 15 :

| Bloc | URLs | Part de phishing |
| :--- | ---: | ---: |
| entraînement | 90 012 → 98 029 | 29,8 % → 27,3 % |
| validation | 19 288 → 21 007 | **0,2 % → 0,2 %** |
| test | 19 288 → 21 006 | 4,7 % → 5,6 % |

La validation ne contient quasiment aucun phishing : on ne pourrait ni régler un seuil ni mesurer un rappel.

### Ce qu'on fait (étape 1.4, fait : voir [`split.md`](split.md))

1. **Découper dans le temps à l'intérieur de chaque classe**, et plus finement de chaque source (70 / 15 / 15 de chacune séparément), sous la contrainte de groupe par domaine. Résultat : 20,0 % de phishing dans chacun des trois blocs, et la même composition de sources partout.
2. Signaler dans le rapport d'évaluation que la dimension temporelle ne porte vraiment que sur le phishing : le légitime ne couvre que trois semaines (captures Common Crawl comprises). Avec la collecte quotidienne, la liste Tranco change et cette limite s'atténuera.

## Limites de cet audit

- Le modèle sonde est un modèle parmi d'autres. Un modèle à features (étape 1.5) ou un LightGBM peut exploiter les raccourcis différemment : l'ablation sera refaite sur eux.
- Un seul split, une seule graine : les écarts de moins de 1 point ne sont pas significatifs. Les écarts retenus ici (de 4 à 62 points) le sont largement.
- PhiUSIIL date de 2023 : une partie de sa différence avec notre jeu est de la dérive temporelle, pas seulement du biais.
- Le FPR sur les pages internes est mesuré sur des pages de **grands** sites (top 5 000 Tranco) : les pages de petits sites, plus variées, peuvent donner plus de faux positifs.
- Les chiffres valent pour les instantanés du 24/10/2026 (avant) et du 25/10/2026 (après). `docs/metrics/data_bias.json` conserve l'empreinte SHA-256 du jeu audité ; relancer `audit_bias.py` après chaque reconstruction du jeu.
