# Fusion du score

*Étape 2.10 du cahier des charges. Code : `src/phishguard/fusion/`. Paramètres : `src/phishguard/fusion/fusion.json`. Tests : `tests/test_fusion_score.py`, `tests/test_fusion_calibration.py`.*

La fusion transforme la probabilité du modèle local et les signaux de Threat Intelligence (étapes 2.4 à 2.9) en **un score de 0 à 100 et un verdict** : sûr, suspect ou phishing.

```python
from phishguard.fusion import ScoreCalibrator, fuse

calibrator = ScoreCalibrator.load("models/url_v1_calibration.json")
probability = calibrator(model.score([url])[0])  # probabilité calibrée
result = fuse(probability, enrichment.signals, allowlisted=False)
result.score, result.verdict, result.hard_rule, result.contributions
```

`fuse()` est une **fonction pure** : même entrée, même sortie, sans réseau ni horloge. Ses paramètres viennent d'un fichier versionné, validé au chargement : toute modification change sa `version`, recopiée dans chaque résultat.

## 1. Calibrer le modèle

Un score de 0,9 doit vouloir dire « environ 90 % des URLs de ce score sont du phishing ». Un modèle à arbres comme `url_v1` (LightGBM) classe bien les URLs, mais rien ne garantit que ses scores soient des probabilités. Or la fusion combine le modèle avec d'autres sources, et un score trop confiant écraserait tous les autres signaux.

`scripts/calibrate_url.py` (ou `make calibrate-url`) apprend sur la **validation** une fonction croissante score → probabilité :

| Méthode | Principe | Quand elle convient |
| --- | --- | --- |
| `isotonic` | Fonction en escalier, sans hypothèse de forme | Beaucoup d'exemples (la validation en a environ 21 000) |
| `sigmoid` (Platt) | Sigmoïde à deux paramètres | Peu d'exemples, ou une déformation simple |

Les deux méthodes sont comparées en **validation croisée sur la validation** (5 plis) : chaque probabilité est mesurée sur un pli qui n'a pas servi à l'apprendre, car une régression isotone colle à ses propres données. Le **test n'est jamais chargé** : il a été lu une fois à l'étape 1.7. La méthode au plus petit score de Brier est retenue, puis apprise sur toute la validation. Le rapport (`docs/metrics/url_calibration.json`) donne pour chaque méthode, et pour le score brut :

- le **score de Brier** : l'écart quadratique moyen entre la probabilité et le label ;
- l'**ECE** (*expected calibration error*) : l'écart moyen entre la probabilité annoncée et la proportion observée, tranche par tranche ;
- la perte logarithmique et le tableau de fiabilité.

### Résultats sur `url_v1`

Mesurés par `make calibrate-url` sur les 21 007 URLs de la validation (20 % de phishing), en validation croisée à 5 plis (`docs/metrics/url_calibration.json`) :

| Méthode | Brier | ECE | Perte logarithmique |
| --- | --- | --- | --- |
| Score brut | 0,0320 | 0,0109 | 0,1184 |
| **Isotone (retenue)** | **0,0315** | **0,0029** | **0,1168** |
| Platt | 0,0332 | 0,0091 | 0,1319 |

Le score brut est déjà correct **en moyenne** (ECE de 1,1 point), car 90 % des URLs ont un score sous 0,1 ou au-dessus de 0,9, deux zones où il est juste. Mais il est **trop confiant au milieu**, là où se jouent les verdicts « suspect » : les URLs notées entre 0,6 et 0,7 ne sont du phishing qu'à 49 %, celles entre 0,5 et 0,6 à 41 %. Après calibration isotone, les tranches de 0,5 à 0,6 et de 0,6 à 0,7 annoncent en moyenne 0,56 et 0,66, pour 60 % et 71 % observés, et l'ECE est divisée par près de 4. La méthode de Platt fait moins bien : sa sigmoïde ne suit pas la forme en S très marquée des scores LightGBM.

Une réserve : la validation a aussi servi à choisir le modèle à l'étape 1.6. Ces mesures sont donc un peu optimistes, mais le test reste intact pour une mesure finale.

C'est ce que fait `sklearn.calibration.CalibratedClassifierCV` sur un estimateur déjà entraîné, à une différence près : on calibre le **score** (une seule colonne), pas l'estimateur. La calibration tient dans quelques points enregistrés en **JSON** (`models/url_v1_calibration.json`), sans `pickle` : elle se relit sans exécuter de code et se porte telle quelle dans l'extension (module 5). La fonction étant croissante, le classement des URLs, et donc les seuils de l'étape 1.7, ne changent pas.

### La prévalence

Une probabilité calibrée dépend de la **proportion de phishing des données de calibration** : 20 % sur la validation, environ 1 % ou moins dans la réalité (`docs/evaluation.md`). Une probabilité de 0,9 calibrée sur la validation ne vaut plus que 0,27 à 1 % de phishing. `adjust_prevalence()` fait cette correction (règle de Bayes sur les cotes).

**La fusion utilise la probabilité calibrée sur la validation, sans correction**, et c'est un choix assumé : corrigée à 1 %, le modèle seul ne pourrait presque jamais dépasser le seuil « phishing ». C'est fidèle aux 47 % de précision mesurés à l'étape 1.7, mais cela ferait reposer tout le verdict sur la Threat Intelligence, qui est optionnelle. Les seuils de 30 et 70 sont donc à lire comme des **seuils de décision**, réglés sur la validation, et non comme des probabilités réelles. La correction reste disponible pour l'API (module 4), si l'on veut afficher une probabilité à prévalence réaliste.

## 2. Règles dures

Appliquées avant tout calcul, dans cet ordre :

| Règle | Verdict | Pourquoi |
| --- | --- | --- |
| Liste noire personnelle | phishing (100) | Choix explicite de l'utilisateur |
| Correspondance **Google Safe Browsing** | phishing (100) | Page confirmée par Google : aucun autre signal ne doit l'adoucir |
| Hôte qui imite des lettres latines (**`lookalike_host`**, étape 3.12) | phishing (100) | `аpple.com` n'est pas `apple.com`. Règle locale, mesurée à l'étape 3.8 : 99,4 % des homographes du test signalés, aucune URL légitime ([robustness-report.md](robustness-report.md)) |
| Liste blanche personnelle | sûr (0) | Choix explicite de l'utilisateur |

Safe Browsing passe **avant** la liste blanche : une page confirmée dangereuse reste signalée même si son domaine a été mis en liste blanche, par exemple un domaine légitime compromis, ou une liste blanche obtenue par manipulation (« ajoutez notre site à vos exceptions »). Une erreur ou une absence de réponse de Safe Browsing ne déclenche jamais la règle. La règle `lookalike_host` passe aussi avant la liste blanche : une liste blanche obtenue par confusion entre deux hôtes identiques à l'œil ne doit pas innocenter l'imitation. Elle entre dans la fusion comme un signal local (`lookalike_host_signal`), jamais comme une source interrogée. Elle a fait passer la configuration en version **1.1.0**.

## 3. Combinaison des signaux

Les signaux restants se combinent par un **« OU probabiliste » pondéré** :

```
p = 1 − (1 − p_modèle) × Π (1 − poids_source × risque_source)
```

Chaque indice indépendant de phishing **augmente** la probabilité, sans jamais la faire dépasser 1. Avec une moyenne pondérée, au contraire, des signaux rassurants dilueraient un indice fort, et une source absente changerait le résultat des autres.

Trois règles à connaître :

1. **Seuls les signaux `ok` comptent.** Une source en erreur, hors délai, désactivée ou en pause n'apporte rien : un signal manquant n'est pas un risque.
2. **Un signal rassurant ne fait pas baisser le score.** Un domaine de 10 ans ou un VirusTotal sans détection ne prouvent pas l'innocence d'une page : 21 % des phishings manqués à l'étape 1.8 étaient sur des sites anciens compromis. Le modèle reste le point de départ.
3. **Le poids** traduit la confiance accordée à une source, de 0 (ignorée) à 1 (crue telle quelle). Le risque, lui, est déjà normalisé par chaque source (étapes 2.4 à 2.7).

### Les poids, et pourquoi

| Source | Poids | Risque maximal apporté | Justification |
| --- | --- | --- | --- |
| Modèle URL | 1,0 | sa probabilité | Probabilité calibrée : elle entre telle quelle, c'est le point de départ de chaque analyse |
| VirusTotal | 0,9 | 0,9 | Verdict agrégé de dizaines de moteurs, déjà amorti par la source (1 moteur = 0,2, 5 moteurs = 1) |
| urlscan.io | 0,8 | 0,8 | Verdict d'un navigateur isolé sur la page réelle, mais un seul juge et parfois un scan ancien |
| RDAP (âge) | 0,6 | 0,6 | Un domaine de quelques jours est un signal fort, mais des services légitimes en créent aussi : il ne suffit pas seul |
| DNS | 0,5 | 0,25 | Signaux faibles (DNS gratuit, *fast flux*), déjà plafonnés à 0,5 par la source |
| Certificate Transparency | 0,4 | 0,24 | Un premier certificat récent recoupe l'âge RDAP ; un domaine ancien peut obtenir son premier certificat tard |
| Safe Browsing | règle dure | — | Voir plus haut |

Ces justifications sont aussi dans `fusion.json` (champ `rationale`) : la configuration refuse un poids qui n'est pas justifié.

Ce sont des **poids d'expert**, pas des poids appris. Les apprendre demanderait un jeu où chaque URL a ses signaux de Threat Intelligence *au moment de la collecte* : les flux de phishing disparaissent en quelques jours, et VirusTotal ou RDAP rejoués des semaines plus tard ne disent plus la même chose. Constituer ce jeu, en interrogeant les sources le jour même de la collecte (étape 1.1), est la piste pour la v2.

## 4. Score et verdict

Score = probabilité × 100, arrondi au plus proche.

| Score | Verdict |
| --- | --- |
| moins de 30 | **sûr** |
| de 30 à 70 compris | **suspect** |
| plus de 70 | **phishing** |

Les seuils sont dans `fusion.json` et sont à ajuster d'après l'évaluation de l'étape 1.7, sur la validation, jamais sur le test.

Le résultat donne aussi la **contribution de chaque source** en points de score : les effets se combinant par produit, ils s'additionnent en passant au logarithme, ce qui donne une répartition exacte et indépendante de l'ordre. Par exemple, pour l'exemple du plan ci-dessous : VirusTotal 65 points, RDAP 26, le modèle 6. C'est la matière des explications du module 3.

## Table de vérité

Les 18 cas de `tests/test_fusion_score.py`, avec les poids ci-dessus :

| Cas | Modèle | Signaux | Score | Verdict |
| --- | --- | --- | --- | --- |
| **Exemple du plan** | 0,2 | domaine de 3 jours, 6 moteurs VirusTotal | 97 | phishing |
| Modèle seul, très bas | 0,05 | — | 5 | sûr |
| Modèle seul, incertain | 0,5 | — | 50 | suspect |
| Modèle seul, très haut | 0,85 | — | 85 | phishing |
| Safe Browsing contre un modèle confiant | 0,01 | listé par Google | 100 | phishing |
| Liste blanche personnelle | 0,95 | — | 0 | sûr |
| Safe Browsing contre la liste blanche | 0,1 | listé, en liste blanche | 100 | phishing |
| Liste noire personnelle | 0,01 | — | 100 | phishing |
| Un seul moteur VirusTotal | 0,1 | 1 moteur | 26 | sûr |
| Deux moteurs VirusTotal | 0,1 | 2 moteurs | 42 | suspect |
| urlscan juge la page malveillante | 0,1 | verdict urlscan | 82 | phishing |
| Domaine de 20 jours | 0,2 | RDAP 0,8 | 58 | suspect |
| DNS gratuit seul | 0,1 | DNS 0,3 | 24 | sûr |
| Infrastructure neuve | 0,05 | domaine de 5 jours, premier certificat de 2 jours | 71 | phishing |
| Toutes les sources en panne | 0,6 | erreur, délai, désactivée | 60 | suspect |
| Signaux rassurants | 0,3 | VirusTotal propre, domaine ancien, Safe Browsing propre | 30 | suspect |
| Limite basse | 0,29 | — | 29 | sûr |
| Limite haute | 0,70 | — | 70 | suspect |

Des tests de propriétés (Hypothesis) vérifient aussi, sur des combinaisons aléatoires de signaux, que le score reste entre 0 et 100 et ne descend jamais sous celui du modèle. Plus de risque ne baisse jamais le score, et l'ordre des signaux ne change rien.

## Limites

- Les sources sont supposées **indépendantes**, ce que le « OU probabiliste » suppose. Ce n'est qu'approché : urlscan et VirusTotal peuvent s'appuyer sur les mêmes listes. Les poids inférieurs à 1 compensent en partie ce double comptage.
- Seul le modèle URL est calibré. Les modèles SMS et email (étapes 1.9 et 1.11) le seront quand ils entreront dans la fusion.
- Les poids sont des choix d'expert, documentés et testés, mais pas mesurés (voir plus haut).
