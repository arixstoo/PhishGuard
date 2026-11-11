# Rapport de robustesse

*Étapes 3.7 et suivantes du cahier des charges. Code : `src/phishguard/adversarial/perturb.py` (perturbations), `src/phishguard/adversarial/benchmark.py` (mesures), `scripts/robustness_benchmark.py` (`make robustness`). Tests : `tests/test_adversarial_perturb.py`, `tests/test_robustness_benchmark.py`. Techniques mesurées : [evasion-catalog.md](evasion-catalog.md).*

Ce rapport mesure ce que gagne un attaquant qui modifie la forme de ses leurres sans en changer le sens, avant puis après chaque défense. Les chiffres sont ceux des modèles réels, sur les jeux de test réels, **même quand ils sont mauvais** : c'est leur raison d'être.

## Méthode

- **Modèle de menace** : celui du [catalogue](evasion-catalog.md#modèle-de-menace). L'attaquant teste ses leurres en boîte noire et doit garder leur effet sur la victime. Il n'a ni le modèle ni les données.
- **Perturbations** : celles de l'étape 3.6, appliquées telles quelles, une à la fois, avec une graine fixe (0) et une graine propre à chaque échantillon. Les réglages modérés ont été fixés **avant** toute mesure. Trois variantes à intensité maximale (`homoglyphs_full`, `zero_width_dense`, `pad_benign_long`) ont été ajoutées après le premier passage, qui montrait que les réglages modérés touchaient peu le modèle SMS. Elles sont signalées comme telles.
- **Jeux** :
  - **URL** : le bloc de test de l'étape 1.4 (21 004 URLs, dont 4 200 de phishing), le plus récent dans le temps et sans domaine commun avec l'entraînement ;
  - **SMS** : le bloc de test de la SMS Spam Collection (774 messages), avec le même dédoublonnage et le même split groupé par gabarit que `scripts/train_text.py` ;
  - **SMS français / arabe** : les 100 messages de `datasets/sms_fr_ar.csv`, hors distribution. Ils sont à lire avec leurs intervalles de confiance.
- **Mesures**, au seuil de décision de chaque modèle, réglé sur la validation (aucun réglage sur le test) :
  - **rappel** du phishing perturbé et son écart au rappel d'origine (**Δ rappel**) : ce que gagne l'attaquant ;
  - **FPR** du légitime perturbé de la même façon (**Δ FPR**). Un message légitime peut contenir des chiffres, une URL légitime de longs paramètres. Une défense qui signale toute forme inhabituelle n'est pas une défense ;
  - **Échappés** : phishing détecté sans perturbation, manqué avec.
- **Ce qui est perturbé** : tous les échantillons, phishing et légitimes. Ceux où la technique ne s'applique pas (une URL sur une adresse IP n'a pas de sous-domaine) restent dans le calcul, inchangés. La colonne « Phishing modifié » donne la part réellement touchée.

## Résultats avant défenses

<!-- generated:robustness-baseline:start -->
*Généré par `scripts/robustness_benchmark.py` le 2026-11-09, passage `baseline` : modèles d'origine, avant toute défense. Graine des perturbations : 0. Intervalles de Wilson à 95 % entre crochets ; « Échappés » : phishing détecté sans perturbation, manqué avec. Chiffres complets : [`metrics/robustness_baseline.json`](metrics/robustness_baseline.json).*

#### URL (test)

Modèle `url_v1` (`9aa07df2ec23`), seuil `fpr_0_5pct` (score > 0,8263), 4 200 URLs de phishing et 16 804 légitimes.

| Perturbation | Technique | Phishing modifié | Rappel | Δ rappel | FPR | Δ FPR | Échappés |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| *aucune* |  |  | 73,9 % [72,6–75,2 %] |  | 0,83 % [0,71–0,98 %] |  |  |
| `url_subdomains` | URL-03 | 100 % | 61,4 % [59,9–62,9 %] | **−12,5 pts** | 5,56 % [5,22–5,91 %] | +4,73 pts | 676 |
| `url_benign_path` | URL-04 | 100 % | 70,0 % [68,6–71,4 %] | **−3,9 pts** | 11,34 % [10,87–11,83 %] | +10,51 pts | 433 |
| `url_long_param` | URL-06 | 100 % | 82,2 % [81,0–83,3 %] | **+8,3 pts** | 49,14 % [48,38–49,89 %] | +48,30 pts | 126 |
| `url_uppercase` | URL-07 | 100 % | 73,9 % [72,6–75,2 %] | **±0,0 pts** | 0,83 % [0,71–0,98 %] | ±0,00 pts | 0 |
| `url_homoglyphs` | URL-02 | 98 % | 75,1 % [73,8–76,4 %] | **+1,2 pts** | 1,02 % [0,88–1,18 %] | +0,18 pts | 40 |

Pire perturbation : `url_subdomains` (URL-03), −12,5 pts de rappel ; 676 phishing détectés sans perturbation passent.

#### SMS (test UCI, anglais)

Modèle `text_v1` (`d583ba3f3e3a`), seuil `decision` (score > -0,2538), 96 spams et 678 légitimes.

| Perturbation | Technique | Phishing modifié | Rappel | Δ rappel | FPR | Δ FPR | Échappés |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| *aucune* |  |  | 94,8 % [88,4–97,8 %] |  | 1,47 % [0,80–2,69 %] |  |  |
| `zero_width` | TXT-02 | 100 % | 92,7 % [85,7–96,4 %] | **−2,1 pts** | 0,88 % [0,41–1,92 %] | −0,59 pts | 2 |
| `homoglyphs` | TXT-01 | 100 % | 93,8 % [87,0–97,1 %] | **−1,0 pts** | 0,88 % [0,41–1,92 %] | −0,59 pts | 2 |
| `leetspeak` | TXT-04 | 99 % | 96,9 % [91,2–98,9 %] | **+2,1 pts** | 10,03 % [7,99–12,52 %] | +8,55 pts | 0 |
| `split_symbols` | TXT-03 | 99 % | 94,8 % [88,4–97,8 %] | **±0,0 pts** | 0,59 % [0,23–1,51 %] | −0,88 pts | 0 |
| `pad_benign` | TXT-05 | 100 % | 83,3 % [74,6–89,5 %] | **−11,5 pts** | 0,15 % [0,03–0,83 %] | −1,33 pts | 11 |
| `homoglyphs_full` | TXT-01 | 100 % | 89,6 % [81,9–94,2 %] | **−5,2 pts** | 0,29 % [0,08–1,07 %] | −1,18 pts | 5 |
| `zero_width_dense` | TXT-02 | 100 % | 78,1 % [68,9–85,2 %] | **−16,7 pts** | 0,15 % [0,03–0,83 %] | −1,33 pts | 16 |
| `pad_benign_long` | TXT-05 | 100 % | 62,5 % [52,5–71,5 %] | **−32,3 pts** | 0,00 % [0,00–0,56 %] | −1,47 pts | 31 |

Pire perturbation : `pad_benign_long` (TXT-05), −32,3 pts de rappel ; 31 phishing détectés sans perturbation passent.

#### SMS français / arabe (hors distribution)

Modèle `text_v1` (`d583ba3f3e3a`), seuil `decision` (score > -0,2538), 50 messages frauduleux et 50 légitimes.

| Perturbation | Technique | Phishing modifié | Rappel | Δ rappel | FPR | Δ FPR | Échappés |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| *aucune* |  |  | 70,0 % [56,2–80,9 %] |  | 42,00 % [29,37–55,77 %] |  |  |
| `zero_width` | TXT-02 | 100 % | 70,0 % [56,2–80,9 %] | **±0,0 pts** | 46,00 % [32,97–59,60 %] | +4,00 pts | 3 |
| `homoglyphs` | TXT-01 | 86 % | 70,0 % [56,2–80,9 %] | **±0,0 pts** | 38,00 % [25,86–51,85 %] | −4,00 pts | 2 |
| `leetspeak` | TXT-04 | 86 % | 82,0 % [69,2–90,2 %] | **+12,0 pts** | 66,00 % [52,15–77,56 %] | +24,00 pts | 1 |
| `split_symbols` | TXT-03 | 100 % | 64,0 % [50,1–75,9 %] | **−6,0 pts** | 24,00 % [14,30–37,41 %] | −18,00 pts | 3 |
| `pad_benign` | TXT-05 | 100 % | 2,0 % [0,4–10,5 %] | **−68,0 pts** | 0,00 % [0,00–7,14 %] | −42,00 pts | 34 |
| `homoglyphs_full` | TXT-01 | 86 % | 58,0 % [44,2–70,6 %] | **−12,0 pts** | 42,00 % [29,37–55,77 %] | ±0,00 pts | 7 |
| `zero_width_dense` | TXT-02 | 100 % | 28,0 % [17,5–41,7 %] | **−42,0 pts** | 20,00 % [11,24–33,04 %] | −22,00 pts | 21 |
| `pad_benign_long` | TXT-05 | 100 % | 0,0 % [0,0–7,1 %] | **−70,0 pts** | 0,00 % [0,00–7,14 %] | −42,00 pts | 35 |

Pire perturbation : `pad_benign_long` (TXT-05), −70,0 pts de rappel ; 35 phishing détectés sans perturbation passent.
<!-- generated:robustness-baseline:end -->

## Lecture

### URL : le modèle a appris la forme des URLs de son jeu, dans les deux sens

- **Les sous-domaines ajoutés sont l'évasion la plus efficace** : −12,5 points de rappel, et 676 phishing détectés passent. `url_v1` associe un hôte court et sans sous-domaine au phishing (étape 3.1 : « 0 sous-domaine » est une raison quand l'hôte est long). Deux labels anodins (`support.`, `fr.`) suffisent à déplacer l'URL vers le légitime, alors que l'attaquant les crée gratuitement sur son propre domaine.
- **Le chemin bénin gagne peu en rappel (−3,9 points), mais fait exploser les faux positifs** (+10,5 points) : les pages d'accueil légitimes à qui l'on ajoute un chemin deviennent suspectes. C'est le biais de chemin mesuré dès l'étape 1.3, vu sous un autre angle : le modèle ne juge pas le chemin, il juge sa présence.
- **Un long paramètre de suivi fait signaler près d'une URL légitime sur deux** (FPR de 0,83 % à 49,1 %). Il ne sert donc pas l'attaquant : le rappel monte de 8,3 points. Mais les liens d'emailing légitimes portent justement de longs paramètres `utm_*`. C'est un **risque de faux positifs en production**, plus qu'une évasion, et il faudra le corriger (étape 3.9).
- **La casse de l'hôte ne change rien** (Δ nul, aucun échappé) : l'hôte est mis en minuscules avant les features. C'était attendu, et c'est le test de non-régression de la normalisation.
- **Les homographes ne trompent pas le modèle** : le rappel monte de 1,2 point, grâce aux features `host_mixed_script` et `homograph_brand` de l'étape 1.5. 40 phishing passent quand même. Ici, le « FPR » est trompeur : une URL légitime dont l'hôte est réécrit en cyrillique n'est plus le site légitime, c'en est une imitation, et la signaler est juste.

### SMS : les n-grammes de caractères résistent, la dilution non

- **Aux réglages modérés, homoglyphes et largeur nulle coûtent peu** (−1,0 et −2,1 points). Un n-gramme de 2 à 5 caractères survit si la lettre remplacée n'en fait pas partie, et le spam a beaucoup d'autres indices (numéros surtaxés, montants, « call », « free »). C'était l'argument du choix de `char_wb` à l'étape 1.9, et il tient.
- **À intensité maximale, ils coûtent cher** : une largeur nulle entre toutes les lettres fait perdre 16,7 points de rappel, et le remplacement de toutes les lettres possibles en fait perdre 5,2. Pour le lecteur, le message est identique. Ce sont exactement les cas que la normalisation de l'étape 3.8 doit annuler.
- **La dilution est l'attaque la plus forte** : 20 mots anodins font perdre 11,5 points de rappel, 50 mots en font perdre 32,3. Le TF-IDF est normalisé : chaque mot ajouté réduit le poids des n-grammes suspects, et ces mots ont des coefficients négatifs. La normalisation n'y peut rien. Les catégories de leurre (lien, code, argent), qui ne dépendent pas de la longueur, et l'entraînement adversarial (3.9) sont les pistes.
- **Le leetspeak augmente les faux positifs** (+8,55 points), plus qu'il n'aide l'attaquant : le modèle a appris que les chiffres signalent le spam (numéros, montants, codes). Un message légitime « c0mpte » est rare. Le même mécanisme expliquerait des faux positifs sur des messages légitimes riches en chiffres (horaires, références).
- **Couper les mots par des points ne change pas le rappel.** Les n-grammes qui contiennent `.` existent déjà dans le spam (URLs, abréviations).

### SMS français / arabe : déjà fragile sans perturbation

Le modèle, entraîné sur de l'anglais, signale 42 % des messages légitimes français et arabes avant toute perturbation. C'était déjà connu depuis l'étape 1.9. Sous dilution par des mots anglais anodins, le rappel tombe à 2 %, puis à 0 % : les mots anglais pèsent plus que tout ce que le modèle sait lire du message. Sur 100 messages, les intervalles de confiance sont larges, mais la conclusion ne dépend pas de quelques points. **Sans données d'entraînement en français et en arabe, aucune défense de ce module ne rendra le modèle fiable dans ces langues.**

## Ce que les défenses doivent viser

| Faiblesse mesurée | Perturbations | Défense prévue |
| --- | --- | --- |
| caractères différents, même lecture | `homoglyphs_full`, `zero_width_dense`, `zero_width`, `homoglyphs` | normalisation Unicode et repli des confusables (3.8) |
| hôte en écritures mêlées | `url_homoglyphs` | règle explicite d'alerte (3.8), en plus des features existantes |
| forme de l'URL (sous-domaines, chemin, requête) | `url_subdomains`, `url_benign_path`, `url_long_param` | entraînement adversarial (3.9) ; la normalisation n'y peut rien |
| dilution du texte | `pad_benign`, `pad_benign_long` | entraînement adversarial (3.9), catégories de leurre |
| chiffres pris pour un indice de spam | `leetspeak` | entraînement adversarial (3.9) |

## Comparaison des passages

Un passage par défense : `baseline` (modèles d'origine), puis chaque défense, sur les mêmes jeux et avec les mêmes perturbations.

<!-- generated:robustness-comparison:start -->
*Généré par `scripts/robustness_benchmark.py` à partir de `robustness_baseline.json`. Rappel et FPR au seuil de décision de chaque modèle.*

#### URL (test)

| Perturbation | Rappel `baseline` | FPR `baseline` |
| :--- | ---: | ---: |
| *aucune* | 73,9 % | 0,83 % |
| `url_subdomains` | 61,4 % | 5,56 % |
| `url_benign_path` | 70,0 % | 11,34 % |
| `url_long_param` | 82,2 % | 49,14 % |
| `url_uppercase` | 73,9 % | 0,83 % |
| `url_homoglyphs` | 75,1 % | 1,02 % |

#### SMS (test UCI, anglais)

| Perturbation | Rappel `baseline` | FPR `baseline` |
| :--- | ---: | ---: |
| *aucune* | 94,8 % | 1,47 % |
| `zero_width` | 92,7 % | 0,88 % |
| `homoglyphs` | 93,8 % | 0,88 % |
| `leetspeak` | 96,9 % | 10,03 % |
| `split_symbols` | 94,8 % | 0,59 % |
| `pad_benign` | 83,3 % | 0,15 % |
| `homoglyphs_full` | 89,6 % | 0,29 % |
| `zero_width_dense` | 78,1 % | 0,15 % |
| `pad_benign_long` | 62,5 % | 0,00 % |

#### SMS français / arabe (hors distribution)

| Perturbation | Rappel `baseline` | FPR `baseline` |
| :--- | ---: | ---: |
| *aucune* | 70,0 % | 42,00 % |
| `zero_width` | 70,0 % | 46,00 % |
| `homoglyphs` | 70,0 % | 38,00 % |
| `leetspeak` | 82,0 % | 66,00 % |
| `split_symbols` | 64,0 % | 24,00 % |
| `pad_benign` | 2,0 % | 0,00 % |
| `homoglyphs_full` | 58,0 % | 42,00 % |
| `zero_width_dense` | 28,0 % | 20,00 % |
| `pad_benign_long` | 0,0 % | 0,00 % |
<!-- generated:robustness-comparison:end -->

## Limites

- **Perturbations écrites à la main.** Elles reproduisent des techniques connues, une à la fois. Un attaquant les combine, et peut chercher automatiquement les mots qui font basculer le verdict. L'attaque automatisée par TextAttack, optionnelle à cette étape, n'a pas été lancée : elle demande PyTorch et un modèle à gradients ou des milliers de requêtes par message, et le modèle SMS est un SVM sur des caractères. Elle reste une piste pour le rapport final (3.11).
- **Un seul seuil.** Les mesures sont faites au seuil de décision. Le décalage moyen du score, dans le JSON, donne une idée de l'effet loin du seuil.
- **Le SMS n'est pas le phishing.** La classe positive de la SMS Spam Collection est le spam, dont le smishing n'est qu'une partie. Le jeu français / arabe est petit (100 messages).
- **Les jeux portent leurs biais.** Le légitime URL est fait de pages d'accueil Tranco et de pages internes Common Crawl ([data-bias.md](data-bias.md)). Une partie des faux positifs sous perturbation vient de ce mélange, pas seulement du modèle.
