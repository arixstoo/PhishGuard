# Évaluation réaliste du modèle URL (étape 1.7)

Le jeu de test contient 20 % de phishing (voir [`split.md`](split.md)). Les URLs qu'un utilisateur visite en contiennent bien moins de 1 %. Le rappel et le taux de faux positifs (FPR) ne dépendent pas de cette proportion, la **précision** si : un détecteur qui paraît excellent sur le test peut produire plus de fausses alertes que de vraies dans la vie réelle. Ce document mesure cet écart et en déduit le seuil de décision.

```bash
make evaluate-url                      # = python scripts/evaluate_url.py (après make train-url)
python -m pytest tests/test_prevalence.py tests/test_url_evaluation.py
```

| Sortie | Contenu | Versionné |
| :--- | :--- | :--- |
| `docs/metrics/url_v1_test.json` | Points de fonctionnement sur la validation et le test, tables de prévalence, sources, rangs Tranco, empreintes du jeu et du modèle | Oui : aucune URL ni aucun domaine |
| Bloc généré de ce document | Tableaux de la section [Résultats](#résultats) | Oui |

| Fichier | Rôle |
| :--- | :--- |
| `src/phishguard/evaluation/prevalence.py` | Précision à une prévalence (formule et bootstrap), alertes pour 10 000 URLs, intervalle de Wilson |
| `src/phishguard/urls/evaluation.py` | Points de fonctionnement par type de page, règle du seuil de décision, sources, rangs Tranco |
| `scripts/evaluate_url.py` | Commande unique, écrit le rapport et les tableaux |

## Méthode

### Ce que voit chaque bloc

- **Validation** : choix du seuil de décision, par la règle ci-dessous. Les seuils candidats sont ceux enregistrés avec le modèle à l'étape 1.6 (score qui donne 5 %, 2 %, 1 %, 0,5 %, 0,2 % et 0,1 % de faux positifs sur le légitime de validation).
- **Test** : uniquement des mesures, une fois le seuil fixé. Si l'on retouche le modèle après avoir lu ces chiffres, le test n'est plus un test : il faut le dire dans la model card (étape 1.12).

### Prévalence et précision

Pour une prévalence `p`, un rappel `R` et un FPR `F` :

```
précision = p × R / (p × R + (1 − p) × F)
fausses alertes par vraie alerte = (1 − p) × F / (p × R)
```

À 0,1 % de prévalence, un FPR de 1 % et un rappel de 85 % donnent une précision de 7,8 % : **douze fausses alertes pour une vraie**. Le FPR doit descendre sous le millième pour qu'une alerte sur deux soit vraie.

Le plan demande de **rééchantillonner** le test à 1 % et 0,1 % de phishing. Le script le fait par bootstrap : chaque échantillon garde autant d'URLs légitimes que le test et le nombre d'URLs de phishing qui donne la prévalence voulue (environ 170 à 1 %, 17 à 0,1 %), tirées avec remise. 2 000 échantillons donnent la précision moyenne, qui concorde avec la formule, et un **intervalle à 95 %** (percentiles 2,5 et 97,5).

Ce que mesure cet intervalle, précisément : le rappel et le FPR sont **fixés** à leurs valeurs mesurées sur le test, et l'on regarde comment varie la précision **d'un échantillon de cette taille** à cette prévalence. C'est la dispersion qu'on observerait en évaluant le modèle sur un seul jeu qui aurait le légitime du test et 17 URLs de phishing : à 0,1 %, une ou deux détections de plus ou de moins font bouger la précision de plusieurs points, et il faut le voir. Ce n'est **pas** un intervalle de confiance sur la précision du modèle en conditions réelles :

- l'incertitude sur le rappel et le FPR eux-mêmes est donnée par les intervalles de Wilson du tableau des seuils (sur tout le phishing du test, donc bien plus serrée côté rappel) ;
- l'incertitude due au choix des sources et à la prévalence supposée n'est mesurée nulle part (voir [Limites](#limites)).

### Deux légitimes différents

Le légitime du test est fait à 90 % de pages d'accueil (Tranco), sur lesquelles le modèle se trompe rarement, et à 10 % de pages internes (Common Crawl), où il se trompe vingt fois plus (voir [`url-features.md`](url-features.md#lecture)). Un utilisateur, lui, visite surtout des pages internes : articles, fiches produit, pages de connexion. La précision est donc donnée sous deux hypothèses :

1. avec le FPR mesuré sur tout le légitime du test (hypothèse optimiste) ;
2. avec le FPR des seules pages internes (hypothèse plus proche de la navigation réelle).

La réalité est entre les deux, plus près de la seconde.

### Règle du seuil de décision

> **Le seuil retenu est celui qui détecte le plus de phishing parmi ceux pour lesquels, à 1 % de prévalence, au moins une alerte sur deux est vraie** (calculé sur la validation, avec le FPR de tout le légitime).

Pourquoi ces deux nombres :

- **Une alerte sur deux** : en dessous, l'utilisateur apprend que l'avertissement se trompe plus souvent qu'il n'a raison, et il clique sans lire. Une alerte ignorée ne protège personne.
- **1 % de prévalence** : c'est la proportion attendue parmi les liens **reçus** dans un SMS ou un email non sollicité, le cas d'usage principal de PhishGuard (extension sur Gmail, bot, page « coller et analyser »). Sur la navigation générale, la prévalence est plus proche de 0,1 % : aucun seuil lexical ne tient alors une alerte sur deux, d'où les deux mesures qui suivent.

Ce que la règle implique pour la suite :

1. **Le score URL seul ne doit pas bloquer.** Sous le seuil de décision, la fusion de l'étape 2.10 parle de « suspect », jamais de « phishing ». Au-dessus, la Threat Intelligence (module 2 : Safe Browsing, âge du domaine, certificat) sert à confirmer avant une alerte forte.
2. **Le seuil se revoit à chaque nouveau modèle**, avec la même règle : le script le recalcule, il n'est jamais fixé à la main.

## Résultats

<!-- generated:evaluate-url:start -->
*Généré par `scripts/evaluate_url.py` le 2026-10-27 (modèle `70b7838415a3`, jeu `0310e419432c`, test : 21 004 URLs dont 4 200 de phishing, soit 20,0 %). Chiffres complets : [`metrics/url_v1_test.json`](metrics/url_v1_test.json).*

### Sur le test, sans seuil

| PR-AUC | ROC-AUC | R@1%FPR | R@0,1%FPR |
| ---: | ---: | ---: | ---: |
| 0,939 | 0,975 | 0,755 | 0,582 |

### Seuils réglés sur la validation, mesurés sur le test

Intervalles de confiance à 95 % (Wilson) entre crochets.

| Seuil | Score | Rappel | FPR légitime | FPR pages d'accueil | FPR pages internes |
| :--- | ---: | ---: | ---: | ---: | ---: |
| FPR 5 % (val.) | 0,1892 | 90,7 % [89,8–91,6 %] | 5,60 % [5,26–5,96 %] | 1,82 % [1,62–2,05 %] | 39,2 % [36,9–41,6 %] |
| FPR 2 % (val.) | 0,5063 | 82,9 % [81,7–84,0 %] | 2,54 % [2,31–2,79 %] | 0,78 % [0,65–0,93 %] | 18,2 % [16,4–20,1 %] |
| FPR 1 % (val.) | 0,6960 | 78,9 % [77,6–80,1 %] | 1,43 % [1,26–1,62 %] | 0,44 % [0,35–0,56 %] | 10,2 % [8,8–11,7 %] |
| FPR 0,5 % (val.) **(décision)** | 0,8263 | 73,9 % [72,6–75,2 %] | 0,83 % [0,71–0,98 %] | 0,21 % [0,15–0,30 %] | 6,4 % [5,3–7,6 %] |
| FPR 0,2 % (val.) | 0,9342 | 65,0 % [63,5–66,4 %] | 0,27 % [0,21–0,36 %] | 0,05 % [0,03–0,10 %] | 2,2 % [1,6–3,1 %] |
| FPR 0,1 % (val.) | 0,9719 | 58,1 % [56,6–59,6 %] | 0,09 % [0,05–0,15 %] | 0,03 % [0,01–0,07 %] | 0,6 % [0,4–1,2 %] |

### Prévalence et précision

Précision attendue quand 1 % ou 0,1 % des URLs sont du phishing (formule ; entre crochets, intervalle bootstrap à 95 % : dispersion de la précision sur un échantillon de cette taille, rappel et FPR fixés, voir [Méthode](#prévalence-et-précision)). « Pages internes » : même calcul si le légitime visité ne contenait que des pages internes, plus proche de la navigation réelle.

| Seuil | Précision au test (20 %) | Précision à 1 % | Précision à 0,1 % | Fausses alertes par vraie à 0,1 % | Précision à 1 %, pages internes | Fausses par vraie à 0,1 %, pages internes |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| FPR 5 % (val.) | 80,2 % | 14,1 % [13,2–15,1 %] | 1,6 % [1,3–1,8 %] | 61,7 | 2,3 % | 432,2 |
| FPR 2 % (val.) | 89,1 % | 24,8 % [22,7–27,0 %] | 3,2 % [2,4–3,9 %] | 30,6 | 4,4 % | 219,5 |
| FPR 1 % (val.) | 93,2 % | 35,8 % [32,6–39,5 %] | 5,2 % [3,9–6,6 %] | 18,1 | 7,2 % | 129,1 |
| FPR 0,5 % (val.) **(décision)** | 95,7 % | 47,3 % [42,8–52,4 %] | 8,2 % [5,8–10,8 %] | 11,3 | 10,5 % | 86,0 |
| FPR 0,2 % (val.) | 98,3 % | 70,6 % [64,3–77,0 %] | 19,2 % [12,5–27,7 %] | 4,2 | 22,7 % | 34,4 |
| FPR 0,1 % (val.) | 99,4 % | 86,8 % [80,5–92,5 %] | 39,5 % [25,9–58,3 %] | 1,5 | 47,5 % | 11,1 |

**Seuil de décision** : `fpr_0_5pct` (score > 0,8263). Règle appliquée sur la validation : meilleur rappel parmi les seuils dont la précision attendue à 1 % de phishing atteint 50 % ; précision attendue sur la validation : 61,8 %, rappel 80,1 %.

### Par source (seuil de décision)

| Source | Classe | Mesure | URLs | Valeur |
| :--- | :--- | :--- | ---: | ---: |
| `commoncrawl` | légitime | FPR | 1 697 | 6,4 % [5,3–7,6 %] |
| `openphish` | phishing | rappel | 183 | 78,1 % [71,6–83,5 %] |
| `phishtank` | phishing | rappel | 4 016 | 73,7 % [72,3–75,1 %] |
| `tranco` | légitime | FPR | 15 107 | 0,2 % [0,2–0,3 %] |
| `urlhaus` | phishing | rappel | 1 | 0,0 % [0,0–79,3 %] |

### Pages d'accueil légitimes par rang Tranco (seuil de décision)

| Rang Tranco | URLs | FPR |
| :--- | ---: | ---: |
| 1 à 1 000 | 110 | 0,91 % [0,16–4,97 %] |
| 1 001 à 10 000 | 1 249 | 0,00 % [0,00–0,31 %] |
| 10 001 à 100 000 | 13 748 | 0,23 % [0,16–0,32 %] |
| au-delà de 100 000 | 0 | n/d |
| hors liste | 0 | n/d |
<!-- generated:evaluate-url:end -->

## Lecture

Lecture du modèle `url_v1` (`70b7838415a3`), relue le 27/10/2026. Les chiffres de validation viennent de [`metrics/url_v1.json`](metrics/url_v1.json) et du champ `validation_operating_points` de [`metrics/url_v1_test.json`](metrics/url_v1_test.json).

**Le seuil de décision atteint-il la cible ?** Sur la validation, oui : `fpr_0_5pct` donne 61,8 % de précision attendue à 1 % de prévalence, et le seuil suivant, `fpr_1pct`, n'y arrive pas (46 %). Sur le test, **non, de peu** : 47,3 % (intervalle bootstrap 42,8–52,4 %), parce que le FPR passe de 0,50 % à 0,83 % et le rappel de 80 % à 74 %. On ne change pas le seuil après avoir lu le test : ce serait régler le modèle sur le test. On note l'écart, et c'est la règle appliquée à la prochaine version du modèle qui le corrigera. Avec l'hypothèse « pages internes », on est loin de la cible quel que soit le seuil : 10,5 % de précision à 1 % pour le seuil de décision, et 47,5 % au mieux avec le seuil le plus strict.

**Combien de fausses alertes par vraie à 0,1 % ?** 11 au seuil de décision avec le légitime du test, **86** avec l'hypothèse « pages internes ». Même au seuil le plus strict (`fpr_0_1pct`), il en reste 11 avec cette hypothèse. Sur la navigation générale, le score URL seul ne peut donc qu'alimenter un niveau « suspect », comme le prévoit la règle.

**Les scores de test sont-ils proches de ceux de validation ?** Non, l'écart dépasse quelques points. Sans seuil, la PR-AUC passe de 0,956 à 0,939, le rappel à 1 % FPR de 0,841 à 0,755, à 0,1 % FPR de 0,671 à 0,582. L'écart vient de deux endroits :

- **le phishing** : le rappel au seuil de décision baisse de 80 % à 74 % pour PhishTank, la source principale. C'est cohérent avec une dérive dans le temps, le test étant le bloc le plus récent ;
- **les pages internes** : leur FPR double (3,4 % → 6,4 % au seuil de décision ; 6,8 % → 10,2 % au seuil `fpr_1pct`), alors que celui des pages d'accueil ne bouge pas (0,18 % → 0,21 %). Ces pages viennent de seulement 449 domaines en validation et 500 en test, et les fausses alertes se concentrent sur 33 et 58 d'entre eux : une bonne partie de l'écart peut venir du tirage des domaines, pas du modèle.

Les seuils réglés sur la validation sont donc un peu optimistes, surtout pour les pages internes. Ce sont les chiffres du test qu'il faut citer.

**Le rappel est-il homogène entre PhishTank et OpenPhish ?** Oui à la précision près : 73,7 % [72,3–75,1 %] pour PhishTank, 78,1 % [71,6–83,5 %] pour OpenPhish, dont les 183 URLs ne permettent pas de trancher. Aucun écart fort, donc pas de signe ici du biais de source de l'étape 1.3. URLhaus (une seule URL) ne se lit pas.

**Le FPR monte-t-il quand le rang Tranco baisse ?** Non, rien de mesurable au seuil de décision : 0,9 % sur le top 1 000 (une seule URL sur 110), 0 % de 1 001 à 10 000, 0,23 % de 10 001 à 100 000. Les intervalles se recouvrent tous. Le biais de popularité de `host_len` ne se voit pas à ce seuil sur les pages d'accueil. Il ne pourra se tester vraiment qu'avec des domaines au-delà du top 100 000, que le jeu ne contient pas.

## Limites

- L'intervalle bootstrap mesure la variabilité d'un petit échantillon à la prévalence voulue, à rappel et FPR fixés (voir [Prévalence et précision](#prévalence-et-précision)) ; il ne couvre ni l'erreur sur le rappel et le FPR mesurés, ni le choix des sources : un test tiré des mêmes flux que l'entraînement reste optimiste face à des campagnes nouvelles.
- Les intervalles de Wilson supposent des URLs indépendantes. Or le jeu garde jusqu'à 5 URLs par domaine, qui se ressemblent et sont souvent signalées ensemble. L'effet est fort pour les pages internes (environ 1 700 URLs de 500 domaines seulement) : leurs intervalles sont trop étroits, et un intervalle calculé par domaine (bootstrap groupé) serait plus honnête.
- La prévalence réelle n'est pas mesurée, elle est supposée (1 % et 0,1 %). Elle varie selon le canal (navigation, email, SMS) et selon l'utilisateur.
- Les pages internes viennent des 5 000 domaines les plus visités (Common Crawl, étape 1.3 bis) : les sites peu connus, sur lesquels le modèle se trompe probablement plus, n'y sont pas.
- Le FPR par rang Tranco demande les listes Tranco brutes qui ont servi à construire le jeu (`data/raw/tranco_*.csv`, non versionnées) : le script les retrouve dans `docs/metrics/urls_dataset.json` et vérifie leur empreinte. Un domaine prend son rang dans la plus récente de ces listes qui le contient. Le jeu ne retient que le top 100 000 : la tranche « au-delà de 100 000 » reste vide tant qu'on ne collecte pas une liste plus longue.
