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

Le plan demande de **rééchantillonner** le test à 1 % et 0,1 % de phishing. Le script le fait par bootstrap : chaque échantillon garde autant d'URLs légitimes que le test et le nombre d'URLs de phishing qui donne la prévalence voulue (environ 170 à 1 %, 17 à 0,1 %), tirées avec remise. 2 000 échantillons donnent la précision moyenne, qui concorde avec la formule, et surtout un **intervalle de confiance** : à 0,1 %, 17 URLs de phishing par échantillon rendent la précision très instable, et il faut le voir.

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
*Pas encore généré : lancez `make evaluate-url` après `make train-url`. Ce bloc est réécrit à chaque exécution.*
<!-- generated:evaluate-url:end -->

## Lecture

*À rédiger après la première exécution sur le jeu réel*, en répondant à ces questions :

- Le seuil de décision atteint-il la cible (une alerte vraie sur deux à 1 %) ? Sinon, de combien en est-on loin ?
- Combien de fausses alertes par vraie alerte à 0,1 % de prévalence, avec l'hypothèse « pages internes » ?
- Les scores de test sont-ils proches de ceux de validation (`docs/metrics/url_v1.json`) ? Un écart de plus de quelques points signale un sur-ajustement à la validation ou une dérive dans le temps (le test est le bloc le plus récent).
- Le rappel est-il homogène entre PhishTank et OpenPhish ? Un écart fort confirme le biais de source de l'étape 1.3.
- Le FPR monte-t-il quand le rang Tranco baisse ? Si oui, le biais de popularité de `host_len` (étape 1.5) est confirmé.

## Limites

- Le bootstrap mesure l'incertitude due à la taille du test, pas celle due au choix des sources : un test tiré des mêmes flux que l'entraînement reste optimiste face à des campagnes nouvelles.
- La prévalence réelle n'est pas mesurée, elle est supposée (1 % et 0,1 %). Elle varie selon le canal (navigation, email, SMS) et selon l'utilisateur.
- Les pages internes viennent des 5 000 domaines les plus visités (Common Crawl, étape 1.3 bis) : les sites peu connus, sur lesquels le modèle se trompe probablement plus, n'y sont pas.
- Le FPR par rang Tranco demande la liste Tranco brute (`data/raw/tranco_*.csv`), non versionnée.
