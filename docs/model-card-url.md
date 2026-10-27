# Model card : modèle URL `url_v1`

Fiche d'identité du modèle de détection de phishing par URL, au format des *model cards* (Mitchell et al., 2019). Les chiffres sont générés depuis `docs/metrics/` par `make cards` ; le reste est écrit à la main. Détails : [`url-features.md`](url-features.md), [`url-models.md`](url-models.md), [`evaluation.md`](evaluation.md), [`error-analysis-url.md`](error-analysis-url.md).

## En bref

| | |
| :--- | :--- |
| Tâche | Probabilité qu'une URL soit une page de phishing, **à partir de l'URL seule** |
| Modèle | LightGBM sur 25 features lexicales calculées hors ligne |
| Entrée | Une URL (chaîne de caractères), jamais visitée ni résolue |
| Sortie | Un score de 0 à 1 et une décision au seuil `fpr_0_5pct` |
| Version | `url_v1`, module 1 de PhishGuard, licence MIT |
| Fichier | `models/url_v1.joblib`, régénéré par `make train-url` (non publié) |

## Usage prévu

- **Premier filtre, local et instantané**, dans l'extension, le bot et l'API (modules 4 et 5) : quelques millisecondes par URL, aucun appel réseau, aucune donnée envoyée.
- **Niveau « suspect », pas verdict final.** À la prévalence de la navigation réelle, le score seul produit plus de fausses alertes que de vraies (voir [Chiffres](#chiffres)). Il doit être combiné à la Threat Intelligence (module 2) avant toute alerte forte, et c'est ce que fera la fusion de l'étape 2.10.
- Utilisateurs visés : particuliers non techniciens, via l'extension et le bot ; analystes, via l'API et la vue technique.

## Ce que le modèle ne fait pas

- Il **ne visite pas la page** : aucun contenu, aucune capture, aucune redirection suivie. Un lien raccourci est jugé sur le raccourcisseur, pas sur sa destination.
- Il **ne connaît pas la réputation** du domaine, ni son âge, ni son certificat. Ce sont les signaux du module 2.
- Il **ne détecte pas** le phishing hébergé sur une plateforme réputée (Google Forms, `*.web.app`, SharePoint), sur un site honnête compromis, ou sous un nom de domaine neuf d'apparence banale. Ces trois cas représentent environ 58 % des faux négatifs de la validation ([`error-analysis-url.md`](error-analysis-url.md#lecture)).
- Il ne traite pas les malwares, le spam ou les arnaques sans page de connexion.
- Il n'est pas destiné à bloquer automatiquement un site, ni à juger un domaine pour une décision juridique ou commerciale.

## Données

- **Phishing** : PhishTank (validé par des humains, dates de signalement depuis 2011), OpenPhish (flux communautaire), URLhaus restreint aux étiquettes de phishing. Collecte quotidienne archivée ([`data-sources.md`](data-sources.md)).
- **Légitime** : pages d'accueil des domaines Tranco (top 100 000) et pages internes de ces domaines tirées de Common Crawl (top 5 000).
- **Nettoyage** ([`url-dataset.md`](url-dataset.md)) : URLs normalisées, doublons fusionnés, au plus 5 URLs par domaine enregistré, pages Common Crawl retirées si leur domaine héberge aussi du phishing.
- **Split** ([`split.md`](split.md)) : 70 / 15 / 15, **temporel** dans chaque source et **groupé par domaine enregistré** (aucun domaine dans deux blocs). Le test est le bloc le plus récent.
- Les données brutes ne sont pas publiées : les conditions d'OpenPhish interdisent la redistribution. Chaque rapport conserve l'empreinte SHA-256 du jeu utilisé.

## Chiffres

<!-- generated:card-url:start -->
*Généré par `scripts/model_cards.py` depuis [`metrics/url_v1.json`](metrics/url_v1.json) et [`metrics/url_v1_test.json`](metrics/url_v1_test.json).*

**Modèle** : LightGBM (`n_estimators=300, learning_rate=0.05, num_leaves=63, min_child_samples=20`), 25 features (jeu `without_scheme`), fichier `models/url_v1.joblib` (SHA-256 `9aa07df2ec23`), jeu `0310e419432c`, scikit-learn 1.9.1, LightGBM 4.7.0.

**Données**

| Bloc | URLs | Phishing | Première apparition | Sources |
| :--- | ---: | ---: | :--- | :--- |
| entraînement | 98 031 | 20,0 % | 18/02/2011 – 25/10/2026 | commoncrawl 7 933, openphish 853, phishtank 18 741, tranco 70 499, urlhaus 5 |
| validation | 21 007 | 20,0 % | 12/07/2026 – 25/10/2026 | commoncrawl 1 702, openphish 182, phishtank 4 016, tranco 15 107 |
| test | 21 004 | 20,0 % | 07/06/2024 – 25/10/2026 | commoncrawl 1 697, openphish 183, phishtank 4 016, tranco 15 107, urlhaus 1 |

**Sans seuil** (validation → test)

| Mesure | Validation | Test |
| :--- | ---: | ---: |
| PR-AUC | 0,956 | 0,939 |
| ROC-AUC | 0,981 | 0,975 |
| Rappel à 1 % FPR | 0,841 | 0,755 |
| Rappel à 0,1 % FPR | 0,671 | 0,582 |

**Au seuil de décision** (`fpr_0_5pct` : score > 0,8263, réglé sur la validation ; test, IC à 95 %)

| Mesure | Valeur |
| :--- | ---: |
| Rappel | 73,9 % [72,6–75,2 %] |
| FPR, tout le légitime | 0,83 % [0,71–0,98 %] |
| FPR, pages d'accueil | 0,21 % [0,15–0,30 %] |
| FPR, pages internes | 6,4 % [5,3–7,6 %] |

**Précision à la prévalence réelle** (même seuil)

| Phishing parmi les URLs | Précision | Fausses alertes par vraie | Précision, pages internes | Fausses par vraie, pages internes |
| :--- | ---: | ---: | ---: | ---: |
| 1 % | 47,3 % | 1,1 | 10,5 % | 9 |
| 0,1 % | 8,2 % | 11,3 | 1,1 % | 86 |

**Par source** (test, seuil de décision) : `commoncrawl` FPR 6,4 % (1 697 URLs) ; `openphish` rappel 78,1 % (183 URLs) ; `phishtank` rappel 73,7 % (4 016 URLs) ; `tranco` FPR 0,2 % (15 107 URLs).
<!-- generated:card-url:end -->

Comment lire ces chiffres :

- **Les chiffres à citer sont ceux du test.** Ceux de validation ont servi à choisir le modèle, les hyperparamètres et le seuil : ils sont optimistes. L'écart entre les deux vient d'une dérive dans le temps du phishing (le test est le plus récent) et du tirage des domaines des pages internes.
- **La règle du seuil** visait au moins une alerte vraie sur deux à 1 % de prévalence. Elle est atteinte sur la validation mais **pas sur le test, de peu**. Le seuil n'a pas été changé après lecture du test.
- **Pages internes** : c'est le chiffre à surveiller. Avec l'hypothèse « l'utilisateur ne visite que des pages internes », la précision s'effondre (voir le tableau de prévalence).

## Biais connus

| Biais | Effet mesuré | Ce qui a été fait |
| :--- | :--- | :--- |
| **Chemin** : le légitime Tranco n'a pas de chemin | Les pages internes légitimes reçoivent 20 fois plus de faux positifs que les pages d'accueil | Pages internes Common Crawl ajoutées (étape 1.3 bis) ; FPR rapporté séparément partout |
| **Schéma** : les URLs Tranco sont fabriquées en `https://` | `is_https` séparait les classes par construction | Feature retirée du modèle déployé (2 points de rappel perdus) |
| **Popularité** : le légitime vient des domaines les plus visités, aux noms courts | « Domaine peu connu, long ou chargé » : un tiers des faux positifs de la validation | Non corrigé. Il faudrait du légitime au-delà du top 100 000 |
| **TLD** : le taux de phishing par extension reflète aussi nos sources | Feature la plus utile, et la plus exposée | Table apprise sur l'entraînement seul, lissée ; vérifiée par un encodage hors-pli (écart < 1 point) |
| **Source** : 95 % du phishing vient de PhishTank | Rappel homogène PhishTank / OpenPhish sur le test | Surveillé par source dans chaque rapport |
| **Étiquettes** : Tranco classe par trafic, pas par honnêteté | Quelques « faux positifs » Tranco sont de vrais domaines malveillants | Noté ; le FPR des pages d'accueil est légèrement pessimiste |

## Limites

- Une seule graine et un seul split : un écart de moins d'un point de rappel entre deux variantes n'est pas significatif.
- Les features de marque et de typosquatting se déclenchent trop rarement à l'entraînement pour peser : `santandder[.]net` est reconnu comme typosquat mais manqué. Une contrainte de monotonie ou une règle explicite est à l'étude.
- Les listes de marques et de mots-clés sont surtout en anglais : les leurres en français (`votre-espace-clients`) et en arabe passent davantage.
- Le modèle vieillit : les campagnes changent de TLD et de formes d'URL. Il doit être réentraîné et réévalué régulièrement (étape 6.8).
- `models/url_v1.joblib` est un fichier pickle : ne jamais le charger depuis une source non fiable. Distribution signée : étape 4.12.

## Reproduire

```bash
make data          # collecte du jour, construction et split du jeu (voir la réserve ci-dessous)
make train-url evaluate-url errors-url cards
```

**Réserve** : les flux de phishing sont éphémères. Une collecte faite aujourd'hui ne redonne pas le jeu de ce rapport (empreinte ci-dessus) : elle donne un jeu comparable, avec d'autres chiffres. Retrouver exactement ces chiffres demande les archives chiffrées de la collecte quotidienne (`scripts/sync_feed_archives.py`), qui ne sont pas publiques, à cause des conditions d'OpenPhish.
