# Features URL (étape 1.5)

`src/phishguard/urls/features.py` transforme une URL en 26 features numériques, sans accès réseau. Elles alimentent les modèles URL de l'étape 1.6 et seront portées à l'identique en TypeScript pour l'extension (module 5).

```bash
python -m pytest tests/test_url_features.py          # 79 tests, dont les cas pièges du plan
python scripts/evaluate_url_features.py              # apport de chaque feature, sur la validation
```

```python
from phishguard.urls.features import url_features

url_features("http://paypa1-secure.com/login")
# {'is_https': 0.0, ..., 'brand_min_distance': 1.0, 'is_typosquat': 1.0, ...}
```

| Fichier | Rôle |
| :--- | :--- |
| `src/phishguard/urls/features.py` | Liste des features (`FEATURES`), découpage de l'URL, extracteur |
| `src/phishguard/urls/brands.py` | Marques hors de leur domaine officiel, typosquatting |
| `src/phishguard/urls/idn.py` | Punycode, écritures Unicode, squelette visuel (homographes) |
| `src/phishguard/urls/tld.py` | Taux de phishing par TLD, appris sur l'entraînement |
| `src/phishguard/urls/data/brands.json` | 172 marques souvent usurpées et leurs domaines officiels |
| `src/phishguard/urls/data/shorteners.json` | 33 raccourcisseurs d'URL |
| `src/phishguard/urls/ablation.py`, `scripts/evaluate_url_features.py` | Mesure de l'apport, écrit `docs/metrics/url_features.json` |
| `tests/fixtures/url_features_golden.json` | Valeurs de référence pour le portage TypeScript |

## Règles de conception

1. **Fonctions pures.** Aucun accès réseau (un test le vérifie en coupant les sockets), aucune dépendance à l'heure. La liste des suffixes publics est celle embarquée dans `tldextract`.
2. **Même lecture qu'à la construction du jeu.** L'URL passe d'abord par `normalize_url` (étape 1.2) : schéma ajouté s'il manque, hôte en minuscules, URL invalide refusée (`InvalidUrlError`).
3. **Groupes et familles.** Chaque feature a un *groupe* (schéma, hôte, chemin, longueur), pour retirer d'un coup les features exposées à un biais, et une *famille* (base, marque, homographe, TLD, raccourcisseur), pour mesurer l'apport de chaque ajout du plan.
4. **Longueur par composant** (hôte, chemin, requête), jamais de l'URL entière, comme décidé dans [`data-bias.md`](data-bias.md#ce-quon-fait).
5. **`www` n'est pas un sous-domaine.** Sa présence dépend de la source (100 % des URLs légitimes de PhiUSIIL), pas du risque.
6. **L'hôte se compte sous sa forme Unicode**, celle que lit l'utilisateur : `xn--pple-43d.com` (`аpple.com`) n'a ni tiret ni chiffre. La forme Punycode et la forme Unicode d'un même hôte donnent des features identiques (testé).
7. **Le chemin est décodé** (`%6Cogin` → `login`) pour chercher mots-clés, marques et URLs imbriquées ; les longueurs restent celles du texte brut.
8. **Petit ensemble.** 26 features, simples à porter et à expliquer.

## Les features

| Feature | Groupe | Famille | Définition |
| :--- | :--- | :--- | :--- |
| `is_https` | schéma | base | 1 si le schéma est `https` |
| `host_is_ip` | hôte | base | IPv6, ou hôte terminé par un nombre (IPv4, y compris `0x7f000001` ou `3232235777`, règle WHATWG) |
| `host_n_subdomains` | hôte | base | labels avant le domaine enregistré, sans un `www` initial |
| `host_n_hyphens`, `host_n_digits` | hôte | base | tirets, chiffres de l'hôte |
| `host_entropy` | hôte | base | entropie de Shannon des caractères de l'hôte |
| `host_kw_hits`, `path_kw_hits` | hôte, chemin | base | mots-clés de leurre présents (`login`, `verify`, `connexion`, `compte`…), comptés une fois chacun |
| `host_is_idn` | hôte | base | 1 si l'hôte contient un label internationalisé |
| `has_userinfo` | hôte | base | 1 si l'URL a des identifiants avant l'hôte (`https://paypal.com@evil.example/`) |
| `has_port` | hôte | base | 1 si un port non standard est indiqué |
| `path_depth`, `query_n_params` | chemin | base | segments du chemin, paramètres de la requête |
| `path_n_digits` | chemin | base | chiffres du chemin et de la requête |
| `path_has_embedded_url` | chemin | base | `http:`, `https:` ou `www.` dans le chemin ou la requête (redirection) |
| `host_len`, `path_len`, `query_len` | longueur | base | longueur de chaque composant |
| `brand_in_host` | hôte | marque | une marque apparaît dans l'hôte sans que ce soit son domaine officiel |
| `brand_min_distance` | hôte | marque | distance de Levenshtein du domaine à la marque la plus proche (plafond 3) |
| `is_typosquat` | hôte | marque | domaine à 1 modification d'une marque (2 pour un nom de 9 lettres ou plus) |
| `brand_in_path` | chemin | marque | une marque apparaît dans le chemin d'un domaine qui n'est pas le sien |
| `host_mixed_script` | hôte | homographe | un label mêle des écritures non admises ensemble (UTS #39) |
| `homograph_brand` | hôte | homographe | le squelette visuel de l'hôte contient une marque absente de sa forme réelle |
| `tld_phish_rate` | hôte | TLD | part de phishing du TLD à l'entraînement, lissée vers la moyenne |
| `is_shortener` | hôte | raccourcisseur | domaine de raccourcisseur connu |

### Marques

`brands.json` liste 172 marques souvent usurpées : grands services en ligne, banques, transporteurs, administrations françaises, services algériens, cryptomonnaies. Pour chacune, ses domaines officiels, **sous forme de domaines enregistrés** : un test vérifie que chacun en est bien un (il a trouvé `gov.uk`, un suffixe public, que la marque n'aurait jamais reconnu comme officiel).

- **Marques strictes.** Un nom court ou courant (`ups`, `orange`, `booking`) n'est reconnu que comme mot entier : `ups-suivi.com` oui, `groups.example.com` non. Elles sont exclues du typosquatting.
- **Domaines nationaux.** Une marque marquée `any_cctld` possède son nom sous les domaines nationaux (`maps.google.co.th`, `amazon.com.mx`). Exception : les codes pays vendus comme génériques (`.co`, `.io`, `.me`…), où `google.co` reste une usurpation.
- **Un mot contenu dans une marque n'est pas un typosquat.** `cloud` est à une lettre d'`icloud`, `mobile` de `tmobile` : sans cette règle, 187 URLs légitimes de l'entraînement étaient signalées, contre 92 avec. Ce qui reste est surtout une ressemblance réelle (`lacoste`/`laposte`, `pcloud`/`icloud`), parfois un vrai squat présent dans Tranco (`instgram.com`, `mlcrosoft.vip`).

### Homographes

`аpple.com` (« а » cyrillique) est envoyé en `xn--pple-43d.com`. `idn.py` le décode, repère le mélange latin + cyrillique, puis calcule un **squelette visuel** (accents retirés, lettres confusables remplacées par leur sosie latin, d'après un sous-ensemble court de la table *confusables* d'Unicode) et y cherche les marques. Le japonais, le chinois et le coréen mêlent légitimement plusieurs écritures : les combinaisons admises sont celles du profil « Highly Restrictive » d'UTS #39.

### TLD

`tld_phish_rate` est une moyenne lissée : `(phishing + 20 × a priori) / (total + 20)`, où l'a priori est la part globale de phishing à l'entraînement (20 %). Un TLD rare reste proche de l'a priori, un TLD inconnu le reçoit. La table s'apprend **sur l'entraînement seul** ; l'extracteur refuse la famille `tld` sans table.

## Apport mesuré

Validation de l'étape 1.4 (21 007 URLs, dont 4 198 de phishing et 1 702 pages internes légitimes). Même LightGBM pour tous, paramètres fixes non réglés. Les faux positifs par type de page sont mesurés au seuil qui donne 1 % de faux positifs sur tout le légitime. Chiffres complets : [`metrics/url_features.json`](metrics/url_features.json).

### Familles ajoutées une par une

| Features | Nombre | PR-AUC | R@1%FPR | R@0,1%FPR | FPR pages d'accueil | FPR pages internes |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| base | 18 | 0,952 | 0,804 | 0,587 | 0,32 % | 7,05 % |
| + marques | 22 | 0,952 | 0,807 | 0,568 | 0,32 % | 6,99 % |
| + homographes | 24 | 0,952 | 0,807 | 0,568 | 0,32 % | 6,99 % |
| + TLD | 25 | 0,965 | **0,857** | **0,689** | 0,34 % | 6,87 % |
| + raccourcisseurs | 26 | 0,965 | 0,853 | 0,657 | 0,34 % | 6,87 % |

Retirer une famille du modèle complet confirme l'ordre : sans TLD, le rappel à 1 % FPR perd 4,6 points ; sans marques, il ne perd rien (0,856).

### Groupes retirés

| Features | Nombre | PR-AUC | R@1%FPR | R@0,1%FPR | FPR pages d'accueil | FPR pages internes |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| toutes | 26 | 0,965 | 0,853 | 0,657 | 0,34 % | 6,87 % |
| sans schéma | 25 | 0,957 | 0,838 | 0,641 | 0,37 % | 6,58 % |
| sans chemin | 20 | 0,963 | 0,851 | 0,673 | 0,32 % | 7,05 % |
| sans longueur | 23 | 0,956 | 0,825 | 0,657 | 0,34 % | 6,87 % |
| sans chemin ni longueur | 17 | 0,902 | 0,722 | 0,599 | 0,65 % | 4,11 % |
| hôte seul | 16 | 0,892 | 0,703 | 0,589 | 0,71 % | 3,58 % |

### Lecture

- **Le TLD apporte le plus** (+5 points de rappel à 1 % FPR, +12 à 0,1 %), mais c'est aussi la feature la plus exposée au biais de collecte : le légitime vient des domaines les plus visités, surtout en `.com` et en domaines nationaux, alors que le phishing se loge dans des extensions bon marché. Une partie du gain mesure nos sources, pas le phishing. L'évaluation croisée entre sources (étape 1.7) dira ce qui en reste.
- **Les marques n'apportent rien de mesurable** au score : elles se déclenchent sur 4,3 % du phishing (0,8 % du légitime), et LightGBM retrouve l'essentiel avec les tirets, les chiffres et la longueur de l'hôte. On les garde pour l'explication : « imite PayPal » parle à l'utilisateur, « 3 tirets dans l'hôte » non (module 4).
- **Les homographes sont absents du jeu** : aucun hôte à écritures mêlées dans la validation. Leur apport n'est pas mesurable ici. On les garde parce que l'attaque est grave et la feature quasi gratuite ; les tests unitaires couvrent les cas d'attaque.
- **Les raccourcisseurs** ne concernent que 0,07 % du phishing. Leur effet (−3 points à 0,1 % FPR) n'est pas significatif : 0,1 % du légitime de validation, c'est 17 URLs, et une ou deux URLs suffisent à déplacer le rappel de plusieurs points. Seuls les écarts à 1 % FPR, sur 168 faux positifs, sont lisibles.
- **Le biais de chemin persiste.** Au seuil de 1 % de faux positifs, les pages internes en reçoivent 6,9 %, vingt fois plus que les pages d'accueil : elles font 10 % du légitime mais 70 % des faux positifs. Retirer chemin et longueur divise ce taux par 1,7, pour 13 points de rappel perdus. Retirer le chemin seul ne change rien, parce que `path_len` (groupe longueur) porte la même information.
- **Deux raccourcis nouveaux** apparaissent :
  - `is_https` est un **artefact de construction** : les URLs Tranco sont fabriquées en `https://<domaine>/` (étape 1.2), donc 100 % https, contre 94 % pour les vraies pages Common Crawl et 72 % pour le phishing. Le retirer coûte 1,5 point ;
  - `host_len` sépare à lui seul les classes (ROC-AUC 0,91) et porte la moitié du gain du modèle : un **biais de popularité**. Les domaines du haut de Tranco sont courts (12,5 caractères en moyenne, 17,5 pour les pages Common Crawl, 29 pour le phishing). Les sites peu connus que l'utilisateur visite aussi ont des noms plus longs.
- **Extraction** : 89 µs par URL en Python, cache par hôte compris.

### Ce qu'on en fait

1. **Toutes les features sont gardées** pour l'étape 1.6, qui réglera les modèles sur la validation. La décision finale de retirer une famille se prendra avec les modèles réglés, pas avec ce LightGBM par défaut.
2. **L'étape 1.6 entraînera chaque modèle avec et sans les groupes `scheme`, `path` et `length`**, et rapportera le FPR sur les pages internes ; un modèle « hôte seul » sert de référence.
3. **Remède de données au schéma Tranco** : récupérer le schéma réel de la page d'accueil (redirection effective) au lieu de supposer `https`. Noté dans [`data-bias.md`](data-bias.md).
4. **Le biais de popularité** sera mesuré à l'étape 1.7 en testant sur des domaines légitimes moins visités (bas du classement Tranco).

## Portage en TypeScript (module 5)

L'extension recevra l'URL du navigateur et devra produire exactement les mêmes valeurs. Points à reproduire :

- normalisation de `normalize_url` (schéma par défaut `http`, hôte en minuscules) ;
- liste des suffixes publics **avec** les domaines privés (`github.io`, `blogspot.com`), comme `tldextract(include_psl_private_domains=True)` ;
- Punycode RFC 3492, normalisation NFKC (vers ASCII) et NFKD (squelette) ;
- décodage du chemin : `%XX` en octets, puis UTF-8 avec remplacement des séquences invalides (comportement d'`urllib.parse.unquote`), `decodeURIComponent` levant une erreur dans ce cas ;
- écriture d'une lettre : premier mot de son nom Unicode (`LATIN`, `CYRILLIC`, `CJK` → `HAN`). En TypeScript, `\p{Script=…}` donne le même résultat sur les écritures concernées ;
- distance de Levenshtein classique (insertion, suppression, substitution de coût 1).

Les listes `brands.json` et `shorteners.json` sont relues telles quelles, la table des TLD sera exportée avec le modèle (`TldRiskTable.save`). `tests/fixtures/url_features_golden.json` donne les valeurs attendues pour 16 URLs pièges ; le test TypeScript devra les retrouver.

## Limites

- Les mesures portent sur un seul split et une seule graine.
- `brands.json` est écrite à la main : une marque absente n'est ni protégée ni comptée. Les filiales et domaines secondaires d'une marque (`samsungads.com`) ne sont pas tous listés et déclenchent `brand_in_host` à tort (0,8 % du légitime).
- La table des confusables est un sous-ensemble court (cyrillique, grec, quelques lettres latines) ; la table complète d'Unicode en compte plusieurs milliers.
- `label_to_ascii` approche IDNA sans en appliquer toutes les règles (bidirectionnel, caractères interdits) : un hôte que le navigateur refuserait peut recevoir des features.
- Les chiffres valent pour le jeu dont `docs/metrics/url_features.json` conserve l'empreinte SHA-256 ; relancer le script après chaque reconstruction du jeu.
