# Analyse d'erreurs du modèle URL (étape 1.8)

Les métriques disent **combien** le modèle se trompe ([`evaluation.md`](evaluation.md)) ; l'analyse d'erreurs dit **comment**. On extrait les 50 pires faux positifs (URLs légitimes avec la note la plus haute) et les 50 pires faux négatifs (phishing avec la note la plus basse) au seuil de décision de l'étape 1.7. On les range ensuite par catégorie et on en tire des pistes d'amélioration.

```bash
make errors-url                                   # = python scripts/analyze_url_errors.py
python scripts/analyze_url_errors.py --split test # lecture du test, une fois le modèle figé
python -m pytest tests/test_url_errors.py
```

| Sortie | Contenu | Versionné |
| :--- | :--- | :--- |
| `data/reports/url_errors_<bloc>.csv` | Les 100 erreurs avec URL complète, score, catégorie et étiquettes, pour la relecture | **Non** : URLs de phishing réelles |
| `docs/metrics/url_errors.json` | Effectifs par catégorie et par source, scores médians, exemples défangés | Oui |
| Blocs générés de ce document | Règles des catégories, résultats | Oui |

| Fichier | Rôle |
| :--- | :--- |
| `src/phishguard/urls/errors.py` | Sélection des pires erreurs, règles de catégorie, synthèse publiable, défangage |
| `src/phishguard/urls/data/hosting.json` | 50 plateformes où n'importe qui peut publier une page (stockage, images, sites gratuits, formulaires, déploiement) |
| `scripts/analyze_url_errors.py` | Commande unique |

## Méthode

1. **Bloc analysé : la validation.** L'analyse d'erreurs sert à choisir les prochaines améliorations. Si on la menait sur le test, on finirait par régler le modèle sur lui, et le test ne mesurerait plus rien. `--split test` existe pour une relecture finale, une fois le modèle figé.
2. **Seuil** : celui de l'étape 1.7, recalculé sur la validation avec la même règle (meilleur rappel tout en gardant une alerte vraie sur deux à 1 % de prévalence).
3. **Pires erreurs** : faux positifs triés par score décroissant, faux négatifs par score croissant ; les ex aequo sont départagés par la position, pour un résultat stable.
4. **Toutes les erreurs, pas seulement les pires.** La colonne « Toutes les erreurs » applique les mêmes règles à toutes les erreurs du seuil. Les 50 pires sont des cas extrêmes, et leur répartition peut être très différente.
5. **Catégories par règles explicites.** Chaque règle ne lit que l'URL (features de l'étape 1.5 et `hosting.json`), et les règles sont appliquées dans l'ordre du tableau ci-dessous : la première vraie donne la catégorie principale, toutes les vraies sont gardées comme étiquettes dans l'export. Une règle décrit ce que les features voient, pas la vérité du terrain : **la relecture humaine de l'export reste l'étape décisive**, et une catégorie mal remplie est un signal pour corriger la règle.
6. **Publication.** Les URLs de phishing réelles ne sont jamais versionnées. Le rapport ne garde que des exemples **défangés** (`hxxps://exemple[.]com/…`), sans requête (elle peut contenir un identifiant de session ou l'adresse de la victime), avec les adresses email masquées. Ils viennent uniquement des sources dont la licence permet la publication : PhishTank, URLhaus, Tranco, Common Crawl. Les conditions d'OpenPhish interdisent la redistribution ([`data-sources.md`](data-sources.md)). Les exemples de phishing publiés ici viennent de **PhishTank** (Cisco Talos), dont les conditions demandent une attribution : *données de phishing fournies par PhishTank, phishtank.org*.

### Catégories

Les catégories viennent du plan (service légitime avec long paramètre, hébergeur gratuit détourné, domaine neuf mais honnête) et des biais mesurés aux étapes 1.3 à 1.5 (chemin, popularité, TLD). Ce tableau est généré depuis `src/phishguard/urls/errors.py`, la seule source de vérité.

<!-- generated:errors-url-categories:start -->
| Type | Catégorie | Règle (dans l'ordre) | Piste d'amélioration |
| :--- | :--- | :--- | :--- |
| faux positif | Page légitime sur une plateforme d'hébergement | hôte dans `hosting.json` | Ne pas juger le domaine de la plateforme mais le sous-domaine ou le chemin ; réputation du compte (module 2). |
| faux positif | Nom proche d'une marque | `brand_in_host` ou `is_typosquat` | Compléter `brands.json` avec les domaines secondaires et filiales des marques ; liste d'autorisation des domaines les plus visités. |
| faux positif | Service légitime avec long paramètre | requête d'au moins 50 caractères ou 3 paramètres | Plus de pages légitimes avec requête à l'entraînement (Common Crawl) ; features sur la nature des paramètres (suivi, pagination) plutôt que leur longueur. |
| faux positif | Page interne profonde | au moins 4 segments ou 60 caractères de chemin | Biais de chemin (étape 1.3) : plus de pages internes légitimes, ou un modèle sans chemin ni longueur pour la navigation courante. |
| faux positif | Domaine peu connu, long ou chargé | hôte d'au moins 20 caractères, 2 tirets, 3 chiffres ou 2 sous-domaines | Biais de popularité (étape 1.5) : légitime moins visité à l'entraînement (bas du classement Tranco, Common Crawl au-delà des 5 000 premiers domaines). |
| faux positif | Extension souvent vue dans le phishing | `tld_phish_rate` au moins 2 fois l'a priori | Lisser davantage la table des TLD ou plafonner le poids de la feature ; le taux mesure aussi nos sources (étape 1.5). |
| faux positif | Autre | aucune règle précédente | Relecture manuelle de l'export détaillé. |
| faux négatif | Phishing sur une plateforme réputée | hôte dans `hosting.json` (stockage, site gratuit, formulaire) | Invisible pour des features lexicales : réputation de l'URL complète (Safe Browsing, urlscan.io, module 2) et analyse du contenu de la page. |
| faux négatif | Lien raccourci | `is_shortener` | Résoudre la redirection côté serveur, avec le garde-fou anti-SSRF (étape 2.3), puis analyser la destination. |
| faux négatif | Adresse IP | `host_is_ip` | Peu d'exemples à l'entraînement : règle explicite dans la fusion du score (étape 2.10) plutôt qu'un poids appris. |
| faux négatif | Signal lexical présent mais ignoré | `brand_in_host`, `is_typosquat`, `homograph_brand` ou mot-clé dans l'hôte | La feature voit le signal, le modèle ne lui donne presque aucun poids (trop rare à l'entraînement, étape 1.5) : contrainte de monotonie sur ces features (LightGBM `monotone_constraints`) ou règle explicite dans la fusion du score (étape 2.10). |
| faux négatif | Site honnête compromis | hôte sans signal lexical et chemin d'au moins 2 segments | Âge et historique du domaine (RDAP, étape 2.7) ne suffisent pas : c'est le chemin qui est nouveau. Réputation de l'URL et du contenu (module 2). |
| faux négatif | Nom composé trompeur, hors des listes | hôte sans signal lexical mais avec un tiret, chemin court, aucun mot-clé | Le leurre est dans le texte (`renew-<marque déformée>`, `info-<service public>`) mais hors des listes : compléter `brands.json` (services publics, opérateurs) et les mots-clés (`auth`, `renew`, `support`…), en mesurant le gain comme à l'étape 1.5. |
| faux négatif | Domaine neuf d'apparence honnête | hôte sans signal lexical ni tiret, chemin court, aucun mot-clé | Date de création du domaine (RDAP) et certificat récent (journaux CT, module 2) : le signal est dans le temps, pas dans le texte. |
| faux négatif | Autre | aucune règle précédente | Relecture manuelle de l'export détaillé. |
<!-- generated:errors-url-categories:end -->

## Résultats

<!-- generated:errors-url:start -->
*Généré par `scripts/analyze_url_errors.py` le 2026-10-27 (modèle `9aa07df2ec23`, bloc **validation**, seuil `fpr_0_5pct` : score > 0,8263). Exemples défangés, sans requête, hors OpenPhish. Chiffres complets : [`metrics/url_errors.json`](metrics/url_errors.json).*

### Faux positifs (légitime signalé)

84 erreurs au seuil de décision ; les 50 pires sont classées.

| Catégorie | Erreurs | Part | Toutes les erreurs | Score médian | Sources | Exemples |
| :--- | ---: | ---: | ---: | ---: | :--- | :--- |
| Page légitime sur une plateforme d'hébergement | 9 | 18 % | 9 (11 %) | 0,988 | commoncrawl 9 | `hxxps://ibb[.]co/fFczL9R`<br>`hxxps://ibb[.]co/G4TMyrWh`<br>`hxxps://ibb[.]co/F4tQ3sCg` |
| Nom proche d'une marque | 1 | 2 % | 3 (4 %) | 0,939 | tranco 1 | `hxxps://rakutenadvertising[.]io/` |
| Service légitime avec long paramètre | 6 | 12 % | 14 (17 %) | 0,921 | commoncrawl 6 | `hxxps://cs-server-s2s[.]yellowblue[.]io/sync-iframe?…`<br>`hxxps://cs-server-s2s[.]yellowblue[.]io/sync-iframe?…`<br>`hxxps://west[.]exch025[.]serverdata[.]net/owa/auth/logon.aspx?…` |
| Page interne profonde | 1 | 2 % | 5 (6 %) | 0,934 | commoncrawl 1 | `hxxps://doubleverify[.]com/pt/blog/tag/programmatic` |
| Domaine peu connu, long ou chargé | 20 | 40 % | 28 (33 %) | 0,960 | tranco 13, commoncrawl 7 | `hxxps://f8824e712f4b4a9114f13c173ccf90987716b7612c5d93eeaa883fed[.]com/`<br>`hxxps://disney-solitaire[.]app/`<br>`hxxps://chatcomepyoer3z5b75emxofz3vq74hb[.]com/` |
| Extension souvent vue dans le phishing | 6 | 12 % | 7 (8 %) | 0,934 | tranco 6 | `hxxps://helloservicemsk[.]app/`<br>`hxxps://chat-whaptsap[.]app/`<br>`hxxps://servermanager[.]app/` |
| Autre | 7 | 14 % | 18 (21 %) | 0,947 | commoncrawl 7 | `hxxps://onetag-sys[.]com/usync/?…`<br>`hxxps://onetag-sys[.]com/usync/?…`<br>`hxxps://ipapi[.]co/privacy/` |

### Faux négatifs (phishing manqué)

837 erreurs au seuil de décision ; les 50 pires sont classées.

| Catégorie | Erreurs | Part | Toutes les erreurs | Score médian | Sources | Exemples |
| :--- | ---: | ---: | ---: | ---: | :--- | :--- |
| Phishing sur une plateforme réputée | 3 | 6 % | 72 (9 %) | 0,009 | phishtank 3 | `hxxp://5l4fem[.]duckdns[.]org/`<br>`hxxp://vugkpb[.]duckdns[.]org/`<br>`hxxp://cdkctb[.]duckdns[.]org/` |
| Signal lexical présent mais ignoré | 4 | 8 % | 75 (9 %) | 0,008 | phishtank 4 | `hxxps://updatenetfx[.]fr/`<br>`hxxps://santandder[.]net/`<br>`hxxp://logindirect[.]net/` |
| Site honnête compromis | 0 | 0 % | 175 (21 %) | n/d |  | — |
| Nom composé trompeur, hors des listes | 5 | 10 % | 139 (17 %) | 0,009 | phishtank 5 | `hxxps://drive-workg[.]net/`<br>`hxxps://auth2-telekom[.]de/`<br>`hxxps://info-vitale[.]fr/` |
| Domaine neuf d'apparence honnête | 37 | 74 % | 235 (28 %) | 0,006 | phishtank 35, openphish 2 | `hxxps://irsci[.]net/`<br>`hxxp://cocrr[.]com/`<br>`hxxp://arovs[.]com/` |
| Autre | 1 | 2 % | 141 (17 %) | 0,003 | phishtank 1 | `hxxps://gift86[.]com/` |
<!-- generated:errors-url:end -->

## Ce que les features statiques ne verront jamais

Trois familles de faux négatifs n'ont **aucune trace lexicale** : l'URL ressemble à une URL honnête parce qu'elle l'est en partie.

- **Phishing sur une plateforme réputée** (`docs.google.com/forms/…`, `*.web.app`, `*.sharepoint.com`, `ipfs.io`) : le domaine est l'un des plus fiables du web. Le bloquer casserait des millions de pages légitimes.
- **Site honnête compromis** : un vieux domaine propre, avec une page de phishing déposée dans un sous-dossier.
- **Domaine neuf d'apparence honnête** : un nom court et sans mot-clé, enregistré la veille.

C'est la justification du module 2. Le signal qui manque n'est pas dans le texte de l'URL mais dans sa **réputation** (Google Safe Browsing, VirusTotal, urlscan.io), son **âge** (date de création RDAP, certificat récent dans les journaux de Certificate Transparency) et son **contenu** (formulaire de mot de passe sur une page qui n'appartient pas à la marque imitée). Le score lexical reste utile, hors ligne et instantané, mais il ne peut pas être le seul juge.

## Lecture

Lecture du 27/10/2026, après relecture de `data/reports/url_errors_validation.csv` (modèle `url_v1`, validation, seuil `fpr_0_5pct`). Au seuil de décision, la validation compte 84 faux positifs et 837 faux négatifs : le modèle manque bien plus de phishing qu'il ne dérange de pages légitimes, ce qui est le choix fait à l'étape 1.7.

**Corrections des règles après relecture.** La première exécution rangeait 43 des 50 pires faux négatifs dans « domaine neuf d'apparence honnête », dont `santandder[.]net`, qui est pourtant reconnu comme typosquat de Santander par la feature `is_typosquat`. Aucune catégorie de faux négatif ne regardait les marques ni les mots-clés. On a donc ajouté « signal lexical présent mais ignoré » et « nom composé trompeur ». On a aussi placé la règle « plateforme » avant la règle « marque » pour les faux positifs (`*.chatgpt[.]site` est un site d'utilisateur, pas une usurpation de ChatGPT), et ajouté `ibb.co` et `chatgpt.site` à `hosting.json`.

### Faux positifs

- **Domaine peu connu, long ou chargé (33 % de toutes les erreurs) : c'est le biais de popularité.** Ce sont des noms longs, avec des chiffres ou des tirets, que le modèle associe au phishing parce que le légitime d'entraînement est fait de domaines très visités aux noms courts.
- **Plusieurs « faux positifs » Tranco ressemblent à de vraies erreurs d'étiquette** : `chat-whaptsap[.]app` (imitation de WhatsApp), `f8824e712f…[.]com`, `chatcomepyoer3z5b75emxofz3vq74hb[.]com`, `30nqt3mainfkyl16mirror[.]cfd`. Tranco classe des domaines par trafic, pas par honnêteté : un domaine publicitaire, de suivi ou malveillant très actif peut y entrer. Le modèle a peut-être raison sur ces URLs, et le FPR mesuré sur les pages d'accueil est légèrement pessimiste. À noter dans [`data-bias.md`](data-bias.md).
- **Les pages internes signalées sont des services techniques ou des contenus d'utilisateurs** : synchronisation publicitaire avec redirection encodée dans la requête (`sync-iframe?…`, `usync/?…`), images hébergées sur `ibb[.]co`, et une vraie page de connexion Outlook Web (`/owa/auth/logon.aspx?url=…`). Sur cette dernière, l'URL a exactement la forme d'un phishing : aucune feature lexicale ne peut trancher.

### Faux négatifs

- **Les 50 pires ne représentent pas l'ensemble.** Ce sont presque tous des pages d'accueil nues sur un nom court et aléatoire (`irsci[.]net`, `cocrr[.]com`), avec un score proche de 0. Mais sur les 837 faux négatifs, « domaine neuf d'apparence honnête » ne fait que 28 %, et « site compromis » 21 %, alors qu'il est absent des 50 pires. Ce n'est pas non plus la forme « page d'accueil » qui trompe le modèle : 64 % du phishing de validation est une page d'accueil, et le rappel y est même meilleur (82 % contre 77 % avec chemin).
- **Hors de portée des features lexicales : environ 58 % des faux négatifs** (domaine neuf 28 %, site compromis 21 %, plateforme réputée 9 %). C'est la borne haute du gain à attendre de la réputation, de l'âge du domaine et du contenu (module 2), voir la section précédente.
- **Récupérable sans quitter l'URL : environ 26 %.** Les noms composés trompeurs (17 % : `auth2-telekom[.]de`, `info-vitale[.]fr`, `drive-workg[.]net`) portent un leurre absent des listes de l'étape 1.5 (`telekom`, `vitale`, `auth`, `renew`…). Pour le signal ignoré (9 % : `santandder[.]net`, `logindirect[.]net`), la feature se déclenche bien, mais le modèle n'en tient pas compte. C'est l'étape 1.5 qui l'annonçait : ces features sont trop rares à l'entraînement pour peser. Une contrainte de monotonie (une marque détectée ne peut pas faire baisser le score) ou une règle explicite dans la fusion (étape 2.10) est la piste la moins coûteuse.
- **« Autre » (17 %) reste sous le quart.** Ce sont surtout des cas proches du seuil qui cumulent des signaux faibles : plusieurs tirets (`votre-acces-prime[.]com`), TLD à risque (`.icu`, `.cyou`, `.lat`), chiffres. Il ne manque pas de catégorie, mais certaines URLs portent des leurres en français (`votre-espace-clients`, `pass-ca-services`) que la liste de mots-clés en anglais ne voit pas.

**Erreurs d'étiquette côté phishing.** Les URLs `duckdns[.]org` manquées n'ont pas de chemin : ce sont peut-être des pages déjà supprimées au moment du signalement, mais rien dans l'URL ne permet de le vérifier. Aucune URL de phishing de la relecture n'est clairement légitime.

## Limites

- 50 erreurs de chaque type, c'est un échantillon des cas extrêmes, pas de l'ensemble des erreurs : les parts par catégorie ne se généralisent pas aux erreurs proches du seuil.
- Les règles reposent sur des seuils fixés à la main (`LONG_QUERY_LENGTH`, `DEEP_PATH_DEPTH`…) ; changer un seuil change la répartition.
- `hosting.json` est une liste courte, écrite à la main : une plateforme absente fait tomber son phishing dans une autre catégorie. La relecture en a trouvé deux manquantes (`ibb.co`, `chatgpt.site`), et il en manque sûrement d'autres.
- Les règles ont été corrigées **après** avoir lu les erreurs de validation. C'est le rôle de la relecture, mais la répartition est donc un peu ajustée à ce bloc. Elle ne doit pas servir de chiffre de référence.
- Les exemples sont choisis parmi les 50 pires : une catégorie qui n'y figure pas, comme « site compromis », n'a pas d'exemple publié, même si elle pèse lourd parmi toutes les erreurs.
