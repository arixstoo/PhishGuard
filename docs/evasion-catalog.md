# Catalogue des techniques d'évasion

*Étape 3.5 du cahier des charges. Ce catalogue recense les façons dont un attaquant peut modifier une URL, un message ou un email pour qu'il échappe aux détecteurs de PhishGuard. Il sert de cahier des charges aux étapes suivantes : la bibliothèque de perturbations (3.6) reproduit une partie de ces techniques, le banc d'essai (3.7) mesure leur effet sur les modèles, et les défenses (3.8, 3.9) les ciblent une par une.*

## Pourquoi un catalogue

Un détecteur de phishing appris sur des exemples a un adversaire, contrairement à la plupart des modèles. L'attaquant voit le verdict (il teste ses pages contre les filtres avant d'envoyer sa campagne) et il modifie son leurre jusqu'à passer. Les modèles de PhishGuard lisent des **formes** : la longueur d'un hôte, des n-grammes de caractères, des mots-clés. Changer la forme sans changer le sens est donc l'attaque naturelle, et elle ne demande aucun accès au modèle.

Chaque fiche répond à cinq questions :

- **Description** : ce que fait l'attaquant, avec un exemple sur un domaine réservé (`example.com`, `.test`, `.example`) ;
- **Vecteur** : URL, texte (SMS, messagerie) ou email ;
- **Pourquoi ça trompe un modèle** : la feature ou le mécanisme précis de PhishGuard qui est contourné ;
- **Contre-mesure** : ce qui existe déjà dans le code, et ce qui est prévu, avec l'étape correspondante ;
- **Références** : technique de [MITRE ATLAS](https://atlas.mitre.org/) (attaques contre les systèmes d'IA) et de [MITRE ATT&CK](https://attack.mitre.org/) (comportement de l'attaquant).

## Modèle de menace

- **Attaquant visé** : un opérateur de campagne de phishing ou de smishing. Il peut tester ses leurres contre PhishGuard autant qu'il veut (boîte noire, ATLAS AML.T0042 *Verify Attack*), mais il n'a ni le modèle, ni ses poids, ni ses données d'entraînement.
- **Contrainte de l'attaquant** : la modification doit **garder l'effet sur la victime**. Une URL doit rester cliquable et mener à la page, un message doit rester lisible. C'est ce qui sépare une évasion d'un simple bruit, et c'est ce que les perturbations de l'étape 3.6 respectent.
- **Hors périmètre** : l'empoisonnement des données d'entraînement (les flux publics de l'étape 1.1 en seraient le vecteur, voir les [pistes futures](#pistes-futures)), le vol du modèle par requêtes, et les attaques contre l'API elle-même (module 4).

## Références communes

Vérifiées le 9 novembre 2026 contre les données officielles : paquet STIX d'**ATT&CK Enterprise v20.1** ([attack-stix-data](https://github.com/mitre-attack/attack-stix-data)) et **ATLAS 5.6.0** ([atlas-data](https://github.com/mitre-atlas/atlas-data)). Aucune technique citée n'est révoquée ni dépréciée.

| Identifiant | Intitulé | Rôle dans ce catalogue |
| --- | --- | --- |
| [AML.T0015](https://atlas.mitre.org/techniques/AML.T0015) | Evade AI Model (anciennement *Evade ML Model*) | objectif de toutes les techniques : obtenir un verdict « sûr » pour un leurre |
| [AML.T0043.003](https://atlas.mitre.org/techniques/AML.T0043.003) | Craft Adversarial Data: Manual Modification | modification à la main, sans optimisation : la plupart des fiches |
| [AML.T0043.001](https://atlas.mitre.org/techniques/AML.T0043.001) | Craft Adversarial Data: Black-Box Optimization | modification guidée par les verdicts du détecteur (dilution, attaques automatisées) |
| [AML.T0042](https://atlas.mitre.org/techniques/AML.T0042) | Verify Attack | l'attaquant vérifie que son leurre passe avant de l'envoyer |
| [AML.T0052](https://atlas.mitre.org/techniques/AML.T0052) | Phishing | phishing rédigé ou personnalisé à l'aide d'un modèle de langage |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing (.001 Attachment, .002 Link, .003 via Service) | vecteur d'accès initial de toutes les fiches |
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains | domaines achetés pour imiter une marque |
| [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | Acquire Infrastructure: Web Services | pages hébergées sur un service de confiance |
| [T1584.001](https://attack.mitre.org/techniques/T1584/001/) | Compromise Infrastructure: Domains | site légitime compromis |
| [T1608.005](https://attack.mitre.org/techniques/T1608/005/) | Stage Capabilities: Link Target | lien intermédiaire (raccourcisseur, redirection) |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading (.008 Masquerade File Type) | se faire passer pour un objet légitime |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information (.006 HTML Smuggling) | masquer un contenu à l'analyse |

ATT&CK décrit des comportements d'attaquant, pas des attaques contre un modèle : la plupart des évasions de texte n'ont pas de technique dédiée. T1027 est alors la plus proche (rendre un contenu difficile à analyser), et c'est indiqué comme tel. T1656 *Impersonation*, qui aurait convenu à l'usurpation de marque, est révoquée depuis ATT&CK v20.0 ([mitre-attack.md](mitre-attack.md)).

## Vue d'ensemble

Statut de la contre-mesure, établi à l'étape 3.5 et mis à jour à chaque défense (dernière mise à jour : étape 3.9) : **en place** (le code la contient et des tests la vérifient), **partielle** (elle existe mais ne couvre pas toutes les variantes), **prévue** (une étape du plan la traite), **non couverte** (aucune étape ne la traite encore).

| Id | Technique | Vecteur | Contre-mesure | Statut |
| --- | --- | --- | --- | --- |
| [URL-01](#url-01--typosquatting) | Typosquatting | URL | `is_typosquat`, `brand_min_distance` | partielle |
| [URL-02](#url-02--homographes-idn) | Homographes IDN | URL | `host_mixed_script`, `homograph_brand`, règle d'alerte des hôtes (3.8) | en place |
| [URL-03](#url-03--sous-domaines-trompeurs) | Sous-domaines trompeurs | URL | `brand_in_host`, `host_n_subdomains`, entraînement adversarial (3.9) | en place |
| [URL-04](#url-04--chemins-et-paramètres-bénins) | Chemins et paramètres bénins | URL | entraînement adversarial (3.9) | en place |
| [URL-05](#url-05--domaine-de-confiance-détourné) | Domaine de confiance détourné | URL | Threat Intelligence (module 2) | partielle |
| [URL-06](#url-06--url-très-longue) | URL très longue | URL | longueurs par composant ; entraînement adversarial (3.9) | en place |
| [URL-07](#url-07--casse-mêlée) | Casse mêlée | URL | normalisation de l'hôte, mots-clés sans casse | en place |
| [URL-08](#url-08--raccourcisseurs-et-redirections) | Raccourcisseurs et redirections | URL | `is_shortener`, `path_has_embedded_url` | partielle |
| [URL-09](#url-09--identifiants-avant-lhôte) | Identifiants avant l'hôte | URL | `has_userinfo` | en place |
| [TXT-01](#txt-01--homoglyphes) | Homoglyphes | texte | repli des confusables (3.8) | en place |
| [TXT-02](#txt-02--caractères-de-largeur-nulle) | Caractères de largeur nulle | texte | catégories Cf et Cc retirées, mots-clés et modèle (3.8) | en place |
| [TXT-03](#txt-03--mots-coupés-par-des-symboles) | Mots coupés par des symboles | texte | n-grammes de caractères ; entraînement adversarial (3.9) | en place |
| [TXT-04](#txt-04--leetspeak) | Leetspeak | texte | n-grammes de caractères ; entraînement adversarial (3.9) | en place |
| [TXT-05](#txt-05--dilution-par-du-texte-légitime) | Dilution par du texte légitime | texte | catégories de leurre ; entraînement adversarial (3.9) | partielle |
| [TXT-06](#txt-06--message-en-image) | Message en image | texte, email | aucune | non couverte |
| [TXT-07](#txt-07--message-rédigé-par-un-llm) | Message rédigé par un LLM | texte, email | signaux d'infrastructure (module 2) ; mesure (3.10) | prévue |
| [EML-01](#eml-01--texte-caché-en-html) | Texte caché en HTML | email | texte caché détecté et compté | en place |
| [EML-02](#eml-02--lien-dans-une-image) | Lien dans une image | email | domaines des liens | partielle |
| [EML-03](#eml-03--qr-code-quishing) | QR code (quishing) | email | aucune | non couverte |
| [EML-04](#eml-04--usurpation-du-nom-affiché) | Usurpation du nom affiché | email | `display_name_spoof`, authentification | partielle |
| [EML-05](#eml-05--pièce-jointe-déguisée-et-contrebande-html) | Pièce jointe déguisée, contrebande HTML | email | inspection du contenu (2.13) | en place |

Vingt et une techniques : neuf sur l'URL, sept sur le texte, cinq sur l'email.

### Techniques reproduites par les perturbations

Dix techniques sont reproduites par `src/phishguard/adversarial/perturb.py` (étape 3.6) pour mesurer la robustesse des modèles (étape 3.7). Ce sont celles qui changent la forme d'un échantillon sans en changer le sens, et qu'on peut appliquer telles quelles au jeu de test. Les autres demandent un contenu qui n'existe pas dans les jeux (image, QR code, page hébergée) ou ne visent pas le modèle.

| Id | Perturbation | Réglage du banc d'essai |
| --- | --- | --- |
| URL-02 | `url_homoglyphs` | 30 % des lettres remplaçables de l'hôte (hors suffixe public) en cyrillique |
| URL-03 | `url_subdomains` | 2 sous-domaines d'allure légitime devant l'hôte |
| URL-04 | `url_benign_path` | page déplacée sous 3 répertoires d'allure légitime |
| URL-06 | `url_long_param` | paramètre de suivi de 200 caractères |
| URL-07 | `url_uppercase` | la moitié des lettres de l'hôte en majuscules |
| TXT-01 | `homoglyphs` | 30 % des lettres remplaçables en cyrillique |
| TXT-02 | `zero_width` | U+200B après chaque troisième lettre d'un mot |
| TXT-03 | `split_symbols` | la moitié des mots de 4 lettres ou plus coupés par des points |
| TXT-04 | `leetspeak` | 50 % des lettres a, e, i, l, o, s, t remplacées par un chiffre |
| TXT-05 | `pad_benign` | 20 mots de messages personnels ajoutés à la fin |

Trois variantes à intensité maximale ont été ajoutées à l'étape 3.7, après le premier passage du banc d'essai : `homoglyphs_full` (toutes les lettres remplaçables), `zero_width_dense` (U+200B entre toutes les lettres d'un mot) et `pad_benign_long` (50 mots). Les réglages modérés ci-dessus avaient été fixés avant toute mesure ; les variantes montrent ce que gagne un attaquant qui ne s'arrête pas là ([robustness-report.md](robustness-report.md)).

---

## URL

Le modèle `url_v1` (étape 1.6) est un LightGBM sur 25 features lexicales calculées hors ligne ([url-features.md](url-features.md)). Il ne voit ni la page, ni le contenu, ni la réputation : seulement la chaîne de l'URL. Toute technique qui donne à une URL de phishing la **forme** d'une URL légitime le vise directement.

### URL-01 — Typosquatting

- **Description** : enregistrer un domaine à une ou deux lettres d'une marque : substitution (`paypa1.example`), inversion (`pyapal`), omission, doublement, ou lettres qui se lisent pareil (`rn` pour `m` : `rnicrosoft`).
- **Vecteur** : URL.
- **Pourquoi ça trompe un modèle** : un modèle qui ne connaît la marque que par son nom exact ne reconnaît pas la variante. Les features de forme (longueur, entropie) d'un domaine typosquatté sont celles d'un domaine ordinaire.
- **Contre-mesure** : `is_typosquat` (distance de Levenshtein de 1, ou 2 pour un nom d'au moins 9 caractères) et `brand_min_distance` comparent le label du domaine aux marques de `urls/data/brands.json`. **Limites** : une marque absente de la liste n'est pas protégée, et `rn` → `m` compte deux modifications, au-delà du seuil pour une marque courte. Le squelette visuel (3.8) traite une partie de ces confusions.
- **Références** : AML.T0015, AML.T0043.003 ; T1583.001.

### URL-02 — Homographes IDN

- **Description** : remplacer une lettre latine par une lettre identique d'une autre écriture : `аpple.example`, dont le « а » est cyrillique. Le navigateur transmet `xn--pple-43d.example`, l'utilisateur lit `apple`.
- **Vecteur** : URL.
- **Pourquoi ça trompe un modèle** : pour un modèle de caractères, `а` (U+0430) et `a` (U+0061) n'ont rien en commun ; pour une liste de marques, `аpple` n'est pas `apple`. La forme Punycode ajoute en plus des chiffres et des tirets sans rapport avec ce que lit l'utilisateur.
- **Contre-mesure** : `host_mixed_script` (écritures non admises ensemble dans un label, profil *Highly Restrictive* d'UTS #39) et `homograph_brand` (le squelette visuel de l'hôte contient une marque absente de sa forme réelle). **Limites** : la table des confusables de `urls/idn.py` est volontairement courte (cyrillique, grec, quelques lettres latines) ; un hôte **entièrement** cyrillique (`раураl`) n'est pas mixte. Depuis l'étape 3.8, `host_script_alert` donne une alerte forte à tout hôte qui imite des lettres latines, y compris un label entièrement cyrillique (`раура.com`) : sous `url_homoglyphs`, le rappel passe de 75,1 % à 99,4 % ([normalization.md](normalization.md)).
- **Perturbation** : `url_homoglyphs` (étape 3.6).
- **Références** : AML.T0015, AML.T0043.003 ; T1583.001, T1036.

### URL-03 — Sous-domaines trompeurs

- **Description** : placer la marque à gauche d'un domaine quelconque : `paypal.com.secure-login.example`. Sur mobile, la barre d'adresse tronque souvent la fin, et l'utilisateur ne voit que `paypal.com.secure…`.
- **Vecteur** : URL.
- **Pourquoi ça trompe un modèle** : une feature qui ne lit que le domaine enregistré ne voit jamais la marque. Inversement, un attaquant peut **ajouter** des sous-domaines anodins (`fr.support.`) pour rapprocher son hôte d'un hôte d'entreprise légitime.
- **Contre-mesure** : `brand_in_host` cherche la marque dans **tous** les labels de l'hôte, sauf sur son domaine officiel ; `host_n_subdomains` compte les labels (sans un `www` initial). Mesuré à l'étape 3.7 : deux sous-domaines bénins coûtaient 12,5 points de rappel à `url_v1`. Depuis l'étape 3.9, `url_v2` est entraîné avec des sous-domaines ajoutés aux deux classes : sous `url_subdomains`, il détecte 66,9 % du phishing (61,4 % pour `url_v1`), pour un FPR de 0,96 % au lieu de 5,6 % ([robustness-report.md](robustness-report.md#52-entraînement-adversarial-étape-39)).
- **Perturbation** : `url_subdomains` (étape 3.6).
- **Références** : AML.T0015, AML.T0043.003 ; T1583.001, T1036.

### URL-04 — Chemins et paramètres bénins

- **Description** : ajouter à l'URL un chemin ou des paramètres d'allure légitime : `/fr/aide/index.html`, `?utm_source=newsletter&lang=fr`.
- **Vecteur** : URL.
- **Pourquoi ça trompe un modèle** : l'audit des biais (étape 1.3) et SHAP (étape 3.1) ont montré que `url_v1` associe les chemins courts au phishing et les chemins profonds au légitime : beaucoup d'URLs légitimes du jeu sont des pages internes de Common Crawl. Allonger le chemin pousse donc le score vers « légitime » sans rien changer à la page. C'est la technique la plus simple à exécuter contre ce modèle, et probablement la plus efficace.
- **Contre-mesure** : les features de longueur sont calculées par composant, jamais sur l'URL entière ; les mots-clés (`path_kw_hits`) et les marques (`brand_in_path`) du chemin restent lus. Depuis l'étape 3.9, entraînement adversarial avec des chemins ajoutés aux deux classes : sous `url_benign_path`, le FPR passe de 11,3 % à 0,71 %. **Limite** : le rappel sous perturbation reste 4,4 points sous le rappel propre.
- **Perturbation** : `url_benign_path` (étape 3.6).
- **Références** : AML.T0015, AML.T0043.003 ; T1566.002.

### URL-05 — Domaine de confiance détourné

- **Description** : héberger la page de phishing sur un service réputé où tout le monde peut publier : stockage de fichiers, constructeurs de sites, formulaires, plateformes de déploiement (`hosting.json` en liste 50). Variante : un site légitime compromis.
- **Vecteur** : URL.
- **Pourquoi ça trompe un modèle** : l'hôte est celui d'un service connu, ancien, au TLD sûr ; ses features lexicales sont celles d'une URL légitime. L'analyse d'erreurs (étape 1.8) en fait une catégorie de faux négatifs à part, « invisible pour des features lexicales » : aucune feature de l'URL ne peut la corriger.
- **Contre-mesure** : la Threat Intelligence du module 2 (Safe Browsing, VirusTotal, urlscan.io), qui juge l'URL complète et non sa forme. `brand_in_path` repère une marque dans le chemin d'un hébergeur. **Limites** : sans l'opt-in d'enrichissement, l'analyse reste lexicale ; une campagne récente n'est pas encore dans les listes.
- **Références** : AML.T0015 ; T1583.006, T1584.001.

### URL-06 — URL très longue

- **Description** : rallonger l'URL par un paramètre de plusieurs centaines de caractères, pour repousser la partie suspecte hors de l'écran ou noyer les mots-clés.
- **Vecteur** : URL.
- **Pourquoi ça trompe un modèle** : comme URL-04, une longue requête rapproche l'URL des URLs légitimes à paramètres de suivi. Un modèle qui lirait l'URL entière diluerait ses n-grammes suspects.
- **Contre-mesure** : `query_len` et `query_n_params` sont des features séparées, et l'hôte est mesuré à part (`host_len`) : rallonger la requête ne change pas les features de l'hôte. Depuis l'étape 3.9, entraînement adversarial avec de longs paramètres de suivi ajoutés aux deux classes : sous `url_long_param`, le FPR passe de 49,1 % à 0,77 %. Le modèle ne prend plus un lien d'emailing pour du phishing.
- **Perturbation** : `url_long_param` (étape 3.6).
- **Références** : AML.T0015, AML.T0043.003 ; T1566.002.

### URL-07 — Casse mêlée

- **Description** : écrire l'URL en casse mêlée : `PayPal.Example/LogIn`.
- **Vecteur** : URL.
- **Pourquoi ça trompe un modèle** : un modèle qui distingue les majuscules voit des n-grammes inconnus. Pour l'utilisateur, rien ne change : l'hôte est insensible à la casse.
- **Contre-mesure** : l'hôte est mis en minuscules par la normalisation (`data/urls.normalize_url`), à l'entraînement comme à l'inférence ; les mots-clés et les marques du chemin sont cherchés sans tenir compte de la casse. Le chemin garde sa casse (il est sensible à la casse côté serveur), mais aucune feature n'en dépend. Le banc d'essai (3.7) doit le confirmer : une perturbation sans effet attendu est un test de non-régression.
- **Perturbation** : `url_uppercase` (étape 3.6).
- **Références** : AML.T0043.003.

### URL-08 — Raccourcisseurs et redirections

- **Description** : cacher la destination derrière un raccourcisseur (`bit.ly`), une redirection ouverte d'un site de confiance (`https://trusted.example/redirect?u=https://evil.example`) ou une suite de redirections.
- **Vecteur** : URL.
- **Pourquoi ça trompe un modèle** : le modèle lexical juge l'URL qu'on lui montre, pas sa destination. Un raccourcisseur a une forme neutre ; une redirection ouverte a l'hôte d'un site réputé.
- **Contre-mesure** : `is_shortener` (liste `shorteners.json`) et `path_has_embedded_url` (une URL dans le chemin ou la requête). `url_v1` donne un poids nul au raccourcisseur, mais la raison est quand même citée à l'utilisateur (étape 3.2). **Limites** : PhishGuard ne suit jamais les redirections, par choix ([ssrf.md](ssrf.md)) ; la destination n'est connue que par urlscan.io, sur opt-in.
- **Références** : AML.T0015 ; T1608.005.

### URL-09 — Identifiants avant l'hôte

- **Description** : `https://paypal.com@evil.example/` : tout ce qui précède `@` est un identifiant, l'hôte réel est `evil.example`.
- **Vecteur** : URL.
- **Pourquoi ça trompe un modèle** : un analyseur naïf (ou un humain) lit `paypal.com` comme hôte. Une feature calculée sur le mauvais hôte serait rassurante.
- **Contre-mesure** : l'URL est découpée par `urllib.parse` (RFC 3986), l'hôte est celui après `@`, et `has_userinfo` vaut 1. La normalisation conserve l'identifiant pour que la feature le voie.
- **Références** : AML.T0043.003 ; T1036.

---

## Texte (SMS, messageries)

Le modèle `text_v1` (étape 1.9) est un SVM linéaire sur des n-grammes de caractères (`char_wb`, 2 à 5), entraîné sur la SMS Spam Collection (anglais). Les catégories de leurre (urgence, argent, lien, code, compte) sont repérées à part par des mots-clés normalisés ([explain-text.md](explain-text.md)). Toute technique qui change les caractères sans changer la lecture vise les n-grammes.

### TXT-01 — Homoglyphes

- **Description** : remplacer des lettres latines par des lettres cyrilliques ou grecques identiques : `Vоtre cоmpte` avec des « о » cyrilliques.
- **Vecteur** : texte (aussi : objet et corps d'un email).
- **Pourquoi ça trompe un modèle** : chaque lettre remplacée fait disparaître tous les n-grammes qui la contiennent, jusqu'à cinq par lettre. Le modèle voit des n-grammes jamais vus à l'entraînement, de poids nul : le score tombe vers la constante du SVM. Le lecteur, lui, ne voit aucune différence.
- **Contre-mesure** : depuis l'étape 3.8, repli des confusables vers leur squelette latin, à l'entraînement comme à l'inférence, pour le modèle et pour les mots-clés des catégories, et journalisation quand l'entrée a été modifiée ([normalization.md](normalization.md)). Sous `homoglyphs_full`, le rappel SMS revient à celui du texte propre. **Limite** : la table ne couvre que le cyrillique, le grec et quelques lettres latines.
- **Perturbation** : `homoglyphs` (étape 3.6).
- **Références** : AML.T0015, AML.T0043.003 ; T1027 (technique la plus proche).

### TXT-02 — Caractères de largeur nulle

- **Description** : glisser des caractères invisibles (U+200B *zero width space*, U+200C, U+200D, U+2060, U+FEFF) au milieu des mots : `blo​qué`.
- **Vecteur** : texte, email.
- **Pourquoi ça trompe un modèle** : invisibles à l'écran, ils coupent les n-grammes comme une lettre étrangère. Un filtre par mots-clés ne retrouve plus « bloqué ».
- **Contre-mesure** : la normalisation des mots-clés smishing (`text/smishing.normalize`) retirait déjà la catégorie Unicode Cf, et le score email compte les caractères de largeur nulle (`zero_width_chars`). Depuis l'étape 3.8, le modèle lui-même lit le texte sans caractères de format ni de contrôle : sous `zero_width_dense`, le rappel SMS remonte de 78,1 % à 94,8 %, celui du texte propre.
- **Perturbation** : `zero_width` (étape 3.6).
- **Références** : AML.T0015, AML.T0043.003 ; T1027.

### TXT-03 — Mots coupés par des symboles

- **Description** : séparer les lettres d'un mot-clé par des points, des tirets ou des espaces : `V.é.r.i.f.i.e.z`, `c-o-m-p-t-e`, `c o d e`.
- **Vecteur** : texte.
- **Pourquoi ça trompe un modèle** : `char_wb` construit ses n-grammes à l'intérieur des mots. Avec des espaces, chaque lettre devient un mot d'une lettre et les n-grammes informatifs disparaissent ; avec des points, les n-grammes sont nouveaux. Les mots-clés ne correspondent plus.
- **Contre-mesure** : aucune à l'étape 3.5. La normalisation de l'étape 3.8 ne recolle pas les lettres : défaire cette coupure sans abîmer les sigles et les numéros est un choix délicat, laissé à l'entraînement adversarial (3.9). Mesuré : les n-grammes de caractères résistaient déjà (rappel inchangé sous `split_symbols` avant défense), et `text_v2`, entraîné avec d'autres séparateurs (`-`, `_`, `*`), perd un message sur 96 sous la coupure par des points du banc.
- **Perturbation** : `split_symbols` (étape 3.6).
- **Références** : AML.T0015, AML.T0043.003 ; T1027.

### TXT-04 — Leetspeak

- **Description** : remplacer des lettres par des chiffres ou des symboles qui leur ressemblent : `c0mpte`, `v3r1f13z`, `$ecurite`.
- **Vecteur** : texte, URL (domaine).
- **Pourquoi ça trompe un modèle** : comme les homoglyphes, chaque substitution efface des n-grammes. La lecture reste facile pour un humain.
- **Contre-mesure** : **partielle**. Les n-grammes de caractères gardent ceux des lettres non modifiées (`mpte`), ce qui avait motivé leur choix à l'étape 1.9. Côté URL, `is_typosquat` traite `paypa1` comme une modification. Remplacer systématiquement les chiffres par des lettres détruirait les montants et les codes : traité par l'entraînement adversarial (3.9) plutôt qu'en normalisation. Avec `text_v2`, entraîné sur une autre table leet (`@`, `$`, `!`…) appliquée aux deux classes, le FPR sous `leetspeak` passe de 10,2 % à 5,2 %, à rappel égal.
- **Perturbation** : `leetspeak` (étape 3.6).
- **Références** : AML.T0015, AML.T0043.003 ; T1027.

### TXT-05 — Dilution par du texte légitime

- **Description** : ajouter au leurre des phrases anodines (« Merci de votre fidélité. Votre conseiller reste à votre disposition. ») ou une liste de mots typiques des messages légitimes (*good word attack*).
- **Vecteur** : texte, email.
- **Pourquoi ça trompe un modèle** : le TF-IDF est normalisé (norme L2) : plus le message est long, plus le poids de chaque n-gramme suspect baisse. Les mots ajoutés ont en plus des coefficients négatifs. L'attaquant peut choisir ces mots en observant les verdicts (AML.T0043.001).
- **Contre-mesure** : les catégories de leurre ne dépendent pas de la longueur (un lien reste un lien, une demande de code reste une demande de code) ; dans un email, la Threat Intelligence juge les liens indépendamment du texte. L'entraînement adversarial (3.9) avec des exemples dilués n'aide presque pas : 50 mots anodins coûtent encore 29,2 points de rappel à `text_v2`, car le TF-IDF normalise la longueur. **Statut partiel** : la défense restante est l'ensemble modèle + catégories de leurre (3.12).
- **Perturbation** : `pad_benign` (étape 3.6).
- **Références** : AML.T0015, AML.T0043.001, AML.T0043.003 ; T1027.

### TXT-06 — Message en image

- **Description** : envoyer le leurre sous forme d'image (MMS, image dans une messagerie, email dont le corps n'est qu'une image), avec peu ou pas de texte.
- **Vecteur** : texte (MMS, messageries), email.
- **Pourquoi ça trompe un modèle** : le modèle de texte ne reçoit rien à lire, ou seulement un texte neutre.
- **Contre-mesure** : **aucune**. PhishGuard ne fait pas de reconnaissance de caractères (OCR), et n'en prévoit pas : c'est coûteux, et un OCR local ajouterait une grosse dépendance au client. Dans un email, les liens et l'authentification restent analysés. Piste : un signal « corps presque vide avec une image » dans le score email.
- **Références** : AML.T0015 ; T1027, T1566.

### TXT-07 — Message rédigé par un LLM

- **Description** : faire rédiger le leurre par un modèle de langage : sans fautes, au ton d'un service client, personnalisé, et différent à chaque envoi.
- **Vecteur** : texte, email.
- **Pourquoi ça trompe un modèle** : les corpus d'entraînement (SMS Spam Collection, Nazario) contiennent surtout des messages maladroits ; un modèle qui a appris les fautes et les tournures de spam ne les retrouve plus. Chaque message est unique, ce qui contourne aussi les empreintes.
- **Contre-mesure** : prévu à l'étape 3.10 : un jeu de test local de messages synthétiques mesurera la dégradation (rappel **et** faux positifs, car un courrier professionnel bien écrit lui ressemble). La compensation attendue vient des signaux qui ne dépendent pas du texte : âge du domaine, réputation, concordance du lien (module 2).
- **Références** : AML.T0052, AML.T0015 ; T1566.

---

## Email

Le score email (étape 1.11) combine des règles explicables et un modèle appris sur des features du message : authentification, expéditeur, liens, pièces jointes, contenu ([email-score.md](email-score.md)). Un email offre plus de surface qu'un SMS : HTML, images, pièces jointes, en-têtes.

### EML-01 — Texte caché en HTML

- **Description** : insérer dans le HTML du texte que le lecteur ne voit pas (`display:none`, police de 0 ou 1 px, texte de la couleur du fond, `opacity:0`) : des paragraphes légitimes pour diluer le signal (TXT-05), ou des mots qui cassent les mots-clés.
- **Vecteur** : email.
- **Pourquoi ça trompe un modèle** : un extracteur de texte naïf garde tout le texte du HTML, y compris l'invisible, et le modèle juge un message que la victime ne lit pas.
- **Contre-mesure** : `email/html.py` repère le texte caché (attribut `hidden`, styles **en ligne** : `display:none`, `opacity:0`, police minuscule, couleur du fond, hauteur nulle avec débordement caché), l'**exclut** du texte analysé et le compte (`log_hidden_chars`). **Limite** : les feuilles `<style>` et les classes CSS ne sont pas interprétées.
- **Références** : AML.T0015, AML.T0043.003 ; T1027.

### EML-02 — Lien dans une image

- **Description** : rendre une image cliquable (`<a href=…><img …></a>`) au lieu d'un lien textuel. L'image montre un bouton « Se connecter à votre banque ».
- **Vecteur** : email.
- **Pourquoi ça trompe un modèle** : la règle « le texte affiché ne correspond pas au lien » (`mismatched_links`) n'a aucun texte à comparer, et les mots du bouton échappent au texte analysé.
- **Contre-mesure** : **partielle**. Le lien reste extrait, et son domaine passe par les features de liens et, sur opt-in, par la Threat Intelligence. Piste : compter les liens sans texte (image seule) comme un signal à part.
- **Références** : AML.T0015 ; T1566.002.

### EML-03 — QR code (quishing)

- **Description** : remplacer le lien par un QR code, dans le corps de l'email ou dans une pièce jointe PDF : « Scannez pour réactiver votre authentification ».
- **Vecteur** : email (puis URL, sur le téléphone de la victime).
- **Pourquoi ça trompe un modèle** : il n'y a **aucune URL** dans le message. La victime scanne avec son téléphone, souvent hors de la protection de son poste de travail, et l'URL n'est jamais vue par l'analyse de l'email.
- **Contre-mesure** : **aucune** à l'étape 3.5. Pistes : décoder les QR codes des images et des PDF joints (en mémoire, sans réseau, comme l'inspection de l'étape 2.13) et analyser l'URL obtenue ; côté extension et application, analyser l'URL scannée avant de l'ouvrir.
- **Références** : AML.T0015 ; T1566.001, T1566.002.

### EML-04 — Usurpation du nom affiché

- **Description** : `From: "service@paypal.com" <noreply@random.example>`, ou simplement `"Service Client PayPal"`. La plupart des clients de messagerie n'affichent que le nom.
- **Vecteur** : email.
- **Pourquoi ça trompe un modèle** : un modèle qui ne lit que le corps ignore l'en-tête ; l'adresse réelle est souvent valide et correctement authentifiée (SPF et DKIM passent pour `random.example`).
- **Contre-mesure** : **partielle**. `display_name_spoof` repère une adresse ou un domaine écrit dans le nom affiché et le compare au domaine réel de l'expéditeur ; un nom de marque seul (« Service Client PayPal ») n'est pas encore comparé à la liste des marques. Par ailleurs, `reply_to_differs` et `return_path_differs` repèrent les adresses de réponse détournées ; DMARC est lu dans `Authentication-Results`, sans faire confiance aux en-têtes ajoutés par l'expéditeur (fixture `10_fake_auth_results.eml`).
- **Références** : AML.T0043.003 ; T1566, T1036.

### EML-05 — Pièce jointe déguisée et contrebande HTML

- **Description** : `facture.pdf.exe`, un `.docx` qui est en réalité un document à macros, une archive chiffrée contenant un exécutable, ou une page HTML jointe qui reconstruit un fichier dans le navigateur (*HTML smuggling*) ou affiche un faux formulaire de connexion.
- **Vecteur** : email.
- **Pourquoi ça trompe un modèle** : une règle qui ne lit que l'extension croit le nom. Une archive chiffrée ne peut pas être inspectée, et c'est le but.
- **Contre-mesure** : l'inspection du contenu de l'étape 2.13 ([attachments.md](attachments.md)) lit le vrai type par signature (`type_mismatch`), les macros, les modèles distants, les archives listées sans décompression (`hidden_archive_payload`), les PDF actifs et les pages HTML qui demandent un mot de passe (`credential_form_attachment`). Rien n'est jamais exécuté ni extrait.
- **Références** : AML.T0015 ; T1566.001, T1036.008, T1027.006.

---

## Ce que le catalogue apprend

- **Les modèles lexicaux sont fragiles par construction.** Huit techniques sur vingt et une (URL-04, URL-06, TXT-01 à TXT-05, EML-01) ne changent rien au sens, seulement à la forme. Ce sont celles que les étapes 3.6 et 3.7 reproduisent et mesurent : elles sont bon marché pour l'attaquant et automatisables.
- **Certaines évasions ne relèvent pas du modèle.** Un domaine de confiance détourné (URL-05), un QR code (EML-03) ou un message en image (TXT-06) ne laissent rien à lire au modèle lexical. La défense est ailleurs : Threat Intelligence, inspection des pièces jointes, analyse de l'URL au moment où elle est ouverte. Une défense par le modèle seul ne suffira jamais, et le rapport de robustesse devra le dire.
- **Normaliser ne suffit pas.** La normalisation de l'étape 3.8 vise TXT-01, TXT-02 et URL-02 : des caractères différents pour une même lecture. Elle ne peut rien contre les chemins ajoutés ou la dilution, qui demandent un modèle entraîné sur ces formes (3.9).

## Pistes futures

- **Empoisonnement des données** : les flux publics de phishing (étape 1.1) peuvent recevoir des URLs légitimes signalées à tort, volontairement ou non. Mesurer leur part et filtrer les domaines populaires (Tranco) avant l'entraînement (ATLAS AML.T0020 *Poison Training Data*, hors périmètre ici).
- **Attaques automatisées** : TextAttack (optionnel à l'étape 3.7) cherche des substitutions de mots qui font basculer le verdict, plus agressives que les perturbations écrites à la main.
- **QR codes et images** : décodage local des QR codes des pièces jointes (EML-03), signal « email presque vide avec image » (TXT-06).
