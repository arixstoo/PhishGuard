# Extension navigateur : architecture (étapes 5.1 à 5.4)

L'extension PhishGuard (Chrome, Manifest V3) analyse une URL **sur l'appareil**, avec le
même extracteur de features, le même modèle et la même fusion que l'API. Par défaut, elle
n'envoie rien à personne : ce n'est pas une promesse, la politique de contenu l'impose.

```bash
make extension-install   # npm ci, sans script d'installation
make extension-test      # types, parité avec Python, vecteurs de référence
make extension-build     # extension/dist, modèle signé vérifié
```

Puis `chrome://extensions` → mode développeur → « Charger l'extension non empaquetée » →
`extension/dist`.

## 1. Décisions (étape 5.1)

### Quand analyser

| Mode | Permission | Avertissement à l'installation | Décision |
|---|---|---|---|
| À la demande : clic sur l'icône | `activeTab` | aucun | **v1, par défaut** |
| À la demande : clic droit sur un lien | `contextMenus` | aucun | **v1, par défaut** |
| Automatique, chaque page visitée | `tabs` (ou `webNavigation`) | « lire votre historique de navigation » | **optionnel** (5.7), demandé par `chrome.permissions.request` au moment où l'utilisateur l'active |
| Gmail : le message ouvert | script de contenu sur `https://mail.google.com/*` | « lire et modifier vos données sur mail.google.com » | étape 5.6, justifiée dans la fiche du Chrome Web Store |
| Enrichissement en ligne (API) | `optional_host_permissions` | aucun à l'installation | optionnel (5.7), opt-in explicite |

Un avertissement effrayant à l'installation fait fuir exactement les personnes que
l'outil doit protéger. L'analyse automatique n'est donc jamais imposée.

### Chaque permission arrive avec l'étape qui s'en sert

Le manifeste du plan (étape 5.2) déclare dès le départ le script Gmail,
`optional_permissions: ["tabs"]` et un hôte d'API. Ils ne sont **pas** déclarés ici :
un script de contenu Gmail vide demanderait l'accès à la messagerie sans rien en faire,
et une permission déclarée « pour plus tard » est une permission qu'on oublie de
justifier. Manifeste actuel :

| Permission | Pourquoi |
|---|---|
| `activeTab` | lire l'adresse de l'onglet **seulement** quand l'utilisateur clique sur l'icône |
| `contextMenus` | entrée « Analyser ce lien avec PhishGuard » du clic droit |
| `storage` | liste blanche (`storage.local`), cache des analyses en mémoire (`storage.session`) |

Aucune permission d'hôte. Aucun script de contenu.

### Politique de contenu (CSP)

```text
default-src 'self'; script-src 'self'; object-src 'none'; connect-src 'self';
img-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

`connect-src 'self'` : le service worker et la fenêtre contextuelle ne peuvent joindre
**aucun** serveur, seulement les fichiers du paquet. Vérifié dans Chromium : un
`fetch("https://example.com/")` depuis le service worker est bloqué. L'étape 5.7 n'ouvrira
que l'hôte d'API choisi par l'utilisateur.

## 2. Projet (étape 5.2)

```text
extension/
  .npmrc               ignore-scripts, save-exact
  package.json         4 dépendances de développement, 0 dépendance d'exécution
  build.mjs            esbuild, vérification du modèle signé, icônes, garde-fous
  static/              manifest.json, popup.html/.css, _locales/{fr,en,ar}
  src/core/            extracteur, modèle, décision : pur, sans API Chrome
  src/generated/       données exportées depuis Python (ne pas modifier)
  src/background.ts    service worker
  src/popup/           fenêtre contextuelle minimale (complète à l'étape 5.5)
  test/                vitest : parité, vecteurs de référence, modèle, décision
```

- **Chaîne d'approvisionnement.** TypeScript, esbuild, vitest et `@types/chrome` : 41
  paquets au total, versions exactes, `package-lock.json`, `npm ci`, **aucun script
  d'installation exécuté** (`ignore-scripts=true` : esbuild fournit son binaire par une
  dépendance optionnelle). Installation faite avec `--before` (versions publiées depuis
  au moins deux semaines). `npm audit` : 0 vulnérabilité, bloquant en CI. Rien n'est
  embarqué dans l'extension en dehors de notre code : ni `tldts`, ni `punycode.js`, ni
  `onnxruntime-web`.
- **Code lisible.** Pas de minification (le Chrome Web Store exige un code relisible).
  Le build échoue si un bundle contient `eval(`, `new Function(`, `importScripts(` ou une
  injection HTML (`innerHTML =`, `insertAdjacentHTML`, `document.write`).
- **Icônes** générées par `build.mjs` (PNG écrits à la main) : aucun binaire dans le dépôt.
- **Langues** : `fr` (par défaut), `en`, `ar` ; `dir` posé depuis `@@bidi_dir`. L'étape
  5.8 complète l'accessibilité et le rendu de droite à gauche.

## 3. Porter l'extracteur et le modèle (étape 5.3)

### Python est la source de vérité

Le plan prévoit de réécrire `url_features` « à l'identique » avec la classe `URL` du
navigateur et `tldts`. C'est précisément ce qui fait diverger les deux implémentations :

| Composant | Ce que ferait le navigateur | Ce que fait Python, donc l'extension |
|---|---|---|
| découpage | `new URL()` (WHATWG) : décode `0x7f.1`, retire tabulations, résout `..` | `urllib.parse.urlsplit` de Python 3.13, traduit ligne à ligne (`src/core/pyurl.ts`) |
| hôte internationalisé | UTS #46 (autre repli, rejets) | NFKC + minuscules + codec `punycode` de Python (`punycode.ts`, en `BigInt`) |
| suffixes publics | liste de `tldts`, plus récente | **la liste embarquée par `tldextract` 5.4.0**, et son algorithme (`psl.ts`) |
| `isdigit`, `isalpha`, `isspace`, catégories Cf/Cc, écriture | `\p{…}` du moteur, autre version d'Unicode ; aucune notion d'« écriture déduite du nom » | tables générées depuis Python (`text.ts`) |
| longueurs | unités UTF-16 (`"😀".length === 2`) | points de code (`len("😀") == 1`) |
| `unquote` | `decodeURIComponent` (lève une exception) | `urllib.parse.unquote` : plages ASCII, U+FFFD par sous-partie maximale, BOM conservé |
| IP | règle WHATWG partout | règle WHATWG pour `host_is_ip`, `ipaddress` strict ailleurs, comme Python |
| `numpy.interp`, `to_score` | — | traduits, points répétés et arrondi compris |

`scripts/export_extension_data.py` (`make extension-data`) exporte depuis les objets
Python eux-mêmes :

- `extension/src/generated/reference-data.json` (216 Kio) : marques, raccourcisseurs,
  mots-clés, confusables, combinaisons d'écritures admises, seuils de la fusion, et les
  6 871 suffixes publics et 2 882 privés de tldextract ;
- `extension/src/generated/unicode-data.json` (18 Kio) : les propriétés Unicode telles
  que Python 3.13 (Unicode 15.1) les calcule, en plages. On y voit pourquoi `\p{Script}`
  ne convenait pas : pour Python, `µ` est de l'écriture `MICRO`, `ᵃ` de `MODIFIER`, `ー`
  de `KATAKANA-HIRAGANA`, et c'est ce que le modèle a vu à l'entraînement ;
- `extension/test/fixtures/python-parity.json` : les cas de parité ci-dessous.

Il vérifie aussi une hypothèse du port de tldextract : Python décode un label `xn--`
avec `idna` (IDNA 2008, strict) avant de le chercher dans la liste, l'extension avec le
seul décodeur Punycode. Les deux trouvent les mêmes suffixes parce que **chaque** label
non ASCII de la liste se retrouve depuis sa forme Punycode (contrôlé à chaque export,
et par `tests/test_extension_data.py`).

### Trois niveaux de preuve

1. **Vecteurs de référence** (`tests/golden/url_vectors.json`, étape 4.11) : les 200
   URLs donnent les mêmes 25 features, le même score brut, la même probabilité et la même
   probabilité calibrée, à 1e-6 près (les features sont même comparées à 1e-12).
   **Critère de fin de l'étape atteint.**
2. **Parité composant par composant** : 190 URLs choisies (ports invalides, crochets
   IPv6 et IPvFuture, identifiants, `@@`, IP décimales, hexadécimales et à zéros, IDN,
   homographes, Punycode malformé, labels de plus de 63 caractères, émojis, `İ`, sigma
   final, pleine chasse, points idéographiques, largeur nulle, encodages pourcent
   invalides, surrogates…) et, pour chacune, `urlsplit`, `normalize_url`, `parse_url`,
   les 25 features, l'alerte d'hôte et le TLD ; plus `unquote` (34 cas), Punycode (41
   labels), tldextract (32 hôtes, jokers et exceptions compris), `is_ip_host` (29),
   `skeleton` (9), `numpy.interp` (12).
3. **Fuzzing différentiel** : 600 URLs déterministes tirées d'un alphabet hostile
   (délimiteurs, `%` tronqués, cyrillique, grec, CJK, arabe, hébreu, invisibles,
   émojis), dont 402 valides : mêmes résultats sur toute la chaîne.

La suite a été vérifiée par mutation : multiplier l'entropie par 1,0000001 fait échouer
163 cas, oublier les suffixes privés 10 cas, changer l'amortissement de Punycode 5 cas,
ne plus conserver le BOM dans `unquote` 1 cas.

Le modèle exporté n'est pas versionné. En CI, sans lui, on vérifie tout sauf
`tld_phish_rate` (sa table vient du modèle) et les scores ; deux **petits modèles
LightGBM synthétiques** entraînés avec des valeurs manquantes (`NaN`, et
`zero_as_missing`) testent alors le parcours des arbres sur les branches que les URLs
n'atteignent jamais. Avec le modèle (poste de développement, build), les 200 vecteurs
sont vérifiés en entier.

### Le modèle est une entrée non fiable

Il sera téléchargé au module 6. `loadUrlModel` vérifie tout ce que l'inférence lit avant
de compiler les arbres en tableaux typés : format, **version et empreinte de
l'extracteur** (un modèle produit par un autre extracteur donnerait des scores faux sans
erreur), features connues et distinctes, même ordre de colonnes que le booster, binaire,
chaque nœud (coupure `<=`, feature dans les bornes, `missing_type` connu, feuille
numérique finie), calibration croissante. Compilation itérative : un arbre de profondeur
100 000 ne fait pas déborder la pile (testé).

### Limites connues du portage

- **NFKC et minuscules** viennent du moteur JavaScript (ICU, Unicode 16) et non de Python
  (Unicode 15.1) : un caractère ajouté à Unicode 16 peut être normalisé différemment.
  Aucun cas observé ; les tables générées couvrent tout le reste.
- **Surrogates** : un Punycode malformé peut se décoder en deux demi-codets *isolés*
  consécutifs. Python les compte pour deux caractères, JavaScript en forme une paire et
  en compte un. Cas construit à la main, sans intérêt pour un attaquant (l'hôte ne se
  résout pas), non reproduit.
- `log2` peut différer au dernier bit d'une bibliothèque mathématique à l'autre : l'entropie
  est comparée à 1e-12 près.

## 4. Service worker : analyse et badge (étape 5.4)

### Décision : la même que l'API

`decide` reprend `fuse` sans enrichissement (fusion 1.1.0) :

1. règle dure `lookalike_host` (hôte qui imite des lettres latines) → phishing, **avant**
   la liste blanche, comme côté serveur : une liste blanche obtenue par confusion
   (`аpple.com` pris pour `apple.com`) n'innocente pas ;
2. liste blanche personnelle → sûr ;
3. sinon probabilité calibrée → score de 0 à 100 → `safe` sous 30, `suspicious` de 30 à
   70, `phishing` au-delà.

Les autres règles locales du plan (IP en hôte, marque imitée, identifiants dans l'URL,
raccourcisseur) produisent des **raisons**, pas un verdict : le modèle les a apprises
comme features, et l'extension ne doit pas contredire l'API sur la même URL. Une URL de
plus de 65 536 caractères n'est pas découpée mais signalée comme suspecte : refuser de
l'analyser offrirait une évasion gratuite (allonger le lien).

### Contraintes de MV3

- Le service worker peut s'arrêter à tout moment : le modèle est rechargé à la demande
  (≈ 140 ms : lecture, SHA-256, validation, compilation), les analyses sont mises en
  cache dans `storage.session` (mémoire seulement, effacée à la fermeture du navigateur,
  inaccessible aux scripts de contenu), 100 entrées au plus, clé = SHA-256 de la version
  du modèle et de l'URL. La liste blanche est relue à chaque analyse.
- Le modèle du paquet est vérifié deux fois : au build (signature Ed25519 du manifeste,
  taille, empreinte, égalité avec l'export des vecteurs de référence ; un octet modifié
  fait échouer le build, vérifié) et au chargement (SHA-256 injecté au build).
- Écouteurs enregistrés au premier niveau, de façon synchrone (sinon Chrome ne réveille
  pas le service worker pour eux).

### Le badge ne doit jamais mentir

Le badge décrit une URL précise. Sans précaution, un « ✓ » posé sur une page sûre
resterait affiché quand l'onglet navigue vers une page de phishing. Sans la permission
`tabs`, Chrome retire `url` des événements `tabs.onUpdated` : le badge est donc effacé
dès qu'un événement *peut* être une navigation (tout sauf `status: complete`, le son, la
mise en veille ou l'épinglage). Vérifié dans Chromium : « ! » après analyse, vide après
navigation.

Icône + couleur + texte, jamais la couleur seule : `✓` vert, `?` orange, `!` rouge
(blanc sur ces fonds : contraste 5,3, 4,6 et 5,6, WCAG AA), et l'infobulle dit le verdict
en toutes lettres avec l'hôte.

### Messages

Seules les pages de l'extension (vérifiées par **origine** : un script de contenu porte
le même identifiant d'extension, mais l'origine de la page web) peuvent interroger le
service worker. Elles désignent un onglet, jamais une URL : le service worker lit
lui-même l'adresse, que `activeTab` ne lui donne qu'après un clic de l'utilisateur.
Requêtes validées strictement (`parseRequest`), toute forme inconnue refusée.

### Menu contextuel

« Analyser ce lien avec PhishGuard » : le résultat (hôte, verdict, raisons ; jamais
l'URL) passe par `storage.session` et s'affiche dans la fenêtre contextuelle
(`action.openPopup`), sans permission de notifications. Lu une fois, puis effacé ; ignoré
au-delà de 2 minutes.

### Mesures (Chromium 156, build de test, 16 novembre 2026)

Aucune page réelle chargée : les requêtes des onglets sont servies par une page factice,
les URLs de phishing ne sont que des chaînes (règle du labo).

| URL | Verdict | Score | Règle / raisons | Analyse | En cache |
|---|---|---|---|---|---|
| `https://www.wikipedia.org/` | sûr | 1 | | 3,3 ms | 0,5 ms |
| `https://www.google.com/search?q=meteo` | sûr | 28 | | 2,4 ms | 0,6 ms |
| `https://github.com/arixstoo` | sûr | 15 | | 2,8 ms | 0,3 ms |
| `https://www.lemonde.fr/international/` | sûr | 28 | | 2,3 ms | 0,4 ms |
| `https://www.impots.gouv.fr/accueil` | sûr | 25 | | 2,3 ms | 0,4 ms |
| `https://www.amazon.fr/gp/cart/view.html` | sûr | 2 | | 3,1 ms | 0,6 ms |
| `http://paypa1-secure-login.example/verify/account` | phishing | 90 | | 3,0 ms | 0,5 ms |
| `http://192.0.2.10/paypal/login.php` | phishing | 88 | IP en hôte | 2,2 ms | 0,4 ms |
| `http://xn--pple-43d.com/` | phishing | 100 | `lookalike_host`, marque | 4,2 ms | 0,5 ms |
| `https://appleid.apple.com.verify-account.example/signin` | phishing | 97 | marque | 2,2 ms | 0,4 ms |

**10 verdicts corrects sur 10, de 2 à 4 ms** (objectif : moins de 50 ms hors chargement
du modèle), cache compris. Deux scores légitimes frôlent le seuil « suspect » (28) : les
pages internes sont la faiblesse connue de `url_v2` (« le chiffre à surveiller » de
[model-card-url.md](model-card-url.md)), à suivre pendant les tests utilisateurs (5.13).

Le build de test (`node build.mjs --test`, `dist-test/`) ajoute un point d'entrée qui
expose l'analyse du service worker à un test automatisé, qui ne peut pas cliquer sur
l'icône. Il n'est jamais inclus dans `dist/` (le build échoue sinon). Les tests de bout
en bout Playwright entrent dans la CI à l'étape 5.10.

## 5. Ce qui vient ensuite

| Étape | Ajoute |
|---|---|
| 5.5 | fenêtre contextuelle complète : conseil d'action, détails repliables, « Toujours faire confiance » (message `allowlist-add-tab` déjà prêt), signalement |
| 5.6 | script de contenu Gmail (Shadow DOM, `textContent`, sélecteurs isolés), décodage de `google.com/url?q=` |
| 5.7 | options : analyse automatique (`tabs` optionnelle), enrichissement en ligne (hôte optionnel, CSP élargie à cet hôte seul) |
| 5.9 | audit des permissions, `docs/extension-privacy.md` |
| module 6 | téléchargement de modèles signés : `loadUrlModel` est déjà prêt pour une entrée non fiable ; reste la vérification Ed25519 dans l'extension (WebCrypto) |
