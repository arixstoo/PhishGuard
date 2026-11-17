# Extension navigateur : architecture (étapes 5.1 à 5.8)

L'extension PhishGuard (Chrome, Manifest V3) analyse une URL **sur l'appareil**, avec le
même extracteur de features, le même modèle et la même fusion que l'API, et les liens du
message ouvert dans Gmail avec les mêmes règles que l'analyse d'email de l'API. Par
défaut, elle n'envoie rien à personne : l'analyse en ligne et les signalements sont des
options éteintes, qui exigent chacune un réglage **et** une permission accordée par
l'utilisateur (section 7).

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

Le manifeste du plan (étape 5.2) déclarait dès le départ le script Gmail, `tabs` et un
hôte d'API. Ils sont arrivés avec les étapes qui s'en servent (5.6, 5.7) : une permission
déclarée « pour plus tard » est une permission qu'on oublie de justifier.

| Permission | Avertissement | Pourquoi |
|---|---|---|
| `activeTab` | aucun | lire l'adresse de l'onglet **seulement** quand l'utilisateur clique sur l'icône |
| `contextMenus` | aucun | entrée « Analyser ce lien avec PhishGuard » du clic droit |
| `storage` | aucun | réglages et liste blanche (`storage.local`), cache des analyses demandées (`storage.session`) |
| script de contenu `https://mail.google.com/*` | « lire et modifier vos données sur mail.google.com » | analyser les liens et l'expéditeur du message ouvert (section 6) |
| `tabs` (**optionnelle**) | « lire votre historique de navigation », quand l'utilisateur l'active | analyse automatique de chaque page (section 7) ; rendue à la désactivation |
| hôtes `https://*/*`, `http://localhost/*`, `http://127.0.0.1/*` (**optionnels**) | aucun à l'installation | seul l'hôte du serveur **choisi par l'utilisateur** est demandé, quand il active l'analyse en ligne ou les signalements ; rendu à la désactivation |

Le motif large des hôtes optionnels est le seul moyen d'admettre un serveur
auto-hébergé, dont Chrome doit connaître le motif d'avance. Il ne donne aucun accès tant
qu'un hôte précis n'a pas été accordé.

### Politique de contenu (CSP)

```text
default-src 'self'; script-src 'self'; object-src 'none';
connect-src 'self' https: http://localhost:* http://127.0.0.1:*;
img-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

Jusqu'à l'étape 5.4, `connect-src 'self'` interdisait toute requête. L'analyse en ligne
(5.7) doit joindre un serveur choisi par l'utilisateur, inconnu au build. Or la CSP d'un
manifeste est figée : elle ne peut pas s'ouvrir à un seul hôte au moment du choix.
`connect-src` admet donc `https:` (et la boucle locale pour `make api`). La garantie
« rien ne part par défaut » repose désormais sur trois contrôles :

1. **le build** (`build.mjs`) : `fetch` n'apparaît que dans `src/api.ts` et
   `src/background.ts` (lecture du modèle dans le paquet) ; aucun bundle ne contient
   `XMLHttpRequest`, `WebSocket`, `EventSource` ni `sendBeacon` ; la fenêtre
   contextuelle, les options et le script Gmail ne contiennent aucun `fetch`. Vérifié
   par mutation : un `fetch` ajouté au popup fait échouer le build ;
2. **`api.ts`**, juste avant chaque `fetch` : réglage activé **et** permission de l'hôte
   accordée (`chrome.permissions.contains`). Un script de contenu ne peut pas accorder de
   permission : une page Gmail compromise qui réécrirait les réglages n'obtiendrait
   aucune requête (testé) ;
3. **la permission d'hôte** elle-même, demandée par la page d'options au clic.

Vérifié dans Chromium : sur tout le parcours de test (popup, options, 10 messages Gmail),
34 requêtes, toutes vers le paquet de l'extension ou vers la maquette Gmail, aucune vers
l'extérieur.

## 2. Projet (étape 5.2)

```text
extension/
  .npmrc               ignore-scripts, save-exact
  package.json         4 dépendances de développement, 0 dépendance d'exécution
  build.mjs            esbuild, vérification du modèle signé, icônes, garde-fous
  static/              manifest.json, popup.html/.css, _locales/{fr,en,ar}
  src/core/            extracteur, modèle, décision : pur, sans API Chrome
  src/generated/       données exportées depuis Python (ne pas modifier)
  src/core/mail.ts     liens et expéditeur d'un email (port de phishguard.email)
  src/core/inspect.ts  verdict d'un message Gmail
  src/background.ts    service worker
  src/api.ts           seul module réseau (options en ligne)
  src/i18n.ts          catalogues embarqués, pluriels, sens d'écriture
  src/settings.ts      réglages validés
  src/popup/           fenêtre contextuelle
  src/options/         page d'options
  src/gmail/           script de contenu Gmail (sélecteurs, bannière)
  test/                vitest : parité, vecteurs de référence, modèle, décision, emails,
                       langues, accessibilité, réseau ; maquette Gmail
```

- **Chaîne d'approvisionnement.** TypeScript, esbuild, vitest et `@types/chrome` : 41
  paquets au total, versions exactes, `package-lock.json`, `npm ci`, **aucun script
  d'installation exécuté** (`ignore-scripts=true` : esbuild fournit son binaire par une
  dépendance optionnelle). Installation faite avec `--before` (versions publiées depuis
  au moins deux semaines). `npm audit` : 0 vulnérabilité, bloquant en CI. Rien n'est
  embarqué dans l'extension en dehors de notre code : ni `tldts`, ni `punycode.js`, ni
  `onnxruntime-web`.
- **Code lisible.** Pas de minification (le Chrome Web Store exige un code relisible).
  Le build échoue si un bundle contient `eval(`, `new Function(`, `importScripts(`, une
  injection HTML (`innerHTML =`, `outerHTML =`, `insertAdjacentHTML`, `document.write`,
  `createContextualFragment`) ou un canal réseau non admis (section 1).
- **Icônes** générées par `build.mjs` (PNG écrits à la main) : aucun binaire dans le dépôt.
- **Langues** : `fr` (par défaut), `en`, `ar` (section 8).

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

Deux émetteurs, deux protocoles distincts, reconnus par leur **origine** (un script de
contenu porte le même identifiant d'extension, mais l'origine de la page web) :

- les **pages de l'extension** (popup, options) : analyse d'un onglet, liste blanche,
  signalement. Elles désignent un onglet, jamais une URL : le service worker lit
  lui-même l'adresse, que `activeTab` ne lui donne qu'après un clic de l'utilisateur ;
- le **script Gmail** (origine `https://mail.google.com`, cadre principal) : une seule
  requête, `mail-inspect`, bornée (500 liens, 2 048 caractères de texte par lien). Il ne
  peut ni lire ni modifier la liste blanche, ni analyser un onglet, ni déclencher une
  requête réseau.

Requêtes validées strictement (`parseRequest`, `parseMailRequest`) ; toute forme
inconnue est refusée, et une requête d'un protocole est refusée par l'autre (testé).

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

## 5. Fenêtre contextuelle (étape 5.5)

- **Verdict par icône, couleur et texte** (`⛔ Phishing probable`), jamais la couleur
  seule ; l'hôte, isolé du sens d'écriture de la page ; une phrase d'explication propre
  au cas (liste blanche, alphabets mélangés, adresse trop longue, ou verdict) ; le
  **conseil d'action de l'API**, mot pour mot (vérifié par `tests/test_extension_data.py`) ;
  les raisons.
- **Détails techniques** repliés par défaut (bouton `aria-expanded`) : score, domaine
  enregistré **en Punycode** (un homographe s'y voit : `xn--pple-43d.com`), probabilité,
  score brut, règle, modèle, durée, et résultat du serveur s'il y en a un.
- **Toujours faire confiance à ce site** : confirmation qui nomme le domaine et ses
  sous-domaines. Si le verdict est suspect ou phishing, avertissement, et le focus va sur
  « Annuler », pas sur « Confirmer ». **Impossible** pour un hôte aux alphabets mélangés :
  la règle passe avant la liste blanche (étape 5.4), et proposer le bouton serait mentir.
  Un site de confiance propose « Ne plus faire confiance ».
- **Signaler une erreur** : faux positif si le verdict n'est pas sûr, faux négatif s'il
  n'est pas phishing (la cohérence que l'API exige). Envoi désactivé par défaut : le
  panneau explique pourquoi et ouvre les options. Activé, il dit avant l'envoi que seul
  le domaine part, et après, vers quel serveur.
- Lien analysé par le menu contextuel : l'URL n'est pas gardée (étape 5.4). Après
  « Ne plus faire confiance » sur un lien jugé sous liste blanche, son verdict propre est
  inconnu : la fenêtre invite à l'analyser de nouveau plutôt que d'inventer un verdict.
- Tout texte par `textContent`, y compris les messages du serveur.

## 6. Script de contenu Gmail (étape 5.6)

### Ce qui est lu, et ce qui ne l'est jamais

Un `MutationObserver` (anti-rebond de 300 ms) cherche les corps de message **dépliés**
(`div.a3s`) dans la zone de lecture. Gmail n'en crée que pour les messages ouverts : la
liste des messages, les messages repliés et le reste de la boîte ne sont jamais lus
(vérifié : aucune analyse dans la vue liste). Pour chaque corps : les liens (`href` brut,
et texte **tel qu'affiché**, `innerText`) et l'expéditeur (`email`, `name`). Rien n'est
stocké, ni dans le script ni dans le service worker (pas de cache pour Gmail), et rien ne
part en ligne, **quel que soit le réglage** d'analyse en ligne : le contenu d'un email ne
quitte jamais l'appareil.

Tous les sélecteurs sont dans `src/gmail/selectors.ts` ; la maquette
`test/fixtures/gmail-mock.html` reproduit exactement cette structure.

### Les mêmes règles que l'API

`src/core/mail.ts` traduit à l'identique `make_link`, `unwrap_rewritten`,
`registered_domain`, `display_name_domain` et `make_address` de `phishguard.email`,
expressions régulières comprises. Elles ne se recopient pas telles quelles en
JavaScript : `\w`, `\s` et `\b` de Python sont Unicode, et `[a-z]` sous `re.IGNORECASE`
reconnaît aussi `İ ı ſ K` (signe kelvin). Ces classes viennent donc de Python
(`unicode-data.json` : `word`, `ignorecase`). 656 liens (dont 400 de fuzzing), 52
déballages, 50 domaines de texte, 22 noms affichés et 40 expéditeurs calculés par Python
sont rejoués (`test/mail.test.ts`). La suite tue les mutations « `\w` ASCII », « casse
ASCII », « `parse_qs` garde les valeurs vides » et « caractères retirés autour du texte ».

Verdict d'un lien (`src/core/inspect.ts`) :

1. redirection de Google (`www.google.com/url?q=`, `google.com/url?url=`, jusqu'à 5
   niveaux) déballée. La liste d'hôtes est **fermée** : déballer `google.evil/url?q=…`
   ferait analyser la cible annoncée au lieu de l'hôte visité. Puis les passerelles de
   sécurité (Safe Links, Symantec, Proofpoint), comme l'API ;
2. `javascript:`, `data:`, `vbscript:`, `file:` → suspect (`non_web_link`) ;
3. lien web → analyse locale de la cible, liste blanche comprise (étape 5.4) ;
4. texte affiché qui ressemble à une adresse d'un autre domaine enregistré que la cible
   (`mismatch`) → **au moins suspect**, même si le modèle trouve la cible sûre : c'est le
   leurre le plus courant. Une cible de confiance reste de confiance.

Pour l'expéditeur, la règle `display_name_spoof` de l'API est **graduée**. Dans le score de
l'API, elle ne pèse que 25 points, sous le seuil « suspect » : seule, elle n'alerte pas.
Le premier essai dans Chromium l'appliquait comme déclencheur, et le message légitime
`« impots.gouv.fr » <ne-pas-repondre@dgfip.finances.gouv.fr>` affichait une bannière :

| Le nom affiché contient… | Raison | Effet |
|---|---|---|
| une **adresse** d'un autre domaine (`"service@paypal.com" <x@autre.example>`) | `display_name_spoof` | suspect à lui seul : presque jamais légitime |
| seulement un **domaine** différent (`impots.gouv.fr`) | `display_name_domain` | citée si la bannière s'affiche déjà, jamais déclencheur |
| (adresse dont le domaine imite des lettres latines) | `sender_lookalike` | phishing |

### Affichage

Bannière **avant** le corps du message, dans le flux (aucun calque), dans un Shadow DOM
**fermé** : ni le style ni les scripts de Gmail ne l'atteignent. Titre au pluriel exact
(« 1 lien suspect » ; en arabe, six formes), liste des liens (texte affiché, hôte
réellement visité, raisons ; 5 au plus), conseil d'email de l'API, bouton « Masquer ».
`role="alert"` pour un phishing, `role="status"` pour un message suspect. Une marque
(icône et libellé pour lecteur d'écran) **après** chaque lien suspect ; le lien lui-même
n'est jamais modifié. Feuilles de style construites (`adoptedStyleSheets`), non soumises
à la CSP de Gmail.

### Mesures (Chromium 156, maquette servie sous `https://mail.google.com/`)

Les requêtes vers `mail.google.com` sont interceptées : aucune page réelle, domaines
`.example`, IP de documentation.

| # | Message | Attendu | Obtenu |
|---|---|---|---|
| 1 | lettre du Monde, liens vers `lemonde.fr`, `mailto:` | rien | rien |
| 2 | `impots.gouv.fr` depuis `dgfip.finances.gouv.fr` | rien | rien (après graduation) |
| 3 | notification GitHub | rien | rien |
| 4 | Google Docs, `google.com/url?q=https://www.wikipedia.org/` | rien | rien |
| 5 | Safe Links vers `www.amazon.fr`, texte `www.amazon.fr` | rien | rien |
| 6 | texte `www.paypal.com`, cible `paypa1-secure-login.example` | bannière | phishing, 1 marque |
| 7 | `http://192.0.2.10/paypal/login.php` | bannière | phishing (IP), 1 marque |
| 8 | homographe `аpple.com` | bannière | phishing (alphabets), 1 marque |
| 9 | nom affiché `service@paypal.com`, adresse `notice-mail.co.uk` | bannière | suspect (expéditeur) |
| 10 | `google.com/url?q=` vers `appleid.apple.com.verify-account.example`, texte `appleid.apple.com` | bannière | phishing, 1 marque |

**10 sur 10.** La bannière apparaît environ 340 ms après l'ouverture, dont 150 ms
d'arrivée du corps (maquette) et 300 ms d'anti-rebond ; le premier message ajoute le
chargement du modèle. L'analyse tourne dans le service worker : la page Gmail ne fait que
lire le DOM et insérer la bannière.

### Limites connues

- **Texte affiché** : l'extension lit `innerText` (le texte rendu, sans le texte masqué
  par CSS), l'API `get_text(" ")` sur le HTML. `<a>www.pay<span>pal</span>.com</a>` donne
  `www.paypal.com` ici, mais `www.pay pal .com` côté API, qui n'y reconnaît pas une
  adresse. Écart voulu : l'extension voit ce que l'utilisateur voit.
- **Sélecteurs** : les classes de Gmail sont générées et non documentées. Si Gmail les
  change, plus rien n'est analysé (échec silencieux, jamais de fausse alerte). Le test de
  bout en bout (étape 5.10) le détecte sur la maquette, pas sur le vrai Gmail : vérifier
  sur un compte de test à chaque version.
- **Lettres d'information** : texte `www.boutique.fr`, lien de suivi
  `boutique.us12.list-manage.com` → `mismatch`, donc suspect. C'est aussi le
  comportement de l'API ; l'utilisateur peut faire confiance au domaine de suivi.

## 7. Options, analyse automatique et analyse en ligne (étape 5.7)

`options.html` (`options_ui`, ouverte dans un onglet). Chaque réglage est suivi d'une
phrase qui dit **quelles données partent où**, reliée au champ par `aria-describedby`.

| Réglage | Défaut | Permission | Ce qui part, et où |
|---|---|---|---|
| langue | navigateur | — | rien |
| analyse de Gmail | oui | (script de contenu) | rien : sur l'appareil |
| analyse automatique | non | `tabs`, demandée au clic, rendue à la désactivation | rien : sur l'appareil, **sans cache** (ni `storage.session` ni mémoire), donc aucune trace des pages visitées |
| serveur, clé d'API | vide | — | rien tant qu'aucune option réseau n'est active |
| analyse en ligne | non | hôte du serveur, au clic | au clic sur l'icône seulement : l'URL **sans fragment** (un `#access_token=…` reste sur l'appareil) ; jamais pour l'analyse automatique, jamais pour Gmail |
| signalements | non | hôte du serveur, au clic | le domaine, le verdict reçu, le jugement ; jamais l'URL |
| sites de confiance | vide | — | rien : `storage.local` |

- **Serveur** (`parseServerUrl`) : `https` obligatoire, `http` pour la seule boucle
  locale ; ni identifiants, ni paramètres, ni fragment. Changer de serveur rend la
  permission de l'ancien et éteint les options réseau.
- **Requêtes** (`api.ts`) : `credentials: "omit"`, `redirect: "error"` (une redirection
  pourrait mener la clé d'API vers un autre hôte), `referrerPolicy: "no-referrer"`,
  délai de 8 s. Clé d'API au format de l'API (`pg_` suivi de 43 caractères), ou aucune.
- **La réponse du serveur est non fiable** : 256 Kio au plus, schéma vérifié champ par
  champ (verdict, score entier de 0 à 100, 3 raisons au plus, textes bornés), seuls
  quelques champs gardés, affichés par `textContent`. Surtout, **le serveur peut alerter
  davantage, jamais rassurer davantage** : le verdict affiché est le plus prudent des deux
  (`strictest`). Un serveur auto-hébergé compromis ne peut pas faire passer pour sûr ce
  que l'appareil soupçonne.
- **Permissions retirées** depuis `chrome://extensions` : le service worker
  (`permissions.onRemoved`) et la page d'options réalignent les réglages.

**Critère de fin atteint** : avec les réglages par défaut, aucune requête hors du paquet
(Chromium, section 1), et aucun `fetch` sans les deux clés (`test/network.test.ts`).

### Risques résiduels

- **`storage.local` est accessible aux scripts de contenu.** Chrome ne permet de
  restreindre que `storage.session`. Une page Gmail dont le moteur de rendu serait
  compromis pourrait lire la clé d'API (stockée sans chiffrement, ce que dit la page
  d'options) et ajouter un domaine à la liste blanche. Elle ne pourrait toujours ni
  envoyer de requête (permission d'hôte), ni innocenter un hôte aux alphabets mélangés.
  Les valeurs relues sont validées (`parseSettings`) : une valeur invalide revient à son
  défaut, toujours le plus prudent.
- **La clé d'API** ne protège qu'un quota sur le serveur choisi par l'utilisateur, d'où
  le conseil de ne pas réutiliser une clé partagée.

## 8. Langues et accessibilité (étape 5.8)

- **Langues** : `chrome.i18n` suit toujours la langue du navigateur et ne permet pas le
  choix des options. Les trois catalogues (`_locales/{fr,en,ar}`) sont donc embarqués et
  lus par `src/i18n.ts` avec les substitutions de Chrome (`$NOM$`, `$1`, `$$`), en **un
  seul passage** : un nom d'hôte substitué n'est jamais réinterprété (testé avec
  `$2$HOST$`). En mode « langue du navigateur », c'est Chrome qui choisit le catalogue
  (`langCode`). Pluriels par `Intl.PluralRules` : l'arabe a six formes (`zero`, `one`,
  `two`, `few`, `many`, `other`), le français trois ; un test exige chaque forme dans
  chaque langue, et chaque clé employée par le code ou les pages. Les conseils et trois
  raisons sont ceux de l'API, mot pour mot.
- **Droite à gauche** : `dir` et `lang` posés depuis la langue effective ; mise en page en
  propriétés logiques (`border-inline-start`, `padding-inline-start`…), qui se retourne
  d'elle-même (vérifié : bordure de la carte à droite en arabe). Hôtes, domaines et
  adresses toujours isolés et de gauche à droite (`unicode-bidi: isolate`) ; marque RLM
  avant un hôte inséré dans une phrase arabe.
- **Contrastes WCAG AA** calculés par `test/a11y.test.ts` depuis les couleurs réelles de
  `theme.css` (clair et sombre) et de la bannière : 4,5 pour tout texte sur son fond
  (verdict sur sa carte compris), 3 pour les contours, les bordures et l'anneau de focus
  (critère 1.4.11). Modifier une couleur relance la vérification. Mode `forced-colors`
  (contraste élevé de Windows) : contour explicite.
- **Clavier** : boutons natifs, ordre naturel, anneau de focus jamais retiré. Échap ferme
  un panneau et rend le focus au bouton qui l'a ouvert ; après une action, le focus va au
  titre du verdict ; une ligne retirée de la liste blanche passe le focus à la suivante.
  Vérifié dans Chromium (Tab, Maj+Tab, Entrée, Échap).
- **Lecteurs d'écran** : icônes `aria-hidden` (le texte du verdict suffit), flèche du
  bouton de détails sans texte de remplacement (`content: "▸" / ""`), état par
  `aria-expanded`. Annonces courtes dans une zone `role="status"` (verdict, résultat
  d'une action) plutôt que la relecture de toute la carte. Erreurs de champ reliées par
  `aria-describedby` et `aria-invalid`. Bannière Gmail : `role="alert"` (phishing) ou
  `status` (suspect) ; marque `role="img"` avec un libellé.
- **Non vérifié** : le passage réel avec NVDA, JAWS ou VoiceOver. Les attributs ARIA sont
  en place et testés ; l'écoute réelle reste à faire pendant les tests utilisateurs
  (étape 5.13).

### Vérification de bout en bout (Chromium 156, build de test, 16 novembre 2026)

41 vérifications, toutes réussies : verdict en texte, conseil, explication, détails
repliés ; ordre de tabulation, Maj+Tab, Entrée, Échap ; confirmation de confiance avec
focus sur « Annuler » pour un phishing ; signalement désactivé et expliqué ; homographe
sans bouton de confiance ; page non analysable ; arabe (`rtl`, traduction, bordure à
droite) et anglais ; options par défaut, refus d'un serveur `http`, liste blanche ; les 10
messages Gmail ; `href` intacts ; ombre fermée ; aucune requête externe. Ces parcours
entrent dans la CI avec Playwright à l'étape 5.10.

## 9. Audit et tests de bout en bout (étapes 5.9 et 5.10)

### Audit (5.9)

[extension-privacy.md](extension-privacy.md) dit en langage simple ce que l'extension lit,
garde et envoie, avec **une phrase par permission** pour le Chrome Web Store.
`test/audit.test.ts` garde ce document vrai :

- son tableau des autorisations contient **exactement** celles du manifeste, avec leur
  type, chaque justification en une phrase de moins de 1 000 caractères (limite du
  formulaire du store) ; une permission ajoutée sans justification fait échouer le test ;
- le manifeste n'ouvre rien d'autre : ni `host_permissions`, ni
  `web_accessible_resources` (un site ne peut pas détecter l'extension en sondant ses
  fichiers), ni `externally_connectable`, ni page remplacée ; script de contenu sur Gmail,
  cadre principal, monde isolé ;
- CSP : `script-src 'self'` seul, `object-src 'none'`, aucun `unsafe-*`, aucun joker
  d'hôte ; le seul relâchement est `connect-src https:` (section 1) ;
- sources : seuls les espaces `action`, `contextMenus`, `i18n`, `permissions`, `runtime`,
  `storage`, `tabs` ; `chrome.tabs.query` seulement sur l'onglet actif ; jamais
  `storage.sync`, ni `randomUUID`, `getRandomValues`, `Math.random` (aucun identifiant),
  ni `navigator.userAgent` et voisins, ni `console.log`, ni `document.cookie` ;
- aucune dépendance d'exécution, versions exactes, `ignore-scripts=true`.

En CI : `npm audit` (0 vulnérabilité) et `npm audit signatures` (signatures du registre
de chaque paquet installé).


## 10. Ce qui vient ensuite

| Étape | Ajoute |
|---|---|
| 5.9 | audit des permissions (tableau de la section 1 : une phrase par permission pour le Chrome Web Store), `docs/extension-privacy.md` |
| 5.10 | tests de bout en bout Playwright en CI : maquette Gmail et parcours de la section 8 |
| module 6 | téléchargement de modèles signés : `loadUrlModel` est déjà prêt pour une entrée non fiable ; reste la vérification Ed25519 dans l'extension (WebCrypto) |
