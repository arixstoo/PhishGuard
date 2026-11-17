# Page « coller et analyser » (étape 5.12)

Pour celles et ceux qui n'installeront jamais d'extension ni de bot : une page où l'on
colle un SMS, un message ou un lien, et qui affiche le verdict, ses raisons et un conseil.

Elle est **servie par l'API elle-même**, à la racine : `make api`, puis
<http://127.0.0.1:8000/>. En production, derrière le proxy TLS du module 6, la même
adresse que l'API. Désactivable : `PHISHGUARD_API_WEB_PAGE_ENABLED=false`.

| Fichier | Rôle |
|---|---|
| `src/phishguard/api/static/index.html` | page, sans aucun script ni style en ligne |
| `src/phishguard/api/static/paste.js` | extraction des liens, appels à l'API, affichage |
| `src/phishguard/api/static/paste.css` | thème clair et sombre, droite à gauche |
| `src/phishguard/api/routers/web.py` | les quatre fichiers, et la politique de contenu de la page |

## Pourquoi dans l'API

Même origine que `/v1/analyze/*` : **aucun CORS à ouvrir**, aucune clé d'API dans la page
(elle appelle l'API au palier anonyme, 30 analyses par minute et par IP, étape 4.4).
Une page hébergée ailleurs aurait demandé d'autoriser son origine, et l'API resterait
exposée à tout site qui la copierait.

## Ce que fait la page

1. **Avertissement en tête** : « Ne collez pas de mot de passe ou de données
   personnelles. » Puis : le texte est envoyé à ce serveur pour être analysé, puis oublié.
2. Le texte (5 000 caractères au plus, la borne de l'API) et ses liens (5 au plus, avec ou
   sans `https://`) sont analysés **en parallèle** : `POST /v1/analyze/text`
   (`channel: messaging`) et `POST /v1/analyze/url` (sans Threat Intelligence). Un lien
   seul n'est analysé que comme lien.
3. Verdict global : le plus grave ; icône, couleur **et** texte ; score ; une ligne par
   élément (le message, chaque lien) avec ses raisons ; le conseil du résultat le plus
   grave. Une partie en échec est signalée (« verdict incomplet ») ; une limite de débit
   atteinte affiche le délai à attendre.
4. Langue : celle du navigateur (`fr`, `en`, `ar`), modifiable ; l'arabe passe la page en
   droite à gauche (propriétés logiques), et les analyses sont demandées dans la langue
   choisie.

## Sécurité

- **Tout texte par `textContent`**, ce qui vient du serveur comme ce qui a été collé. Un
  message piégé ne peut pas exécuter de script dans la page (testé avec
  `<img src=x onerror=…>` dans une raison renvoyée par le serveur).
- **Politique de contenu de la page** (`WEB_CSP`) :
  ```text
  default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
  connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';
  require-trusted-types-for 'script'; trusted-types 'none'
  ```
  Ses seuls fichiers, ses seules requêtes vers son origine. **Trusted Types** : le
  navigateur lui-même refuse toute insertion de HTML par chaîne (`innerHTML`…), même si
  une modification future du code l'introduisait (testé). Les autres en-têtes de
  sécurité de l'API (`X-Frame-Options`, `nosniff`, `no-store`, `no-referrer`…) s'y
  appliquent aussi.
- **Le texte ne peut pas finir dans une URL** : le champ n'a pas d'attribut `name`, et
  `form-action 'none'` bloque tout envoi natif du formulaire (par exemple si le script ne
  se chargeait pas, un formulaire `GET` mettrait le message dans l'historique et les
  journaux du proxy).
- **Correcteur orthographique désactivé** sur le champ (`spellcheck="false"`) : le
  correcteur « amélioré » de certains navigateurs envoie le texte saisi à un service en
  ligne.
- **Aucun lien cliquable**, seul l'hôte de chaque lien est affiché, jamais son chemin ni
  ses paramètres, et en ASCII : la classe `URL` du navigateur donne la forme Punycode
  d'un homographe (`xn--pple-43d.com`).
- **Rien n'est stocké** : ni cookie, ni stockage local, ni statistiques, aucune ressource
  externe (testé : aucun `localStorage`, `document.cookie`, `XMLHttpRequest`, `WebSocket`,
  `sendBeacon` dans le code ; une seule fonction appelle `fetch`, vers les deux routes
  d'analyse seulement).
- Quatre fichiers fixes, lus une fois au démarrage : aucun chemin n'est construit depuis
  la requête (`/static/..%2Fmain.py` → 404, testé).

## Accessibilité

Étiquette sur le champ, compteur de caractères, erreur reliée au champ
(`aria-describedby`, `aria-invalid`) avec le focus qui y revient ; après une analyse, le
focus va au titre du verdict et une zone `role="status"` annonce le résultat. Contrastes
WCAG AA calculés depuis les couleurs réelles de `paste.css`, en clair et en sombre
(`tests/test_api_web.py`) ; mêmes couleurs que l'extension. Anneau de focus visible,
contour explicite en mode de contraste élevé.

## Tests

- `tests/test_api_web.py` (20 tests) : en-têtes et politique de contenu, aucun script ni
  style en ligne ni ressource externe, champ sans `name`, garde-fous du code de la page,
  bornes identiques à celles de l'API, fichiers servis et refusés, page hors du schéma
  OpenAPI, désactivation, contrastes.
- `extension/e2e/web-page.spec.ts` (6 parcours Playwright, réponses de l'API simulées,
  avec la vraie politique de contenu) : message piégé (verdict le plus grave, HTML piégé
  affiché comme texte, aucun chemin ni lien), lien seul, texte vide, limite de débit,
  arabe, Trusted Types. Vérifié par mutation : afficher l'URL au lieu de l'hôte fait
  échouer le premier parcours.
