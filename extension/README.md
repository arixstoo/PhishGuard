# Extension PhishGuard (Chrome, Manifest V3)

Analyse locale des URLs et des liens du message ouvert dans Gmail : par défaut, rien ne
quitte l'appareil. Architecture, décisions et mesures :
[docs/extension-design.md](../docs/extension-design.md).

```bash
npm ci                 # dépendances exactes, sans script d'installation (.npmrc)
npm run typecheck
npm test               # parité avec Python, vecteurs de référence, modèle, emails, langues, accessibilité, réseau, audit
npm run build          # dist/ ; exige models/manifest.json signé (make export && make sign)
node build.mjs --allow-missing-model   # sans modèle (CI)
node build.mjs --test  # dist-test/ : crochets pour tests automatisés, jamais à publier
npm run test:e2e       # Playwright : build de test avec le modèle de test, puis e2e/ (npx playwright install chromium)
npm run package        # release/phishguard-extension-<version>.zip, reproductible, et son .sha256
```

Ce que l'extension fait des données, en langage simple : [docs/extension-privacy.md](../docs/extension-privacy.md).
Installer une bêta : [docs/beta.md](../docs/beta.md).

Charger `dist/` dans `chrome://extensions` (mode développeur, « Charger l'extension non
empaquetée »), puis cliquer sur l'icône sur n'importe quelle page, ou ouvrir un message
dans Gmail. Réglages : clic droit sur l'icône → Options.

| Dossier | Contenu |
|---|---|
| `src/core/` | extracteur, modèle, décision, liens et expéditeur d'un email : pur, sans API Chrome |
| `src/background.ts` | service worker |
| `src/api.ts` | module réseau des options en ligne (désactivées par défaut) |
| `src/updates.ts`, `src/core/signed-model.ts` | mises à jour signées du modèle (désactivées par défaut) : téléchargement, vérification Ed25519 ([docs/model-updates.md](../docs/model-updates.md)) |
| `src/popup/`, `src/options/` | fenêtre contextuelle, page d'options |
| `src/gmail/` | script de contenu Gmail ; **tous les sélecteurs de Gmail dans `selectors.ts`** |
| `static/_locales/` | `fr`, `en`, `ar` ; toute clé employée doit exister dans les trois (test) |
| `test/fixtures/gmail-mock.html` | maquette de Gmail (10 messages), même structure que `selectors.ts` |
| `test/audit.test.ts` | permissions = tableau de `docs/extension-privacy.md`, CSP, API Chrome employées (étape 5.9) |
| `e2e/` | parcours Playwright (étape 5.10) ; `stub-model.mjs` : modèle de test, mêmes verdicts que `url_v2` sur ces parcours |
| `package.mjs` | archive ZIP reproductible de la version (étape 5.14) |

`src/generated/` et `test/fixtures/python-parity.json` sont produits par
`make extension-data` à la racine du dépôt : ne pas les modifier à la main. Après toute
modification de l'extracteur Python ou de `phishguard.email`, relancer `make export` puis
`make extension-data`, et `npm test`.

Règles de sécurité vérifiées par le build : aucun `eval`, aucune injection HTML (tout
texte par `textContent`), aucun `fetch` hors de `api.ts` et du chargement du modèle,
aucun autre canal réseau.
