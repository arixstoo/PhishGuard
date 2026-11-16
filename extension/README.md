# Extension PhishGuard (Chrome, Manifest V3)

Analyse locale des URLs : l'adresse d'une page ne quitte pas l'appareil. Architecture,
décisions et mesures : [docs/extension-design.md](../docs/extension-design.md).

```bash
npm ci                 # dépendances exactes, sans script d'installation (.npmrc)
npm run typecheck
npm test               # parité avec Python, vecteurs de référence, modèle, décision
npm run build          # dist/ ; exige models/manifest.json signé (make export && make sign)
node build.mjs --allow-missing-model   # sans modèle (CI)
node build.mjs --test  # dist-test/ : crochets pour tests automatisés, jamais à publier
```

Charger `dist/` dans `chrome://extensions` (mode développeur, « Charger l'extension non
empaquetée »), puis cliquer sur l'icône sur n'importe quelle page.

`src/generated/` et `test/fixtures/python-parity.json` sont produits par
`make extension-data` à la racine du dépôt : ne pas les modifier à la main. Après toute
modification de l'extracteur Python, relancer `make export` puis `make extension-data`,
et `npm test`.
