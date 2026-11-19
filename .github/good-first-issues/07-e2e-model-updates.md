---
title: Test Playwright de la section « Mises à jour du modèle » de la page d'options
labels: good first issue, area:extension, tests
---

## Contexte

La page d'options de l'extension a une section « Mises à jour du modèle » (étape 6.8) :
une case qui demande la permission des hôtes de GitHub, et un bouton « Vérifier
maintenant ». La logique est testée par vitest (`extension/test/updates.test.ts`), mais
le parcours dans un vrai Chromium ne l'est pas encore, contrairement aux autres sections
(`extension/e2e/options.spec.ts`).

## À faire

Dans `extension/e2e/options.spec.ts`, ajoutez un test qui vérifie, avec les réglages par
défaut :

1. la case « Recevoir les mises à jour signées du modèle de détection » est décochée ;
2. le bouton « Vérifier maintenant » est désactivé ;
3. la ligne d'état indique le modèle livré avec l'extension ;
4. aucune requête ne part (la fixture de `extension/e2e/fixtures.ts` le vérifie déjà
   après chaque test).

Inspirez-vous des tests existants du même fichier (sélecteurs par rôle et par nom
accessible, pas par classe CSS).

## Vérifier

```bash
cd extension && npm ci && npx playwright install chromium && npm run test:e2e
```

## Terminé quand

- le nouveau test passe localement et dans le job `e2e` de la CI ;
- il échoue si l'on coche la case par défaut dans `extension/src/settings.ts`
  (essayez-le, puis annulez).
