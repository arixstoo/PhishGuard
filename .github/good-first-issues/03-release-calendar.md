---
title: Refuser les dates impossibles (2026.02.31) dans les numéros de publication des modèles
labels: good first issue, area:extension, tests, security
---

## Contexte

Les modèles publiés portent un numéro daté, `AAAA.MM.JJ` ou `AAAA.MM.JJ.N`. L'extension
s'en sert pour refuser un retour à un modèle plus ancien
([docs/model-updates.md](docs/model-updates.md#4-côté-extension)). Aujourd'hui,
`parseRelease` dans `extension/src/core/signed-model.ts` vérifie que le jour est entre 1
et 31, mais accepte `2026.02.31` ou `2026.04.31`, qui n'existent pas.

Ce n'est pas une faille (le manifeste reste signé), mais un numéro impossible ne devrait
jamais être accepté.

## À faire

1. Dans `parseRelease`, refusez un jour qui n'existe pas dans le mois (années bissextiles
   comprises : `2028.02.29` est valide, `2027.02.29` ne l'est pas).
2. Ajoutez les cas correspondants au test « ordre total des publications » de
   `extension/test/signed-model.test.ts`.

## Vérifier

```bash
cd extension && npm ci && npm test
```

## Terminé quand

- `parseRelease("2026.02.31")` et `parseRelease("2027.02.29")` renvoient `null`,
  `parseRelease("2028.02.29")` est accepté ;
- `npm test` et `npm run typecheck` passent.
