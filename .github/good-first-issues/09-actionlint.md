---
title: Vérifier les workflows GitHub Actions avec actionlint dans la CI
labels: good first issue, ci
---

## Contexte

Le dépôt a huit workflows (`.github/workflows/`), dont certains planifiés (collecte
quotidienne, réentraînement mensuel) : une faute de frappe dans une expression `${{ }}`
ne se voit qu'au premier déclenchement, parfois un mois plus tard.
[actionlint](https://github.com/rhysd/actionlint) les vérifie en quelques secondes.

## À faire

1. Ajoutez un job `actionlint` à `.github/workflows/ci.yaml`.
2. Règles du dépôt ([docs/ci-security.md](docs/ci-security.md)) : action épinglée par SHA
   de commit (version lisible en commentaire), ou binaire téléchargé à une version
   précise **et vérifié par son empreinte SHA-256** publiée ; permissions minimales
   (`contents: read`) ; `persist-credentials: false`.
3. Corrigez ce qu'actionlint signale, ou expliquez dans la PR pourquoi un avertissement
   est ignoré.

## Vérifier

```bash
actionlint   # localement, après installation
```

## Terminé quand

- le job `actionlint` passe sur la PR ;
- il échoue si l'on introduit une faute volontaire dans un workflow (essayez-le, puis
  annulez).
