---
title: Compléter la liste des plateformes d'hébergement ouvertes à tous (Netlify, GitLab Pages, Carrd…)
labels: good first issue, area:detection
---

## Contexte

`src/phishguard/urls/data/hosting.json` liste les plateformes où n'importe qui peut
publier une page (Firebase, Vercel, GitHub Pages…). Une page de phishing hébergée là
ressemble, par son adresse, à une page légitime : c'est une des causes des faux négatifs
classées par l'analyse d'erreurs ([docs/error-analysis-url.md](docs/error-analysis-url.md)).
Plusieurs plateformes courantes manquent, par exemple `netlify.app`, `gitlab.io`,
`carrd.co`, `jimdosite.com`, `strikingly.com`.

## À faire

1. Ajoutez au moins **5 domaines** à la liste `domains`, en gardant l'ordre alphabétique.
2. Pour chacun, vérifiez sur le site officiel qu'un compte gratuit permet de publier une
   page sous ce domaine.
3. Mettez à jour le champ `version` (date du jour, `AAAA-MM-JJ`).

Cette liste sert à l'analyse d'erreurs, **pas** au modèle : aucun réentraînement n'est
nécessaire.

## Vérifier

```bash
pytest tests/test_url_errors.py
```

## Terminé quand

- au moins 5 plateformes ajoutées, liste triée ;
- `pytest tests/test_url_errors.py` passe.
