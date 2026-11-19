---
title: Ajouter 10 sites légitimes de Belgique, de Suisse ou du Québec au garde-fou des faux positifs
labels: good first issue, area:detection, tests
---

## Contexte

Chaque mois, un nouveau modèle n'est publié que s'il ne signale pas **davantage** de sites
légitimes courants que le modèle en service ([docs/model-updates.md](docs/model-updates.md#2-garde-fou-de-non-régression)).
La liste couvre surtout la France, le Maghreb et les grands services internationaux. Les
utilisateurs belges, suisses et québécois n'y sont pas représentés.

## À faire

1. Dans `src/phishguard/urls/data/common_legitimate_urls.json`, ajoutez un groupe
   (par exemple `"Belgique, Suisse, Québec"`) avec **10 URLs** de pages d'accueil ou de
   connexion très utilisées : banques, poste, impôts, administration, opérateurs.
2. Uniquement des URLs `https://` officielles, sans paramètre (`?`) ni fragment (`#`).
   Vérifiez chaque adresse dans votre navigateur avant de l'ajouter.

Cette liste ne change **pas** le modèle : aucun réentraînement n'est nécessaire.

## Vérifier

```bash
pytest tests/test_model_update.py
```

## Terminé quand

- 10 URLs ajoutées, aucune en double (le test le vérifie) ;
- `pytest tests/test_model_update.py` passe.
