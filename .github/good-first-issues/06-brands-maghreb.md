---
title: Ajouter des marques tunisiennes et marocaines à la détection du typosquatting
labels: good first issue, area:detection, needs-retraining
---

## Contexte

Le modèle repère les adresses qui imitent une marque (`paypa1.com`, `laposte-colis.info`)
grâce à `src/phishguard/urls/data/brands.json`. La liste contient La Poste, Algérie
Poste, Djezzy, Ooredoo… mais aucune marque tunisienne ou marocaine, alors que ces pays
font partie du public visé.

**Important** : cette liste fait partie des données de référence du modèle
(`reference_data_sha256`). La modifier change l'empreinte : l'extension refusera le
modèle actuel tant qu'il n'a pas été réentraîné avec la nouvelle liste. Votre PR est
donc relue et validée, puis fusionnée **avec le prochain réentraînement mensuel**
(label `needs-retraining`). Rien à faire de plus de votre côté.

## À faire

1. Ajoutez au moins 4 marques, par exemple La Poste Tunisienne (`poste.tn`), Tunisie
   Telecom (`tunisietelecom.tn`), Barid Al-Maghrib (`barid.ma`), Maroc Telecom (`iam.ma`).
   Format : celui des entrées existantes (`name` en minuscules sans espace, `domains`
   officiels). Vérifiez chaque domaine sur le site officiel.
2. Régénérez les données de l'extension : `make extension-data`.

## Vérifier

```bash
pytest tests/test_url_features.py tests/test_extension_data.py
cd extension && npm ci && npm test
```

`npm test` échouera sur les vecteurs de référence du modèle tant que le modèle n'est pas
réentraîné : c'est attendu, indiquez-le dans la PR.

## Terminé quand

- au moins 4 marques ajoutées, domaines vérifiés ;
- `src/phishguard/urls/data/brands.json` et `extension/src/generated/reference-data.json`
  modifiés dans la même PR ;
- les tests Python passent.
