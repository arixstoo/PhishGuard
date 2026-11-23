---
title: Traduire la politique de confidentialité en arabe
labels: good first issue, translation, documentation, help wanted
---

## Contexte

L'extension est disponible en français, en anglais et en arabe, mais sa politique de
confidentialité ([PRIVACY.md](PRIVACY.md)) n'existe qu'en français et en anglais. La
fiche du Chrome Web Store sera publiée dans les trois langues.

## À faire

1. Créez `docs/privacy.ar.md`, traduction en arabe standard moderne de la partie
   anglaise de `PRIVACY.md` (sections 1 à 7).
2. Gardez exactement les mêmes chiffres (100 analyses, 1 000 sites, 90 jours, 14 jours,
   30 jours) et les mêmes liens.
3. En tête du fichier, ajoutez une ligne disant que la version française fait foi.
4. Ajoutez un lien vers ce fichier au début de `PRIVACY.md`.

Pas besoin d'être développeur : une relecture attentive suffit. Si un terme technique n'a
pas d'équivalent courant, laissez-le en latin (`HTTPS`, `Chrome`).

## Vérifier

```bash
pytest tests/test_privacy_policy.py
```

## Terminé quand

- `docs/privacy.ar.md` existe et couvre les sections 1 à 7 ;
- `PRIVACY.md` y renvoie ;
- un second arabophone a relu la traduction (commentaire dans la PR).
