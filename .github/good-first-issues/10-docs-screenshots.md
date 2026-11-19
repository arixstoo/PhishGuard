---
title: Captures d'écran de l'installation de l'extension pour la page d'accueil du site
labels: good first issue, documentation
---

## Contexte

La page d'accueil du site de documentation (`docs/index.md`) explique en trois étapes
comment installer l'extension. Les emplacements des captures sont prévus, mais les
images n'existent pas encore. Un non-technicien doit pouvoir installer l'extension en
suivant seulement cette page.

## À faire

1. Prenez trois captures, en français, navigateur sans autre extension visible :
   - `docs/img/install-1-store.png` : la page de l'extension (Chrome Web Store, ou
     `chrome://extensions` en mode développeur tant qu'elle n'y est pas publiée) ;
   - `docs/img/install-2-pin.png` : le menu des extensions, avec PhishGuard épinglé ;
   - `docs/img/install-3-verdict.png` : la fenêtre de PhishGuard sur `https://www.wikipedia.org/`.
2. Largeur 1280 px au plus, PNG optimisé (moins de 300 Kio chacune), aucune donnée
   personnelle visible (onglets, favoris, nom de profil, adresse email).
3. Retirez les commentaires `<!-- capture : … -->` de `docs/index.md` qui les annoncent.

## Vérifier

```bash
pip install -e '.[docs]' && mkdocs serve   # puis http://127.0.0.1:8000
```

## Terminé quand

- les trois images s'affichent sur la page d'accueil, sans donnée personnelle ;
- `mkdocs build --strict` passe.
