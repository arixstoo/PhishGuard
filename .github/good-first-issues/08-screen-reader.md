---
title: Écouter la fenêtre de l'extension avec un lecteur d'écran (NVDA, VoiceOver ou TalkBack)
labels: good first issue, accessibility, area:extension, help wanted
---

## Contexte

La fenêtre et les options de l'extension sont testées au clavier et pour l'ARIA dans
Chromium ([docs/extension-design.md](docs/extension-design.md)), mais personne ne les a
encore **écoutées** avec un vrai lecteur d'écran. Un verdict « phishing » doit être
annoncé clairement, sans dépendre de la couleur.

## À faire

1. Installez l'extension en mode développeur ([CONTRIBUTING.md](CONTRIBUTING.md#extension)).
2. Avec NVDA (Windows, gratuit), VoiceOver (macOS) ou un autre lecteur, ouvrez la fenêtre
   sur trois pages : une page sûre (`https://www.wikipedia.org/`), puis les deux exemples
   de test `http://paypa1-secure-login.example/verify/account` et
   `http://192.0.2.10/paypal/login.php` (adresses réservées : elles ne mènent nulle part).
3. Notez, pour chacune : ce qui est lu à l'ouverture, dans quel ordre, et ce qui manque
   ou gêne. Faites de même pour la page d'options.
4. Rapportez vos notes en commentaire de cette issue (lecteur, version, navigateur).

Aucune ligne de code n'est demandée ; si vous voyez la correction, une PR est bienvenue.

## Terminé quand

- un compte rendu pour la fenêtre (3 pages) et pour les options est posté ici ;
- chaque problème trouvé a sa propre issue (label `accessibility`).
