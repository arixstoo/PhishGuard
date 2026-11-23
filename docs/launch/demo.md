# Vidéo de démonstration (90 secondes) et GIF du README

La vidéo sert l'article, le post LinkedIn et la fiche du store ; le GIF, le haut du README.
Elle montre **une** idée : PhishGuard prévient avant le clic, explique pourquoi, et ne
regarde rien d'autre.

## Règles de tournage

- **Aucune vraie URL de phishing, aucune vraie personne.** Les mêmes cas que les tests :
  `http://paypa1-secure-login.example/verify/account`, l'homographe `xn--pple-43d.com`,
  la maquette Gmail des tests ou un message que l'on s'envoie à soi-même depuis une
  adresse de test. Un domaine `.example` ne mène nulle part : rien n'est visité.
- Profil Chrome neuf, extension installée **depuis le store**, barre de favoris vide,
  notifications coupées, zoom à 125 % pour la lisibilité.
- Langue de l'interface : français pour la version FR, anglais pour la version EN (réglage
  « Langue » des options), même scénario.

## Scénario

| Temps | Image | Voix off / sous-titre |
|---|---|---|
| 0–8 s | Une boîte mail ; un message « Votre compte est limité » | « Chaque jour, des millions de messages piégés imitent votre banque, votre opérateur, l'administration. » |
| 8–20 s | Le message s'ouvre : la bannière PhishGuard apparaît au-dessus | « PhishGuard vérifie les liens du message ouvert, sur votre ordinateur. Ici, le lien affiché dit paypal.com, mais il mène ailleurs. » |
| 20–35 s | Clic droit sur le lien → « Analyser ce lien avec PhishGuard » ; la fenêtre s'ouvre : « Phishing probable » | « Avant de cliquer, un clic droit suffit. Le verdict est en mots et en couleur, avec ce qu'il faut faire. » |
| 35–48 s | « Détails techniques » dépliés : domaine, score, règle | « Pas de boîte noire : les raisons sont là pour qui veut vérifier. » |
| 48–60 s | Un site légitime (wikipedia.org) : « Aucun signe de phishing » | « Et quand tout va bien, il reste discret. » |
| 60–75 s | Options : tout ce qui est en ligne est désactivé ; puis **mode avion** activé, nouvelle analyse qui marche | « Par défaut, rien ne quitte votre appareil. La preuve : il fonctionne en mode avion. » |
| 75–90 s | Logo, « Libre, gratuit, en français, anglais et arabe », lien du store et du dépôt | « PhishGuard est libre et gratuit. Installez-le, et signalez-nous ses erreurs. » |

## Enregistrer

1. Construire et installer la version du store, ou `make extension-build` puis « Charger
   l'extension non empaquetée » sur `extension/dist/`.
2. Pour la scène Gmail sans vrai compte, rejouer le parcours des tests pas à pas, dans
   `extension/` : `npm run build:e2e && npx playwright test e2e/gmail.spec.ts --headed --debug`
   (Chromium avec l'extension et la maquette Gmail) ; ou s'envoyer un message de test.
3. Enregistrer l'écran en 1920 × 1080 (OBS Studio, ou l'enregistreur du système), voix
   enregistrée à part, montage simple (coupes franches, aucun effet).
4. Sous-titres FR et EN (fichiers `.srt`) : beaucoup de vidéos sont regardées sans le son.

## Le GIF du README

10 à 15 secondes : scènes 2 et 3 (bannière, puis clic droit et verdict). Moins de 5 Mo pour
s'afficher vite sur GitHub. Depuis la vidéo montée, avec ffmpeg :

```bash
ffmpeg -ss 8 -t 14 -i demo.mp4 -vf "fps=12,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96[p];[b][p]paletteuse=dither=bayer" -loop 0 docs/img/demo.gif
```

Puis remplacer dans le README l'image `docs/img/extension-verdict.png` par
`docs/img/demo.gif`. En attendant, le README montre une vraie capture de l'extension,
produite par `make store-assets` (vrai modèle signé, cas des tests).
