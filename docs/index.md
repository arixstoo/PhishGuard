---
hide:
  - navigation
---

# PhishGuard

**Un avertissement clair au moment où vous allez cliquer sur un lien piégé.**
PhishGuard est une extension gratuite pour Google Chrome qui vérifie les liens, sur votre
ordinateur, et vous dit en une phrase pourquoi un site est douteux. En français, en
anglais et en arabe.

- **Rien ne quitte votre ordinateur** par défaut : pas de compte, pas d'historique, pas de
  publicité ([confidentialité](privacy.md)).
- **Une raison lisible** à chaque verdict : « L'adresse ressemble à celle de PayPal mais
  n'est pas la sienne », pas un simple voyant rouge.
- **Libre et vérifiable** : tout le code est [public](https://github.com/arixstoo/PhishGuard),
  les chiffres de détection aussi, y compris ses limites.

## Installer en 3 étapes

Il faut Google Chrome, Microsoft Edge ou Brave, à jour.

!!! info "Pas encore sur le Chrome Web Store"
    La publication sur le Chrome Web Store est en cours. En attendant, la version de
    test s'installe en quelques minutes en suivant [ce guide](beta.md#pour-les-testeurs--installer-lextension).
    Les étapes ci-dessous seront celles de la version publiée.

### 1. Ajouter l'extension

Ouvrez la page de PhishGuard sur le Chrome Web Store et cliquez sur **« Ajouter à
Chrome »**, puis sur **« Ajouter l'extension »**.

<!-- capture : docs/img/install-1-store.png (issue « Captures d'écran de l'installation ») -->

Chrome prévient que PhishGuard peut « lire et modifier vos données sur
mail.google.com ». C'est ce qui lui permet de vérifier les liens du message que vous
ouvrez dans Gmail, **sur votre ordinateur** : il n'envoie rien, à personne.

### 2. Épingler le bouclier

Cliquez sur l'icône en forme de **pièce de puzzle**, à droite de la barre d'adresse,
puis sur l'**épingle** à côté de PhishGuard. Son bouclier bleu reste alors visible.

<!-- capture : docs/img/install-2-pin.png -->

### 3. Vérifier un site

Sur n'importe quel site, cliquez sur le bouclier. PhishGuard affiche son verdict
(**sûr**, **suspect** ou **phishing**), une phrase d'explication et un conseil.

<!-- capture : docs/img/install-3-verdict.png -->

Dans Gmail, ouvrez simplement un message : un bandeau apparaît en haut s'il contient un
lien douteux. Pour un lien précis, faites un clic droit dessus, puis **« Analyser ce lien
avec PhishGuard »**.

## Et ensuite ?

| Vous voulez… | Lisez |
| --- | --- |
| savoir ce que PhishGuard fait de vos données | [Confidentialité](privacy.md) |
| comprendre un verdict, signaler une erreur | [Questions fréquentes](faq.md) |
| apprendre à reconnaître le phishing | [Phishing 101](phishing-101.md) |
| savoir comment ça marche | [Architecture](architecture.md) |
| connaître les chiffres et les limites | [Fiche du modèle URL](model-card-url.md), [rapport de robustesse](robustness-report.md) |
| contribuer | [Contribuer](contributing.md) |

<!-- vidéo de démonstration (90 s) : fichier docs/img/demo.mp4, lu sans service tiers -->

PhishGuard ne remplace pas votre vigilance : aucun détecteur ne voit tout. En cas de
doute, ne saisissez ni mot de passe ni code, et passez par le site officiel en tapant
vous-même son adresse.
