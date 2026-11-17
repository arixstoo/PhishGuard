# Version bêta 0.5.0-beta.1 (étape 5.14)

Version de test de l'extension PhishGuard, distribuée aux participants des tests
utilisateurs ([user-tests.md](user-tests.md)), **pas** sur le Chrome Web Store (module 6).

## Pour les testeurs : installer l'extension

Il faut Google Chrome (ou Microsoft Edge, Brave), version 127 ou plus récente.

1. **Enregistrez** le fichier `phishguard-extension-0.5.0-beta.1.zip` reçu, puis
   **décompressez-le** (clic droit → « Extraire tout… »). Vous obtenez un dossier.
   Gardez-le : si vous le supprimez, l'extension cesse de fonctionner.
2. Dans Chrome, tapez `chrome://extensions` dans la barre d'adresse, puis Entrée.
3. En haut à droite, activez **« Mode développeur »**.
4. Cliquez sur **« Charger l'extension non empaquetée »** et choisissez le dossier
   décompressé (celui qui contient `manifest.json`).
5. PhishGuard apparaît dans la liste. Cliquez sur l'icône en forme de pièce de puzzle, à
   droite de la barre d'adresse, puis sur l'épingle à côté de PhishGuard : son bouclier
   bleu reste visible.

Chrome indique que PhishGuard peut « lire et modifier vos données sur mail.google.com ».
C'est ce qui lui permet de vérifier les liens du message que vous ouvrez dans Gmail, sur
votre ordinateur : il n'envoie rien, à personne ([extension-privacy.md](extension-privacy.md)).

**Utiliser** : cliquez sur le bouclier sur n'importe quel site pour avoir son avis ; dans
Gmail, ouvrez un message : un bandeau apparaît en haut s'il contient un lien douteux.

**Désinstaller** : `chrome://extensions` → PhishGuard → « Supprimer ». Tout ce que
l'extension avait enregistré est effacé avec elle.

**Vérifier que le fichier n'a pas été modifié** (facultatif) : son empreinte SHA-256 doit
être celle du fichier `.sha256` fourni avec lui.

```powershell
Get-FileHash phishguard-extension-0.5.0-beta.1.zip   # Windows (PowerShell)
```
```bash
sha256sum -c phishguard-extension-0.5.0-beta.1.zip.sha256   # Linux, macOS : shasum -a 256
```

## Pour le mainteneur : publier une bêta

```bash
make export sign          # modèle signé (étapes 4.11, 4.12), s'il a changé
make extension-test       # types, parité avec Python, audit (étapes 5.3 à 5.9)
make extension-e2e        # parcours Playwright (étape 5.10)
make extension-package    # extension/release/phishguard-extension-<version>.zip et .sha256
```

`npm run package` construit `dist/` avec le **modèle signé** (signature Ed25519 vérifiée,
un octet modifié fait échouer le build) et refuse d'emballer :

- un `dist/` construit pour une autre version que celle de `package.json` ;
- un `dist/` sans modèle (`--allow-missing-model`) ou issu du build de test ;
- une carte de sources ou un lien symbolique.

L'archive est **reproductible** : fichiers triés, date fixe, aucun attribut du système.
Deux constructions du même code donnent le même fichier, octet pour octet (vérifié :
même SHA-256 après un nouveau build complet). N'importe qui peut donc reconstruire
l'archive depuis le tag et comparer l'empreinte.

**Vérifié pour 0.5.0-beta.1** (16 novembre 2026) : 18 fichiers, 474 Kio, archive valide
(contrôle des CRC par `zipfile`) ; décompressée et chargée dans Chromium 156, elle passe
les parcours Gmail (10 messages, vrai modèle `url_v2`) et options de Playwright.

### Numéros de version

`package.json` porte la version complète (`0.5.0-beta.1`). Chrome n'admet dans le
manifeste que des entiers : le build écrit `version: "0.5.0"` et
`version_name: "0.5.0-beta.1"` (affiché dans `chrome://extensions`). Le paquet Python
porte la même version au format PEP 440 (`0.5.0b1`), que l'API renvoie.

Une nouvelle bêta après les corrections du groupe 1 des tests utilisateurs :
`0.5.0-beta.2`. Elles sont installées hors du Chrome Web Store, où une version doit
toujours augmenter : la première version publiée sur le store (module 6) sera donc
supérieure à `0.5.0`.

### Distribution

- Envoyer l'archive **et** son `.sha256` par un canal où l'on reconnaît l'expéditeur, avec
  le lien vers ce guide. Ne jamais la déposer sur un service de partage public.
- Une archive par version : ne pas remplacer un fichier déjà distribué sous le même nom.

### Tag

Le cahier des charges clôt le module 5 par le tag `v0.5.0`. **Il n'est posé qu'après les
tests utilisateurs** : SUS d'au moins 70 sur le dernier groupe, rapport
[user-tests.md](user-tests.md) complété, cinq problèmes les plus fréquents corrigés.
D'ici là, une bêta peut être marquée `v0.5.0-beta.1` pour retrouver son code exact.

## Ce que contient cette bêta

Tout le module 5 ([CHANGELOG.md](../CHANGELOG.md)) : analyse locale (clic sur l'icône, clic
droit sur un lien), Gmail, options et confidentialité, trois langues ; et côté serveur,
le bot Telegram ([telegram-bot.md](telegram-bot.md)) et la page « coller et analyser »
([web-page.md](web-page.md)).

## Limites connues

- Installation en mode développeur : c'est l'obstacle principal attendu des tests
  utilisateurs ; le Chrome Web Store le supprimera (module 6).
- Chrome peut afficher, au démarrage, un rappel sur les extensions en mode développeur :
  le fermer.
- Pages internes légitimes parfois proches du seuil « suspect » (faiblesse connue du
  modèle, [model-card-url.md](model-card-url.md)).
- Gmail seulement (pas Outlook web) ; lecteurs d'écran pas encore essayés en vrai.
