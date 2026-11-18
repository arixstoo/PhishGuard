# Extension PhishGuard : vos données (étape 5.9)

Ce document dit, en langage simple, ce que l'extension PhishGuard lit, ce qu'elle garde,
ce qu'elle envoie et à qui. Il décrit la version `0.5.0-beta`, plus les mises à jour
signées du modèle (étape 6.8). Les détails techniques sont
dans [extension-design.md](extension-design.md). Chaque affirmation ci-dessous est
vérifiée par un test ou par le build (section 7).

## En bref

- **Par défaut, rien ne quitte votre ordinateur.** L'analyse se fait dans votre
  navigateur, avec un modèle livré dans l'extension. L'extension n'envoie aucune requête
  réseau tant que vous n'avez pas activé une option en ligne vous-même.
- **Rien ne permet de vous identifier.** Pas de compte, pas d'identifiant d'installation,
  pas de statistiques d'usage, pas de publicité, pas de revente.
- **Aucun historique de navigation.** L'extension ne regarde une page que si vous le
  lui demandez (clic sur l'icône, clic droit sur un lien), ou si vous avez activé
  l'analyse automatique, qui ne garde rien.
- **Dans Gmail, seul le message ouvert est lu**, sur votre ordinateur, et rien n'en est
  gardé ni envoyé, quels que soient vos réglages.

## 1. Ce que l'extension lit

| Quand | Ce qui est lu | Ce qui n'est jamais lu |
|---|---|---|
| Vous cliquez sur l'icône | l'adresse de l'onglet ouvert | le contenu de la page, les autres onglets |
| Vous faites un clic droit sur un lien → « Analyser ce lien » | l'adresse de ce lien | la page autour |
| Vous ouvrez un message dans Gmail | les liens de **ce** message (adresse et texte affiché) et son expéditeur (adresse et nom) | le reste du message, les autres messages, la liste de votre boîte, vos contacts, les pièces jointes |
| Analyse automatique (**désactivée par défaut**) | l'adresse de chaque page que vous ouvrez | le contenu des pages |

L'adresse d'une page n'est jamais « visitée » par l'extension : elle est découpée et
évaluée comme du texte.

## 2. Ce que l'extension garde

Tout est gardé **sur votre ordinateur**, dans le stockage de l'extension. Rien n'est
synchronisé avec votre compte Google (l'extension n'utilise pas `storage.sync`).

| Donnée | Où | Combien de temps | Pourquoi |
|---|---|---|---|
| Vos réglages (langue, options, adresse de votre serveur, clé d'API si vous en avez saisi une) | `storage.local` | jusqu'à ce que vous les changiez ou désinstalliez l'extension | se souvenir de vos choix |
| Vos sites de confiance (noms de domaine que **vous** avez ajoutés, 1 000 au plus) | `storage.local` | jusqu'à ce que vous les retiriez | ne plus signaler ces sites |
| Résultats des 100 dernières analyses **que vous avez demandées** (clic sur l'icône) : nom du site, score, raisons ; l'adresse complète n'est gardée que sous forme d'empreinte | `storage.session` (mémoire) | **effacés à la fermeture du navigateur** | réafficher un résultat sans tout recalculer |
| Résultat du dernier lien analysé par clic droit : nom du site, verdict, raisons ; jamais l'adresse complète | `storage.session` (mémoire) | effacé dès son affichage, ignoré après 2 minutes | l'afficher dans la fenêtre de PhishGuard |
| Si vous avez activé les mises à jour du modèle : le dernier modèle reçu, son manifeste et sa signature, et la date du dernier essai | `storage.local` | jusqu'à la publication suivante, ou effacés dès que vous désactivez l'option | analyser avec le modèle le plus récent ; il est revérifié à chaque chargement |

**Rien n'est gardé** de l'analyse automatique ni de Gmail : ni sur le disque, ni en
mémoire de session.

La clé d'API est enregistrée sans chiffrement : un navigateur ne fournit pas de coffre
aux extensions. Utilisez une clé propre à l'extension, jamais une clé partagée.

Pour tout effacer : retirez vos sites de confiance dans les options, ou désinstallez
l'extension (Chrome efface alors tout son stockage).

## 3. Ce que l'extension envoie, et à qui

**Par défaut : rien, à personne.** Trois options, éteintes à l'installation, font partir
des requêtes. Chacune exige deux gestes de votre part : cocher l'option **et** accepter la
demande d'autorisation de Chrome pour les hôtes concernés.

| Option | Ce qui part | Vers qui | Quand |
|---|---|---|---|
| Analyse en ligne | l'adresse de la page, **sans** la partie après `#` (qui peut contenir un jeton de connexion) | le serveur PhishGuard **que vous avez saisi** (le vôtre, ou celui d'une personne de confiance) | seulement quand vous cliquez sur l'icône ; jamais pour l'analyse automatique, jamais pour Gmail |
| Signalements d'erreur | le **nom de domaine** seulement, le verdict reçu et votre jugement (« faux positif » ou « faux négatif ») | ce même serveur | seulement quand vous cliquez sur « Signaler » |
| Mises à jour du modèle | **rien** : trois téléchargements anonymes (signature, manifeste, modèle), sans cookie ni `Referer` ; GitHub voit votre adresse IP, comme pour toute page | les publications GitHub du projet (`github.com` et son stockage `*.githubusercontent.com`) | au plus une fois par jour, au démarrage du navigateur, ou quand vous cliquez sur « Vérifier maintenant » |

Il n'existe **aucun serveur par défaut** : l'extension ne contacte ni l'auteur, ni Google,
ni aucun service de statistiques.

Un modèle téléchargé n'est installé que si sa **signature Ed25519** correspond à la clé
publique intégrée à l'extension, si son empreinte correspond au manifeste signé, s'il a
été produit pour le même extracteur de features, et s'il est plus récent que le modèle en
place. Sinon, il est ignoré et le modèle actuel reste en service. Une compromission de
GitHub ou du réseau ne suffit donc pas à vous faire utiliser un faux modèle. Un modèle est
une donnée (des arbres de décision en JSON), jamais du code. Si le serveur que vous choisissez interroge à son tour
des services d'analyse (VirusTotal, Google Safe Browsing…), c'est sa propre politique
qui s'applique ; celle de l'API PhishGuard est dans [api.md](api.md#politique-de-confidentialité-de-lapi).

**Le contenu d'un email ne quitte jamais votre ordinateur**, même si l'analyse en ligne
est activée.

Les requêtes vers votre serveur partent sans cookie, sans en-tête `Referer`, et sans
suivre de redirection (une redirection pourrait emmener votre clé ailleurs).

## 4. Ce que l'extension ne fait jamais

- créer un identifiant d'utilisateur ou d'installation, ou lire celui du navigateur ;
- tenir un journal des pages visitées ;
- lire votre historique, vos cookies, vos favoris, vos téléchargements, vos mots de passe
  ou vos formulaires ;
- modifier une page ou un lien : dans Gmail, elle ajoute une bannière et une icône à côté
  des liens suspects, sans toucher aux liens eux-mêmes ;
- exécuter du code téléchargé : tout son code est dans le paquet installé, lisible (non
  minifié) ;
- montrer des publicités, vendre ou partager des données.

## 5. Les autorisations demandées

À l'installation, Chrome affiche un seul avertissement : **« Lire et modifier vos données
sur mail.google.com »**. Il correspond à l'analyse des liens du message ouvert (section 1).
Vous pouvez la couper dans les options (« Analyser les messages ouverts dans Gmail ») ; pour
retirer aussi l'autorisation elle-même : `chrome://extensions` → PhishGuard → Détails →
Accès aux sites.

Les autres autorisations n'affichent aucun avertissement, ou ne sont demandées qu'au
moment où vous activez l'option qui s'en sert. Une autorisation optionnelle est rendue
quand vous désactivez l'option.

Le tableau ci-dessous est celui que l'on fournit au Chrome Web Store : une phrase par
autorisation. Un test (`extension/test/audit.test.ts`) vérifie qu'il contient exactement
les autorisations du manifeste, ni plus ni moins.

<!-- permissions:start -->
| Autorisation | Type | Justification |
|---|---|---|
| `activeTab` | requise | Lire l'adresse de l'onglet uniquement lorsque l'utilisateur clique sur l'icône de PhishGuard, pour l'analyser sur l'appareil. |
| `contextMenus` | requise | Ajouter l'entrée « Analyser ce lien avec PhishGuard » au clic droit sur un lien. |
| `storage` | requise | Garder sur l'appareil les réglages et les sites de confiance de l'utilisateur, et en mémoire de session les résultats des analyses qu'il a demandées. |
| `https://mail.google.com/*` | script de contenu | Analyser sur l'appareil les liens et l'expéditeur du seul message ouvert dans Gmail, et y afficher une alerte quand un lien est suspect ; rien n'est stocké ni envoyé. |
| `tabs` | optionnelle | Lire l'adresse de chaque page ouverte pour l'analyser sur l'appareil, seulement si l'utilisateur active l'analyse automatique ; rendue à la désactivation. |
| `https://*/*` | hôte optionnel | Joindre le serveur PhishGuard que l'utilisateur a lui-même saisi et autorisé, pour l'analyse en ligne ou les signalements, ou télécharger depuis les publications GitHub du projet les mises à jour signées du modèle s'il les active ; seuls ces hôtes précis sont demandés, au moment de l'activation. |
| `http://localhost/*` | hôte optionnel | Joindre un serveur PhishGuard lancé sur l'ordinateur de l'utilisateur, aux mêmes conditions. |
| `http://127.0.0.1/*` | hôte optionnel | Joindre un serveur PhishGuard lancé sur l'ordinateur de l'utilisateur, aux mêmes conditions. |
<!-- permissions:end -->

**Objectif unique** (déclaration demandée par le Chrome Web Store) : *détecter et
signaler les liens de phishing.*

**Code distant** : aucun. Tout le JavaScript exécuté est dans le paquet ; aucune
évaluation de code (`eval`, `new Function`), aucun script chargé depuis Internet.

## 6. Ce que d'autres pourraient voir

Limites honnêtes, que l'extension ne peut pas supprimer :

- **Gmail peut savoir que l'extension est installée** : la bannière et les icônes sont
  ajoutées à sa page. Leur contenu est isolé (Shadow DOM fermé), mais leur présence se
  voit. Les sites web ordinaires, eux, ne peuvent pas la détecter : l'extension n'expose
  aucune ressource aux pages (`web_accessible_resources` absent) et n'accepte aucun
  message d'un site (`externally_connectable` absent).
- **Le stockage local est lisible par le script Gmail de l'extension.** C'est une règle
  de Chrome. Si la page Gmail elle-même était compromise au point d'exécuter du code dans
  ce script, elle pourrait lire vos réglages (dont la clé d'API) et ajouter un site de
  confiance. Elle ne pourrait toujours ni envoyer de requête (l'autorisation de votre
  serveur ne s'obtient que depuis la page d'options), ni faire passer pour sûr un site
  qui imite des lettres latines (cette règle passe avant les sites de confiance).
- **Le serveur que vous choisissez** voit les adresses que vous lui envoyez, et votre
  adresse IP. Choisissez-le comme vous choisiriez un fournisseur de messagerie.

## 7. Comment c'est vérifié

| Garantie | Vérification |
|---|---|
| exactement ces autorisations ; ni `host_permissions`, ni `web_accessible_resources`, ni `externally_connectable` ; script de contenu sur Gmail seulement, cadre principal seulement | `extension/test/audit.test.ts` |
| CSP : scripts du paquet seulement (`script-src 'self'`), ni `unsafe-eval` ni `unsafe-inline`, `object-src 'none'` | `extension/test/audit.test.ts` |
| aucune API qui identifie ou suit l'utilisateur (`chrome.history`, `chrome.identity`, `chrome.cookies`, `webRequest`…), seulement les espaces `action`, `contextMenus`, `i18n`, `permissions`, `runtime`, `storage`, `tabs` ; jamais `storage.sync` ; aucun générateur d'identifiant (`randomUUID`, `getRandomValues`, `Math.random`) | `extension/test/audit.test.ts` |
| aucun `eval`, `new Function`, `importScripts`, aucune injection HTML ; `fetch` seulement dans `api.ts`, `updates.ts` et pour lire le modèle du paquet ; aucun autre canal réseau | `extension/build.mjs` (le build échoue) |
| aucune requête sans le réglage **et** l'autorisation de l'hôte ; URL sans fragment ; réponse du serveur validée et incapable d'innocenter | `extension/test/network.test.ts` |
| mises à jour du modèle : aucune requête sans le réglage **et** les trois autorisations de GitHub ; requêtes `GET` sans corps, sans en-tête, sans cookie ; au plus une par jour ; redirection hors de GitHub refusée ; modèle falsifié (un octet), autre clé, retour arrière, autre extracteur refusés sans rien stocker ; modèle stocké revérifié à chaque chargement | `extension/test/updates.test.ts`, `extension/test/signed-model.test.ts` |
| rien en mémoire de session pour l'analyse automatique et Gmail | `extension/background.ts` (`persist: false`, pas de cache) ; parcours Playwright |
| **aucune requête hors du paquet** sur tout un parcours (fenêtre, options, 10 messages Gmail) avec les réglages par défaut | `extension/e2e/` (Playwright, en CI) |
| aucune dépendance embarquée ; dépendances de développement en versions exactes, sans script d'installation, sans vulnérabilité connue, signatures du registre vérifiées | `package.json`, `.npmrc`, `npm audit` et `npm audit signatures` en CI |

### Audit du 16 novembre 2026

| Contrôle | Résultat |
|---|---|
| `npm audit` | 0 vulnérabilité |
| `npm audit signatures` | 46 paquets (Playwright compris), signatures du registre vérifiées, 24 avec attestation de provenance |
| dépendances d'exécution (embarquées dans l'extension) | **0** : seul notre code est dans le paquet |
| `eval`, `new Function`, code distant | absents (build) |
| CSP | celle de la section 1 de [extension-design.md](extension-design.md#politique-de-contenu-csp), sans relâchement pour les scripts |
| identifiant d'utilisateur, statistiques, journal de navigation | absents |
| `chrome.*` employés | `action`, `contextMenus`, `i18n`, `permissions`, `runtime`, `storage`, `tabs` |

Le seul relâchement assumé de la politique par défaut de Chrome est `connect-src https:` :
la CSP d'un manifeste ne peut pas viser un serveur choisi après l'installation. Ce sont le
build, `api.ts` et l'autorisation d'hôte qui garantissent qu'aucune requête ne part sans
votre accord (détail : [extension-design.md](extension-design.md#politique-de-contenu-csp)).

## 8. Contact

Une question, ou un comportement qui contredit ce document : ouvrez une issue sur
[GitHub](https://github.com/arixstoo/PhishGuard/issues). Une faille de sécurité : suivez
[SECURITY.md](../SECURITY.md), sans la publier.
