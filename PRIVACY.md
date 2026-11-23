# Politique de confidentialité de PhishGuard

*En vigueur le 19 novembre 2026. [English version below](#phishguard-privacy-policy).*

PhishGuard est un logiciel libre de détection du phishing : une extension Chrome, une
API, un bot Telegram et une page web. Il est publié par son auteur, à titre personnel,
sans entreprise, sans publicité et sans revente de données. Ce document dit quelles
données sont traitées, pourquoi, combien de temps, avec qui elles sont partagées et
comment les supprimer. Chaque affirmation est vérifiée par le code ou par un test
([section 8](#8-comment-cest-vérifié)).

## 1. L'extension Chrome

**Par défaut, rien ne quitte votre ordinateur.** L'analyse se fait dans le navigateur,
avec un modèle livré dans l'extension. Aucun compte, aucun identifiant d'installation,
aucune statistique d'usage.

| Donnée | Pourquoi | Où | Combien de temps |
|---|---|---|---|
| adresse de l'onglet, quand vous cliquez sur l'icône, ou d'un lien, quand vous faites « Analyser ce lien » | l'analyser | en mémoire | le temps de l'analyse |
| liens et expéditeur **du seul message ouvert** dans Gmail | les analyser | en mémoire | le temps de l'analyse ; rien n'est gardé |
| résultats des 100 dernières analyses demandées (nom du site, score, raisons ; l'adresse complète seulement sous forme d'empreinte) | les réafficher | mémoire de session du navigateur | effacés à la fermeture du navigateur |
| réglages, sites de confiance (1 000 au plus) | se souvenir de vos choix | stockage local de l'extension | jusqu'à ce que vous les retiriez ou désinstalliez l'extension |
| modèle reçu par mise à jour (si l'option est active) | analyser avec le modèle le plus récent | stockage local de l'extension | jusqu'à la publication suivante ou la désactivation de l'option |

Trois options, **désactivées par défaut**, envoient des données. Chacune demande votre
accord deux fois : la case dans les options, puis l'autorisation de Chrome.

- **Analyse en ligne** : l'adresse de la page (sans ce qui suit `#`) part vers **le
  serveur PhishGuard que vous avez vous-même saisi**, seulement quand vous cliquez sur
  l'icône. Il n'existe aucun serveur par défaut.
- **Signalements d'erreur** : le nom de domaine, le verdict et votre jugement partent vers
  ce même serveur, seulement quand vous cliquez sur « Signaler ».
- **Mises à jour du modèle** : au plus une fois par jour, l'extension télécharge le dernier
  modèle publié sur GitHub. Rien n'est envoyé ; GitHub voit votre adresse IP, comme pour
  toute page. Un modèle n'est installé que si sa signature correspond à la clé intégrée à
  l'extension.

Le contenu d'un email ne quitte jamais votre ordinateur, quels que soient les réglages.
Détail complet et justification de chaque autorisation :
[docs/extension-privacy.md](docs/extension-privacy.md).

## 2. L'API PhishGuard

L'API reçoit ce que l'extension, le bot ou la page web lui envoient : une URL, un texte
ou un email à analyser.

- **Le contenu analysé** est traité en mémoire puis oublié : jamais écrit sur disque ni en
  base, jamais journalisé.
- **Le journal** contient, par requête : un identifiant de requête, la route, le statut, la
  durée, le verdict, le score et la version du modèle. Jamais le contenu, l'URL, l'adresse
  IP ni la clé d'API. Il tourne sur 3 fichiers de 10 Mo.
- **Votre adresse IP** sert, en mémoire, à limiter le nombre de requêtes (compteurs d'une
  minute ou d'une heure). Elle n'est ni stockée ni journalisée.
- **Les clés d'API** ne sont stockées que sous forme d'empreinte SHA-256.
- **Les signalements d'erreur** (domaine, verdict, jugement, date, pseudonyme du jour qui
  ne permet pas de vous retrouver) sont relus par une personne et **supprimés au plus tard
  90 jours après réception**, relus ou non. Ils ne modifient jamais le modèle.
- **Statistiques d'usage** : l'API compte ses analyses par jour, route (URL, texte,
  email), verdict et type de client (anonyme ou avec clé). Ce sont des totaux : ni adresse
  IP, ni clé, ni contenu, ni heure. Ils servent à savoir si l'outil est utilisé et combien
  de verdicts sont contestés, et sont **supprimés après 365 jours**.
- **Sauvegardes** : la base (empreintes des clés, signalements) est copiée chaque jour,
  chiffrée avec une clé que le serveur ne possède pas. Les copies sont supprimées après
  14 jours sur le serveur et 30 jours chez le fournisseur de stockage. Une sauvegarde
  peut donc contenir un signalement jusqu'à 30 jours de plus.

## 3. Le bot Telegram et la page « coller et analyser »

- **Le bot** transmet le texte et les liens du message à l'API, répond, et ne garde rien.
  En mémoire seulement : l'heure de votre dernier message (contre l'abus) et la langue
  choisie, perdues au redémarrage. Son journal ne contient ni le texte, ni les liens, ni
  votre identifiant Telegram. Telegram voit vos messages, comme pour tout bot : n'y
  envoyez jamais de mot de passe ni de code.
- **La page web** envoie le texte collé à l'API, sans cookie, sans stockage local, sans
  statistiques ni ressource externe.

## 4. Avec qui les données sont partagées

Personne n'achète ni ne reçoit vos données à des fins commerciales. Des services
techniques voient passer certaines requêtes :

| Service | Ce qu'il voit | Quand |
|---|---|---|
| **Vercel** (relais HTTPS devant l'API publique) | les requêtes vers `api-phishguard.vercel.app`, dont votre adresse IP | à chaque appel de l'API publique ; [politique de Vercel](https://vercel.com/legal/privacy-policy) |
| **l'hébergeur du serveur** | le trafic chiffré | idem |
| **Telegram** | vos messages au bot | quand vous utilisez le bot ; [politique de Telegram](https://telegram.org/privacy) |
| **GitHub** | les téléchargements de modèle, votre adresse IP | si vous activez les mises à jour du modèle ; [politique de GitHub](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement) |
| **Google Safe Browsing, VirusTotal, urlscan.io** | l'URL analysée ou son domaine | **jamais par défaut** : seulement si le serveur a activé la Threat Intelligence **et** que l'analyse la demande ; la réponse l'indique (`enrichment: used`). Jamais pour un texte ni un email |

Si vous utilisez **votre propre serveur** PhishGuard, c'est vous qui le contrôlez : cette
politique décrit le logiciel, ses réglages par défaut, et l'instance publique de l'auteur.

## 5. Vos droits et comment supprimer vos données

- **Extension** : retirez vos sites de confiance dans les options, désactivez une option
  (le modèle reçu est alors effacé), ou désinstallez l'extension : Chrome efface tout son
  stockage.
- **API** : aucun contenu n'est conservé. Les signalements sont pseudonymes et effacés
  après 90 jours au plus ; une clé d'API peut être révoquée sur demande.
- **Bot** : rien n'est conservé par PhishGuard ; supprimez la conversation dans Telegram.

Vous pouvez demander l'accès, la rectification ou l'effacement de données vous
concernant, ou poser une question : voir [section 7](#7-contact). Vous pouvez aussi
saisir l'autorité de protection des données de votre pays (en France, la
[CNIL](https://www.cnil.fr/)).

## 6. Mineurs, sécurité, modifications

PhishGuard ne collecte sciemment aucune donnée sur les enfants. Les communications avec
l'API sont chiffrées (HTTPS). Toute modification de cette politique est publiée dans ce
fichier, datée, et visible dans l'historique du dépôt ; une modification qui élargit
les données traitées sera annoncée dans le [CHANGELOG](CHANGELOG.md).

## 7. Contact

- Question publique : [ouvrir une issue](https://github.com/arixstoo/PhishGuard/issues).
- Demande privée (données personnelles, faille de sécurité) :
  [signalement privé GitHub](https://github.com/arixstoo/PhishGuard/security/advisories/new),
  voir [SECURITY.md](SECURITY.md).

## 8. Comment c'est vérifié

Une affirmation de cette politique qui ne correspondrait plus au code est un bogue.
`tests/test_privacy_policy.py` vérifie que chaque fichier cité ici existe et que les
valeurs chiffrées ci-dessus (100 analyses, 1 000 sites, une fois par jour, 90 jours, 365 jours,
14 jours, 3 × 10 Mo) sont celles du code.

<!-- claims:start -->
| Affirmation | Vérifiée par |
|---|---|
| aucune requête réseau de l'extension avec les réglages par défaut | `extension/e2e/fixtures.ts`, `extension/test/network.test.ts`, `extension/test/updates.test.ts` |
| aucun identifiant, aucune statistique, jamais `storage.sync` | `extension/test/audit.test.ts` |
| 100 analyses en mémoire de session, 1 000 sites de confiance | `extension/src/storage.ts` |
| mises à jour du modèle au plus une fois par jour, signature vérifiée, rien d'envoyé | `extension/src/updates.ts`, `extension/test/signed-model.test.ts` |
| contenu analysé jamais stocké ni journalisé ; journal sans URL, IP ni clé | `tests/test_api_logging.py` |
| clés d'API stockées sous forme d'empreinte | `src/phishguard/api/storage.py` |
| signalements supprimés au plus tard après 90 jours | `src/phishguard/api/settings.py`, `tests/test_api_feedback.py` |
| statistiques d'usage : des totaux sans identifiant, supprimés après 365 jours | `src/phishguard/api/usage.py`, `tests/test_api_usage.py` |
| journal en rotation, 3 fichiers de 10 Mo | `docker-compose.yml`, `deploy/compose.prod.yml` |
| sauvegardes chiffrées, 14 jours sur le serveur | `deploy/server/backup.sh` |
| Threat Intelligence désactivée par défaut | `src/phishguard/api/settings.py` |
| bot : rien de conservé, journal sans contenu ni identifiant | `tests/test_bot.py` |
| page web : ni cookie, ni stockage local, ni ressource externe | `tests/test_api_web.py` |
<!-- claims:end -->

La rétention de 30 jours hors du serveur est une règle d'expiration à configurer chez le
fournisseur de stockage ([docs/operations.md](docs/operations.md#sauvegardes-de-la-base)) :
le serveur, volontairement, ne peut pas effacer ses sauvegardes hors site.

---

# PhishGuard privacy policy

*Effective 19 November 2026. The French version above prevails in case of doubt.*

PhishGuard is free, open-source phishing detection software: a Chrome extension, an API,
a Telegram bot and a web page. It is published by its author as an individual, with no
company, no advertising and no sale of data.

## 1. Chrome extension

**By default, nothing leaves your computer.** Analysis runs in the browser with a model
shipped in the extension. No account, no installation identifier, no usage statistics.

- It reads the address of the current tab when you click the icon, the address of a
  link when you choose "Analyse this link", and the links and sender of **the open
  message only** in Gmail. These are analysed in memory and not kept.
- It keeps, in browser session memory, the results of your last 100 requested analyses
  (site name, score, reasons; the full address only as a hash), erased when the browser
  closes; and, in local extension storage, your settings, your trusted sites (at most
  1,000) and, if enabled, the last model update, until you remove them or uninstall.
- Three options, **off by default**, send data, each requiring both the setting and
  Chrome's permission prompt: **online analysis** (the page address, without the part
  after `#`, to the PhishGuard server **you entered**; there is no default server),
  **error reports** (domain, verdict and your judgement, to that server), and **model
  updates** (at most once a day, downloads from GitHub; nothing is sent, GitHub sees your
  IP address; a model is installed only if its signature matches the key built into the
  extension).
- Email content never leaves your computer, whatever the settings.

## 2. PhishGuard API

- Analysed content (URL, text, email) is processed in memory and forgotten: never
  written to disk or a database, never logged.
- The log records a request id, route, status, duration, verdict, score and model
  version; never the content, URL, IP address or API key. It rotates over 3 files of
  10 MB.
- Your IP address is used in memory for rate limiting (one-minute or one-hour counters),
  never stored or logged. API keys are stored only as SHA-256 hashes.
- Error reports (domain, verdict, judgement, date, a daily pseudonym that cannot identify
  you) are reviewed by a person and **deleted at the latest 90 days after receipt**. They
  never change the model.
- Usage statistics: the API counts its analyses per day, route (URL, text, email),
  verdict and client type (anonymous or with a key). These are totals: no IP address, key,
  content or time of day. They tell whether the tool is used and how many verdicts are
  disputed, and are **deleted after 365 days**.
- The database (key hashes, reports) is backed up daily, encrypted with a key the server
  does not hold; copies are deleted after 14 days on the server and 30 days at the
  storage provider, so a backup may hold a report up to 30 more days.

## 3. Telegram bot and paste-and-check page

The bot forwards the message text and links to the API, replies, and keeps nothing
except, in memory, the time of your last message (abuse protection) and your chosen
language, lost on restart. Its log holds neither text, links nor your Telegram id.
Telegram sees your messages, as with any bot: never send passwords or codes. The web page
sends the pasted text to the API, with no cookie, local storage, analytics or external
resource.

## 4. Sharing

Nobody buys or receives your data for commercial purposes. Technical services see some
requests: **Vercel** (HTTPS relay in front of the public API, sees requests and your IP),
the **server host** (encrypted traffic), **Telegram** (your messages to the bot),
**GitHub** (model downloads, if enabled), and **Google Safe Browsing, VirusTotal,
urlscan.io** (the analysed URL or its domain) **never by default**: only if the server
enabled Threat Intelligence and the analysis requests it, which the response states
(`enrichment: used`); never for text or email. If you run your own PhishGuard server, you
control it; this policy covers the software, its defaults and the author's public
instance.

## 5. Your rights and deletion

Remove trusted sites in the options, disable an option (a received model is then
erased) or uninstall the extension (Chrome erases its storage). The API keeps no content;
reports are pseudonymous and erased within 90 days; an API key can be revoked on
request. The bot keeps nothing; delete the conversation in Telegram. You may request
access, correction or erasure of data about you (see contact below), and contact your
data protection authority.

## 6. Children, security, changes

PhishGuard does not knowingly collect data about children. Connections to the API use
HTTPS. Changes to this policy are published in this file, dated, visible in the
repository history, and announced in the [CHANGELOG](CHANGELOG.md) when they widen the
data processed.

## 7. Contact

Public question: [open an issue](https://github.com/arixstoo/PhishGuard/issues). Private
request (personal data, security issue):
[GitHub private report](https://github.com/arixstoo/PhishGuard/security/advisories/new),
see [SECURITY.md](SECURITY.md).
