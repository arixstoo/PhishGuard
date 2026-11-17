# Bot Telegram (étape 5.11)

Pour celles et ceux qui n'installeront jamais d'extension : on transfère au bot un message
suspect (ou on lui colle un lien), il répond en quelques secondes par un verdict, ses
raisons et un conseil. Le bot n'analyse rien lui-même : il interroge l'API PhishGuard
(module 4) et met sa réponse en forme.

```text
⛔ Phishing probable

Le message : ⚠️ suspect
   • Le message vous presse d'agir sur un compte, une carte ou un colis.
Lien vers 192[.]0[.]2[.]10 : ⛔ phishing
   caché derrière le texte « Suivre mon colis »
   • L'adresse est une adresse IP au lieu d'un nom de site.

Conseil : Ne cliquez pas sur le lien et ne répondez pas. Contactez l'organisme par son
numéro ou son site officiel.

Les adresses sont écrites avec [.] pour ne pas être cliquables.
```

## Mise en route

1. **Créer le bot** avec [@BotFather](https://t.me/BotFather) : `/newbot`, puis noter le
   jeton. Dans BotFather, toujours :
   - `/setjoingroups` → **Disable** : le bot ne peut pas être ajouté à un groupe ;
   - `/setprivacy` → **Enable** (défaut) : s'il l'était quand même, il ne recevrait que
     les commandes ;
   - `/setcommands` :
     ```text
     start - Présentation
     aide - Comment m'utiliser
     confidentialite - Ce que je fais de vos messages
     langue - Choisir la langue
     ```
2. **Une clé d'API pour le bot** : tous ses utilisateurs passent par lui, le palier
   anonyme (30 requêtes par minute et par IP) serait vite épuisé.
   ```bash
   make api-key NAME=telegram-bot
   ```
3. **Lancer**, en développement (API sur `127.0.0.1:8000` : `make api`) :
   ```bash
   # .env : PHISHGUARD_BOT_TOKEN=…  PHISHGUARD_BOT_API_KEY=pg_…
   make bot          # python -m phishguard.bot
   ```
   ou en conteneur, à côté de l'API :
   ```bash
   # .env.bot (jamais commité) : PHISHGUARD_BOT_TOKEN=…  PHISHGUARD_BOT_API_KEY=pg_…
   docker compose --profile bot up -d
   ```

Configuration complète : `PHISHGUARD_BOT_*` dans [.env.example](../.env.example). Une valeur
invalide empêche le démarrage, avec le nom du champ et jamais sa valeur.

## Ce que fait le bot d'un message

1. **Conversation privée seulement.** Dans un groupe ou un canal, il ne lit rien et ne
   répond rien.
2. **Liens** : ceux que Telegram a reconnus dans le texte (avec ou sans `https://`),
   **ceux cachés derrière un texte** (entité `text_link` : « Suivre mon colis » qui mène
   ailleurs, le leurre le plus courant d'un message transféré), et en secours tout
   `http(s)://` écrit en clair. Telegram compte les positions en **unités UTF-16** : un
   émoji avant le lien décale de deux, pas d'un (testé). Doublons retirés, 5 liens au plus,
   les liens non web (`tg://`, `mailto:`) comptés et signalés.
3. **Analyse en parallèle** : le texte par `POST /v1/analyze/text` (`channel: messaging`)
   et chaque lien par `POST /v1/analyze/url`, sous un **délai global de 2,5 s**. Une partie
   en retard ou en échec est annoncée (« verdict incomplet »), elle ne bloque pas le
   reste. Verdict global : le plus grave de tous ; conseil du résultat le plus grave.
4. **Réponse désarmée**, en texte brut (aucun `parse_mode` : rien n'est interprété comme
   HTML ou Markdown), **sans aperçu de lien** :
   - seul l'**hôte** est cité, jamais le chemin ni les paramètres (ils portent souvent un
     jeton ou un identifiant) ;
   - en **ASCII** : un homographe `аpple.com` (а cyrillique) s'affiche
     `xn--pple-43d[.]com`, pas sous une forme trompeuse ;
   - **`[.]` au lieu des points**, partout, raisons et conseil compris : Telegram ne peut
     en faire un lien cliquable. Le bot ne doit jamais devenir le relais d'un lien de
     phishing ;
   - caractères invisibles et d'inversion de sens (U+202E…) retirés, hôtes isolés du sens
     d'écriture (lisibles dans une phrase arabe).

## Limites

| Limite | Défaut | Variable |
|---|---|---|
| liens analysés par message | 5 | `PHISHGUARD_BOT_MAX_URLS` |
| taille du message | 4 096 caractères (maximum de Telegram) | `PHISHGUARD_BOT_MAX_TEXT_CHARS` |
| délai entre deux messages d'un utilisateur | 3 s | `PHISHGUARD_BOT_MIN_INTERVAL_SECONDS` |
| durée d'une analyse | 2,5 s | `PHISHGUARD_BOT_ANALYSIS_TIMEOUT_SECONDS` |
| analyses simultanées | 16 | `PHISHGUARD_BOT_MAX_CONCURRENT` |

La limite de débit vaut pour **tout** message, commandes comprises, et un utilisateur trop
rapide n'est prévenu qu'**une fois** par fenêtre : répondre à chaque message ferait du bot
un amplificateur.

## Confidentialité

C'est ce que dit `/confidentialite` :

- le texte et les liens vont à l'API PhishGuard, qui les analyse et les oublie (sa
  politique : [api.md](api.md#politique-de-confidentialité-de-lapi)) ; le bot ne garde
  rien ;
- Threat Intelligence **désactivée** par défaut (`PHISHGUARD_BOT_THREAT_INTEL=false`) :
  aucune URL ne part chez des tiers (VirusTotal…) ;
- aucun lien n'est visité ;
- en mémoire seulement, bornés, perdus au redémarrage : l'heure du dernier message de
  chaque utilisateur (quelques secondes) et la langue choisie par `/langue`. Sans choix,
  la langue de l'interface Telegram de l'utilisateur ;
- **journal sans contenu** : une ligne par message, « 2 lien(s), verdict phishing,
  complet, 412 ms ». Jamais le texte, les liens, ni l'identifiant de l'utilisateur ou de
  la conversation (testé).

Ce que Telegram voit : tout ce qui passe par sa messagerie, comme pour n'importe quel bot.
Les conversations avec un bot ne sont pas chiffrées de bout en bout ; le dire aux
utilisateurs plutôt que le taire. C'est aussi pourquoi l'aide demande de ne jamais envoyer
de mot de passe ni de code.

## Sécurité

- **Le jeton** est dans l'URL de chaque appel à l'API Bot (`/bot<jeton>/getUpdates`). Le
  journal de `httpx`, qui écrit les URLs, est coupé ; les erreurs sont réduites à un code ;
  la configuration ne recopie pas une valeur refusée (`hide_input_in_errors`). Tout cela
  est testé. En cas de fuite : `/revoke` dans BotFather.
- **Long polling** plutôt que webhook, en développement comme en production : le bot va
  chercher ses messages, aucun port n'est ouvert, il n'y a aucune requête entrante à
  authentifier. Un webhook n'apporterait qu'une latence un peu plus basse.
- **Entrées hostiles** : chaque mise à jour est lue champ par champ (`parse_update`) ; une
  forme inattendue est ignorée, jamais une exception. Réponses de Telegram et de l'API
  bornées en taille ; réponse de l'API validée par le contrat `AnalysisResponse` (hors
  contrat : panne, pas verdict).
- **Aucune redirection suivie**, aucune variable de proxy lue (`trust_env=False`) : la clé
  d'API et le jeton ne partent que vers les hôtes configurés. Le serveur de l'API Bot doit
  être en `https` (sauf boucle locale) ; l'API PhishGuard en `http` n'est admise que sur
  un réseau privé (`http://api:8000` dans compose).
- **Conteneur** : même image durcie que l'API (utilisateur sans privilège, système de
  fichiers en lecture seule, aucune capacité Linux), 256 Mo, aucun port publié.

## Écart au cahier des charges : pas d'aiogram

Le plan proposait `aiogram` 3. À l'essai (`uv lock`), aiogram 3.31.0, la dernière version
publiée depuis plus de deux semaines (règle de la chaîne d'approvisionnement du projet),
impose `pydantic<2.14` : **pydantic aurait été rétrogradé de 2.14.3 à 2.13.5 dans tout le
projet**, API comprise, et neuf paquets ajoutés (aiohttp, yarl, multidict, frozenlist…).
Le bot n'emploie que quatre méthodes de l'API Bot (`getMe`, `getUpdates`, `sendMessage`,
`answerCallbackQuery`) : `phishguard/bot/telegram.py` les appelle avec `httpx`, déjà
présent. **Aucune dépendance ajoutée.** À revoir si le bot doit un jour gérer des
conversations complexes, des paiements ou un webhook.

## Tests

`tests/test_bot.py` (43 tests, Telegram et API simulés par respx, aucun appel réseau) :
positions UTF-16, liens cachés, ponctuation, ports, limites, mises à jour malformées ;
désarmement (hôte seul, ASCII, `[.]`, invisibles) ; forme exacte des requêtes et erreurs
réduites à un code ; commandes, langues, groupes ignorés, limite de débit, message trop
long ; **message transféré avec lien caché : verdict en moins de 3 s** avec 200 ms de
latence simulée par appel ; délai global respecté quand l'API ne répond pas ; boucle de
réception (accusé de réception, reprise après panne) ; aucun secret ni contenu dans le
journal ; et les requêtes du bot **acceptées par la vraie application** FastAPI (schémas
stricts).

**Reste à faire avec un vrai jeton** (critère de fin de l'étape) : transférer un message
de test depuis un compte Telegram et mesurer le délai de bout en bout. Le code et les
tests sont prêts ; la mesure demande un jeton de BotFather, que le dépôt n'a pas.
