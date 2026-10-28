# Protection contre la SSRF

*Étape 2.3 du cahier des charges. Code : `src/phishguard/security/netguard.py`. Tests : `tests/test_netguard.py`.*

## La menace

Une SSRF (*Server-Side Request Forgery*, falsification de requête côté serveur) consiste à faire envoyer par le serveur une requête vers une destination choisie par l'attaquant. Pour un outil qui reçoit des URLs à analyser, c'est la première menace du modèle STRIDE : si le serveur « va voir » l'URL soumise, un attaquant peut lui faire contacter `http://169.254.169.254/latest/meta-data/` (identifiants du service de métadonnées cloud), une base Redis sur `127.0.0.1:6379`, ou n'importe quelle machine du réseau interne.

## Décision de conception : le serveur ne visite jamais l'URL analysée

**PhishGuard ne télécharge pas la page analysée.** Il calcule ses features sur la chaîne de caractères (module 1), puis interroge des **tiers** à son sujet : Google Safe Browsing, VirusTotal, urlscan.io, RDAP, DNS (module 2). Les enrichisseurs contactent des adresses fixes (`safebrowsing.googleapis.com`, `www.virustotal.com`…), et l'URL de l'utilisateur n'est qu'un **paramètre** de leur requête, jamais une destination.

Ce choix supprime la SSRF par construction, et il protège aussi l'utilisateur : visiter une page de phishing avertit l'attaquant (pixel de suivi, lien unique par victime) et peut déclencher un téléchargement.

Le garde-fou existe pour le jour où une fonctionnalité **devra** contacter une adresse fournie par l'utilisateur, par exemple déplier un lien raccourci (`bit.ly/…`) pour analyser sa vraie destination. Cette fonctionnalité sera **optionnelle**, désactivée par défaut, et passera obligatoirement par `guarded_request()`. Aucun autre code ne doit ouvrir une connexion vers une adresse fournie par l'utilisateur.

## Ce que fait le garde-fou, à chaque saut

| # | Contrôle | Contre quoi |
| --- | --- | --- |
| 1 | Schémas `http` et `https` seulement | `file:///etc/passwd`, `gopher://` (forge de requêtes Redis ou SMTP), `ftp://`, `data:` |
| 2 | Ports `80` et `443` seulement (configurable) | Balayage de ports, attaques entre protocoles (`:22`, `:6379`) |
| 3 | Pas d'identifiants dans l'URL | `http://banque.example@10.0.0.1/`, qui trompe l'humain et certains parseurs |
| 4 | Formes ambiguës d'IPv4 décodées | `0x7f000001`, `2130706433`, `0177.0.0.1`, `127.1` : le résolveur système les accepte, `ipaddress` non |
| 5 | Noms locaux refusés avant résolution | `localhost`, `*.localhost`, `*.local`, `*.internal` (`metadata.google.internal`), `*.home.arpa` |
| 6 | Résolution DNS par nous ; refus si **une** adresse n'est pas publique | Domaine qui pointe vers `10.0.0.5` ; réponse mixte publique et privée |
| 7 | Adresses IPv4 cachées dans l'IPv6 vérifiées | `::ffff:127.0.0.1`, 6to4 `2002:7f00:1::`, Teredo, NAT64 `64:ff9b::a9fe:a9fe` |
| 8 | Connexion à l'**IP validée** ; nom dans `Host` et dans le SNI TLS | *DNS rebinding* : une seconde réponse DNS, différente, entre la vérification et la connexion |
| 9 | Redirections suivies à la main (3 au plus), chacune revalidée | Redirection d'un site public vers `http://169.254.169.254/` |
| 10 | Délais : DNS 2 s, connexion 2 s, lecture 3 s, **total 5 s** | Serveur lent (*slowloris*) qui épuise les connexions |
| 11 | Réponse limitée à 1 Mo **après décompression** | Réponse énorme, « bombe gzip » (2 Ko compressés, 2 Mo décompressés) |
| 12 | Pas de proxy implicite (`trust_env=False`), pas de réutilisation de connexion | Proxy de l'environnement qui choisirait lui-même la destination ; connexion TLS d'un nom réutilisée pour un autre nom servi par la même IP |
| 13 | `GET` et `HEAD` seulement, en-têtes minimaux | Envoi de données ; fuite de cookies ou d'en-têtes d'authentification |

### Qu'est-ce qu'une adresse « publique » ?

`is_public_ip()` exige `ip.is_global` **et** l'absence de chacun des drapeaux `is_private`, `is_loopback`, `is_link_local`, `is_reserved`, `is_multicast` et `is_unspecified` du module `ipaddress`. Les deux conditions sont nécessaires :

- `is_global` seul accepte le multicast global (`224.0.0.1`, `ff0e::1`) ;
- les drapeaux seuls acceptent l'espace partagé des opérateurs (`100.64.0.0/10`, CGNAT), qui n'est ni privé ni global.

Une adresse IPv6 avec une zone (`fe80::1%eth0`) est toujours refusée : elle désigne une interface de la machine.

### Pourquoi se connecter à l'IP et pas au nom

Vérifier le DNS puis laisser la bibliothèque HTTP résoudre le nom à nouveau laisse une fenêtre : l'attaquant contrôle son serveur DNS, répond avec une IP publique (TTL de 0) à la vérification, puis avec `127.0.0.1` à la connexion. Le garde-fou résout **une seule fois par saut** et construit la requête vers l'IP elle-même :

```
URL de la requête : https://93.184.215.14/page
En-tête Host      : example.com
SNI TLS           : example.com   (le certificat est vérifié pour ce nom)
```

Le serveur reçoit donc la requête comme si elle visait le nom, et le certificat reste vérifié, mais la destination ne peut plus changer.

## Utilisation

```python
from phishguard.security.netguard import BlockedDestination, guarded_request

try:
    response = await guarded_request(url)  # GET, politique par défaut
except BlockedDestination as exc:
    ...  # exc.reason : 'blocked_address', 'scheme_not_allowed', 'dns_failure'…
```

`guarded_request()` lève `BlockedDestination` (destination refusée), `TooManyRedirects`, `ResponseTooLarge` (tous des `NetGuardError`), `TimeoutError` (durée totale dépassée) ou une erreur `httpx` (échec réseau). Dans un enrichisseur, ces exceptions deviennent un signal `error` ou `timeout` (étape 2.2). `resolve_target()` fait seulement la validation, sans requête.

La politique se règle avec `NetPolicy` (ports, nombre de redirections, taille, délais). Elle est figée : on en crée une nouvelle, on ne modifie pas celle par défaut.

## Ce qui est testé

Le critère de l'étape est couvert, ainsi que les contournements connus :

- `http://127.0.0.1`, `http://localhost`, `http://169.254.169.254`, `http://[::1]`, `http://0x7f000001`, `http://2130706433`, `file:///etc/passwd`, et un domaine dont le DNS (simulé) répond `10.0.0.5` ;
- les formes octale, abrégée et entière, les plages privées, partagées, de documentation et multicast, et les adresses IPv6 locales et de transition ;
- une réponse DNS mixte, le *DNS rebinding*, les redirections vers une destination interdite (jamais contactée) et les boucles de redirection ;
- les réponses trop grandes, déclarées ou en flux, la bombe gzip, le serveur trop lent, et un proxy défini dans l'environnement ;
- une propriété vérifiée avec Hypothesis sur des IPv4 aléatoires : une IPv4 non globale n'est jamais acceptée, ni telle quelle, ni dans `::ffff:…`, et chaque IPv4 est reconnue écrite en entier, en hexadécimal ou en octal.

Aucun test n'utilise le réseau : le DNS est simulé, et les réponses HTTP passent par `httpx.MockTransport`.

## Limites connues

- **Ce garde-fou protège le serveur, pas la vie privée de l'utilisateur.** Une requête vers l'URL reste visible de l'attaquant. C'est une raison de plus pour que l'expansion de liens reste optionnelle.
- Seule la première adresse validée est essayée : pas de repli vers une autre adresse si elle ne répond pas.
- Les politiques réseau de l'hébergeur (pare-feu sortant, métadonnées cloud protégées par IMDSv2 sur AWS) restent nécessaires en complément : elles seront traitées au déploiement (module 6).

## Références

- OWASP, *Server-Side Request Forgery Prevention Cheat Sheet*
- WHATWG, *URL Standard*, analyse des hôtes IPv4 (formes hexadécimale, octale et abrégée)
- RFC 6761 (`localhost`), RFC 6762 (`.local`), RFC 8375 (`home.arpa`), RFC 6052 (NAT64), RFC 6598 (espace partagé `100.64.0.0/10`)
