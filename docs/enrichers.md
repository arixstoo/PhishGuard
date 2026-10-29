# Enrichisseurs : le contrat commun

*Étape 2.2 du cahier des charges. Code : `src/phishguard/enrichers/base.py`.*

Un enrichisseur interroge **une** source de Threat Intelligence (Google Safe Browsing, VirusTotal, urlscan.io, RDAP, DNS…) au sujet d'une URL et de son domaine. Toutes les sources respectent le même contrat, pour que l'orchestrateur (étape 2.9) et la fusion du score (étape 2.10) les traitent de la même façon.

## Le signal

```python
class Signal(BaseModel):  # figé, champs inconnus refusés
    source: str  # 'virustotal', 'rdap', ...
    status: SignalStatus  # 'ok' | 'error' | 'skipped' | 'timeout'
    risk: float = 0.0  # contribution normalisée, de 0 à 1
    evidence: dict[str, Any] = {}  # données utiles à l'analyste
    latency_ms: int = 0
```

| Statut | Sens | `risk` |
| --- | --- | --- |
| `ok` | La source a répondu | de 0 à 1, utilisable par la fusion |
| `error` | Échec : réseau, quota, réponse illisible, bug de la source | toujours 0 |
| `skipped` | Source non interrogée : désactivée, clé absente (étape 2.1) | toujours 0 |
| `timeout` | La source n'a pas répondu à temps | toujours 0 |

**Un signal absent n'est pas un signal de risque.** Une source en panne ne doit ni rendre un site suspect, ni le blanchir : hors `ok`, `risk` vaut 0, et la fusion sait que la source manque (`signal.usable` est faux).

`risk` est borné à `[0, 1]` par validation : une source qui renverrait `7.0` après une erreur de normalisation produit un signal `error`, pas un score faussé.

## L'enrichisseur

```python
class Example(Enricher):
    name = "example"

    def is_enabled(self) -> bool:  # facultatif, vrai par défaut
        return get_settings().is_enabled("example")

    async def _enrich(self, url: str, domain: str) -> Signal:
        listed = await lookup(domain)  # peut lever : c'est géré
        return self.ok(risk=1.0 if listed else 0.0, evidence={"listed": listed})


signal = await Example().enrich(url, domain)  # ne lève jamais
```

Une sous-classe implémente `_enrich()` ; l'appelant utilise `enrich()`. Il s'agit d'une méthode modèle (*template method*) qui garantit le contrat pour toutes les sources :

1. si `is_enabled()` est faux, elle renvoie `skipped` sans appeler la source ;
2. elle mesure `latency_ms` ;
3. elle convertit toute exception : `TimeoutError` et `httpx.TimeoutException` deviennent `timeout`, les autres `error` ;
4. elle impose `source = name` et `risk = 0` hors `ok`, même si la source se trompe.

Les sous-classes disposent de trois constructeurs : `self.ok(risk, evidence)`, `self.skipped(reason)` et `self.error(reason)` (pour un échec attendu et compris, comme un quota épuisé).

Les erreurs de définition sont détectées **à l'import**, pas en production : une sous-classe concrète sans `name`, avec un `_enrich` synchrone (qui bloquerait la boucle asynchrone) ou qui redéfinit `enrich()` (et contournerait le contrat) lève `TypeError`.

## Pourquoi « ne jamais lever »

Un service tiers en panne ne doit jamais faire tomber l'API. Avec cinq sources indépendantes, la probabilité qu'au moins une échoue sur une requête n'est pas négligeable : l'analyse doit **se dégrader** (verdict du modèle local, moins de signaux) au lieu d'échouer. Si chaque source devait gérer ce cas elle-même, il suffirait d'un oubli dans l'une d'elles. Ici, la règle est appliquée une seule fois, dans la classe de base.

Deux exceptions sont volontairement **propagées** :

- `asyncio.CancelledError` : l'orchestrateur (étape 2.9) annule ainsi une source qui dépasse le budget de temps. L'avaler rendrait l'annulation impossible et le budget inopérant ;
- `KeyboardInterrupt`, `SystemExit` et plus généralement toute `BaseException` qui n'est pas une `Exception`.

## Pas de message d'erreur dans le signal

Le signal d'erreur ne contient que le **type** de l'exception (`{"error": "ConnectError"}`), jamais son message. Les erreurs `httpx` contiennent l'URL de la requête, et les API Google acceptent la clé en paramètre (`?key=…`) : recopier le message ferait fuiter la clé dans la réponse de l'API et dans les journaux. Le détail complet part dans le journal Python, au niveau `DEBUG` seulement. Un test vérifie qu'une clé présente dans le message d'une exception n'apparaît pas dans le signal.

## Vérifier une source avec ses propres clés

Les tests automatiques n'utilisent que des réponses simulées (`respx`) : ils ne demandent ni clé ni réseau. Pour vérifier une source contre la vraie API, avec les clés de son `.env` :

```bash
python scripts/check_enrichers.py https://testsafebrowsing.appspot.com/s/phishing.html
python scripts/check_enrichers.py https://example.com --source google_safe_browsing
```

Le script affiche le signal de chaque source. Il se termine avec le code 1 si l'une d'elles est en erreur. **L'URL est envoyée aux services tiers** : n'utilise pas une URL qui contient des données personnelles.

## Sources

### Google Safe Browsing (`google_safe_browsing`, étape 2.4)

*Code : `src/phishguard/enrichers/safe_browsing.py`. Clé : `GSB_API_KEY`.*

**Version de l'API.** Google propose aujourd'hui la **v5**. La v4 (Lookup et Update API) fonctionne toujours. On utilise le mode temps réel de la v5, `urls:search`, l'équivalent de la recherche directe `threatMatches:find` de la v4 :

```
GET https://safebrowsing.googleapis.com/v5/urls:search?urls=<url>&alt=json
X-Goog-Api-Key: <clé>
```

| Réponse | Signal |
| --- | --- |
| `threats` contient au moins un type (`SOCIAL_ENGINEERING`, `MALWARE`, `UNWANTED_SOFTWARE`, `POTENTIALLY_HARMFUL_APPLICATION`) | `ok`, `risk = 1.0`, `listed = true` : **règle dure** pour la fusion (étape 2.10) |
| `threats` vide ou absent | `ok`, `risk = 0.0`, `listed = false` |
| HTTP 400 avec `API_KEY_INVALID` | `error`, `invalid_api_key` |
| HTTP 429 | `error`, `rate_limited` |
| HTTP 5xx | `error`, `server_error` |
| Délai dépassé | `timeout` |

Le type `THREAT_TYPE_UNSPECIFIED` est ignoré, comme le demande la documentation. Un type inconnu, que Google ajouterait plus tard, compte comme une correspondance.

Choix de mise en œuvre :

- `alt=json` est obligatoire : sans lui, la v5 répond en protobuf binaire (vérifié contre l'API réelle) ;
- la clé part dans l'en-tête `X-Goog-Api-Key`, pas dans l'URL : elle n'apparaît ni dans les journaux, ni dans le message d'une exception `httpx` ;
- une clé invalide reçoit un **400**, pas un 401 : la réponse est lue pour le dire clairement (vérifié contre l'API réelle) ;
- le résultat est gardé en cache pendant la durée `cacheDuration` donnée par Google, et 24 h au plus pour un résultat négatif, comme le demandent les conditions. Les erreurs ne sont pas mises en cache.

**Vie privée.** Cette version envoie l'URL complète à Google : elle n'est appelée que si l'utilisateur a activé l'enrichissement (étape 2.9). Avant l'envoi, on retire le fragment (`#…`) et les identifiants (`user:pass@`). La canonicalisation de Safe Browsing les ignore de toute façon : la détection est la même, la fuite en moins. La version 2, plus tard, utilisera la base locale de préfixes de hachage de la v5 (`hashLists`), qui évite d'envoyer l'URL.

**Conditions.** L'API Safe Browsing est réservée à un usage **non commercial**. Un usage commercial passe par Google Web Risk.

### VirusTotal (`virustotal`, étape 2.5)

*Code : `src/phishguard/enrichers/virustotal.py`. Clé : `VT_API_KEY`.*

On lit le dernier rapport existant, **sans jamais soumettre** l'URL à une nouvelle analyse. On cherche d'abord l'URL, puis le domaine si VirusTotal ne connaît pas l'URL (404) :

```
GET https://www.virustotal.com/api/v3/urls/{id}       x-apikey: <clé>
GET https://www.virustotal.com/api/v3/domains/{domaine}
```

`id` est l'URL encodée en base64 « url-safe », **sans** les `=` de remplissage. Le mode `lookups=("domain",)` n'envoie que le domaine, jamais l'URL.

**Risque** : `min(1, (malicious + 0.5 × suspicious) / 5)` sur `last_analysis_stats`.

| Moteurs `malicious` | Moteurs `suspicious` | `risk` |
| --- | --- | --- |
| 0 | 0 | 0,0 |
| 1 | 0 | 0,2 : un moteur seul se trompe souvent |
| 2 | 2 | 0,6 |
| 5 ou plus | — | 1,0 |

Les éléments de preuve contiennent aussi les moteurs qui ont signalé l'URL (10 au plus), la réputation, la date de la dernière analyse et le lien vers le rapport. Un rapport ancien n'est pas pénalisé ici : la fusion (étape 2.10) pourra tenir compte de sa date.

**Quota.** Le palier public est d'environ 4 requêtes par minute et 500 par jour, pour un **usage non commercial** seulement. Deux protections locales :

- un limiteur `aiolimiter` (seau percé : 4 requêtes d'un coup, puis une place toutes les 15 s). Quand il est plein, la source renvoie `skipped` (`local_rate_limit`), ou attend au plus `max_wait` secondes si on le demande. Par défaut elle n'attend pas : le budget de temps de l'orchestrateur (étape 2.9) est de 2,5 s ;
- un compteur journalier (UTC), remis à zéro chaque jour.

Les rapports sont gardés en cache 6 h, les absences (404) 1 h. Chaque URL déjà vue économise donc une requête du quota.

| Réponse | Signal |
| --- | --- |
| Rapport trouvé | `ok`, risque selon la formule |
| 404 pour l'URL et le domaine | `ok`, `risk = 0`, `found = false` |
| Quota local atteint | `skipped`, `local_rate_limit` |
| 401 `WrongCredentialsError` | `error`, `unauthorized` |
| 429 `QuotaExceededError` | `error`, `rate_limited` |
| Rapport malformé | `error`, `MalformedResponse` |

### urlscan.io (`urlscan`, étape 2.6)

*Code : `src/phishguard/enrichers/urlscan.py`. Clé : `URLSCAN_API_KEY`. Options : `URLSCAN_SUBMIT` (défaut `false`), `URLSCAN_VISIBILITY` (`unlisted` par défaut, ou `private`).*

urlscan.io visite des pages dans un navigateur isolé et publie ce qu'il a vu. On s'en sert de deux façons.

**1. Recherche des scans existants (par défaut).** Seul le **domaine** est envoyé :

```
GET https://urlscan.io/api/v1/search/?q=domain:exemple.com&size=10
API-Key: <clé>
```

`domain:` couvre aussi les domaines simplement *contactés* par une page (une police, un script de CDN). On ne garde donc que les scans dont la page elle-même est sur le domaine ou sur l'un de ses sous-domaines (`page.domain`). Si le scan le plus récent ne porte pas de verdict, on lit son rapport complet (`/api/v1/result/{uuid}/`). Un rapport indisponible n'empêche pas le signal.

Les preuves gardent, pour les 5 scans les plus récents : date, adresse IP, pays et opérateur du serveur, verdict (malveillant, score, marques imitées, catégories) et l'URL de la capture d'écran. **La capture s'affiche comme une image, jamais comme du HTML.**

**Risque** : `1.0` si urlscan juge la page malveillante, sinon `max(0, score) / 100`. Le score va de -100 (légitime) à 100 (malveillant). Une absence de scan donne `risk = 0`.

**2. Soumission d'un scan (option « analyse approfondie »).** Elle est désactivée par défaut et n'est faite que si aucun scan n'existe. Elle envoie l'URL **complète**, sans fragment ni identifiants, et fait visiter la page par urlscan. Elle n'est **jamais publique** : un scan public expose l'URL, qui peut contenir l'adresse de la victime ou un jeton de connexion. `public` est refusé par la configuration comme par le constructeur. urlscan peut imposer une autre visibilité : celle qu'il annonce est recopiée dans les preuves.

Un scan prend plusieurs secondes, plus que le budget de l'orchestrateur. La soumission renvoie donc `skipped` (`scan_submitted`) avec l'identifiant du scan. La même URL n'est pas soumise à nouveau pendant une heure (`scan_pending`), et la recherche retrouvera le scan aux appels suivants.

Les recherches sont gardées en cache une heure. Un 429 recopie le délai annoncé par `X-Rate-Limit-Reset-After`.

Le format des réponses vient du client Python officiel (`urlscan/urlscan-python`) et de la documentation. Les verdicts peuvent se trouver dans les résultats de recherche (`verdicts.malicious`, `verdicts.score`) ou seulement dans le rapport complet (`verdicts.overall`) : les deux formes sont lues.
