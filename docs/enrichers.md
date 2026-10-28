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

Le signal d'erreur ne contient que le **type** de l'exception (`{"error": "ConnectError"}`), jamais son message. Les erreurs `httpx` contiennent l'URL de la requête, et l'API Safe Browsing reçoit la clé en paramètre (`?key=…`) : recopier le message ferait fuiter la clé dans la réponse de l'API et dans les journaux. Le détail complet part dans le journal Python, au niveau `DEBUG` seulement. Un test vérifie qu'une clé présente dans le message d'une exception n'apparaît pas dans le signal.
