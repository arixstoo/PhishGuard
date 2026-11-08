# Analyse d'une URL : de bout en bout

*Étape 2.12 du cahier des charges. Code : `src/phishguard/analysis.py`. Tests : `tests/test_privacy_and_degradation.py`, `tests/test_enricher_contract.py`.*

`UrlAnalyzer` assemble les briques des modules 1 et 2. C'est le point d'entrée que l'API (module 4), l'extension et le bot (module 5) appelleront.

```python
from phishguard.analysis import UrlAnalyzer
from phishguard.enrichers.orchestrator import Orchestrator

async with Orchestrator.from_settings() as orchestrator:
    analyzer = UrlAnalyzer.from_files(
        "models/url_v1.joblib", "models/url_v1_calibration.json", orchestrator=orchestrator
    )
    analysis = await analyzer.analyze(url, enrichment=user_opted_in)

analysis.verdict, analysis.score, analysis.mitre, analysis.to_dict()
```

| Étape | Toujours ? | Réseau ? |
| --- | --- | --- |
| 1. Modèle URL local (étape 1.6) | oui | non |
| 2. Calibration du score (étape 2.10) | si fournie | non |
| 3. Enrichissement par les six sources (étapes 2.4 à 2.9) | **seulement si `enrichment=True`**, et jamais pour une URL interne | oui |
| 4. Fusion : score et verdict (étape 2.10) | oui | non |
| 5. Techniques MITRE ATT&CK (étape 2.11) | verdict suspect ou phishing | non |

L'enrichissement est **désactivé par défaut** : c'est l'utilisateur qui l'active (opt-in). Quand il n'a pas lieu, `analysis.enrichment_skipped` dit pourquoi : `not_requested` (non demandé, ou aucune source configurée) ou `internal_host`. Un score du modèle non fini (NaN) lève `ValueError` au lieu de devenir un verdict « sûr » silencieux. Une URL invalide lève `InvalidUrlError` : c'est une erreur de l'entrée, que l'API renverra comme telle, pas une panne de source.

## Garanties vérifiées par les tests

### Vie privée

- **Sans enrichissement, rien ne quitte la machine.** Le test configure les six sources avec des clés, puis bloque tout accès au réseau : `socket.getaddrinfo`, `connect`, `connect_ex`, `sendto` et `httpx.AsyncClient.send`. L'analyse doit aboutir sans qu'aucun de ces appels ne soit tenté, ni par HTTP, ni par le DNS (`dnspython` utilise ses propres sockets), ni par une source oubliée.
- **Avec l'enrichissement, seulement le strict nécessaire.** Sur une URL piégée (identifiants `user:pass@`, adresse de la victime dans la requête, jeton dans le fragment), toutes les requêtes sortantes sont capturées. Le test vérifie que :
  - les identifiants et le fragment ne partent **jamais** ;
  - urlscan, RDAP et crt.sh ne reçoivent ni le chemin ni la requête, seulement le domaine ;
  - le DNS ne résout que le domaine enregistré ;
  - Safe Browsing et VirusTotal reçoivent l'URL nettoyée, comme le documente leur section de `docs/enrichers.md` ;
  - aucune clé d'API ne circule dans une URL : elles partent toujours dans un en-tête, qui n'apparaît pas dans les journaux d'accès.
- **Une URL interne n'est jamais envoyée, même avec l'opt-in.** Adresse IP privée, de bouclage ou de lien local (`192.168.1.10`, `127.0.0.1` y compris écrit `0x7f000001`, `::1`, `169.254.169.254`), ou nom sans suffixe public (`localhost`, `nas.lan`, `intranet.corp.local`) : aucun service public ne les connaît, et leur nom révélerait le réseau de l'utilisateur. Le modèle local décide seul. Le test bloque le réseau comme ci-dessus, avec l'enrichissement activé.

Le blocage du réseau laisse passer un seul appel : `socket.socketpair()`. Sous Windows, la boucle `asyncio` s'en sert pour se réveiller elle-même, et Python l'y émule par une connexion vers 127.0.0.1, interne au processus. Sans cette exception, les tests échouaient sous Windows alors qu'aucune donnée ne sortait.

### Dégradation

- **Toutes les sources en panne** (réseau coupé, DNS injoignable) : l'analyse aboutit en moins de 3 s avec le verdict du modèle seul, identique à `fuse(probabilité)` sans signal. Un phishing garde ses techniques ATT&CK.
- **Toutes les sources trop lentes** : elles sont arrêtées par le budget de l'orchestrateur, et le verdict du modèle est renvoyé dans le délai.

### Contrat commun des sources

`tests/test_enricher_contract.py` soumet **les six sources à la fois** à neuf formes de panne : 503, 429, 401, réponse illisible, JSON inattendu, réponse vide, connexion refusée, délai de lecture et protocole rompu. Pour chacune, il vérifie que :

- la source ne lève jamais ;
- elle renvoie un `Signal` à son nom, avec un risque entre 0 et 1, et nul hors `ok` ;
- le signal est sérialisable et ne contient aucune clé.

Il vérifie aussi que chaque source ne contacte **que son propre service**, par une liste d'hôtes autorisés. Une source qui se mettrait à appeler un autre hôte, par erreur ou après une modification, fait échouer le test.

Ces tests ont eux-mêmes été vérifiés : en cassant volontairement le code (enrichissement sans opt-in, URL complète envoyée à urlscan, URL interne enrichie), ils échouent, sous Linux comme sous Windows.
