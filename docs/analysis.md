# Analyse de bout en bout : URL, message, email

*Étapes 2.12 et 3.12 du cahier des charges. Code : `src/phishguard/analysis.py`, `src/phishguard/deployment.py`. Tests : `tests/test_privacy_and_degradation.py`, `tests/test_enricher_contract.py`, `tests/test_pipeline_e2e.py`.*

Trois analyseurs assemblent les briques des modules 1 à 3 et remplissent le même contrat de réponse ([`response-schema.md`](response-schema.md)) : `UrlAnalyzer`, `TextAnalyzer` (SMS, messageries) et `EmailAnalyzer` (email brut). Ce sont les points d'entrée que l'API (module 4), l'extension et le bot (module 5) appelleront.

## Les modèles déployés (étape 3.12)

Les clients ne codent aucun chemin de modèle : ils chargent les trois analyseurs par `load_analyzers`, qui lit `DEPLOYED_MODELS` dans `src/phishguard/deployment.py`.

```python
from phishguard.deployment import load_analyzers

analyzers = load_analyzers("models", orchestrator=orchestrator)  # orchestrateur facultatif
url = await analyzers.url.analyze(url, enrichment=user_opted_in)
sms = analyzers.text.analyze(text, channel="sms")
mail = analyzers.email.analyze(raw_eml_bytes)
response = url.to_response("fr")  # ou sms.to_response(), mail.to_response()
```

| Canal | Modèle déployé | Pourquoi |
| --- | --- | --- |
| URL | `url_v2` (entraînement adversarial, étape 3.9) | compromis assumé : −10,3 points de rappel sur un test biaisé, mais plus d'évasion gratuite par sous-domaines, et 0,8 % de faux positifs au lieu de 49 % sous un long paramètre de suivi ([robustness-report.md](robustness-report.md#52-entraînement-adversarial-étape-39)) |
| SMS, messageries | `text_v2` (entraînement adversarial) | mieux ou aussi bien que `text_v1` partout |
| Email | règles transparentes de l'étape 1.11, avec la règle `url_model` sur `url_v2` | chaque point a une raison lisible ([email-score.md](email-score.md)) |

Un modèle déployé absent lève `FileNotFoundError`, avec la commande qui le produit. Un fichier qui contient un autre modèle que celui annoncé (`text_v1` à la place de `text_v2`) est refusé. Une calibration absente n'empêche pas l'analyse, et elle est signalée dans le journal.

## Normalisation et règle d'hôte (étape 3.12)

La normalisation de l'étape 3.8 ([normalization.md](normalization.md)) est faite par les modèles eux-mêmes, à l'entraînement comme à l'inférence. L'analyse ajoute trois choses :

- **le compte de ce qui a changé** (NFKC, caractères invisibles, homoglyphes repliés), jamais le contenu. Il est journalisé, gardé dans l'analyse (`analysis.normalization`) et exposé dans la vue analyste (`analyst.normalization`). Une entrée modifiée est en soi un indice ;
- **la règle dure `lookalike_host`** : un hôte qui imite des lettres latines (`аpple.com`), dans l'URL analysée ou dans un lien d'un email, donne le verdict phishing (100). La règle passe avant la liste blanche, comme Safe Browsing ([fusion.md](fusion.md#2-règles-dures)), et sa raison est l'unique raison affichée. Elle est calculée localement : aucune source n'est interrogée, et la réponse ne liste aucun signal pour elle ;
- l'imitation est aussi un constat ATT&CK (T1583.001, domaine acquis pour imiter).

## Analyse d'une URL

```python
from phishguard.analysis import UrlAnalyzer
from phishguard.enrichers.orchestrator import Orchestrator

async with Orchestrator.from_settings() as orchestrator:
    analyzer = UrlAnalyzer.from_files(
        "models/url_v2.joblib", "models/url_v2_calibration.json", orchestrator=orchestrator
    )
    analysis = await analyzer.analyze(url, enrichment=user_opted_in)

analysis.verdict, analysis.score, analysis.mitre, analysis.to_dict()
```

| Étape | Toujours ? | Réseau ? |
| --- | --- | --- |
| 1. Modèle URL local (étape 1.6) | oui | non |
| 2. Calibration du score (étape 2.10) | si fournie | non |
| 3. Enrichissement par les six sources (étapes 2.4 à 2.9) | **seulement si `enrichment=True`**, et jamais pour une URL interne | oui |
| 4. Fusion : score et verdict (étape 2.10), avec la règle dure `lookalike_host` (étape 3.12) | oui | non |
| 5. Techniques MITRE ATT&CK (étape 2.11) | verdict suspect ou phishing | non |
| 6. Explication SHAP du score (étape 3.1), traduite en phrases par `to_response(langue)` (étape 3.2, [`reasons.md`](reasons.md)) | si le modèle s'y prête (`UrlModel` à base d'arbres) ; `explain=False` la désactive | non |

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
- **Explication impossible** (modèle sans moteur SHAP, erreur pendant le calcul) : l'analyse aboutit sans explication, l'erreur est journalisée, et la réponse cite une raison générale. L'explication est un plus, jamais une cause d'échec.

### Contrat commun des sources

`tests/test_enricher_contract.py` soumet **les six sources à la fois** à neuf formes de panne : 503, 429, 401, réponse illisible, JSON inattendu, réponse vide, connexion refusée, délai de lecture et protocole rompu. Pour chacune, il vérifie que :

- la source ne lève jamais ;
- elle renvoie un `Signal` à son nom, avec un risque entre 0 et 1, et nul hors `ok` ;
- le signal est sérialisable et ne contient aucune clé.

Il vérifie aussi que chaque source ne contacte **que son propre service**, par une liste d'hôtes autorisés. Une source qui se mettrait à appeler un autre hôte, par erreur ou après une modification, fait échouer le test.

Ces tests ont eux-mêmes été vérifiés : en cassant volontairement le code (enrichissement sans opt-in, URL complète envoyée à urlscan, URL interne enrichie), ils échouent, sous Linux comme sous Windows.

## Analyse d'un email (étape 3.12)

`EmailAnalyzer` lit l'email brut (`.eml`, borné par `EmailLimits`), calcule le score des règles transparentes de l'étape 1.11, puis le fait passer par la même fusion que les autres canaux. Tout est local : aucun lien n'est visité, aucune source n'est interrogée.

| Étape | Code |
| --- | --- |
| 1. Lecture bornée de l'email : en-têtes, authentification, corps, liens, pièces jointes | `email.parser.parse_eml` |
| 2. Score des règles, avec la règle `url_model` sur le modèle URL déployé | `email.score.score_email` |
| 3. Normalisation de l'objet et du corps, comptée et journalisée | `security.normalize` |
| 4. Règle `lookalike_host` sur chaque lien web | `security.normalize.host_script_alert` |
| 5. Fusion, verdict et techniques ATT&CK (lien, pièce jointe, demande d'informations) | `fusion` |
| 6. Raisons : les règles déclenchées les plus lourdes, ou la règle dure seule | `explain.reasons` |

`EmailAnalysis.to_dict()` ne contient ni l'objet, ni le corps, ni aucune adresse : seulement des comptes, les règles déclenchées et le verdict. Un email trop gros lève `EmailTooLargeError`, une entrée qui n'est pas en octets `TypeError` : ce sont des erreurs de l'entrée, que l'API renverra comme telles.
