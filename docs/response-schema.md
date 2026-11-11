# Schéma de la réponse d'analyse

*Étape 2.11 bis du cahier des charges, version 1.1.0 depuis l'étape 3.2. Code : `src/phishguard/schema.py`. Schéma JSON : [`docs/schema/analysis-response.v1.json`](schema/analysis-response.v1.json). Tests : `tests/test_response_schema.py`.*

C'est le **contrat** entre le moteur d'analyse et ses clients : l'API (module 4), l'extension et le bot (module 5) en dépendent. Il est strict : un champ inconnu, un type faux ou une réponse incohérente sont refusés à la construction, avant de partir vers un client.

```python
analysis = await analyzer.analyze(url, enrichment=user_opted_in)
response = analysis.to_response()  # AnalysisResponse, immuable, en français
analysis.to_response("en")  # raisons et conseil en anglais ("ar" : arabe)
response.to_json()
```

## Exemple

Analyse de `https://login.example.com/verify` : modèle à 0,2, domaine de 3 jours et 6 moteurs VirusTotal positifs (l'exemple du plan, étape 2.10) :

```json
{
  "schema_version": "1.1.0",
  "channel": "url",
  "verdict": "phishing",
  "score": 97,
  "confidence": "high",
  "reasons": [
    {"code": "signal.virustotal_engines", "source": "virustotal", "points": 64.8,
     "message": "6 antivirus de VirusTotal signalent ce site comme dangereux.",
     "params": {"n": 6}},
    {"code": "signal.domain_age", "source": "rdap", "points": 25.8,
     "message": "Ce site a été créé il y a seulement 3 jours.", "params": {"n": 3}},
    {"code": "model", "source": "model", "points": 6.3,
     "message": "La forme de cette adresse ressemble à celle de liens de phishing connus.",
     "params": {}}
  ],
  "signals": {
    "rdap": {"status": "ok", "risk": 1.0, "latency_ms": 40, "evidence": {"age_days": 3}},
    "virustotal": {"status": "ok", "risk": 1.0, "latency_ms": 40,
                   "evidence": {"stats": {"malicious": 6, "suspicious": 0}}}
  },
  "mitre": [
    {"id": "T1204.001", "name": "User Execution: Malicious Link", "tactic": "Execution",
     "url": "https://attack.mitre.org/techniques/T1204/001",
     "reason": "l'utilisateur est incité à ouvrir un lien"},
    {"id": "T1598.003", "name": "Phishing for Information: Spearphishing Link",
     "tactic": "Reconnaissance", "url": "https://attack.mitre.org/techniques/T1598/003",
     "reason": "lien vers une page qui demande des informations"},
    {"id": "T1583.001", "name": "Acquire Infrastructure: Domains", "tactic": "Resource Development",
     "url": "https://attack.mitre.org/techniques/T1583/001",
     "reason": "domaine de moins de 30 jours"}
  ],
  "model_version": "url_v1",
  "fusion_version": "1.0.0",
  "enrichment": "used",
  "latency_ms": 812,
  "language": "fr",
  "advice": "N'entrez aucun mot de passe ni aucune information bancaire. Ouvrez le site en tapant vous-même son adresse."
}
```

## Les champs

Les neuf premiers sont ceux du cahier des charges. Les trois suivants ont été ajoutés pour que le contrat serve aux trois canaux et puisse évoluer sans casser les clients ; les deux derniers, par la version 1.1.0 (étape 3.2).

| Champ | Type | Sens |
| --- | --- | --- |
| `verdict` | `safe`, `suspicious` ou `phishing` | Verdict de la fusion (étape 2.10) |
| `score` | entier de 0 à 100 | sûr sous 30, suspect de 30 à 70, phishing au-delà (seuils de `fusion.json`) |
| `confidence` | `low`, `medium` ou `high` | Confiance dans le verdict, voir plus bas |
| `reasons` | liste de 0 à 3 raisons | Pourquoi ce verdict, en langage simple, de la plus forte à la plus faible (voir plus bas) |
| `signals` | objet, une entrée par source | Réponse brute de chaque source interrogée : `status` (`ok`, `error`, `skipped`, `timeout`), `risk` de 0 à 1, `latency_ms`, `evidence` |
| `mitre` | liste de techniques | Techniques ATT&CK (étape 2.11) : `id`, `name` (intitulé officiel MITRE, en anglais), `tactic`, `url`, `reason` |
| `model_version` | texte | Modèle utilisé (`url_v1`) |
| `enrichment` | `used` ou `skipped` | Les sources tierces ont-elles été interrogées ? |
| `latency_ms` | entier | Durée totale de l'analyse |
| `schema_version` | `1.1.0` | Version de ce contrat |
| `channel` | `url`, `email`, `sms` ou `messaging` | Canal analysé : les trois endpoints du module 4 renvoient ce même schéma. Une analyse de message (`TextAnalyzer`, étape 3.3) est toujours locale : `enrichment` vaut `skipped` et `signals` est vide |
| `fusion_version` | `x.y.z` | Version de la configuration de fusion (`fusion.json`) qui a produit le score |
| `language` | `fr`, `en` ou `ar` | Langue des messages et du conseil |
| `advice` | texte | Conseil d'action, **toujours présent**, selon le canal et le verdict |

### Les raisons

Depuis la version 1.1.0, les raisons sont écrites pour l'utilisateur (étape 3.2, [`reasons.md`](reasons.md)) : **au plus trois**, une phrase courte chacune, dans la langue de la réponse. Chaque raison a :

- un `code` **stable**, sur lequel un client peut s'appuyer (traduction, icône) ;
- ses variables dans `params` (marque imitée, nombre de jours, extension), pour qu'un client puisse réécrire la phrase lui-même ;
- un `message` déjà rédigé, qui peut être reformulé d'une version à l'autre. C'est du **texte brut** : un client l'insère comme texte (`textContent`), jamais comme HTML ;
- `points`, la part du score qui lui revient.

| Code | Quand |
| --- | --- |
| `hard_rule.blocklist`, `hard_rule.google_safe_browsing`, `hard_rule.allowlist` | Une règle dure a décidé : c'est alors l'unique raison |
| `url.brand_lookalike`, `url.brand_in_host`, `url.risky_tld`, `url.ip_host`… | Une feature compréhensible du modèle URL a fait monter le score ; la part du modèle est répartie selon les valeurs SHAP (étape 3.1). Liste complète dans [`reasons.md`](reasons.md) |
| `text.urgency`, `text.money`, `text.link`, `text.code`, `text.account`, `text.terms` | Catégorie de leurre ou mots du message qui ont fait monter le score (SMS et messageries, étape 3.3, [`explain-text.md`](explain-text.md)) |
| `model`, `text.model` | Part du modèle local (URL ou texte), quand aucune raison plus précise ne l'explique (verdict suspect ou phishing seulement) |
| `signal.domain_age`, `signal.virustotal_engines`, `signal.urlscan`… | Part du score due à une source de Threat Intelligence |

Leur somme vaut au plus le score : la part du modèle due à des features que l'utilisateur ne peut pas vérifier (la longueur du chemin, par exemple) n'est citée nulle part, et une contribution de moins d'un demi-point non plus. Un constat net qui n'a pas fait monter le score (un raccourcisseur) peut être cité avec `points: 0`. Une source en panne apparaît dans `signals`, mais jamais dans `reasons`.

### La confiance

| Situation | Confiance |
| --- | --- |
| Une règle dure a décidé | `high` |
| Verdict `suspicious` | `low` : c'est, par définition, la zone d'incertitude |
| Score à 20 points ou plus du seuil le plus proche | `high` (par exemple 5 ou 95) |
| De 10 à 19 points | `medium` (15 ou 85) |
| Moins de 10 points | `low` (25 ou 75) |

Elle se lit sur le score calibré : une confiance haute sur un verdict `safe` veut dire que le modèle et les sources sont loin du seuil, pas que la page est garantie sans danger.

## Règles de cohérence

Une réponse qui les enfreint n'est pas construite (`ValidationError`), au lieu d'arriver fausse chez un client :

- un verdict `phishing` cite **au moins une technique ATT&CK** (critère de l'étape 2.11) ;
- un verdict `safe` n'en cite aucune ;
- avec `enrichment: "skipped"`, `signals` est vide : aucune source n'a été interrogée ;
- au plus trois raisons, et un conseil d'action non vide ;
- aucun champ inconnu, bornes vérifiées (`score`, `risk`, identifiants `T1234.001`).

## Versions du schéma

Le schéma suit le versionnage sémantique :

- **mineure** (`1.1.0`) : ajout d'un champ facultatif. Les clients existants continuent de fonctionner ;
- **majeure** (`2.0.0`) : suppression, renommage ou changement de sens d'un champ. Le fichier `analysis-response.v2.json` s'ajoute alors au premier, sans le remplacer.

Historique :

| Version | Étape | Changement |
| --- | --- | --- |
| `1.1.0` | 3.2 | Raisons en langage simple, au plus trois, avec `params` ; nouveaux codes (`url.*`, `signal.domain_age`, `signal.virustotal_engines`) ; champs `language` et `advice` |
| `1.0.0` | 2.11 bis | Contrat initial |

Les champs `language` et `advice` sont toujours présents dans une réponse 1.1.0 ; un client écrit pour la 1.0.0 les ignore sans rien changer.

Le fichier JSON est généré depuis le code (`make schema`). `tests/test_response_schema.py` échoue s'il n'est plus à jour : le contrat ne peut pas changer par accident.
