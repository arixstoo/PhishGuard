# Schéma de la réponse d'analyse

*Étape 2.11 bis du cahier des charges. Code : `src/phishguard/schema.py`. Schéma JSON : [`docs/schema/analysis-response.v1.json`](schema/analysis-response.v1.json). Tests : `tests/test_response_schema.py`.*

C'est le **contrat** entre le moteur d'analyse et ses clients : l'API (module 4), l'extension et le bot (module 5) en dépendent. Il est strict : un champ inconnu, un type faux ou une réponse incohérente sont refusés à la construction, avant de partir vers un client.

```python
analysis = await analyzer.analyze(url, enrichment=user_opted_in)
response = analysis.to_response()  # AnalysisResponse, immuable
response.to_json()
```

## Exemple

Analyse de `https://login.example.com/verify` : modèle à 0,2, domaine de 3 jours et 6 moteurs VirusTotal positifs (l'exemple du plan, étape 2.10) :

```json
{
  "schema_version": "1.0.0",
  "channel": "url",
  "verdict": "phishing",
  "score": 97,
  "confidence": "high",
  "reasons": [
    {"code": "signal.virustotal", "source": "virustotal", "points": 64.8,
     "message": "Des moteurs antivirus de VirusTotal signalent cette adresse."},
    {"code": "signal.rdap", "source": "rdap", "points": 25.8,
     "message": "Le domaine a été enregistré récemment."},
    {"code": "model", "source": "model", "points": 6.3,
     "message": "Le modèle local estime la probabilité de phishing à 20 %."}
  ],
  "signals": {
    "rdap": {"status": "ok", "risk": 1.0, "latency_ms": 40, "evidence": {"age_days": 3}},
    "virustotal": {"status": "ok", "risk": 1.0, "latency_ms": 40, "evidence": {}}
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
  "latency_ms": 812
}
```

## Les champs

Les neuf premiers sont ceux du cahier des charges. Les trois derniers ont été ajoutés pour que le contrat serve aux trois canaux et puisse évoluer sans casser les clients.

| Champ | Type | Sens |
| --- | --- | --- |
| `verdict` | `safe`, `suspicious` ou `phishing` | Verdict de la fusion (étape 2.10) |
| `score` | entier de 0 à 100 | sûr sous 30, suspect de 30 à 70, phishing au-delà (seuils de `fusion.json`) |
| `confidence` | `low`, `medium` ou `high` | Confiance dans le verdict, voir plus bas |
| `reasons` | liste de raisons | Ce qui a fait monter le score, de la plus forte à la plus faible |
| `signals` | objet, une entrée par source | Réponse brute de chaque source interrogée : `status` (`ok`, `error`, `skipped`, `timeout`), `risk` de 0 à 1, `latency_ms`, `evidence` |
| `mitre` | liste de techniques | Techniques ATT&CK (étape 2.11) : `id`, `name` (intitulé officiel MITRE, en anglais), `tactic`, `url`, `reason` |
| `model_version` | texte | Modèle utilisé (`url_v1`) |
| `enrichment` | `used` ou `skipped` | Les sources tierces ont-elles été interrogées ? |
| `latency_ms` | entier | Durée totale de l'analyse |
| `schema_version` | `1.0.0` | Version de ce contrat |
| `channel` | `url`, `email`, `sms` ou `messaging` | Canal analysé : les trois endpoints du module 4 renvoient ce même schéma |
| `fusion_version` | `x.y.z` | Version de la configuration de fusion (`fusion.json`) qui a produit le score |

### Les raisons

Chaque raison a un `code` **stable**, sur lequel un client peut s'appuyer (traduction, icône), et un `message` en français qui peut être reformulé. Le module 3 (explicabilité) détaillera ces phrases.

| Code | Quand |
| --- | --- |
| `hard_rule.blocklist`, `hard_rule.google_safe_browsing`, `hard_rule.allowlist` | Une règle dure a décidé : c'est alors l'unique raison |
| `model` | Part du score due au modèle local |
| `signal.<source>` | Part du score due à une source (`signal.virustotal`, `signal.rdap`…) |

`points` est la part du score attribuée à la raison (répartition exacte de l'étape 2.10) : leur somme vaut le score, à l'arrondi près. Une contribution de moins d'un demi-point n'est pas citée. Une source en panne apparaît dans `signals`, mais jamais dans `reasons`.

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
- aucun champ inconnu, bornes vérifiées (`score`, `risk`, identifiants `T1234.001`).

## Versions du schéma

Le schéma suit le versionnage sémantique :

- **mineure** (`1.1.0`) : ajout d'un champ facultatif. Les clients existants continuent de fonctionner ;
- **majeure** (`2.0.0`) : suppression, renommage ou changement de sens d'un champ. Le fichier `analysis-response.v2.json` s'ajoute alors au premier, sans le remplacer.

Le fichier JSON est généré depuis le code (`make schema`). `tests/test_response_schema.py` échoue s'il n'est plus à jour : le contrat ne peut pas changer par accident.
