# Schéma de la réponse d'analyse

*Étape 2.11 bis du cahier des charges, version 1.3.0 depuis l'étape 3.12. Code : `src/phishguard/schema.py`. Schéma JSON : [`docs/schema/analysis-response.v1.json`](schema/analysis-response.v1.json). Tests : `tests/test_response_schema.py`, `tests/test_analyst_view.py`.*

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
  "schema_version": "1.3.0",
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
  "advice": "N'entrez aucun mot de passe ni aucune information bancaire. Ouvrez le site en tapant vous-même son adresse.",
  "analyst": {"model": {"…": "…"}, "explanation": null, "fusion": {"…": "…"}, "versions": {"…": "…"}}
}
```

## Les champs

Les neuf premiers sont ceux du cahier des charges. Les trois suivants ont été ajoutés pour que le contrat serve aux trois canaux et puisse évoluer sans casser les clients ; `language` et `advice` par la version 1.1.0 (étape 3.2), `analyst` par la 1.2.0 (étape 3.4). Depuis la 1.3.0 (étape 3.12), les réponses du canal `email` remplissent le même contrat.

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
| `schema_version` | `1.3.0` | Version de ce contrat |
| `channel` | `url`, `email`, `sms` ou `messaging` | Canal analysé : les trois endpoints du module 4 renvoient ce même schéma. Une analyse de message (`TextAnalyzer`, étape 3.3) est toujours locale : `enrichment` vaut `skipped` et `signals` est vide |
| `fusion_version` | `x.y.z` | Version de la configuration de fusion (`fusion.json`) qui a produit le score |
| `language` | `fr`, `en` ou `ar` | Langue des messages et du conseil |
| `advice` | texte | Conseil d'action, **toujours présent**, selon le canal et le verdict |
| `analyst` | objet ou `null` | Détails techniques, à n'afficher qu'à la demande (voir plus bas) |

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

### La vue analyste

Depuis la version 1.2.0 (étape 3.4), la réponse a **deux niveaux** :

- `reasons` et `advice`, pour l'utilisateur : trois phrases au plus et un conseil ;
- `analyst`, pour l'analyste ou l'utilisateur curieux : le modèle, son explication, la fusion et les versions.

**Règle d'affichage pour les clients** : l'extension et la page web (module 5) n'affichent `analyst` que si l'utilisateur déplie « Détails techniques », fermé par défaut. Le bot Telegram ne l'affiche pas ; il peut le demander absent (`to_response(analyst=False)`, `analyst: null`). Comme les messages, tout le texte de la vue analyste s'insère comme texte, jamais comme HTML.

Exemple réel, `url_v1` calibré, pour `hxxp://paypa1-secure-login[.]xyz/verify/account` (features tronquées) :

```json
"analyst": {
  "model": {"version": "url_v1", "raw_score": 0.9987, "probability": 1.0, "calibrated": true,
            "thresholds": {"fpr_1pct": 0.696, "fpr_0_5pct": 0.8263}},
  "explanation": {
    "method": "tree_shap", "space": "log_odds", "base_value": -2.870721, "output": 6.676963,
    "features": [
      {"name": "path_len", "value": 15.0, "contribution": 2.422586},
      {"name": "host_len", "value": 23.0, "contribution": 1.701414},
      {"name": "host_kw_hits", "value": 2.0, "contribution": 1.47338},
      {"name": "path_kw_hits", "value": 2.0, "contribution": 1.127559}
    ],
    "terms_phishing": [], "terms_safe": []
  },
  "fusion": {"probability": 1.0, "thresholds": {"suspicious": 30, "phishing": 70}, "hard_rule": null,
             "contributions": [{"source": "model", "risk": 1.0, "weight": 1.0, "points": 100.0}],
             "ignored": []},
  "versions": {"schema": "1.2.0", "model": "url_v1", "fusion": "1.0.0", "templates": "fr-1",
               "explanation": "tree_shap"}
}
```

Depuis la version 1.3.0 (étape 3.12), la vue analyste dit aussi ce que la normalisation a changé dans l'entrée, en comptes seulement, et si l'hôte imite des lettres latines :

```json
"normalization": {"changed": true, "nfkc": false, "format_chars": 1, "control_chars": 0,
                  "confusables": 2, "host_alert": null, "version": "1.0.0"}
```

`host_alert` vaut `mixed_script_label` (un label mêle des écritures, `аpple.com`) ou `lookalike_label` (un label entièrement dans une autre écriture qui imite le latin). Il accompagne alors la règle dure `lookalike_host` de `analyst.fusion.hard_rule`. Pour un email, `analyst.model` décrit le score des règles (`email_rules_v1`, score brut de 0 à 100) et `explanation` vaut `null` : les règles déclenchées sont déjà les raisons.

On y lit ce que les phrases taisent : les deux premières contributions sont `path_len` et `host_len`, les features exposées aux biais de chemin et de popularité ([`explain-url.md`](explain-url.md#lecture)). L'utilisateur, lui, lit « L'adresse contient des mots comme « connexion »… » et « L'adresse ressemble à celle de paypal… » ([`reasons.md`](reasons.md)).

| Champ | Contenu |
| --- | --- |
| `model` | `version`, `raw_score` (probabilité du modèle URL, marge du SVM pour le texte), `probability` après calibration, `calibrated`, `thresholds` du modèle seul sur son score brut (seuils `fpr_*` de l'URL, seuil de décision du texte) |
| `explanation` | `null` si le modèle ne s'explique pas. Sinon `method` (`tree_shap` pour l'URL, `linear` pour le texte), `space` (`log_odds`, `probability` ou `margin`), `base_value` et `output` : `output = base_value + somme des contributions`. URL : `features`, **toutes**, de la plus forte en valeur absolue à la plus faible. Texte : `terms_phishing` et `terms_safe`, les dix mots les plus influents dans chaque sens, nettoyés comme les raisons |
| `fusion` | `probability`, `thresholds` (30 et 70), `hard_rule` (ou `null`), `contributions` (`source`, `risk`, `weight`, `points`), `ignored` (sources en panne ou hors délai) |
| `versions` | `schema`, `model`, `fusion`, `templates` (langue et version des gabarits) et `explanation` (méthode, ou `none`) : tout ce qu'il faut pour reproduire la réponse |

Les **signaux bruts** des sources restent dans `signals` (contrat 1.0.0) : les déplacer dans `analyst` casserait les clients existants.

**Vie privée** : pour un message, `terms_phishing` et `terms_safe` contiennent des mots du message de l'utilisateur. La réponse ne va qu'à lui ; elle ne doit pas être journalisée telle quelle par l'API (étape 4.6).

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
- la vue analyste décrit le modèle et la fusion de la réponse (`analyst.model.version` = `model_version`, `analyst.versions.fusion` = `fusion_version`) ;
- aucun champ inconnu, bornes vérifiées (`score`, `risk`, identifiants `T1234.001`).

## Versions du schéma

Le schéma suit le versionnage sémantique :

- **mineure** (`1.1.0`) : ajout d'un champ facultatif. Les clients existants continuent de fonctionner ;
- **majeure** (`2.0.0`) : suppression, renommage ou changement de sens d'un champ. Le fichier `analysis-response.v2.json` s'ajoute alors au premier, sans le remplacer.

Historique :

| Version | Étape | Changement |
| --- | --- | --- |
| `1.3.0` | 3.12 | `analyst.normalization`, facultatif : ce que la normalisation a changé (comptes) et l'alerte d'hôte ; réponses du canal `email` ; raison `hard_rule.lookalike_host` |
| `1.2.0` | 3.4 | Vue analyste `analyst`, facultative : modèle, explication (SHAP ou linéaire), fusion, versions |
| `1.1.0` | 3.2 | Raisons en langage simple, au plus trois, avec `params` ; nouveaux codes (`url.*`, `signal.domain_age`, `signal.virustotal_engines`) ; champs `language` et `advice` |
| `1.0.0` | 2.11 bis | Contrat initial |

Les champs `language` et `advice` sont toujours présents depuis la 1.1.0, `analyst` est présent par défaut depuis la 1.2.0 (ou `null`) ; un client écrit pour une version antérieure les ignore sans rien changer, et une réponse sans `analyst` reste valide.

Le fichier JSON est généré depuis le code (`make schema`). `tests/test_response_schema.py` échoue s'il n'est plus à jour : le contrat ne peut pas changer par accident.
