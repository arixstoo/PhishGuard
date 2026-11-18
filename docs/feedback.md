# Retours des utilisateurs sans risque (étape 4.10)

`POST /v1/feedback` permet de signaler un faux positif ou un faux négatif. C'est une
entrée **non authentifiée par défaut, écrite par n'importe qui** : la traiter comme une
vérité terrain, c'est offrir le modèle à qui veut l'empoisonner. D'où trois règles :

1. **aucun réentraînement automatique** : un retour ne change ni le modèle, ni un seuil,
   ni un verdict. Il va en quarantaine ;
2. **minimisation** : le domaine seulement, jamais l'URL, ni l'IP, ni la clé ;
3. **relecture humaine, par lots**, avec les outils pour repérer une campagne.

## Ce qui est reçu et stocké

```json
POST /v1/feedback
{"domain": "paypa1-secure.example", "verdict": "phishing", "judgement": "false_positive"}

202 {"status": "quarantined", "received_at": "2026-11-12T21:30:00Z"}
```

| Colonne | Origine | Raison |
|---|---|---|
| `domain` | client, ramené en ASCII (IDNA), ni URL ni IP | le chemin et les paramètres d'une URL portent des jetons et des identifiants |
| `verdict`, `judgement` | client, cohérents entre eux | un « faux positif » sur un verdict `safe` est refusé (422) |
| `received_at` | **serveur** | un horodatage client se falsifie ; il est refusé (422) |
| `client_tier` | serveur | `anonymous` ou `authenticated` : un retour avec clé pèse plus |
| `key_id` | serveur | identifiant public de la clé, pour révoquer une clé abusive |
| `reporter` | serveur | pseudonyme du jour (voir ci-dessous), jamais l'IP |
| `decision`, `reviewed_at` | relecteur | `accepted` ou `rejected`, et quand |

**Pseudonyme du rapporteur** (`phishguard.api.pseudonym`). Pour savoir si cent
signalements viennent de cent personnes ou d'une seule, sans stocker d'IP : HMAC-SHA256
de l'IP (ou de son /64 en IPv6) sous une clé **tirée au hasard, gardée en mémoire et
renouvelée chaque jour**. Le même jour, une même source a le même pseudonyme ; la clé
n'est écrite nulle part, donc personne, l'exploitant compris, ne peut ensuite relier un
pseudonyme à une adresse, même en essayant toutes les adresses IPv4, ni suivre une source
d'un jour à l'autre. Un client avec clé est noté `key:<key_id>`.

## Défenses contre l'abus

| Défense | Réglage | Défaut |
|---|---|---|
| quota du niveau du client (avant lecture du corps) | `PHISHGUARD_API_RATE_LIMIT_ANONYMOUS`… | 30/min |
| **quota propre aux retours**, compteur distinct | `PHISHGUARD_API_RATE_LIMIT_FEEDBACK` | 20/heure |
| déduplication : même rapporteur, même domaine, même jugement | `PHISHGUARD_API_FEEDBACK_DEDUP_SECONDS` | 24 h |
| plafond des retours en attente, au-delà 503 `feedback_unavailable` | `PHISHGUARD_API_FEEDBACK_MAX_PENDING` | 10 000 |
| **rétention maximale**, relu ou non (au démarrage, puis toutes les 6 h ; étape 6.5) | `PHISHGUARD_API_FEEDBACK_RETENTION_DAYS` | 90 jours |
| schéma strict (étape 4.2) | — | — |

- La déduplication répond **exactement** comme pour un nouveau retour (202) : un client
  n'apprend rien de l'état de la base.
- Le plafond et la déduplication sont vérifiés dans la même transaction que l'insertion
  (`BEGIN IMMEDIATE`) : deux requêtes simultanées ne peuvent pas les contourner.
- Le plafond protège le disque : une campagne ne remplit pas la base. Il arrête aussi les
  retours honnêtes, ce qui est voulu : l'alerte (journal `quarantaine des retours pleine`)
  dit qu'il est temps de relire.

## Relecture par lots

```bash
python -m phishguard.api.feedback summary                # par domaine : signalements, sources distinctes
python -m phishguard.api.feedback list --limit 50        # le lot suivant, les plus anciens d'abord
python -m phishguard.api.feedback export --out lot.csv   # le même lot, pour un tableur
python -m phishguard.api.feedback accept 1-40,42
python -m phishguard.api.feedback reject 41,43-50
python -m phishguard.api.feedback purge --older-than 90  # rétention des retours relus
```

En conteneur : `docker compose exec api python -m phishguard.api.feedback summary`.

À regarder pour chaque domaine :

- **nombre de sources distinctes** (`summary`) : beaucoup de signalements, une source,
  c'est une campagne, pas un consensus ;
- **niveau du client** : anonyme ou avec clé ;
- **cohérence avec les autres signaux** : un « faux positif » sur un domaine enregistré
  hier, absent du top Tranco et listé par Safe Browsing est suspect ;
- **le domaine lui-même**, vérifié à la main (RDAP, historique, contenu) dans un
  environnement isolé, jamais depuis le poste de travail.

L'export CSV neutralise les cellules qu'un tableur prendrait pour une formule
(`=`, `+`, `-`, `@` en tête : injection CSV), bien que le schéma n'admette déjà que des
noms de domaine.

## Ce que devient un retour accepté

Rien d'automatique. **Accepter**, c'est seulement enregistrer qu'un humain a jugé le
retour fondé. Les retours acceptés servent ensuite, à la main :

- à l'analyse d'erreurs (comme l'étape 1.8) : quelles features ont trompé le modèle ;
- à compléter le prochain jeu d'entraînement, en particulier en courriers légitimes
  d'entreprise, la faiblesse mesurée au rapport de robustesse (57 à 63 % de faux positifs) ;

et le modèle suivant repasse par toute la chaîne : découpage temporel, évaluation sur un
test non modifié, banc de robustesse, signature (étape 4.12). Un retour ne peut donc pas
faire passer un modèle qui serait moins bon.

## Garanties vérifiées par les tests

`tests/test_api_feedback.py` :

- **non-influence** : 300 faux retours (« ce domaine de phishing est sûr ») puis
  acceptation de tous ; ni les empreintes des fichiers de modèle, ni `GET /v1/model`, ni
  aucune réponse d'analyse (hors latence) ne changent ;
- **structure** : seuls la route, le stockage et l'outil de relecture mentionnent la
  quarantaine ; aucun module hors de `phishguard.api` ni aucun script n'importe
  `phishguard.api` (analyse AST de `src/` et `scripts/`). Un futur réentraînement qui la
  lirait ferait échouer ce test ;
- quota des retours et compteur distinct de celui du niveau, déduplication, plafond (y
  compris son atomicité), pseudonymes (stables sur un jour, sans lien d'un jour à
  l'autre, jamais l'IP), migration en place d'une base de l'étape 4.4, relecture,
  export CSV neutralisé.
