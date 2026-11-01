# Correspondance MITRE ATT&CK

*Étape 2.11 du cahier des charges. Code : `src/phishguard/fusion/mitre.py`. Catalogue : `src/phishguard/fusion/mitre_attack.json`. Tests : `tests/test_fusion_mitre.py`.*

Chaque verdict `suspicious` ou `phishing` est relié aux techniques MITRE ATT&CK qu'il illustre. Un analyste lit ainsi la détection dans le vocabulaire commun de la défense, et peut la rapprocher de ses règles de détection ou de ses rapports d'incident. Un verdict `safe` n'en a aucune.

```python
from phishguard.fusion import Observations, map_techniques

techniques = map_techniques(
    "phishing", Observations("email", has_link=True, requests_information=True)
)
# T1566.002 Phishing: Spearphishing Link            (Initial Access)
# T1204.001 User Execution: Malicious Link          (Execution)
# T1598.003 Phishing for Information: Spearphishing Link (Reconnaissance)
```

## Table de correspondance

| Constat | Technique | Tactique |
| --- | --- | --- |
| Lien malveillant dans un email | T1566.002 Phishing: Spearphishing Link | Initial Access |
| Pièce jointe à risque dans un email | T1566.001 Phishing: Spearphishing Attachment | Initial Access |
| Message reçu par un service tiers (SMS, messagerie, réseau social) | T1566.003 Phishing: Spearphishing via Service | Initial Access |
| L'utilisateur est incité à ouvrir un lien (y compris une URL analysée seule) | T1204.001 User Execution: Malicious Link | Execution |
| L'utilisateur est incité à ouvrir un fichier | T1204.002 User Execution: Malicious File | Execution |
| Le message demande des informations (identifiants, codes, paiement) | T1598 Phishing for Information, ou .003 avec un lien, .002 avec une pièce jointe | Reconnaissance |
| Domaine de moins de 30 jours (RDAP ou premier certificat) ou imitant une marque (typosquatting, homographe) | T1583.001 Acquire Infrastructure: Domains | Resource Development |

**Un verdict de phishing reçoit toujours au moins une technique** : à défaut d'un vecteur plus précis (email sans lien ni pièce jointe identifiés), T1566 Phishing. Un test le vérifie sur les 128 combinaisons de constats.

Les constats viennent de l'analyse, pas du verdict :

- le canal et les liens, du point d'entrée (extension, bot, page web, API) ;
- les pièces jointes et les formulaires, du parseur d'emails (étape 1.10) ;
- les demandes d'informations, des features smishing (étape 1.9) et du score email (étape 1.11) ;
- les domaines récents et les imitations, de `domain_observations()`, d'après les signaux RDAP et Certificate Transparency et les features URL `is_typosquat`, `homograph_brand` et `host_mixed_script` (étape 1.5).

Une URL analysée seule (extension, page web) ne dit pas comment elle a été reçue : on ne retient ni T1566.002 ni T1566.003, mais T1204.001, puisque l'utilisateur s'apprête à l'ouvrir.

## Identifiants vérifiés

Le plan demandait de vérifier les identifiants sur le site de MITRE avant de les figer. Ils sont vérifiés contre les **données officielles d'ATT&CK** (paquet STIX d'ATT&CK Enterprise, `github.com/mitre-attack/attack-stix-data`) par `scripts/verify_mitre.py`. Pour chaque technique du catalogue, le script vérifie qu'elle existe, qu'elle n'est ni révoquée ni dépréciée, et que son nom et sa tactique sont inchangés.

```bash
python scripts/verify_mitre.py           # télécharge les données de MITRE et compare
python scripts/verify_mitre.py --write   # met à jour les noms et la version vérifiée
```

Vérification faite le 01/11/2026 sur **ATT&CK Enterprise v20.0** (publiée le 13/10/2026) : les 12 techniques du catalogue sont à jour. Cette vérification a relevé que T1656 Impersonation, une piste pour les emails qui usurpent une marque, est **révoquée** dans cette version : elle n'est pas utilisée.

ATT&CK publie deux versions par an : relancer le script à chaque version. Les intitulés restent en anglais, ce sont ceux de MITRE, que les analystes recherchent tels quels. Les phrases pour l'utilisateur viendront du module 3.

## Limites

- La correspondance décrit **ce que la détection illustre**, pas une attribution : elle ne dit rien de l'attaquant.
- T1598 (reconnaissance) et T1566 (accès initial) se recouvrent pour le vol d'identifiants : les deux sont retenus quand le message demande des informations, comme le fait couramment la littérature.
- Les sites légitimes compromis (T1584.001 Compromise Infrastructure: Domains) ne sont pas encore détectés comme tels : ce sera possible quand un signal les distinguera des domaines créés pour l'attaque.
