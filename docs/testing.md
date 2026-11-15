# Tests, fuzzing et propriétés (étape 4.7)

Toute entrée de PhishGuard est hostile : une URL, un SMS, un email `.eml`. Les parseurs
sont la cible classique des attaquants, ils sont donc testés de trois façons.

```bash
make test    # suite complète, couverture minimale 90 % (cahier des charges : 70 %)
make fuzz    # fuzzing hypothesis, 1 000 exemples par propriété
```

## 1. Contrat de l'API : un test par endpoint et par cas d'erreur

`tests/test_api_contract.py` est une matrice : chaque ligne est une requête et la réponse
attendue (statut, `code` d'erreur), pour chaque route et chaque cas d'erreur (clé
refusée, méthode, corps trop gros, type de contenu, validation, JSON malformé,
demi-codet isolé, fichier vide…). Sur **chaque** réponse, la matrice vérifie aussi les
invariants transverses :

- enveloppe d'erreur commune, `details` sans `input` ni `ctx` ;
- en-têtes de sécurité (étape 4.5) et `X-Request-ID` (étape 4.6) ;
- aucune recopie de l'entrée : une sentinelle glissée dans les entrées fautives n'est
  jamais renvoyée.

Deux garde-fous relient la matrice à la documentation : chaque statut déclaré dans le
schéma OpenAPI d'une route doit être provoqué par une ligne de la matrice, et chaque
route est limitée en débit (429). Les tests par module (`test_api_app.py`,
`test_api_inputs.py`, `test_api_endpoints.py`, `test_api_security.py`,
`test_api_hardening.py`, `test_api_logging.py`) détaillent chaque mécanisme.

## 2. Fuzzing par propriétés

`tests/test_fuzz.py`, marqueur `fuzz`. Propriété commune : **ne lève jamais d'exception
inattendue et renvoie une sortie bornée**.

| Cible | Propriété |
|---|---|
| `url_features` | exception documentée (`InvalidUrlError`) ou toutes les features, finies, positives, bornées par la taille de l'entrée |
| `parse_url` | hôte ASCII en minuscules, borné, ou `InvalidUrlError` ; demi-codets isolés compris |
| `normalize_text` | idempotente, sans caractère de format ni de contrôle, longueur bornée (expansion NFKC ≤ 18) |
| `normalize_url_text` | idem, sans jamais replier d'homoglyphe |
| `host_script_alert` | une des trois valeurs prévues |
| `parse_eml` | aucune étape défaillante (`*_failed:` dans `defects`), liens, pièces jointes, texte et parties sous les bornes de `EmailLimits`, sortie sérialisable en JSON |
| API | jamais de 500 : statut prévu, contrat de réponse ou enveloppe d'erreur |

Les stratégies ne génèrent pas seulement du bruit : elles fabriquent des URLs et des
emails **presque valides**, là où se cachent les bogues. Côté URL : schémas exotiques,
informations d'utilisateur, IPv4 décimale ou hexadécimale, IPv6, IDN, ports hors bornes,
encodages `%` invalides, URLs de 2 000 caractères. Côté email : MIME imbriqué jusqu'à
plusieurs niveaux, délimiteurs absents ou non fermés, mots encodés RFC 2047 aux jeux de
caractères inconnus, base64 tronqué, adresses malformées, HTML piégé (formulaires,
texte masqué, balises non fermées), noms de pièces jointes à double extension ou à
caractère d'inversion, fins de ligne `\r\n`, `\n` ou `\r`, et emails réels corrompus
octet par octet.

### Profils

| Profil | Exemples | Usage |
|---|---|---|
| `default` | 100 | suite courante (`make test`) |
| `ci` | 100 | job `test` de la CI : la graine d'un échec est affichée |
| `fuzz` | 1 000 | `make fuzz`, job `fuzz` de la CI |

Un échec affiche le cas minimal trouvé et un `@reproduce_failure(...)` pour le rejouer.
La base locale de `hypothesis` (`.hypothesis/`) rejoue aussi les échecs passés.

### Dernière exécution

15 propriétés × 1 000 exemples, sans échec (`make fuzz`, environ 4 minutes).

## 3. Non-régression : chaque bogue trouvé devient un test

| Trouvé par | Bogue | Test |
|---|---|---|
| fuzzing de `parse_eml` (email réel corrompu) | deux octets nuls dans le nom affiché encodé de `From` : le texte décodé contient un retour à la ligne, la bibliothèque standard lève `ValueError` et **toute l'étape des en-têtes est perdue** (expéditeur, Reply-To, détection d'usurpation). Un attaquant aveuglait l'analyse de l'expéditeur avec un octet. Correctif : lecture champ par champ, repli sur un décodage manuel, découpage des adresses sur la forme brute, défaut `header_invalid:From` | `test_email_parser.py::test_regression_*` |
| matrice de contrat | le **nom** d'un champ inconnu, choisi par le client, revenait dans `details.loc` (réflexion de l'entrée). Remplacé par `<champ inconnu>` | `test_api_contract.py::test_endpoint_contract[url-unknown-field]` |
| matrice de contrat | `GET /v1/model` documentait un 422 impossible, et les routes JSON ne documentaient ni 413 ni 415 | `test_api_contract.py::test_every_documented_status_is_exercised` |

Un cas trouvé par le fuzzing qui révèle une propriété mal posée plutôt qu'un bogue est
gardé en `@example` avec son explication. Exemple : un hôte IDN dont la forme Punycode
dépasse 253 octets est accepté, comme par le standard WHATWG que suivent les navigateurs
(pas de vérification des longueurs DNS) ; la propriété borne donc l'hôte par la taille
de l'entrée, pas par la limite DNS.
