# Parseur d'emails (étape 1.10)

`src/phishguard/email/` lit un email brut (`.eml`) et en extrait les signaux de phishing : authentification SPF, DKIM et DMARC, cohérence des expéditeurs, liens trompeurs, formulaires, pièces jointes à risque, texte masqué. Ces signaux alimentent le score de l'étape 1.11.

```bash
python scripts/parse_email.py message.eml           # résumé lisible
python scripts/parse_email.py message.eml --json    # toute l'analyse
python scripts/fetch_email_samples.py               # 50 emails de phishing réels (Phishing Pot) dans data/raw/emails/
python -m pytest tests/test_email_parser.py
```

```python
from phishguard.email import parse_eml

email = parse_eml(open("message.eml", "rb").read())
email.auth.dmarc                 # "pass", "fail", "none"… ou "unknown"
email.reply_to_differs           # Reply-To sur un autre domaine que From
[l.text_domain for l in email.mismatched_links]   # domaines affichés qui ne sont pas la cible
```

| Fichier | Rôle |
| :--- | :--- |
| `src/phishguard/email/parser.py` | `parse_eml`, limites, parties MIME, expéditeurs, pièces jointes |
| `src/phishguard/email/auth.py` | `Authentication-Results` (RFC 8601) et `Received-SPF` |
| `src/phishguard/email/html.py` | Liens, formulaires et texte masqué du HTML |
| `scripts/parse_email.py` | Analyse d'un fichier en ligne de commande |
| `scripts/fetch_email_samples.py` | Téléchargement d'emails réels du corpus Phishing Pot (non versionnés) |
| `tests/fixtures/emails/*.eml` | 13 emails de test rédigés à la main |

## Un email est une entrée hostile

1. **Rien n'est rendu, exécuté ni téléchargé.** La structure est lue par la bibliothèque standard `email` (`policy.default`), le HTML par BeautifulSoup avec `html.parser`, en Python pur. Aucune image, aucun lien n'est chargé, aucune pièce jointe n'est ouverte : on n'en lit que le nom, le type et la taille.
2. **Tout est borné** (`EmailLimits`) :

   | Limite | Valeur | Au-delà |
   | :--- | ---: | :--- |
   | Taille du message | 10 Mio | refusé (`EmailTooLargeError`) |
   | Parties MIME | 200 | les suivantes sont ignorées |
   | Profondeur d'imbrication | 10 | les parties plus profondes sont ignorées |
   | Liens | 500 | les suivants sont ignorés |
   | Pièces jointes | 100 | les suivantes sont ignorées |
   | HTML par partie | 2 millions de caractères | tronqué |
   | Texte conservé | 100 000 caractères | tronqué |

   Chaque troncature est notée dans `defects` (`depth_truncated:10`…), avec les anomalies de structure relevées par la bibliothèque `email`.
3. **Aucune autre exception ne sort de `parse_eml`.** Une étape qui échoue sur un message malformé est notée dans `defects` (`body_failed:…`) et le reste de l'analyse continue. Un message illisible donne un résultat vide, pas une erreur. Deux tests Hypothesis le vérifient sur des octets aléatoires et sur les emails de test corrompus ; le fuzzing du module 4 le vérifiera à grande échelle.
4. Le parcours des parties est **itératif** (pile explicite), pas récursif : un message très imbriqué ne peut pas épuiser la pile d'appels.

## Les signaux

### Authentification : ne croire que le dernier serveur

Le serveur de réception vérifie SPF, DKIM et DMARC, puis ajoute **en tête** un en-tête `Authentication-Results`. Un attaquant peut écrire lui-même un `Authentication-Results: …; dmarc=pass` dans son message : il arrive plus bas, sous celui du serveur de l'utilisateur. Le parseur ne lit donc que le **premier** de ces en-têtes (le plus récent). Si `trusted_authserv_ids` est fourni (`--trusted-authserv-id mx.google.com`), il lit le premier dont l'identifiant de serveur en fait partie, ce qui est plus sûr quand on connaît son fournisseur. `Received-SPF` sert de repli pour SPF seul. Plusieurs signatures DKIM : `pass` si l'une passe (une signature valide suffit, RFC 6376).

Valeurs : `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`, `policy`, et `unknown` si aucun résultat n'est lisible. L'email de test `10_fake_auth_results.eml` reproduit l'attaque.

### Expéditeurs

Les domaines de `From`, `Reply-To` et `Return-Path` sont comparés au niveau du **domaine enregistré** (`login.paypal.com` et `paypal.com` sont le même domaine), avec la liste des suffixes publics hors ligne de l'étape 1.2.

- `reply_to_differs` : la réponse partira ailleurs que chez l'expéditeur affiché (fraude au président, `03_phish_reply_to.eml`).
- `return_path_differs` : l'adresse de rebond est sur un autre domaine. C'est fréquent et légitime pour les envois en masse (prestataire d'emailing) : un signal faible.
- `display_name_spoof` : le **nom affiché** contient une adresse ou un domaine différent de l'expéditeur réel (`"service@paypal.com" <alerts@autre.example>`). Seul un domaine avec un suffixe public connu compte : `Bradesco.recompensas` n'est pas comparé.
- Un `From: "Service client", _ <x@y>` (virgule hors des guillemets) se découpe en deux entrées dont la première n'a pas d'adresse : on garde la première vraie adresse. Ce cas, trouvé dans le corpus réel, faisait perdre l'expéditeur.

### Liens

Pour chaque `<a href>`, `<area href>` et `<form action>` : la cible, le texte affiché et leurs domaines enregistrés. Un lien est **trompeur** (`mismatch`) si son texte ressemble à une adresse web dont le domaine diffère de celui de la cible (`https://www.paypal.com` affiché, `paypa1-secure.example.net` visé), ou si une adresse web s'affiche sur une cible qui n'est pas du web (`javascript:`, `data:`). Les liens relatifs (`/aide`) n'ont pas de domaine et ne sont jamais trompeurs. Dans un email sans HTML, les URLs du texte brut sont relevées (`kind="text"`).

Les **formulaires** sont comptés : un email légitime n'en contient presque jamais, puisqu'il renvoie vers un site.

### Pièces jointes

| Famille | Extensions (exemples) |
| :--- | :--- |
| `executable` | `exe`, `scr`, `com`, `msi`, `jar` |
| `script` | `js`, `vbs`, `hta`, `ps1`, `lnk` |
| `macro_document` | `docm`, `xlsm`, `pptm` |
| `html` | `htm`, `html`, `svg`, `mht` : page de connexion locale, qui échappe aux filtres d'URL |
| `disk_image` | `iso`, `img`, `vhd` : contournent le marquage « téléchargé d'Internet » |
| `archive` | `zip`, `rar`, `7z` |

Aussi : la **double extension** (`facture.pdf.exe`) et le caractère **RTLO** (U+202E), qui inverse l'affichage : `invoice<RTLO>fdp.exe` s'affiche `invoiceexe.pdf`. L'extension retenue est celle des caractères réels.

### Texte masqué

Éléments cachés par leur style **en ligne** : `display:none`, `visibility:hidden`, `opacity:0`, police de taille nulle ou de 1 px, hauteur nulle avec `overflow:hidden`, couleur du texte égale à celle du fond (de l'élément ou d'un ancêtre, y compris l'attribut `bgcolor`), ou attribut `hidden`. On compte les éléments masqués de plus haut niveau et leurs caractères, puis on les retire du texte visible. Les caractères invisibles (espace sans chasse, U+200B…) sont comptés à part : ils servent à couper les mots-clés que cherchent les filtres.

Un texte masqué **n'est pas une preuve** : les newsletters légitimes cachent souvent une ligne d'aperçu (`01_legit_newsletter.eml`). Le score (étape 1.11) devra le pondérer en conséquence.

## Vérification sur des emails réels

Les 13 emails de test couvrent chacun un signal ou un piège : lien trompeur, Reply-To, double extension, pièce jointe HTML, texte masqué, en-têtes malformés, imbrication profonde, quoted-printable latin-1, faux `Authentication-Results`, objet en arabe avec lien homographe et RTLO, lien `javascript:` et formulaire, nom affiché trompeur.

Pendant le développement, le parseur a aussi tourné sur **200 emails de phishing réels** du corpus Phishing Pot et sur les **47 emails de test de CPython** (`Lib/test/test_email/data`, cas limites de la bibliothèque standard) : aucune exception, aucune étape en échec, 63 ms au plus par message. Cette vérification a trouvé deux bugs, corrigés et couverts par un test : l'expéditeur perdu sur une virgule hors des guillemets, et des liens relatifs pris pour des noms de domaine. Pour la refaire :

```bash
python scripts/fetch_email_samples.py --count 200
python -m pytest tests/test_email_parser.py -k public   # ignoré si data/raw/emails/ est absent
```

Phishing Pot est sous licence **CC BY-NC 4.0** (usage non commercial, attribution) : ses emails ne sont jamais versionnés dans ce dépôt sous licence MIT (voir [`data-sources.md`](data-sources.md#7-phishing-pot-emails-de-phishing-réels)).

## Limites

- Les feuilles `<style>` et les classes CSS ne sont pas interprétées : un texte masqué par une classe n'est pas vu.
- Le contenu des pièces jointes n'est pas analysé (ni les archives, ni les documents, ni le HTML joint).
- Les signaux d'authentification ne valent que ce que vaut le serveur qui les a écrits : un email transféré ou exporté depuis un autre client peut avoir perdu ses en-têtes d'origine.
- Un nom de marque dans le nom affiché sans domaine (« PayPal Service ») n'est pas un signal ici : c'est le rôle des features de marque de l'étape 1.11.
- Deux domaines différents d'une même organisation (`icims.com` et `icims.eu`) rendent un lien « trompeur » : le score devra en tenir compte.
