# Registre de modèles et signature (étape 4.12)

Les modèles sont des fichiers **pickle** : les charger, c'est exécuter leur contenu.
Quiconque peut écrire dans `models/`, ou servir un faux téléchargement à l'extension,
exécute donc son code. La signature ferme cette porte : chaque publication a un
manifeste signé par une clé **Ed25519** dont la partie privée ne quitte jamais la machine
de publication, et rien n'est désérialisé avant que la signature et chaque empreinte
aient été vérifiées.

```bash
# Une fois : la paire de clés. Privée hors du dépôt (refusée dedans), publique versionnée.
export PHISHGUARD_SIGNING_PASSPHRASE='…'        # jamais en argument (ps, historique)
python scripts/sign_models.py keygen \
    --private-key ~/.config/phishguard/model-signing.key --public-key keys/model-signing.pub

# À chaque publication : export pour l'extension (4.11), puis manifeste et signature.
make export sign
make verify                                     # scripts/verify_models.py, code 0 ou 1
```

## Manifeste

`models/manifest.json`, JSON canonique (clés triées, compact, UTF-8) :

```json
{
  "format": "phishguard-model-manifest", "format_version": 1,
  "release": "2026.11.12", "created_at": "2026-11-12T22:40:00Z",
  "schema_version": "1.0.0", "fusion_version": "1.0.0", "normalization_version": "1.0.0",
  "models": {
    "url":  {"version": "url_v2", "trained_at": "…", "metrics": {…},
             "feature_extractor": {"version": "1.0.0", "reference_data_sha256": "…", "features": […]}},
    "text": {"version": "text_v2", "trained_at": "…", "metrics": null}
  },
  "artifacts": [
    {"name": "url_v2.joblib", "role": "url-model", "sha256": "…", "size": 1234567},
    {"name": "url_v2_calibration.json", "role": "url-calibration", "sha256": "…", "size": 4321},
    {"name": "url_v2.json", "role": "url-export", "sha256": "…", "size": 456789},
    …
  ]
}
```

Signature détachée, `models/manifest.json.sig` :

```json
{"algorithm":"ed25519","format_version":1,"key_id":"035236857a7f0628","signature":"<base64, 64 octets>"}
```

`key_id` : 16 caractères hexadécimaux du SHA-256 de la clé publique brute. Une rotation
de clé se voit, et une signature d'une autre clé est refusée avec un message clair. Ce
n'est qu'une étiquette : seule la vérification cryptographique compte (un test signe avec
une autre clé en recopiant le bon `key_id`).

## Vérification

Ordre, dans `phishguard.registry.verify_manifest`, sans exception :

1. **tailles bornées avant lecture** (manifeste 1 Mio, signature 4 Kio) ; liens
   symboliques refusés ;
2. **signature d'abord**, sur les **octets exacts** du fichier, sans recanonicalisation
   (aucune ambiguïté d'encodage). Base64 **canonique** exigé (voir plus bas) ;
3. seulement ensuite, interprétation du manifeste : format, version, et artefacts dont le
   nom est un **nom de fichier plat** (`url_v2.joblib`), jamais un chemin (`../x`, `/etc/x`,
   `a/b`, fichier caché) ;
4. chaque artefact : fichier ordinaire, **taille** puis **SHA-256** signés.

**Pas de TOCTOU.** `VerifiedManifest.read(nom)` lit le fichier **une fois**, vérifie
l'empreinte de ces octets et les renvoie ; c'est eux que `joblib` désérialise
(`io.BytesIO`), jamais le fichier relu ensuite. Un modèle remplacé entre la vérification
et le chargement n'est donc jamais chargé (testé).

**Un modèle absent du manifeste n'est jamais désérialisé** : `load_analyzers` lève
`IntegrityError` avant tout `joblib.load` (testé en remplaçant `joblib.load` par un échec).

### Deux défauts trouvés par le test « un seul octet »

Le test modifie chaque octet du manifeste et de la signature tour à tour. Le manifeste a
tenu dès le début (ses octets sont signés). La signature, non, deux fois.

**1. Base64 malléable.** Premier échec :
une signature Ed25519 de 64 octets s'écrit en 88 caractères base64, dont le dernier
porte **4 bits inutilisés**. En changer un ne change pas les octets décodés, et
`base64.b64decode(validate=True)` l'accepte : le fichier de signature était **malléable**.
Pas de contournement de la signature (le manifeste reste protégé), mais deux fichiers
différents valaient la même signature, ce que le critère interdit. Correctif : la
signature décodée est réencodée et doit redonner exactement le texte reçu.

**2. Champs ignorés.** Une fois le premier corrigé, le test a trouvé un octet dans un
**nom de champ** : `format_version` devenu `gormat_version` passait, car ce champ n'était
pas contrôlé, seulement lu. Correctif : format strict, jeu de champs exact
(`algorithm`, `format_version`, `key_id`, `signature`), valeurs vérifiées, et octets
**canoniques** exigés (espaces, ordre des clés ou échappements différents sont refusés).

Leçon générale : un fichier de sécurité se valide en entier, pas seulement sur les champs
que le code utilise.

## Dans l'API

| Variable | Défaut | Effet |
|---|---|---|
| `PHISHGUARD_API_MODELS_PUBLIC_KEY` | vide | clé publique PEM : manifeste vérifié avant tout chargement, sinon pas de démarrage |
| `PHISHGUARD_API_ALLOW_UNSIGNED_MODELS` | `false` | dérogation explicite pour démarrer en production sans signature |

- **En production, des modèles non signés empêchent le démarrage**, sauf dérogation
  explicite. En développement, l'API démarre et journalise un avertissement.
- `GET /v1/model` publie la publication vérifiée : `signature.release`,
  `signature.key_id`, `signature.manifest_sha256` (`null` si non signés).
- Conteneur : `docker-compose.yml` monte `keys/model-signing.pub` en lecture seule et
  renseigne la variable ; la CI signe ses modèles synthétiques avec une clé éphémère,
  créée et jetée dans le job, pour tester la chaîne complète.

## Clé privée

- **Jamais dans le dépôt** : `keygen` refuse un chemin à l'intérieur ; `keys/` ne contient
  que la clé publique. Jamais sur la CI non plus : la publication se fait depuis la machine
  de l'auteur.
- PKCS#8 PEM, **chiffrée par phrase de passe** (`PHISHGUARD_SIGNING_PASSPHRASE`, meilleur
  chiffrement disponible de `cryptography`). Sans phrase de passe, `keygen` prévient.
- Créée en `600` avec `O_EXCL` : une clé existante n'est **jamais écrasée** (la perdre
  oblige à redistribuer la clé publique à toutes les extensions) ; refusée au chargement
  si d'autres peuvent la lire.
- Sauvegarde hors ligne recommandée (gestionnaire de mots de passe, support chiffré).

**Compromission de la clé** : générer une nouvelle paire, publier la nouvelle clé
publique (nouvelle version de l'extension, nouvelle image), resigner, et considérer
comme suspect tout modèle signé par l'ancienne clé.

## Hors périmètre

- **Retour à une version antérieure** (*rollback*) : un ancien manifeste correctement
  signé reste valide. L'extension (module 6) gardera la dernière `release` acceptée et
  refusera toute version plus ancienne.
- **Transparence** (journal public des publications, type Sigstore) : utile si plusieurs
  personnes publient ; superflu pour un seul auteur.
