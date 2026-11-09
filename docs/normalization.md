# Normalisation défensive des entrées

*Étape 3.8 du cahier des charges. Code : `src/phishguard/security/normalize.py`. Tests : `tests/test_security_normalize.py`. Effet mesuré : [robustness-report.md](robustness-report.md#51-normalisation-étape-38).*

Plusieurs techniques d'évasion du [catalogue](evasion-catalog.md) changent les caractères d'un leurre sans changer ce que lit la victime : homoglyphes (TXT-01), caractères de largeur nulle (TXT-02), formes de pleine chasse, homographes d'un nom de domaine (URL-02). La défense ramène l'entrée à ce qu'elle **montre**, avant le modèle, **à l'entraînement comme à l'inférence** : le modèle lit alors ce que lit l'utilisateur.

## Les cinq étapes

| # | Étape | Texte (SMS, email) | URL |
| --- | --- | --- | --- |
| 1 | `unicodedata.normalize("NFKC", s)` : pleine chasse, ligatures et exposants ramenés à leur forme ordinaire (`ｌｏｇｉｎ` → `login`) | oui | oui |
| 2 | suppression des caractères de **format** (catégorie Unicode Cf : U+200B, U+200D, U+2060, U+FEFF, marques de direction) et de **contrôle** (Cc, sauf tabulation et sauts de ligne) | oui | oui |
| 3 | **repli des confusables** vers leur squelette latin (`Vоtre` avec un « о » cyrillique → `Votre`) | oui | **jamais** |
| 4 | **règle explicite** : un hôte qui imite des lettres latines reçoit une alerte forte | | oui |
| 5 | **journalisation** quand l'entrée a été modifiée, avec des comptes seulement | oui | oui |

### Repli des confusables, sans abîmer les autres langues

La table vient de `src/phishguard/urls/idn.py` (sous-ensemble d'Unicode UTS #39 : cyrillique, grec, quelques lettres latines spéciales), étendue aux majuscules. Elle couvre toutes les lettres de la perturbation `homoglyphs` de l'étape 3.6, et un test le vérifie. Le repli est **ciblé**. Un mot est replié :

- s'il mêle le latin et une autre écriture (`cоmpte`) ;
- ou s'il n'est fait que de confusables au milieu d'un texte d'allure latine (`соре` dans une phrase anglaise).

Un texte russe, grec, arabe ou japonais reste intact. Les lettres latines étendues (polonais `łódź`, norvégien `ø`) ne sont jamais touchées. Les tests le vérifient sur chacune de ces langues.

### Pourquoi ne jamais replier un hôte

Replier `аpple.com` donnerait `apple.com` : la défense **innocenterait** l'imitation. Les homographes d'un hôte doivent rester visibles pour les features `host_mixed_script` et `homograph_brand` (étape 1.5) et pour la règle d'alerte. Pour une URL, seules les étapes 1 et 2 s'appliquent, par `normalize_url_text`, appelé par `parse_url` avant toute feature.

### Règle d'alerte des hôtes

`host_script_alert(host)` renvoie :

- `mixed_script_label` : un label mêle des écritures non admises ensemble (profil *Highly Restrictive* d'UTS #39) : `аpple.com` ;
- `lookalike_label` : un label est entièrement dans une autre écriture, mais son squelette est fait de lettres latines, alors que l'hôte contient du latin : `раура.com`, tout cyrillique sauf le TLD ;
- rien pour un hôte entièrement dans une autre écriture (`пример.рф`), pour un label étranger qui n'imite pas le latin (`пример.com`), ou pour les mélanges admis (`東京tokyo.jp`).

Sur les 140 042 URLs du jeu, la règle ne se déclenche sur **aucune** URL légitime de validation ni de test, et sur 5 URLs légitimes d'entraînement sur 78 432. L'analyse d'URL (`UrlAnalysis.host_alert`) porte l'alerte et la journalise. Son branchement dans la fusion du score, avec une raison lisible, est fait à l'étape 3.12, qui intègre la normalisation au pipeline principal.

### Journalisation

`log_normalization` écrit, quand l'entrée a changé, une ligne de la forme :

```
entrée sms normalisée : NFKC non, 54 format, 0 contrôle, 0 confusables
```

Ce sont des comptes, **jamais** le texte ni l'URL : un SMS contient des codes, des noms, des montants. Une entrée modifiée par la normalisation est en soi un indice : un message légitime contient rarement des caractères invisibles ou des homoglyphes. L'indice sera exploité dans la fusion à l'étape 3.12.

## Où la normalisation s'applique

- **Modèle SMS** : `TextNormalizer` est le `preprocessor` des vectoriseurs TF-IDF (`text/models.py`). Le même objet sert à l'entraînement, au score et aux explications (`TfidfVectorizer.build_preprocessor`) : les mots cités à l'utilisateur sont ceux du texte normalisé. Un `preprocessor` remplace le `lowercase` et le `strip_accents` du vectoriseur, et `TextNormalizer` les refait donc après la normalisation. Le modèle `text_v1` a été **réentraîné** avec cette normalisation, et sa version est dans ses métadonnées (`normalization`).
- **Features smishing et catégories de leurre** : `text/smishing.normalize` retirait déjà les caractères de format, et replie maintenant aussi les homoglyphes. « blоqué » compte comme un mot d'urgence.
- **Modèle URL** : `parse_url` normalise le texte brut avant les features, à l'entraînement comme à l'inférence. Sur les 98 031 URLs d'entraînement, une seule est modifiée. Les features de `url_v1` sont donc identiques sur tout le reste de l'entraînement, et le modèle n'a pas été réentraîné.

## Limites

- **Table de confusables courte.** Elle couvre les attaques connues, pas les quelque 6 000 entrées d'UTS #39. Une lettre arménienne ou cherokee qui imite le latin passe. La bibliothèque `confusable_homoglyphs` donnerait la table complète au prix d'une dépendance, et d'une table à porter dans l'extension (module 5).
- **La normalisation ne défait que les évasions de caractères.** Les sous-domaines ajoutés, les chemins bénins, la dilution et le leetspeak ne changent pas les caractères mais la forme. Ils relèvent de l'entraînement adversarial (étape 3.9).
- **Le leetspeak n'est pas replié.** Remplacer les chiffres par des lettres détruirait les montants, les numéros et les codes, qui sont des indices.
