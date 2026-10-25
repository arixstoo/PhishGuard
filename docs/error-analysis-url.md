# Analyse d'erreurs du modèle URL (étape 1.8)

Les métriques disent **combien** le modèle se trompe ([`evaluation.md`](evaluation.md)) ; l'analyse d'erreurs dit **comment**. On extrait les 50 pires faux positifs (URLs légitimes avec la note la plus haute) et les 50 pires faux négatifs (phishing avec la note la plus basse) au seuil de décision de l'étape 1.7. On les range ensuite par catégorie et on en tire des pistes d'amélioration.

```bash
make errors-url                                   # = python scripts/analyze_url_errors.py
python scripts/analyze_url_errors.py --split test # lecture du test, une fois le modèle figé
python -m pytest tests/test_url_errors.py
```

| Sortie | Contenu | Versionné |
| :--- | :--- | :--- |
| `data/reports/url_errors_<bloc>.csv` | Les 100 erreurs avec URL complète, score, catégorie et étiquettes, pour la relecture | **Non** : URLs de phishing réelles |
| `docs/metrics/url_errors.json` | Effectifs par catégorie et par source, scores médians, exemples défangés | Oui |
| Blocs générés de ce document | Règles des catégories, résultats | Oui |

| Fichier | Rôle |
| :--- | :--- |
| `src/phishguard/urls/errors.py` | Sélection des pires erreurs, règles de catégorie, synthèse publiable, défangage |
| `src/phishguard/urls/data/hosting.json` | 48 plateformes où n'importe qui peut publier une page (stockage, sites gratuits, formulaires, déploiement) |
| `scripts/analyze_url_errors.py` | Commande unique |

## Méthode

1. **Bloc analysé : la validation.** L'analyse d'erreurs sert à choisir les prochaines améliorations. Si on la menait sur le test, on finirait par régler le modèle sur lui, et le test ne mesurerait plus rien. `--split test` existe pour une relecture finale, une fois le modèle figé.
2. **Seuil** : celui de l'étape 1.7, recalculé sur la validation avec la même règle (meilleur rappel tout en gardant une alerte vraie sur deux à 1 % de prévalence).
3. **Pires erreurs** : faux positifs triés par score décroissant, faux négatifs par score croissant ; les ex aequo sont départagés par la position, pour un résultat stable.
4. **Catégories par règles explicites.** Chaque règle ne lit que l'URL (features de l'étape 1.5 et `hosting.json`), et les règles sont appliquées dans l'ordre du tableau ci-dessous : la première vraie donne la catégorie principale, toutes les vraies sont gardées comme étiquettes dans l'export. Une règle décrit ce que les features voient, pas la vérité du terrain : **la relecture humaine de l'export reste l'étape décisive**, et une catégorie mal remplie est un signal pour corriger la règle.
5. **Publication.** Les URLs de phishing réelles ne sont jamais versionnées. Le rapport ne garde que des exemples **défangés** (`hxxps://exemple[.]com/…`), sans requête (elle peut contenir un identifiant de session ou l'adresse de la victime), avec les adresses email masquées. Ils viennent uniquement des sources dont la licence permet la publication : PhishTank, URLhaus, Tranco, Common Crawl. Les conditions d'OpenPhish interdisent la redistribution ([`data-sources.md`](data-sources.md)).

### Catégories

Les catégories viennent du plan (service légitime avec long paramètre, hébergeur gratuit détourné, domaine neuf mais honnête) et des biais mesurés aux étapes 1.3 à 1.5 (chemin, popularité, TLD). Ce tableau est généré depuis `src/phishguard/urls/errors.py`, la seule source de vérité.

<!-- generated:errors-url-categories:start -->
*Pas encore généré : lancez `make errors-url`.*
<!-- generated:errors-url-categories:end -->

## Résultats

<!-- generated:errors-url:start -->
*Pas encore généré : lancez `make errors-url` après `make train-url`. Ce bloc est réécrit à chaque exécution.*
<!-- generated:errors-url:end -->

## Ce que les features statiques ne verront jamais

Trois familles de faux négatifs n'ont **aucune trace lexicale** : l'URL ressemble à une URL honnête parce qu'elle l'est en partie.

- **Phishing sur une plateforme réputée** (`docs.google.com/forms/…`, `*.web.app`, `*.sharepoint.com`, `ipfs.io`) : le domaine est l'un des plus fiables du web. Le bloquer casserait des millions de pages légitimes.
- **Site honnête compromis** : un vieux domaine propre, avec une page de phishing déposée dans un sous-dossier.
- **Domaine neuf d'apparence honnête** : un nom court et sans mot-clé, enregistré la veille.

C'est la justification du module 2. Le signal qui manque n'est pas dans le texte de l'URL mais dans sa **réputation** (Google Safe Browsing, VirusTotal, urlscan.io), son **âge** (date de création RDAP, certificat récent dans les journaux de Certificate Transparency) et son **contenu** (formulaire de mot de passe sur une page qui n'appartient pas à la marque imitée). Le score lexical reste utile, hors ligne et instantané, mais il ne peut pas être le seul juge.

## Lecture

*À rédiger après la première exécution sur le jeu réel, après relecture de `data/reports/url_errors_validation.csv`*, en vérifiant au moins trois catégories avec des exemples :

- Quelle catégorie domine les faux positifs ? Si ce sont les pages internes profondes ou les longues requêtes, le biais de chemin de l'étape 1.3 n'est pas résolu.
- Les faux négatifs « plateforme réputée » et « site compromis » représentent-ils la majorité ? Le chiffre donne le gain maximal à attendre du module 2.
- Combien d'erreurs tombent dans « Autre » ? Au-delà d'un quart, il manque une catégorie.
- Y a-t-il des **erreurs d'étiquette** (une URL de phishing qui est en fait légitime, ou l'inverse) ? Les flux en contiennent ; les noter dans `docs/data-bias.md`.

## Limites

- 50 erreurs de chaque type, c'est un échantillon des cas extrêmes, pas de l'ensemble des erreurs : les parts par catégorie ne se généralisent pas aux erreurs proches du seuil.
- Les règles reposent sur des seuils fixés à la main (`LONG_QUERY_LENGTH`, `DEEP_PATH_DEPTH`…) ; changer un seuil change la répartition.
- `hosting.json` est une liste courte, écrite à la main : une plateforme absente fait tomber son phishing dans une autre catégorie.
