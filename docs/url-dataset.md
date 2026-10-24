# Jeu d'URLs étiquetées (étape 1.2)

`scripts/build_dataset.py` transforme les flux bruts de `data/raw/` (voir [`data-sources.md`](data-sources.md)) en un jeu unique, normalisé et dédoublonné :

```bash
python scripts/build_dataset.py                      # valeurs par défaut
python scripts/build_dataset.py --max-per-domain 10  # autre limite par domaine
```

| Sortie | Contenu | Versionné |
| :--- | :--- | :--- |
| `data/processed/urls.parquet` | Le jeu, une ligne par URL | Non : les conditions d'OpenPhish interdisent de redistribuer le flux |
| `docs/metrics/urls_dataset.json` | Paramètres, fichiers lus (SHA-256), effectifs de chaque étape, statistiques | Oui : aucune URL n'y figure |

La logique est dans `src/phishguard/data/urls.py`, testée par `tests/test_url_dataset.py`.

## Schéma

| Colonne | Type | Description |
| :--- | :--- | :--- |
| `url` | `str` | URL normalisée (voir plus bas), unique dans le jeu |
| `label` | `int8` | `1` = phishing, `0` = légitime |
| `source` | `str` | `phishtank`, `openphish`, `urlhaus`, `tranco` ou `commoncrawl` : la source qui a vu l'URL en premier |
| `first_seen` | `datetime64[UTC]` | Plus ancienne observation connue (voir plus bas) |
| `host` | `str` | Hôte en minuscules, sans port, sans identifiants, sans point final |
| `registered_domain` | `str` | Domaine enregistré (clé de regroupement pour le split de l'étape 1.4) |

Le fichier est trié par `first_seen` puis `url`.

## Règles, dans l'ordre d'application

1. **Inventaire par les manifestes.** Seules les sources au statut `ok` d'un `manifest_*.json` sont lues. Les trois formats de manifeste produits par les versions successives du collecteur sont acceptés. Un fichier référencé mais absent, ou présent sans manifeste, est signalé et ignoré. Un nom de fichier qui sort du dossier (`../`) est refusé.
2. **Intégrité.** Le SHA-256 de chaque fichier est comparé à celui du manifeste ; un écart arrête la construction (`--no-verify` pour passer outre).
3. **URLhaus filtré.** L'export ne contient que des `malware_download`. Seules les URLs étiquetées `phishing` ou `pdf-link-phishing` sont gardées ; les leurres ClickFix ou FakeCaptcha distribuent un malware et restent dehors.
4. **Normalisation** (`normalize_url`) :
   - espaces de bord retirés ; une URL qui contient un espace ou un saut de ligne est rejetée ;
   - `http://` ajouté si le schéma manque ; seuls `http` et `https` sont acceptés ;
   - schéma et hôte en minuscules ; chemin vide remplacé par `/` ;
   - chemin, paramètres, fragment et identifiants (`user@`) conservés tels quels : ce sont des signaux de phishing.
5. **Domaine enregistré** avec `tldextract`, hors ligne (`suffix_list_urls=()`), suffixes privés compris :
   - `victime.github.io` et `autre.github.io` sont deux domaines distincts, comme deux comptes différents ;
   - un hôte qui est lui-même un suffixe privé (`github.io`, `s3.amazonaws.com`) est son propre domaine ;
   - une adresse IP est son propre domaine ;
   - un hôte sans suffixe connu (`localhost`) est écarté.
6. **Conflits d'étiquette.** Une URL vue à la fois comme phishing et comme légitime (par exemple une page d'accueil du top Tranco signalée à PhishTank) est retirée.
7. **Doublons exacts** fusionnés : on garde la plus ancienne observation et sa source. À date égale : PhishTank (validé par des humains), puis OpenPhish, URLhaus, Tranco, Common Crawl.
8. **Pages crawlées des domaines qui hébergent du phishing** retirées : sur `google.com` (Sites, Forms), une page interne peut avoir été déposée par n'importe qui. La page d'accueil Tranco du domaine reste.
9. **Limite par domaine.** Au plus 5 URLs par couple (étiquette, `registered_domain`), tirées au hasard avec une graine fixe (`--seed`, défaut 42). Le tirage aléatoire préserve la répartition dans le temps ; la limite par étiquette évite qu'un domaine qui héberge du phishing (`sites.google.com`) fasse disparaître sa page d'accueil légitime.

## Sens de `first_seen`

| Source | Valeur |
| :--- | :--- |
| PhishTank | `submission_time` (date du signalement) |
| URLhaus | `dateadded` |
| Common Crawl | Date de capture par le robot de Common Crawl |
| OpenPhish, Tranco | Date de la collecte (`collected_at` du manifeste) |

Une date annoncée par la source est bornée par la date de collecte, et la remplace si elle est absente ou illisible.

## Instantané du 24/10/2026

Huit collectes (21 au 24/10), 810 822 observations :

| Étape | URLs |
| :--- | ---: |
| URLhaus écartées (malware) | 240 955 |
| URLs invalides | 49 |
| Suffixe inconnu | 8 |
| URLs en conflit d'étiquette | 7 |
| Doublons fusionnés | 649 375 |
| Retirées par la limite par domaine | 32 718 |
| **Jeu final** | **128 588** |

- 27 733 phishing (`1`) et 100 855 légitimes (`0`) ;
- 123 670 domaines enregistrés distincts, dont 515 présents dans les deux classes ;
- les plus gros domaines limités sont des hébergeurs ou raccourcisseurs : `google.com` (6 114 URLs de phishing avant limite), `qrco.de`, `q-r.to`, `ead.me`, `weebly.com`, `bit.ly`.

Les chiffres à jour sont dans `docs/metrics/urls_dataset.json`.

## Limites connues (à traiter aux étapes 1.3 et 1.4)

Ces limites sont mesurées, chiffres à l'appui, dans [`data-bias.md`](data-bias.md) (étape 1.3).

- **Biais de chemin et de schéma.** Tranco ne fournit que des domaines, matérialisés en `https://<domaine>/` : aucune URL légitime n'a de chemin ni de `http`.
- **Dates non comparables entre classes.** Les dates PhishTank remontent à 2011 alors que les domaines Tranco datent tous de nos collectes. Un split temporel naïf mettrait presque tout le légitime dans le test : il faudra découper par classe, ou sur la date de collecte.
- **Limite par domaine et plateformes.** Avec 5 URLs au plus, le phishing hébergé sur `google.com` (Sites, Forms) ou derrière un raccourcisseur est fortement sous-représenté par rapport à la réalité.
- **Domaines partagés entre classes.** Les 515 domaines présents dans les deux classes devront rester d'un seul côté du split groupé.
- **Reproductibilité.** La liste des suffixes vient de l'instantané embarqué dans `tldextract` : sa version figure dans le rapport, la changer peut modifier `registered_domain`.
