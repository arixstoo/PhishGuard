# Pipeline de sécurité de la CI (étape 4.8)

Trois workflows GitHub Actions, tous bloquants sur une pull request :

| Workflow | Jobs | Déclenchement |
|---|---|---|
| `ci.yaml` | `test` (ruff, pytest, couverture ≥ 90 %), `fuzz` (1 000 exemples par propriété) | push, pull request |
| `security.yml` | `bandit`, `pip-audit`, `gitleaks` | push, pull request, **chaque lundi**, à la main |
| `fetch-feeds.yml` | collecte quotidienne des flux (module 1) | planifié |

L'exécution hebdomadaire de `security.yml` compte : une vulnérabilité publiée aujourd'hui
touche des dépendances qui n'ont pas changé depuis le dernier commit.

```bash
make audit   # les trois contrôles en local : pip-audit, bandit, gitleaks
make sync    # environnement exact de uv.lock (ce que la CI installe)
make lock    # après une modification des dépendances de pyproject.toml
```

## Contrôles

| Outil | Ce qu'il cherche | Portée |
|---|---|---|
| `bandit -r src` | défauts de sécurité du code Python (`assert` de contrôle, aléa faible, `pickle`, `subprocess`, SQL construit…) | `src/`, tous niveaux de gravité |
| `pip-audit` | dépendances aux vulnérabilités connues (base PyPA et OSV) | tout `uv.lock`, extras compris (`dev`, `explain`, `embeddings`), avec empreintes |
| `gitleaks git` | secrets commités (clés d'API, jetons) | **tout l'historique**, pas seulement le dernier commit : un secret retiré reste dans les anciens |

`gitleaks` tourne aussi avant chaque commit (`pre-commit`), à la même version (8.30.1).

### Base `bandit` propre

Le premier passage a relevé 16 alertes, toutes traitées :

- 7 × `B101` (`assert`) : des invariants vérifiés par `assert`, que `python -O` retire.
  Remplacés par des contrôles explicites (`raise TypeError` / `RuntimeError`), dans les
  gestionnaires d'erreurs de l'API, le limiteur de débit, l'extracteur de features et
  les nouvelles tentatives des enrichisseurs ;
- 9 × `B311` (`random`) : des générateurs **non cryptographiques voulus** (graines
  déterministes des perturbations adversariales et de l'échantillonnage, gigue des
  nouvelles tentatives). Annotés `# nosec B311`, la raison en commentaire sur la ligne
  précédente. L'annotation est par ligne : un nouvel usage de `random` sera signalé.

Les secrets (clés d'API) sont tirés par `secrets`, jamais par `random`.

## Chaîne d'approvisionnement

- **Fichier de verrouillage** : `uv.lock` (uv 0.12), versions exactes et empreintes
  SHA-256 de chaque distribution, pour Python 3.11 et plus et pour toutes les
  plateformes. La CI installe par `uv sync --locked`, qui **échoue si le verrou ne
  correspond plus à `pyproject.toml`** : une dépendance ajoutée sans `make lock` ne passe
  pas. uv est préféré à `pip-compile` parce que Dependabot met `uv.lock` à jour nativement.
- **Actions épinglées par SHA de commit**, version lisible en commentaire
  (`actions/checkout@11d5960… # v4.4.0`) : une étiquette (`@v4`) peut être déplacée vers
  un autre code, un SHA non. Les versions majeures n'ont pas changé en les épinglant.
- **gitleaks** : binaire officiel, vérifié par son empreinte SHA-256 publiée
  (`sha256sum --check --strict`), plutôt qu'une action tierce.
- **Moindre privilège** : `permissions: contents: read` sur chaque workflow,
  `persist-credentials: false` au checkout (le jeton n'est pas laissé dans `.git/config`
  pour les étapes suivantes).

## Dependabot

`.github/dependabot.yml`, chaque lundi :

- `uv` : `uv.lock`. Correctifs et versions mineures regroupés dans une seule PR, chaque
  version majeure dans la sienne ;
- `github-actions` : SHA et commentaire de version mis à jour ensemble.

Les alertes de sécurité Dependabot (*Settings → Code security*) s'ajoutent à ces mises à
jour planifiées et doivent être activées dans les réglages du dépôt.

**npm** (extension, module 5) et **docker** (étape 4.9) s'ajouteront avec leur premier
manifeste : un écosystème déclaré sans manifeste fait échouer chaque passage de
Dependabot.

## Vérification : la CI échoue sur une dépendance vulnérable

Critère de fin de l'étape, vérifié en local avec les commandes du job `pip-audit`, puis
annulé : `jinja2==3.1.2` ajouté à `pyproject.toml`, verrou régénéré, audit.

```console
$ uv lock
$ uv export --locked --all-extras --no-emit-project --no-header --format requirements-txt -o req.txt
$ pip-audit --disable-pip --require-hashes --progress-spinner off -r req.txt
Found 10 known vulnerabilities in 1 package
Name   Version ID              Fix Versions
------ ------- --------------- ------------
jinja2 3.1.2   PYSEC-2026-1473 3.1.3
jinja2 3.1.2   PYSEC-2026-1474 3.1.4
jinja2 3.1.2   PYSEC-2026-1475 3.1.5
jinja2 3.1.2   PYSEC-2026-1472 3.1.5
jinja2 3.1.2   PYSEC-2026-1471 3.1.6
(les cinq mêmes lignes une seconde fois)
$ echo $?
1
```

Sans cette dépendance : `No known vulnerabilities found`, code 0. Le verrou a été
restauré à l'identique (`uv lock --check`).

## `trivy`

Le cahier des charges cite `trivy image` pour l'image Docker : il arrive avec l'image, à
l'étape 4.9. D'ici là, il n'y a pas d'image à analyser, et les dépendances Python sont
déjà couvertes par `pip-audit`. Comme les autres outils, il sera épinglé (version et
empreinte de l'image), jamais référencé par une étiquette mobile.
