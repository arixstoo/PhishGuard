# Mesurer sans pister (étape 6.12)

*Code : `src/phishguard/api/usage.py`, `scripts/adoption_report.py`,
`.github/workflows/adoption.yml`. Tests : `tests/test_api_usage.py`,
`tests/test_adoption_report.py`, `tests/test_privacy_policy.py`.*

Savoir si PhishGuard sert à quelqu'un, et s'il se trompe, sans jamais savoir **qui** s'en
sert. La règle : on ne mesure que des **totaux**, que l'on obtient sans rien ajouter à
l'extension.

## 1. Ce que l'on mesure, et d'où ça vient

| Indicateur | Source | Comment |
|---|---|---|
| installations, utilisateurs actifs hebdomadaires | tableaux de bord du Chrome Web Store et d'AMO | statistiques agrégées que les stores calculent de toute façon ; lues à la main (aucune API) |
| étoiles, forks, observateurs, issues | API GitHub | publiques |
| téléchargements des archives de l'extension | releases GitHub | publics (testeurs de la bêta, installations hors store) |
| visites et clones du dépôt (14 jours) | API de trafic GitHub | agrégées par GitHub ; jeton « Administration : lecture » |
| analyses par l'API, par route et verdict | **totaux d'usage de l'API** (section 2) | aucun identifiant |
| faux positifs et faux négatifs signalés | quarantaine des retours ([feedback.md](feedback.md)) et issues `detection-feedback` | domaine seulement, pseudonyme du jour, 90 jours |

Le **taux de faux positifs signalés** d'une semaine est le nombre de signalements « faux
positif » rapporté au nombre de verdicts « suspect » ou « phishing » rendus par l'API la
même semaine. C'est un plancher : la plupart des gens ne signalent pas une erreur. Sa
**tendance** compte plus que sa valeur.

### Ce que l'on ne mesure pas, volontairement

**Aucune télémétrie dans l'extension.** Pas d'identifiant d'installation, pas de « ping »
quotidien, pas de compteur d'analyses envoyé, même anonyme, même désactivable. Une
télémétrie *opt-in* a été envisagée et écartée pour la v1.0 :

- les stores fournissent déjà les deux chiffres qui comptent (installations, utilisateurs
  actifs) ;
- elle ajouterait une requête réseau par défaut à une extension dont la promesse principale
  est « rien ne quitte votre appareil », et un serveur de collecte à protéger ;
- les signalements volontaires (bouton « Signaler une erreur ») disent ce qu'une
  télémétrie ne dirait pas : *pourquoi* un verdict est faux.

Si une télémétrie devenait nécessaire, elle serait *opt-in*, documentée dans
[PRIVACY.md](../PRIVACY.md) avant d'être livrée, et limitée à des totaux sans identifiant,
comme côté serveur.

## 2. Les totaux d'usage de l'API

Pour chaque jour (UTC), l'API compte ses analyses réussies par **route** (`url`, `text`,
`email`), **verdict** (`safe`, `suspicious`, `phishing`) et **niveau du client**
(`anonymous`, `authenticated`). C'est tout.

- **Aucune colonne ne peut contenir d'identifiant.** La table `usage_daily` n'a que ces
  quatre colonnes et un total ; des contraintes `CHECK` de SQLite ferment chaque colonne à
  sa liste de valeurs. Une URL, un domaine, une clé ou une heure sont refusés par la base
  elle-même (testé), pas seulement par le code qui l'appelle.
- **Aucune écriture par requête.** Les totaux vivent en mémoire et sont ajoutés à la base
  une fois par minute, puis à l'arrêt : la latence d'analyse n'en dépend pas. Un arrêt
  brutal perd au plus une minute de comptage ; une écriture qui échoue remet les totaux en
  mémoire pour le passage suivant.
- **Durée** : 365 jours (`PHISHGUARD_API_USAGE_RETENTION_DAYS`), appliquée au démarrage puis
  toutes les 6 heures.
- **Désactivable** : `PHISHGUARD_API_USAGE_STATS=false`.
- Une entrée refusée (400, 413, 422) ou une requête limitée (429) n'est pas comptée.

```bash
python -m phishguard.api.usage summary              # 8 dernières semaines ISO
python -m phishguard.api.usage summary --weeks 4 --json > usage.json
# en conteneur :
docker compose exec api python -m phishguard.api.usage summary
```

```
semaine     analyses   url  texte  email   inquiétants  FP signalés  FN signalés  taux FP
2026-W46         312   280     30      2            41            1            0     2.4%
2026-W47         405   361     40      4            52            3            1     5.8%
```

*(Chiffres d'exemple. Les signalements n'étant gardés que 90 jours, les semaines plus
anciennes n'en montrent plus.)*

## 3. Le rapport hebdomadaire

Chaque lundi, `.github/workflows/adoption.yml` ouvre une issue **« Tri hebdomadaire
2026-W47 »** (label `weekly-report`) : chiffres GitHub de la semaine précédente, sources
indisponibles, et la liste de tri. On y complète à la main les chiffres des stores et du
serveur, ou on régénère le rapport complet sur sa machine :

```bash
ssh deploy@serveur docker compose exec -T api python -m phishguard.api.usage summary --json > usage.json
python scripts/adoption_report.py --usage usage.json --chrome-users 120 --firefox-users 15
```

Sans le secret `ADOPTION_TOKEN` (jeton GitHub à grain fin, lecture seule, droit
« Administration : lecture » sur ce seul dépôt), les visites et clones sont marqués
indisponibles ; le reste du rapport est produit.

## 4. L'heure de tri

Une heure par semaine, dans cet ordre (la liste est reprise dans chaque issue) :

1. **Faux positifs signalés** : `python -m phishguard.api.feedback summary`, puis les issues
   `detection-feedback`. Chaque domaine est vérifié à la main dans un environnement isolé,
   jamais depuis le poste de travail ; `accept` ou `reject`. Beaucoup de signalements d'une
   seule source : une campagne, pas un consensus ([feedback.md](feedback.md)).
2. **Faux négatifs signalés** : même relecture. Un cas confirmé nourrit l'analyse d'erreurs
   et le prochain jeu d'entraînement, et le modèle suivant repasse par le garde-fou de
   non-régression ([model-updates.md](model-updates.md)) ; jamais de correction directe.
3. **Bogues** : reproduits, étiquetés, priorisés.
4. **Langues et fonctionnalités demandées** : regroupées et rattachées à la
   [feuille de route](roadmap.md).
5. **Avis des stores** : une réponse à chacun.
6. **Chiffres** : mis à jour dans le README et le portfolio quand un palier est franchi
   (100 installations actives, 50 étoiles, 5 retours d'utilisateurs réels : critères du
   cahier des charges).

## 5. Garanties vérifiées

| Garantie | Test |
|---|---|
| la table n'a que `day`, `channel`, `verdict`, `tier`, `count` ; SQLite refuse une URL, une clé, une heure, un total négatif | `tests/test_api_usage.py` |
| comptage d'une analyse réussie seulement, sans écriture pendant le service, écrit à l'arrêt ; rien si désactivé | `tests/test_api_usage.py` |
| une base de schéma 2 est migrée sans perdre les signalements | `tests/test_api_usage.py` |
| rétention de 365 jours, bornée à 730 | `tests/test_api_usage.py`, `tests/test_privacy_policy.py` |
| la politique de confidentialité décrit exactement ces totaux | `tests/test_privacy_policy.py` |
| rapport : semaine ISO complète, sources manquantes signalées sans échec, aucun identifiant | `tests/test_adoption_report.py` |
