# Test de charge (étape 4.13)

Cible du cahier des charges : 50 requêtes par seconde pendant une minute sur l'analyse
d'URL **sans enrichissement**, latence médiane **sous 50 ms**.

**Résultat : atteint.** Médiane de 10,8 à 14,6 ms sur cinq passages, 15 004 requêtes,
aucune erreur. La queue de distribution (p95, p99) dépend fortement de la charge de
l'hôte ; elle est détaillée plus bas, avec la cause d'une partie et la correction
appliquée.

```bash
make loadtest          # bash scripts/loadtest/run.sh 50 60s
bash scripts/loadtest/run.sh 100 30s
```

## Méthode

| Élément | Choix | Raison |
|---|---|---|
| outil | **k6** 1.4.2, en conteneur, image épinglée par empreinte | scénarios en JavaScript, seuils intégrés, rien à installer |
| scénario | `constant-arrival-rate`, 50/s, 60 s (`scripts/loadtest/analyze_url.js`) | débit imposé : un test « N utilisateurs en boucle » ralentirait avec le serveur et masquerait la saturation (omission coordonnée) |
| cible | l'image de production (`docker-compose.yml`) | ce qui sera déployé : lecture seule, 2 CPU, 1 Go, 1 processus, modèles signés vérifiés au démarrage |
| modèles | les vrais `url_v2` et `text_v2`, signés | pas de modèle jouet : 300 arbres, valeurs SHAP calculées à chaque requête |
| réseau | k6 sur le réseau Docker du compose (`http://api:8000`) | pas de traversée du NAT de Docker Desktop |
| limite de débit | **active**, quota d'une clé relevé (`compose.loadtest.yml`) | le limiteur compte chaque requête : son coût fait partie de la mesure |
| clé d'API | créée pour le test, révoquée à la fin, jamais écrite sur disque | |
| URLs | 10 hôtes × 5 chemins × 2 schémas, domaines réservés | pas de cache possible, rien de réel |
| échauffement | 10 s à 10 req/s, hors mesure | premiers appels (pool de threads, caches) |
| seuils k6 | médiane < 50 ms, 0 % d'échec, 100 % de statuts 200 | le test échoue (code non nul) si l'objectif n'est pas tenu |

Machine : poste Windows 11, Docker Desktop 29.1 (WSL2), 20 CPU logiques, 16 Go ; le
conteneur est limité à 2 CPU. **Une dizaine d'autres conteneurs tournaient** (laboratoire
sans lien, dont un indexeur Wazuh, une JVM à la charge irrégulière) : c'est un poste de
développement, pas un banc isolé, d'où la dispersion de la queue.

## Résultats

Après correction (`OMP_NUM_THREADS=1`, voir plus bas), 13 novembre 2026 :

| Passage | Débit | Requêtes | Échecs | Médiane | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|---|
| 1 | 50/s | 3 001 | 0 | 14,6 ms | 245,2 ms | 394,4 ms | 555,8 ms | 645,9 ms |
| 2 | 50/s | 3 001 | 0 | 13,1 ms | 25,6 ms | 40,8 ms | 216,2 ms | 305,5 ms |
| 3 | 50/s | 3 000 | 0 | **10,8 ms** | 13,9 ms | 16,0 ms | 23,4 ms | 36,0 ms |
| 4 | 50/s | 3 000 | 0 | 10,9 ms | 14,1 ms | 16,3 ms | 23,4 ms | 44,9 ms |
| 5 | 50/s | 3 001 | 0 | 12,0 ms | 17,1 ms | 24,7 ms | 73,2 ms | 236,2 ms |
| **médiane des 5** | | | | **12,0 ms** | 17,1 ms | **24,7 ms** | 73,2 ms | 305,5 ms |
| exploratoire | 100/s, 30 s | 3 001 | 0 | 18,3 ms | 274,9 ms | 347,9 ms | 410,9 ms | 468,4 ms |

Lecture :

- **la médiane est stable** (10,8 à 14,6 ms) et loin sous la cible : l'objectif tient ;
- **la queue ne l'est pas** : p95 de 16 à 394 ms à configuration identique. Sur une
  machine calme (passages 3 et 4), p99 sous 25 ms ; quand l'hôte est chargé, des
  requêtes attendent un processeur ;
- à **100/s**, la médiane reste à 18 ms mais la queue dépasse 250 ms dès le p90 : un
  processus unique approche de sa saturation (environ 15 ms de calcul par requête, donc
  au mieux 60 à 70 requêtes par seconde sur un cœur, le GIL sérialisant le Python).

## Diagnostic de la queue

**1. Pas d'URL lente.** En séquentiel (une requête à la fois, depuis le conteneur), chaque
famille d'URL prend 14 à 19 ms en médiane : la queue n'est pas due à un type d'entrée.

**2. Sursouscription OpenMP : corrigée.** Premier passage, image d'origine : médiane
16,0 ms, mais p90 162,5 ms et p95 262,9 ms. LightGBM appelle OpenMP à chaque prédiction,
même d'une seule ligne : chaque requête lançait une équipe de threads, en concurrence
avec les autres requêtes du pool sur 2 CPU. Avec `OMP_NUM_THREADS=1`, au même moment :
p90 53,9 ms, p95 117,4 ms, médiane inchangée (16,3 ms). La variable est désormais fixée
dans le `Dockerfile`. Le parallélisme utile vient des requêtes concurrentes, pas de
l'intérieur d'une prédiction d'une ligne.

**3. Coût d'une analyse, profilé** (`cProfile`, 100 analyses, environ 17 ms chacune) :

| Poste | Part | Remarque |
|---|---|---|
| valeurs SHAP (`pred_contrib`) | ~11 ms | deux appels au booster |
| score du modèle | ~4 ms | un troisième appel au booster |
| extraction des features | ~4 ms | **faite deux fois** : pour le modèle, puis pour les constats ATT&CK |
| construction de `DataFrame` pandas | une part des deux précédents | pour une seule ligne |

Pistes, par gain attendu, **non appliquées ici** (elles touchent le pipeline du module 3
et ses tests d'explication ; la cible est déjà tenue) :

1. **une seule extraction des features** par requête, partagée entre modèle et constats ;
2. **score brut tiré des valeurs SHAP** (leur somme est le score brut) : un appel au
   booster au lieu de trois ;
3. tableau NumPy plutôt que `DataFrame` pour une ligne ;
4. explication SHAP seulement quand la réponse l'utilise.

Ensemble, elles devraient diviser le coût par deux ou trois, donc doubler la capacité
d'un processus.

## Passer à l'échelle

- **Plusieurs processus** (`python -m phishguard.api --workers N`) : un processus par
  cœur contourne le GIL. Les compteurs de débit doivent alors être partagés
  (`PHISHGUARD_API_RATE_LIMIT_STORAGE_URI=redis://…`), sinon chaque processus accorde le
  quota entier ; et chaque processus charge ses modèles (le conteneur occupe 187 Mio après
  chargement et premières requêtes : la limite de 1 Go du compose tient 3 à 4 processus).
- **Plusieurs conteneurs** derrière un répartiteur : même règle pour les compteurs.
- L'enrichissement par la Threat Intelligence (non mesuré ici, par construction du test)
  ajoute la latence des sources externes, bornée par le budget de l'orchestrateur
  (étape 2.9) ; il est asynchrone et n'occupe pas le processeur pendant l'attente.
