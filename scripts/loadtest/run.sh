#!/usr/bin/env bash
# Test de charge de l'analyse d'URL (étape 4.13) : API en conteneur, k6 en conteneur sur le
# même réseau Docker, 50 requêtes par seconde pendant 60 s par défaut.
#
#   bash scripts/loadtest/run.sh [RATE] [DURATION]      # ou : make loadtest
#
# Écrit le résumé complet de k6 dans build/loadtest/summary.json. Code de sortie de k6 :
# non nul si un seuil est dépassé (médiane ≥ 50 ms, une erreur, un statut autre que 200).
set -euo pipefail

RATE="${1:-50}"
DURATION="${2:-60s}"
# k6 épinglé par version et par empreinte, comme trivy.
K6_IMAGE="grafana/k6:1.4.2@sha256:3656673de3f30424e8ebcfa46acd9558d83b6a43612d0f668ffeac953950c6c7"
COMPOSE=(docker compose -f docker-compose.yml -f scripts/loadtest/compose.loadtest.yml)
OUT="$PWD/build/loadtest"
mkdir -p "$OUT"

"${COMPOSE[@]}" up --detach --wait --wait-timeout 180
trap '"${COMPOSE[@]}" down' EXIT

# Clé dédiée, créée pour ce test et révoquée à la fin : jamais écrite sur le disque.
created="$("${COMPOSE[@]}" exec -T api python -m phishguard.api.keys create --name loadtest)"
key_id="$(echo "$created" | awk 'NR == 1 { print $2 }')"
api_key="$(echo "$created" | tail -n 1)"
revoke() { "${COMPOSE[@]}" exec -T api python -m phishguard.api.keys revoke "$key_id" >/dev/null; }
trap 'revoke; "${COMPOSE[@]}" down' EXIT

# Échauffement : premières requêtes (caches de l'extracteur, pool de threads) hors mesure.
network="$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' \
  "$("${COMPOSE[@]}" ps --quiet api)")"
docker run --rm --network "$network" -e BASE_URL=http://api:8000 -e API_KEY="$api_key" \
  -e RATE=10 -e DURATION=10s -v "$PWD/scripts/loadtest:/scripts:ro" "$K6_IMAGE" \
  run --quiet --no-thresholds /scripts/analyze_url.js >/dev/null

docker run --rm --network "$network" -e BASE_URL=http://api:8000 -e API_KEY="$api_key" \
  -e RATE="$RATE" -e DURATION="$DURATION" -e SUMMARY_PATH=/out/summary.json \
  -v "$PWD/scripts/loadtest:/scripts:ro" -v "$OUT:/out" "$K6_IMAGE" \
  run --quiet /scripts/analyze_url.js
