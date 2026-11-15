#!/usr/bin/env bash
# Test de démarrage de l'image (étape 4.9) : l'API répond, et sa configuration de
# production est bien celle de l'image.
#
#   bash scripts/docker_smoke.sh http://127.0.0.1:8000
#
# Fonctionne avec les vrais modèles comme avec ceux de scripts/smoke_models.py : seuls la
# forme des réponses et les en-têtes sont vérifiés, jamais un verdict.
set -euo pipefail

BASE="${1:-http://127.0.0.1:8000}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "ÉCHEC : $*" >&2; exit 1; }

status() { # status <fichier d'en-têtes>
  awk 'NR == 1 { print $2 }' "$1"
}

header() { # header <fichier d'en-têtes> <nom>
  tr -d '\r' < "$1" | awk -v name="$(echo "$2" | tr 'A-Z' 'a-z')" -F': ' \
    'tolower($1) == name { print $2 }'
}

# 1. Santé
curl -sS -D "$TMP/h" -o "$TMP/b" "$BASE/v1/health"
[ "$(status "$TMP/h")" = 200 ] || fail "GET /v1/health : $(status "$TMP/h")"
grep -q '"status":"ok"' "$TMP/b" || fail "GET /v1/health : corps inattendu"

# 2. En-têtes de sécurité de production (HSTS : PHISHGUARD_API_ENVIRONMENT=production)
[ "$(header "$TMP/h" x-content-type-options)" = nosniff ] || fail "nosniff absent"
[ "$(header "$TMP/h" cache-control)" = no-store ] || fail "no-store absent"
[ -n "$(header "$TMP/h" strict-transport-security)" ] || fail "HSTS absent (pas en production ?)"
[ -z "$(header "$TMP/h" server)" ] || fail "en-tête Server présent"

# 3. Documentation fermée en production
curl -sS -o /dev/null -D "$TMP/h" "$BASE/docs"
[ "$(status "$TMP/h")" = 404 ] || fail "/docs ouvert en production"

# 4. Analyse d'une URL : contrat de réponse
curl -sS -D "$TMP/h" -o "$TMP/b" -H 'Content-Type: application/json' \
  -d '{"url": "http://secure-login-verify.example/account"}' "$BASE/v1/analyze/url"
[ "$(status "$TMP/h")" = 200 ] || fail "POST /v1/analyze/url : $(status "$TMP/h")"
for field in '"verdict"' '"score"' '"schema_version"'; do
  grep -q "$field" "$TMP/b" || fail "réponse d'analyse sans $field"
done

# 5. Retour : la base SQLite du volume /data est inscriptible malgré read_only
curl -sS -D "$TMP/h" -o "$TMP/b" -H 'Content-Type: application/json' \
  -d '{"domain": "example.com", "verdict": "phishing", "judgement": "false_positive"}' \
  "$BASE/v1/feedback"
[ "$(status "$TMP/h")" = 202 ] || fail "POST /v1/feedback : $(status "$TMP/h")"

echo "image : santé, en-têtes, documentation fermée, analyse et base SQLite vérifiés"
