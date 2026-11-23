#!/usr/bin/env bash
# Vérification de bout en bout depuis Internet (étapes 6.2 et 6.3) :
# visiteur → Vercel (TLS) → Caddy (TLS, secret) → API.
#
#   bash scripts/edge_smoke.sh https://api-phishguard.vercel.app
#
# Ne vérifie que la forme des réponses et les en-têtes, jamais un verdict.
set -euo pipefail

BASE="${1:-https://api-phishguard.vercel.app}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "ÉCHEC : $*" >&2; exit 1; }
status() { awk 'NR == 1 { print $2 }' "$1"; }
header() {
  tr -d '\r' < "$1" | awk -v name="$(echo "$2" | tr '[:upper:]' '[:lower:]')" -F': ' \
    'tolower($1) == name { print $2 }'
}

# 1. Santé, avec quelques essais (propagation du déploiement Vercel, certificat de l'origine).
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sS --proto '=https' --tlsv1.2 --max-time 10 -D "$TMP/h" -o "$TMP/b" "$BASE/v1/health" \
    && [ "$(status "$TMP/h")" = 200 ] && grep -q '"status":"ok"' "$TMP/b"; then
    break
  fi
  [ "$attempt" = 10 ] && fail "GET /v1/health : $(status "$TMP/h" 2>/dev/null || echo 'sans réponse')"
  sleep 15
done

# 2. En-têtes de l'API de production, relayés par Vercel.
[ "$(header "$TMP/h" cache-control)" = no-store ] || fail "Cache-Control: no-store absent"
[ "$(header "$TMP/h" x-content-type-options)" = nosniff ] || fail "nosniff absent"
[ -n "$(header "$TMP/h" strict-transport-security)" ] || fail "HSTS absent"
[ -z "$(header "$TMP/h" x-phishguard-origin-auth)" ] || fail "secret de l'origine renvoyé au client"

# 3. Le visiteur ne peut pas imposer son propre secret ni son adresse IP : la requête passe
#    quand même (Vercel remplace l'en-tête), sans erreur.
code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  -H 'X-PhishGuard-Origin-Auth: 0000' -H 'X-Forwarded-For: 203.0.113.7' "$BASE/v1/health")"
[ "$code" = 200 ] || fail "en-têtes forgés : HTTP $code"

# 4. Documentation fermée en production.
code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$BASE/docs")"
[ "$code" = 404 ] || fail "/docs ouvert (HTTP $code)"

# 5. Analyse d'une URL (palier anonyme) : contrat de réponse.
curl -sS --max-time 15 -D "$TMP/h" -o "$TMP/b" -H 'Content-Type: application/json' \
  -d '{"url": "http://secure-login-verify.example/account"}' "$BASE/v1/analyze/url"
[ "$(status "$TMP/h")" = 200 ] || fail "POST /v1/analyze/url : $(status "$TMP/h")"
for field in '"verdict"' '"score"' '"schema_version"'; do
  grep -q "$field" "$TMP/b" || fail "réponse d'analyse sans $field"
done
[ -n "$(header "$TMP/h" x-ratelimit-limit)" ] || fail "limite de débit absente"

# 6. Modèles signés servis.
curl -sS --max-time 10 -o "$TMP/b" "$BASE/v1/model"
grep -q '"key_id"' "$TMP/b" || fail "GET /v1/model : modèles non signés"

echo "public : santé, en-têtes, en-têtes forgés, documentation fermée, analyse et signature vérifiés ($BASE)"
