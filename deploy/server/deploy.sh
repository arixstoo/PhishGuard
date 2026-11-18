#!/usr/bin/env bash
# phishguard-deploy : déploiement et retour arrière sur le serveur (étape 6.3).
#
# Installé dans /usr/local/bin/phishguard-deploy par bootstrap.sh. C'est la **seule**
# commande que la clé SSH de GitHub Actions peut lancer : authorized_keys de l'utilisateur
# « deploy » la force (command="…",restrict). La commande demandée par le client arrive
# dans SSH_ORIGINAL_COMMAND et n'est jamais évaluée par un shell : elle est découpée,
# puis chaque mot est validé par une expression régulière stricte.
#
#   deploy <version> <image@sha256:…>   archive tar (compose.prod.yml, Caddyfile) sur stdin
#   rollback [<version>]                version précédente, ou celle indiquée
#   reload                              relit server.env (rotation du secret), même version
#   status                              version courante et versions disponibles
#
# À la main sur le serveur (même validation) :
#   sudo -u deploy phishguard-deploy rollback
#
# Disposition :
#   /opt/phishguard/shared/            server.env, api.env, models/, keys/ (jamais touchés ici)
#   /opt/phishguard/releases/<v>/      compose.prod.yml, Caddyfile, release.env
#   /opt/phishguard/current -> releases/<v>
#
# Un déploiement dont la vérification échoue revient seul à la version précédente.
set -Eeuo pipefail
umask 027

readonly ROOT="${PHISHGUARD_ROOT:-/opt/phishguard}"
readonly SHARED="$ROOT/shared"
readonly RELEASES="$ROOT/releases"
readonly CURRENT="$ROOT/current"
readonly KEEP_RELEASES="${PHISHGUARD_KEEP_RELEASES:-5}"
# Seul dépôt d'images accepté : une clé de déploiement volée ne peut pas faire tourner une
# image arbitraire, seulement une image publiée par le workflow de ce dépôt.
readonly IMAGE_REPOSITORY="${PHISHGUARD_IMAGE_REPOSITORY:-ghcr.io/arixstoo/phishguard-api}"
readonly VERSION_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$'
readonly DIGEST_RE='^sha256:[0-9a-f]{64}$'
readonly SECRET_RE='^[0-9a-f]{64}$'
readonly HOST_RE='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
readonly RELEASE_FILES=(compose.prod.yml Caddyfile)
readonly MAX_ARCHIVE_BYTES=$((1024 * 1024))

log() { printf '%s phishguard-deploy: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "ERREUR : $*"; exit 1; }

# Valeur d'une variable de server.env, sans jamais l'exécuter (pas de « source »).
env_value() { # env_value <fichier> <NOM>
  local line
  line="$(grep -E "^$2=" "$1" | tail -n 1 || true)"
  line="${line#*=}"
  line="${line%\"}"; line="${line#\"}"
  line="${line%\'}"; line="${line#\'}"
  printf '%s' "$line"
}

compose() { # compose <dossier de version> <arguments docker compose…>
  local dir="$1"; shift
  local profiles=()
  if [[ "$(env_value "$SHARED/server.env" COMPOSE_PROFILES)" == *monitoring* ]]; then
    profiles=(--profile monitoring)
  fi
  docker compose --project-name phishguard --project-directory "$dir" \
    --env-file "$SHARED/server.env" --env-file "$dir/release.env" \
    -f "$dir/compose.prod.yml" "${profiles[@]}" "$@"
}

preflight() {
  [[ -f "$SHARED/server.env" ]] || die "$SHARED/server.env absent (docs/deployment.md)"
  [[ -f "$SHARED/keys/model-signing.pub" ]] || die "clé publique des modèles absente"
  [[ -f "$SHARED/models/manifest.json.sig" ]] || die "modèles signés absents de $SHARED/models"
  local secret host
  secret="$(env_value "$SHARED/server.env" PHISHGUARD_ORIGIN_SECRET)"
  host="$(env_value "$SHARED/server.env" PHISHGUARD_ORIGIN_HOST)"
  [[ "$secret" =~ $SECRET_RE ]] || die "PHISHGUARD_ORIGIN_SECRET : 64 caractères hexadécimaux attendus"
  [[ "$host" =~ $HOST_RE ]] || die "PHISHGUARD_ORIGIN_HOST invalide"
}

current_version() {
  if [[ -L "$CURRENT" ]]; then
    basename "$(readlink -f "$CURRENT")"
  fi
}

# Versions installées, de la plus ancienne à la plus récente (ordre de déploiement).
installed_versions() {
  local dir
  for dir in "$RELEASES"/*/; do
    [[ -f "$dir/release.env" ]] && printf '%s %s\n' "$(stat -c %Y "$dir/release.env")" "$(basename "$dir")"
  done | sort -n | awk '{ print $2 }'
}

# Vérification de bout en bout sur la machine : TLS de Caddy, secret, API.
verify() { # verify <dossier de version>
  local dir="$1" host secret expected running
  host="$(env_value "$SHARED/server.env" PHISHGUARD_ORIGIN_HOST)"
  secret="$(env_value "$SHARED/server.env" PHISHGUARD_ORIGIN_SECRET)"
  expected="$(env_value "$dir/release.env" PHISHGUARD_IMAGE)"
  running="$(docker inspect --format '{{.Config.Image}}' "$(compose "$dir" ps --quiet api)")"
  [[ "$running" == "$expected" ]] || { log "image en cours $running ≠ $expected"; return 1; }
  local attempt
  for attempt in 1 2 3 4 5 6; do
    # Le secret passe par un fichier de configuration de curl lu sur stdin : jamais dans
    # la liste des processus (ps).
    if printf 'header = "X-PhishGuard-Origin-Auth: %s"\n' "$secret" | curl --config - \
      --silent --show-error --fail --max-time 5 --resolve "$host:443:127.0.0.1" \
      "https://$host/v1/health" | grep -q '"status":"ok"'; then
      # Sans le secret, l'origine doit refuser.
      local code
      code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
        --resolve "$host:443:127.0.0.1" "https://$host/v1/health" || true)"
      [[ "$code" == 403 ]] || { log "origine ouverte sans secret (HTTP $code)"; return 1; }
      return 0
    fi
    log "santé : tentative $attempt échouée (certificat en cours d'émission ?)"
    sleep 10
  done
  return 1
}

# Appelée dans des conditions (« if activate … ») où bash ignore set -e : chaque étape
# vérifie explicitement son code de retour.
activate() { # activate <version>
  local version="$1" dir="$RELEASES/$1"
  compose "$dir" pull --quiet || return 1
  compose "$dir" up --detach --wait --wait-timeout 180 --remove-orphans || return 1
  # Bascule atomique du lien « current » (rename).
  ln -sfn "$dir" "$CURRENT.tmp" && mv -Tf "$CURRENT.tmp" "$CURRENT" || return 1
  log "version active : $version"
}

prune() {
  local versions=() keep current
  mapfile -t versions < <(installed_versions)
  current="$(current_version)"
  keep=$(( ${#versions[@]} - KEEP_RELEASES ))
  local i
  for (( i = 0; i < keep; i++ )); do
    [[ "${versions[$i]}" == "$current" ]] && continue
    rm -rf -- "${RELEASES:?}/${versions[$i]}"
    log "version retirée : ${versions[$i]}"
  done
  docker image prune --force --filter "label=org.opencontainers.image.title=phishguard-api" >/dev/null || true
}

cmd_deploy() { # cmd_deploy <version> <image@digest>
  local version="$1" reference="$2"
  [[ "$version" =~ $VERSION_RE ]] || die "version invalide"
  [[ "$reference" == *@sha256:* ]] || die "image attendue par empreinte (…@sha256:…), jamais par étiquette"
  local repository="${reference%@*}" digest="${reference#*@}"
  [[ "$repository" == "$IMAGE_REPOSITORY" ]] || die "dépôt d'image refusé : $repository"
  [[ "$digest" =~ $DIGEST_RE ]] || die "empreinte d'image invalide"
  preflight

  local previous staging
  previous="$(current_version)"
  staging="$(mktemp -d "$RELEASES/.staging.XXXXXX")"
  trap 'rm -rf -- "$staging"' EXIT

  # Archive bornée en taille ; seuls les membres attendus sont extraits, sans propriétaire
  # ni droits d'origine (tar refuse déjà les chemins absolus et « .. »).
  head -c "$MAX_ARCHIVE_BYTES" > "$staging/release.tar"
  tar --extract --file "$staging/release.tar" --directory "$staging" \
    --no-same-owner --no-same-permissions --no-overwrite-dir -- "${RELEASE_FILES[@]}" \
    || die "archive invalide (attendu : ${RELEASE_FILES[*]})"
  rm -f -- "$staging/release.tar"
  local file
  for file in "${RELEASE_FILES[@]}"; do
    [[ -f "$staging/$file" && ! -L "$staging/$file" ]] || die "$file absent de l'archive"
  done
  printf 'PHISHGUARD_RELEASE=%s\nPHISHGUARD_IMAGE=%s@%s\n' "$version" "$repository" "$digest" \
    > "$staging/release.env"
  # Lisibles par le conteneur Caddy (root sans CAP_DAC_OVERRIDE) ; aucun secret ici, ils
  # restent dans shared/server.env (0600).
  chmod 0750 "$staging"
  chmod 0644 "$staging"/*
  compose "$staging" config --quiet || die "compose.prod.yml invalide"

  rm -rf -- "${RELEASES:?}/$version"
  mv -T "$staging" "$RELEASES/$version"
  trap - EXIT

  log "déploiement de $version ($digest)"
  if activate "$version" && verify "$RELEASES/$version"; then
    prune
    log "déploiement réussi : $version"
    return 0
  fi
  log "vérification échouée"
  if [[ -n "$previous" && "$previous" != "$version" && -d "$RELEASES/$previous" ]]; then
    log "retour automatique à $previous"
    if activate "$previous" && verify "$RELEASES/$previous"; then
      # La version en échec n'est plus proposée à un « rollback » ultérieur.
      rm -rf -- "${RELEASES:?}/$version"
      touch "$RELEASES/$previous/release.env"
    else
      log "retour arrière en échec : intervention requise"
    fi
  fi
  exit 1
}

cmd_rollback() { # cmd_rollback [version]
  local target="${1:-}" current versions=()
  current="$(current_version)"
  if [[ -z "$target" ]]; then
    mapfile -t versions < <(installed_versions)
    local i
    for (( i = ${#versions[@]} - 1; i >= 0; i-- )); do
      if [[ "${versions[$i]}" == "$current" ]] && (( i > 0 )); then
        target="${versions[$((i - 1))]}"
        break
      fi
    done
    [[ -n "$target" ]] || die "aucune version précédente disponible"
  fi
  [[ "$target" =~ $VERSION_RE ]] || die "version invalide"
  [[ -f "$RELEASES/$target/release.env" ]] || die "version absente du serveur : $target"
  preflight
  log "retour arrière : ${current:-aucune} → $target"
  activate "$target"
  # La version rétablie devient la plus récente : un second « rollback » ne revient pas
  # sur celle qu'on vient de quitter.
  touch "$RELEASES/$target/release.env"
  verify "$RELEASES/$target" || die "version $target active mais vérification échouée"
  log "retour arrière réussi : $target"
}

cmd_reload() {
  local current
  current="$(current_version)"
  [[ -n "$current" ]] || die "aucune version active"
  preflight
  log "rechargement de $current (server.env relu)"
  activate "$current" || die "rechargement en échec"
  verify "$RELEASES/$current" || die "rechargement de $current : vérification échouée"
  log "rechargement réussi : $current"
}

cmd_status() {
  local current
  current="$(current_version)"
  printf 'courante : %s\n' "${current:-aucune}"
  printf 'disponibles :\n'
  installed_versions | sed 's/^/  /'
  if [[ -n "$current" ]]; then
    compose "$RELEASES/$current" ps --format 'table {{.Service}}\t{{.Status}}\t{{.Image}}'
  fi
}

main() {
  local request="${SSH_ORIGINAL_COMMAND:-$*}"
  # Découpage sans évaluation : ni globbing, ni substitution, ni redirection.
  local words=()
  read -r -a words <<< "$request"
  (( ${#words[@]} >= 1 && ${#words[@]} <= 3 )) || die "usage : deploy <v> <image@sha256> | rollback [<v>] | reload | status"
  [[ -d "$RELEASES" ]] || die "$RELEASES absent (bootstrap.sh non exécuté ?)"

  exec 9>"$ROOT/.deploy.lock"
  flock --nonblock 9 || die "un autre déploiement est en cours"

  case "${words[0]}" in
    deploy)   (( ${#words[@]} == 3 )) || die "usage : deploy <version> <image@sha256:…>"
              cmd_deploy "${words[1]}" "${words[2]}" ;;
    rollback) (( ${#words[@]} <= 2 )) || die "usage : rollback [<version>]"
              cmd_rollback "${words[1]:-}" ;;
    reload)   (( ${#words[@]} == 1 )) || die "usage : reload"
              cmd_reload ;;
    status)   (( ${#words[@]} == 1 )) || die "usage : status"
              cmd_status ;;
    *)        die "commande refusée : ${words[0]}" ;;
  esac
}

main "$@"
