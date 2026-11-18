#!/usr/bin/env bash
# phishguard-backup : sauvegarde quotidienne chiffrée de la base SQLite (étape 6.4).
#
# Lancé par phishguard-backup.timer (root). Étapes :
# 1. copie cohérente de la base, à chaud, par l'API de sauvegarde de SQLite, dans le
#    conteneur de l'API (la base est en WAL : une copie de fichier pourrait être déchirée) ;
# 2. PRAGMA integrity_check sur la copie, en mémoire ;
# 3. chiffrement **asymétrique** avec age : le serveur ne détient que la clé publique
#    (destinataire). Une compromission du serveur ne permet pas de lire les sauvegardes ;
# 4. copie hors du serveur avec rclone (Backblaze B2, Cloudflare R2, S3, SFTP…) ;
# 5. rotation locale.
#
# La base en clair ne touche jamais le disque de l'hôte : elle transite de la mémoire du
# conteneur à age par un tube.
#
# Configuration : /etc/phishguard/backup.env (root, 0600) :
#   PHISHGUARD_BACKUP_AGE_RECIPIENT=age1…        clé publique ; la clé privée reste hors ligne
#   PHISHGUARD_BACKUP_RCLONE_REMOTE=b2:phishguard-backups/sqlite
#   PHISHGUARD_BACKUP_KEEP_DAYS=14               rotation locale (défaut 14)
# rclone : /root/.config/rclone/rclone.conf (rclone config), clé d'application limitée à
# ce seul bucket, en écriture seule si le fournisseur le permet.
#
# Restauration : docs/operations.md (« Restaurer la base »).
set -Eeuo pipefail
umask 077

readonly CONFIG="${PHISHGUARD_BACKUP_CONFIG:-/etc/phishguard/backup.env}"
readonly ROOT="${PHISHGUARD_ROOT:-/opt/phishguard}"
readonly LOCAL_DIR="${PHISHGUARD_BACKUP_DIR:-/var/backups/phishguard}"
readonly RECIPIENT_RE='^age1[0-9a-z]{58}$'

value() {
  local line
  line="$(grep -E "^$1=" "$CONFIG" | tail -n 1 || true)"
  printf '%s' "${line#*=}"
}

[[ -r "$CONFIG" ]] || { echo "phishguard-backup: $CONFIG illisible" >&2; exit 1; }
recipient="$(value PHISHGUARD_BACKUP_AGE_RECIPIENT)"
remote="$(value PHISHGUARD_BACKUP_RCLONE_REMOTE)"
keep_days="$(value PHISHGUARD_BACKUP_KEEP_DAYS)"
keep_days="${keep_days:-14}"
[[ "$recipient" =~ $RECIPIENT_RE ]] || { echo "phishguard-backup: destinataire age invalide" >&2; exit 1; }
[[ "$keep_days" =~ ^[0-9]{1,3}$ ]] || { echo "phishguard-backup: PHISHGUARD_BACKUP_KEEP_DAYS invalide" >&2; exit 1; }
[[ -n "$remote" ]] || { echo "phishguard-backup: PHISHGUARD_BACKUP_RCLONE_REMOTE vide (copie hors serveur obligatoire)" >&2; exit 1; }

[[ -L "$ROOT/current" ]] || { echo "phishguard-backup: aucune version déployée" >&2; exit 1; }
release="$(readlink -f "$ROOT/current")"
api="$(docker compose --project-name phishguard --project-directory "$release" \
  --env-file "$ROOT/shared/server.env" --env-file "$release/release.env" \
  -f "$release/compose.prod.yml" ps --quiet api)"
[[ -n "$api" ]] || { echo "phishguard-backup: conteneur de l'API introuvable" >&2; exit 1; }

install -d -m 0700 "$LOCAL_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
target="$LOCAL_DIR/phishguard-$stamp.sqlite3.age"
trap 'rm -f -- "$target.part"' EXIT

# Copie à chaud dans le conteneur (Python standard, aucun outil ajouté à l'image).
# serialize() : la base entière en mémoire, écrite sur stdout, jamais sur un disque.
docker exec -i "$api" python - <<'PY' | age --encrypt --recipient "$recipient" --output "$target.part"
import os, sqlite3, sys

path = os.environ.get("PHISHGUARD_API_DATABASE_PATH", "/data/phishguard.sqlite3")
source = sqlite3.connect(path, timeout=10)
copy = sqlite3.connect(":memory:")
with copy:
    source.backup(copy)
source.close()
status = copy.execute("PRAGMA integrity_check").fetchone()[0]
if status != "ok":
    sys.exit(f"integrity_check : {status}")
sys.stdout.buffer.write(copy.serialize())
PY
mv -f "$target.part" "$target"
# Nom seul (pas le chemin du serveur) : vérifiable là où la copie est restaurée.
(cd "$LOCAL_DIR" && sha256sum -- "$(basename "$target")") > "$target.sha256"

rclone copy --quiet --immutable --checksum "$target" "$remote/"
rclone copy --quiet --immutable --checksum "$target.sha256" "$remote/"
rclone check --quiet --one-way "$LOCAL_DIR" "$remote/" --include "phishguard-$stamp.*"

find "$LOCAL_DIR" -maxdepth 1 -type f -name 'phishguard-*.sqlite3.age*' -mtime "+$keep_days" -delete
echo "phishguard-backup: $(basename "$target") ($(stat -c %s "$target") octets) copié vers $remote"
