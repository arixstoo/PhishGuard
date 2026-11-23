#!/usr/bin/env bash
# phishguard-disk-check : alerte quand un système de fichiers se remplit (étape 6.4).
#
# Lancé toutes les heures par phishguard-disk-check.timer. Échoue (et déclenche
# l'alerte Telegram par OnFailure=) au-delà du seuil, sur / et sur la racine de Docker.
#   PHISHGUARD_DISK_THRESHOLD=85   pourcentage d'occupation (blocs ou inodes)
set -Eeuo pipefail

readonly THRESHOLD="${PHISHGUARD_DISK_THRESHOLD:-85}"
docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)"

status=0
for mount in / "$docker_root"; do
  [[ -e "$mount" ]] || continue
  read -r blocks inodes < <(df --output=pcent,ipcent "$mount" | awk 'NR == 2 { gsub("%", ""); print $1, $2 }')
  echo "phishguard-disk-check: $mount blocs ${blocks}% inodes ${inodes}%"
  if (( blocks >= THRESHOLD || inodes >= THRESHOLD )); then
    echo "phishguard-disk-check: $mount au-delà de ${THRESHOLD}% (blocs ${blocks}%, inodes ${inodes}%)" >&2
    status=1
  fi
done
exit "$status"
