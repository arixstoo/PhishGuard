#!/usr/bin/env bash
# Scan de ports **depuis l'extérieur** de votre propre serveur (étape 6.1, « Terminé quand »).
#
#   bash deploy/server/check-ports.sh <ip-ou-nom> [port-ssh]
#
# À lancer depuis votre poste (pas depuis le serveur : la boucle locale ne passe pas par
# le pare-feu), uniquement sur une machine dont vous êtes responsable. Balaye les 65 535
# ports TCP et échoue si un port autre que SSH, 80 et 443 répond.
set -Eeuo pipefail

target="${1:?usage : check-ports.sh <ip-ou-nom> [port-ssh]}"
ssh_port="${2:-22}"
allowed=" $ssh_port 80 443 "

command -v nmap >/dev/null || { echo "nmap requis (apt install nmap, winget install Insecure.Nmap)" >&2; exit 2; }

# -sT : connexion TCP complète, sans privilège root ; -Pn : pas de ping préalable (ICMP
# peut être filtré) ; --open : seuls les ports ouverts sont listés.
report="$(nmap -Pn -sT -p- --open -T4 --max-retries 2 -oG - "$target")"
open_ports="$(printf '%s\n' "$report" | grep -oE '[0-9]+/open/tcp' | cut -d/ -f1 | sort -n | tr '\n' ' ')"

echo "ports TCP ouverts sur $target : ${open_ports:-aucun}"
status=0
for port in $open_ports; do
  if [[ "$allowed" != *" $port "* ]]; then
    echo "ÉCHEC : port $port ouvert (attendus : $ssh_port, 80, 443)" >&2
    status=1
  fi
done
(( status == 0 )) && echo "conforme : seuls $ssh_port, 80 et 443 sont joignables"
exit "$status"
