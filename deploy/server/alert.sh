#!/usr/bin/env bash
# phishguard-alert : envoie un message d'exploitation sur Telegram (étape 6.4).
#
#   phishguard-alert "texte"
#   systemd : OnFailure=phishguard-alert@%n.service (unité en échec → message)
#
# Configuration : /etc/phishguard/alerts.env (root, 0600), jamais commitée :
#   PHISHGUARD_ALERT_TELEGRAM_TOKEN=123456:ABC…   bot dédié aux alertes (@BotFather)
#   PHISHGUARD_ALERT_TELEGRAM_CHAT_ID=123456789
#
# Le jeton ne passe jamais en argument de commande (visible dans ps) : l'URL est donnée à
# curl par un fichier de configuration lu sur stdin.
set -Eeuo pipefail

readonly CONFIG="${PHISHGUARD_ALERT_CONFIG:-/etc/phishguard/alerts.env}"
readonly TOKEN_RE='^[0-9]{5,16}:[A-Za-z0-9_-]{30,64}$'
readonly CHAT_RE='^-?[0-9]{1,20}$'

value() { # value <NOM> : lu sans exécuter le fichier
  local line
  line="$(grep -E "^$1=" "$CONFIG" | tail -n 1 || true)"
  printf '%s' "${line#*=}"
}

[[ -r "$CONFIG" ]] || { echo "phishguard-alert: $CONFIG illisible" >&2; exit 1; }
token="$(value PHISHGUARD_ALERT_TELEGRAM_TOKEN)"
chat="$(value PHISHGUARD_ALERT_TELEGRAM_CHAT_ID)"
[[ "$token" =~ $TOKEN_RE ]] || { echo "phishguard-alert: jeton Telegram invalide" >&2; exit 1; }
[[ "$chat" =~ $CHAT_RE ]] || { echo "phishguard-alert: chat_id invalide" >&2; exit 1; }

message="[PhishGuard $(hostname -s)] ${*:-alerte sans texte}"
message="${message:0:3500}"  # limite Telegram : 4 096 caractères

printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$token" | curl --config - \
  --silent --show-error --fail --max-time 15 --retry 3 --retry-delay 5 --output /dev/null \
  --data-urlencode "chat_id=$chat" --data-urlencode "text=$message" \
  --data-urlencode "disable_web_page_preview=true"
