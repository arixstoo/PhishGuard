#!/usr/bin/env bash
# Préparation et durcissement du serveur (étape 6.1, docs/deployment.md).
#
# Ubuntu 24.04 LTS ou Debian 12/13, amd64 ou arm64 (Oracle Cloud Ampere A1 compris).
# À lancer **une fois**, en root, depuis une copie du dossier deploy/ sur le serveur :
#
#   scp -r deploy ubuntu@<ip>:/tmp/phishguard-deploy
#   ssh ubuntu@<ip>
#   sudo bash /tmp/phishguard-deploy/server/bootstrap.sh \
#     --admin-user rostom \
#     --admin-key "ssh-ed25519 AAAA… poste-perso" \
#     --deploy-key "ssh-ed25519 AAAA… github-actions-deploy"
#
# Idempotent : relancé, il remet la configuration attendue sans rien dupliquer.
#
# Ce que le script fait :
#  1. mises à jour, paquets de base, mises à jour de sécurité automatiques ;
#  2. utilisateur d'administration (sudo, clé SSH) et utilisateur « deploy » dont la clé
#     ne peut lancer que phishguard-deploy (command=…,restrict) ;
#  3. SSH : clé seulement, pas de root, pas de mot de passe, algorithmes modernes ;
#  4. pare-feu ufw : 22 (limité), 80 et 443 seulement ; fail2ban sur SSH ;
#  5. Docker Engine et le plugin Compose depuis le dépôt officiel (clé GPG vérifiée) ;
#  6. noyau (sysctl), journald borné, arborescence /opt/phishguard, scripts et minuteries.
#
# Garde-fou : l'authentification par mot de passe n'est coupée qu'après installation de
# la clé de l'administrateur. Gardez la session ouverte et testez une **nouvelle**
# connexion avant de la fermer.
set -Eeuo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE
readonly ROOT=/opt/phishguard
readonly DOCKER_GPG_FINGERPRINT=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
readonly USER_RE='^[a-z_][a-z0-9_-]{0,30}$'
readonly KEY_RE='^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/=]+( [^"]*)?$'

ADMIN_USER=""
ADMIN_KEY=""
DEPLOY_KEY=""
SSH_PORT=22
REPLACE_IPTABLES=false

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERREUR : %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<'EOF'
Options :
  --admin-user NOM        utilisateur d'administration (sudo)
  --admin-key  "CLÉ"      sa clé publique SSH (ed25519 recommandée)
  --deploy-key "CLÉ"      clé publique dédiée de GitHub Actions (facultative au premier passage)
  --ssh-port   PORT       port SSH (défaut 22)
  --replace-oracle-iptables
                          Oracle Cloud : retire les règles iptables de l'image (REJECT par
                          défaut) au profit d'ufw ; ouvrir aussi 80/443 dans la VCN
EOF
}

while (( $# )); do
  case "$1" in
    --admin-user) ADMIN_USER="${2:-}"; shift 2 ;;
    --admin-key) ADMIN_KEY="${2:-}"; shift 2 ;;
    --deploy-key) DEPLOY_KEY="${2:-}"; shift 2 ;;
    --ssh-port) SSH_PORT="${2:-}"; shift 2 ;;
    --replace-oracle-iptables) REPLACE_IPTABLES=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "option inconnue : $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "à lancer en root (sudo)"
[[ "$ADMIN_USER" =~ $USER_RE && "$ADMIN_USER" != deploy && "$ADMIN_USER" != root ]] \
  || die "--admin-user invalide"
[[ "$ADMIN_KEY" =~ $KEY_RE ]] || die "--admin-key : clé publique OpenSSH attendue"
[[ -z "$DEPLOY_KEY" || "$DEPLOY_KEY" =~ $KEY_RE ]] || die "--deploy-key : clé publique OpenSSH attendue"
if ! [[ "$SSH_PORT" =~ ^[0-9]{2,5}$ ]] || (( SSH_PORT > 65535 )); then
  die "--ssh-port invalide"
fi
# shellcheck source=/dev/null
. /etc/os-release
[[ "$ID" == ubuntu || "$ID" == debian ]] || die "distribution non prise en charge : $ID"

export DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------------------------------- #
log "1. Mises à jour et paquets"
# --------------------------------------------------------------------------- #
apt-get update -q
apt-get -yq -o Dpkg::Options::=--force-confold upgrade
apt-get -yq install --no-install-recommends \
  ca-certificates curl gnupg ufw fail2ban python3-systemd unattended-upgrades \
  apt-listchanges needrestart age rclone

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat > /etc/apt/apt.conf.d/52phishguard-unattended <<'EOF'
// Étape 6.1 : correctifs de sécurité appliqués chaque jour, redémarrage si le noyau
// l'exige, la nuit. Les conteneurs repartent seuls (restart: unless-stopped).
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
EOF
systemctl enable --now unattended-upgrades.service

# --------------------------------------------------------------------------- #
log "2. Utilisateurs"
# --------------------------------------------------------------------------- #
install_key() { # install_key <utilisateur> <ligne authorized_keys>
  local home
  home="$(getent passwd "$1" | cut -d: -f6)"
  install -d -m 0700 -o "$1" -g "$1" "$home/.ssh"
  printf '%s\n' "$2" > "$home/.ssh/authorized_keys"
  chown "$1:$1" "$home/.ssh/authorized_keys"
  chmod 0600 "$home/.ssh/authorized_keys"
}

if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --groups sudo "$ADMIN_USER"
  # Pas de mot de passe de connexion (SSH par clé) ; sudo en demande un : à définir.
  passwd --lock "$ADMIN_USER" >/dev/null
  echo "    $ADMIN_USER créé : définissez son mot de passe sudo avec « passwd $ADMIN_USER »"
fi
usermod --append --groups sudo "$ADMIN_USER"
install_key "$ADMIN_USER" "$ADMIN_KEY"

if ! id deploy >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /home/deploy --shell /bin/bash deploy
fi
passwd --lock deploy >/dev/null
if [[ -n "$DEPLOY_KEY" ]]; then
  # restrict : ni terminal, ni redirection de ports, d'agent ou de X11 ; command= : la seule
  # commande exécutable, quelle que soit celle demandée par le client.
  install_key deploy "command=\"/usr/local/bin/phishguard-deploy\",restrict $DEPLOY_KEY"
fi
passwd --lock root >/dev/null

# --------------------------------------------------------------------------- #
log "3. SSH"
# --------------------------------------------------------------------------- #
# Premier fichier lu de sshd_config.d : la première valeur l'emporte, y compris sur
# 50-cloud-init.conf (PasswordAuthentication yes de certaines images).
cat > /etc/ssh/sshd_config.d/00-phishguard.conf <<EOF
# Étape 6.1 (deploy/server/bootstrap.sh) : ne pas modifier à la main.
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers $ADMIN_USER deploy
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PermitUserEnvironment no
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256

# Tunnel vers Uptime Kuma (127.0.0.1:3001) pour l'administrateur seulement.
Match User $ADMIN_USER
    AllowTcpForwarding local
    PermitOpen 127.0.0.1:3001
EOF
chmod 0644 /etc/ssh/sshd_config.d/00-phishguard.conf
sshd -t || die "configuration SSH invalide : rien n'a été rechargé"
# Ubuntu 24.04 : sshd activé par socket ; le port se change sur le socket aussi.
if systemctl is-enabled ssh.socket >/dev/null 2>&1 && [[ "$SSH_PORT" != 22 ]]; then
  install -d /etc/systemd/system/ssh.socket.d
  printf '[Socket]\nListenStream=\nListenStream=%s\n' "$SSH_PORT" \
    > /etc/systemd/system/ssh.socket.d/phishguard.conf
  systemctl daemon-reload
  systemctl restart ssh.socket
fi
systemctl try-reload-or-restart ssh.service

# --------------------------------------------------------------------------- #
log "4. Pare-feu et fail2ban"
# --------------------------------------------------------------------------- #
if [[ "$REPLACE_IPTABLES" == true && -f /etc/iptables/rules.v4 ]]; then
  # Images Oracle Cloud : chaîne INPUT terminée par REJECT, chargée par
  # netfilter-persistent, qui masquerait les règles d'ufw.
  systemctl disable --now netfilter-persistent 2>/dev/null || true
  mv /etc/iptables/rules.v4 /etc/iptables/rules.v4.oracle-default
  [[ -f /etc/iptables/rules.v6 ]] && mv /etc/iptables/rules.v6 /etc/iptables/rules.v6.oracle-default
  iptables -P INPUT ACCEPT && iptables -F INPUT
fi
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
# limit : plus de 6 connexions en 30 s depuis une même adresse sont refusées.
ufw limit "$SSH_PORT/tcp" comment 'SSH'
ufw allow 80/tcp comment 'HTTP (ACME, redirection)'
ufw allow 443/tcp comment 'HTTPS (Vercel vers Caddy)'
ufw logging low
ufw --force enable

cat > /etc/fail2ban/jail.d/phishguard.local <<EOF
# Étape 6.1 : bannissement progressif des tentatives SSH répétées.
[DEFAULT]
backend = systemd
banaction = ufw
bantime = 1h
bantime.increment = true
bantime.maxtime = 1w
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = $SSH_PORT
EOF
systemctl enable fail2ban
systemctl restart fail2ban

# --------------------------------------------------------------------------- #
log "5. Docker Engine et Compose (dépôt officiel)"
# --------------------------------------------------------------------------- #
install -d -m 0755 /etc/apt/keyrings
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "https://download.docker.com/linux/$ID/gpg" -o /tmp/docker.asc
fingerprint="$(gpg --batch --with-colons --show-keys /tmp/docker.asc | awk -F: '/^fpr/ { print $10; exit }')"
[[ "$fingerprint" == "$DOCKER_GPG_FINGERPRINT" ]] || die "clé GPG de Docker inattendue : $fingerprint"
install -m 0644 /tmp/docker.asc /etc/apt/keyrings/docker.asc
rm -f /tmp/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/$ID
Suites: $VERSION_CODENAME
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get update -q
apt-get -yq install --no-install-recommends \
  docker-ce docker-ce-cli containerd.io docker-compose-plugin

install -d -m 0755 /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true,
  "no-new-privileges": true,
  "userland-proxy": false,
  "icc": false
}
EOF
systemctl enable docker
systemctl restart docker
# Le groupe docker équivaut à root sur l'hôte : seul « deploy » en fait partie, et sa clé
# ne peut lancer que phishguard-deploy.
usermod --append --groups docker deploy

# --------------------------------------------------------------------------- #
log "6. Noyau, journal, arborescence, scripts"
# --------------------------------------------------------------------------- #
cat > /etc/sysctl.d/90-phishguard.conf <<'EOF'
# Étape 6.1. ip_forward reste actif : Docker en a besoin.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF
sysctl --quiet --system

install -d -m 0755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/phishguard.conf <<'EOF'
[Journal]
SystemMaxUse=500M
MaxRetentionSec=1month
EOF
systemctl restart systemd-journald

install -d -m 0755 -o root -g root "$ROOT"
install -d -m 0750 -o deploy -g deploy "$ROOT/releases" "$ROOT/shared"
install -d -m 0755 -o deploy -g deploy "$ROOT/shared/models" "$ROOT/shared/keys"
touch "$ROOT/.deploy.lock" && chown deploy:deploy "$ROOT/.deploy.lock"
if [[ ! -f "$ROOT/shared/server.env" ]]; then
  install -m 0600 -o deploy -g deploy "$HERE/server.env.example" "$ROOT/shared/server.env"
fi
install -d -m 0700 /etc/phishguard /var/backups/phishguard
for name in alerts backup; do
  [[ -f "/etc/phishguard/$name.env" ]] || install -m 0600 "$HERE/$name.env.example" "/etc/phishguard/$name.env"
done

install -m 0755 "$HERE/deploy.sh" /usr/local/bin/phishguard-deploy
install -m 0755 "$HERE/alert.sh" /usr/local/bin/phishguard-alert
install -m 0700 "$HERE/backup.sh" /usr/local/bin/phishguard-backup
install -m 0755 "$HERE/disk-check.sh" /usr/local/bin/phishguard-disk-check
install -m 0644 "$HERE"/systemd/phishguard-* /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now phishguard-disk-check.timer
# Activée une fois backup.env rempli (docs/operations.md) : sans destinataire age ni
# destination rclone, chaque passage échouerait.
if grep -qE '^PHISHGUARD_BACKUP_AGE_RECIPIENT=age1' /etc/phishguard/backup.env; then
  systemctl enable --now phishguard-backup.timer
fi

log "Terminé"
cat <<EOF
Avant de fermer cette session, dans un autre terminal :
  ssh -p $SSH_PORT $ADMIN_USER@<serveur>      (doit réussir)
  ssh -p $SSH_PORT root@<serveur>             (doit échouer)
Puis, depuis votre poste : bash deploy/server/check-ports.sh <serveur>
Suite : docs/deployment.md, « Premier déploiement ».
EOF
