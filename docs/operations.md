# Supervision, sauvegardes et garde-fous de coût (étape 6.4)

Ce qui tourne sur le serveur une fois [deployment.md](deployment.md) appliqué, et comment
s'en servir.

| Besoin | Outil | Fréquence | En cas de problème |
|---|---|---|---|
| l'API répond-elle ? | Uptime Kuma (sur le serveur) | 60 s | Telegram |
| le serveur entier répond-il ? | `.github/workflows/uptime.yml` (GitHub) | 30 min | Telegram |
| disque, inodes | `phishguard-disk-check.timer` | 1 h | Telegram (`OnFailure=`) |
| base SQLite | `phishguard-backup.timer` : copie chiffrée hors du serveur | 1 jour | Telegram (`OnFailure=`) |
| journaux | `json-file` 3 × 10 Mo par conteneur, journald ≤ 500 Mo | continu | — |
| abus, coût | limites de débit de l'API, pare-feu Vercel, Threat Intelligence désactivée par défaut | continu | 429, mode dégradé |

## Alertes Telegram

Un **bot dédié aux alertes**, distinct du bot d'analyse (étape 5.11) : la fuite de l'un ne
donne pas l'autre.

1. @BotFather : `/newbot`, notez le jeton. Écrivez un message au bot depuis votre compte.
2. Identifiant de la conversation :
   `curl -s "https://api.telegram.org/bot<jeton>/getUpdates" | grep -o '"chat":{"id":[-0-9]*'`
3. Sur le serveur, `sudo nano /etc/phishguard/alerts.env` (root, 0600) :
   `PHISHGUARD_ALERT_TELEGRAM_TOKEN=…`, `PHISHGUARD_ALERT_TELEGRAM_CHAT_ID=…`
4. Test : `sudo phishguard-alert "test d'alerte"`.

Le jeton ne passe jamais en argument de `curl` (visible dans `ps`) : l'URL est lue sur
l'entrée standard (`curl --config -`).

## Uptime Kuma

Lancé avec la pile (`COMPOSE_PROFILES=monitoring` dans `server.env`), en `1000:1000`, sans
aucune capacité Linux, joignable sur `127.0.0.1:3001` seulement. Depuis votre poste :

```bash
ssh -N -L 3001:127.0.0.1:3001 <vous>@<serveur>     # puis http://127.0.0.1:3001
```

(`sshd` n'autorise ce tunnel qu'à l'administrateur, et vers `127.0.0.1:3001` seulement.)

Au premier accès, créez le compte (mot de passe long, puis *Settings > Security >
2FA*). Ensuite :

1. *Settings > Notifications > Setup Notification* : type **Telegram**, jeton et chat ID du
   bot d'alertes, *Default enabled*, *Apply on all existing monitors*. « Test » doit arriver.
2. *Add New Monitor* :

   | Nom | Type | URL | Intervalle | Essais |
   |---|---|---|---|---|
   | API publique | HTTP(s) – Keyword | `https://api-phishguard.vercel.app/v1/health`, mot-clé `"status":"ok"` | 60 s | 2 |
   | API interne | HTTP(s) – Keyword | `http://api:8000/v1/health`, mot-clé `"status":"ok"` | 60 s | 1 |
   | Certificat de l'origine | HTTP(s) | `https://<origine>.duckdns.org/v1/health`, code accepté **403**, *Certificate Expiry Notification* | 1 h | 1 |

   Le troisième vérifie que l'origine refuse un appel sans secret **et** que son certificat
   se renouvelle (Caddy le fait seul, bien avant l'échéance).

**Terminé quand** (6.4) : arrêter volontairement l'API déclenche l'alerte.

```bash
sudo -u deploy docker stop phishguard-api-1      # Telegram : « API interne » puis « API publique » DOWN
sudo -u deploy phishguard-deploy reload          # retour : messages UP
```

**Sonde externe de secours.** Uptime Kuma partage le sort du serveur. Le workflow
`uptime.yml` vérifie l'adresse publique depuis GitHub toutes les 30 minutes et alerte
par le même bot. Activation : secrets de dépôt `ALERT_TELEGRAM_TOKEN`,
`ALERT_TELEGRAM_CHAT_ID`, variable `UPTIME_WATCHDOG_ENABLED=true`.

## Sauvegardes de la base

La base SQLite (`phishguard-data:/data`) contient les **empreintes** des clés d'API (jamais
les clés) et les retours en quarantaine. Elle est petite ; la perdre oblige à réémettre
les clés.

`phishguard-backup` (chaque jour, 03:15 UTC ± 15 min) :

1. copie à chaud par l'API de sauvegarde de SQLite, dans le conteneur, en mémoire ;
2. `PRAGMA integrity_check` sur la copie ;
3. chiffrement **asymétrique** avec [age](https://age-encryption.org) : le serveur ne
   possède que la clé publique ; même compromis, il ne peut pas relire une sauvegarde ;
4. copie hors du serveur par `rclone` (`--immutable`), vérifiée par `rclone check` ;
5. rotation locale (14 jours).

La base en clair ne touche jamais le disque de l'hôte.

**Mise en place**, une fois :

```bash
# Votre poste : la clé privée reste hors ligne (gestionnaire de mots de passe, clé USB)
age-keygen -o phishguard-backup.key     # affiche « Public key: age1… »
# Serveur
sudo rclone config                      # ex. Backblaze B2 (10 Go gratuits) ou Cloudflare R2,
                                        # clé d'application limitée au seul bucket
sudo nano /etc/phishguard/backup.env    # PHISHGUARD_BACKUP_AGE_RECIPIENT=age1…
                                        # PHISHGUARD_BACKUP_RCLONE_REMOTE=b2:phishguard-backups/sqlite
sudo systemctl enable --now phishguard-backup.timer
sudo systemctl start phishguard-backup.service && journalctl -u phishguard-backup -n 5
```

Côté fournisseur, activez la conservation des versions ou le verrouillage d'objets
(*Object Lock*) s'il est proposé : un attaquant qui obtiendrait la clé rclone ne
pourrait alors pas effacer l'historique.

### Restaurer la base

Testez-le au moins une fois, avant d'en avoir besoin.

```bash
rclone copy b2:phishguard-backups/sqlite/phishguard-<date>.sqlite3.age .
rclone copy b2:phishguard-backups/sqlite/phishguard-<date>.sqlite3.age.sha256 .
sha256sum -c phishguard-<date>.sqlite3.age.sha256
age -d -i phishguard-backup.key phishguard-<date>.sqlite3.age > phishguard.sqlite3
sqlite3 phishguard.sqlite3 'PRAGMA integrity_check'          # ok
# Serveur : API arrêtée, base remplacée dans le volume, API relancée
sudo -u deploy docker stop phishguard-api-1
sudo docker run --rm -v phishguard_phishguard-data:/data -v "$PWD:/restore:ro" \
  --user 10001:10001 --entrypoint cp ghcr.io/arixstoo/phishguard-api@sha256:<empreinte> \
  /restore/phishguard.sqlite3 /data/phishguard.sqlite3
sudo -u deploy phishguard-deploy reload
shred -u phishguard.sqlite3
```

Procédure vérifiée le 18 novembre 2026 (Docker-in-Docker) : sauvegarde, copie distante
illisible sans la clé (aucun en-tête SQLite), empreinte vérifiée sur une autre machine,
déchiffrement, `integrity_check` = ok, clé d'API présente.

## Journaux et disque

- Docker : `json-file`, 3 fichiers de 10 Mo par conteneur (`daemon.json` et
  `compose.prod.yml`), soit 30 Mo au plus par service.
- journald : 500 Mo au plus, un mois.
- `phishguard-disk-check` : alerte au-delà de 85 % de blocs **ou** d'inodes, sur `/` et sur
  la racine de Docker. Seuil : `PHISHGUARD_DISK_THRESHOLD` dans l'unité
  (`systemctl edit phishguard-disk-check.service`).
- Images : `phishguard-deploy` retire les images de l'API qui ne sont plus utilisées, et
  ne garde que les cinq dernières versions installées.

## Garde-fous de coût et mode dégradé

| Garde-fou | Où | Valeur |
|---|---|---|
| limite par IP (anonyme) | API, `PHISHGUARD_API_RATE_LIMIT_ANONYMOUS` | 30/min |
| limite par clé | API, `PHISHGUARD_API_RATE_LIMIT_AUTHENTICATED` | 300/min |
| clés invalides | API, `PHISHGUARD_API_RATE_LIMIT_REJECTED` | 10/min |
| retours | API, `PHISHGUARD_API_RATE_LIMIT_FEEDBACK` | 20/h, quarantaine ≤ 10 000 |
| taille des requêtes | Caddy 2 Mo, API 64 Kio (JSON) et 1 Mio (email) | — |
| connexions simultanées | uvicorn `--limit-concurrency` | 100, puis 503 |
| abus volumétriques | pare-feu et protection DDoS de Vercel, devant l'origine | — |
| Threat Intelligence | désactivée par défaut (`PHISHGUARD_API_THREAT_INTEL_ENABLED=false`) | — |
| quotas des sources | VirusTotal : 4/min et 500/jour comptés localement ; un 429 sans délai annoncé n'est pas réessayé (`enrichers/resilience.py`) | — |

L'IP de chaque visiteur est connue malgré les deux proxys (`X-Real-IP` de Vercel, cru de
Caddy seul) : la limite par IP en est une vraie, pas un compteur commun.

**Mode dégradé.** Une source épuisée, lente ou en panne compte pour zéro dans la fusion et
l'analyse locale (modèle, règles) répond quand même, dans le budget de temps de
l'orchestrateur ; garanti par `tests/test_privacy_and_degradation.py` (étape 2.12). Si
l'API entière est injoignable, l'extension continue son analyse locale (module 5).
