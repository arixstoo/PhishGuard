# Déploiement en production (étapes 6.1 à 6.3)

L'API publique répond sur **`https://api-phishguard.vercel.app`**, un nom gratuit fourni
par Vercel. Elle tourne sur un serveur à soi (VPS), derrière deux proxys TLS.

```
                 TLS (Vercel)                     TLS (Let's Encrypt)
 visiteur ───────────────────▶ Vercel ─────────────────────────────▶ Caddy ──────▶ API
 extension, bot, page web      api-phishguard.vercel.app    + X-PhishGuard-     api:8000
                               pare-feu, DDoS, HTTP/3         Origin-Auth        (aucun port
                                                            <origine>.duckdns.org  publié)
```

| Élément | Où | Rôle |
|---|---|---|
| `scripts/render_edge_config.py` | Vercel, projet `phishguard-api` | relaie tout vers l'origine, ajoute l'en-tête secret |
| `deploy/Caddyfile` | serveur, conteneur `caddy` | certificat de l'origine, refuse (403) toute requête sans le secret |
| `deploy/compose.prod.yml` | serveur | Caddy, API, Uptime Kuma ; durcissement à l'exécution |
| `deploy/server/bootstrap.sh` | serveur, une fois | durcissement de la machine (6.1) |
| `deploy/server/deploy.sh` | serveur, `phishguard-deploy` | déploiement par empreinte, vérification, retour arrière (6.3) |
| `.github/workflows/deploy.yml` | GitHub Actions | sur un tag `v*` : image, trivy, ghcr.io, provenance, serveur, Vercel |
| `scripts/edge_smoke.sh` | partout | vérification publique de bout en bout |

Exploitation au quotidien (supervision, sauvegardes, alertes) : [operations.md](operations.md).

## Pourquoi cette architecture

- **L'API reste un conteneur avec un état** (base SQLite des empreintes de clés et des
  retours, compteurs de limite de débit en mémoire, modèles signés chargés une fois). Une
  fonction Vercel n'a ni disque persistant ni processus durable : elle perdrait les clés
  et les retours, et chaque instance compterait ses propres limites. Le serveur garde
  l'état ; Vercel ne fait que relayer.
- **Deux noms gratuits.** `api-phishguard.vercel.app` (public, le seul communiqué) et un
  sous-domaine DuckDNS pour l'origine. DuckDNS figure sur la
  [Public Suffix List](https://publicsuffix.org/list/) : les limites de Let's Encrypt
  s'appliquent à votre sous-domaine seul, pas à tous les utilisateurs du service, comme ce
  serait le cas avec `sslip.io` ou `nip.io` (absents de la liste, vérifié le 18 novembre 2026).
  Un sous-domaine `vercel.app` ne peut pas pointer vers une machine extérieure : d'où le
  relais plutôt qu'un simple enregistrement DNS.
- **Vercel devant l'origine** tient le rôle du « Cloudflare gratuit » de l'étape 6.4 :
  pare-feu, absorption des abus, adresse du serveur jamais publiée.
- **L'origine ne sert que Vercel.** Sans l'en-tête secret, Caddy répond 403 : contourner
  Vercel pour viser l'adresse IP du serveur ne mène nulle part.

## Modèle de menace du déploiement

| Menace | Parade | Vérifiée par |
|---|---|---|
| contournement de Vercel vers l'IP du serveur | secret de 256 bits exigé par Caddy, 403 sinon | `deploy.sh` (verify), test d'intégration |
| visiteur qui forge le secret ou son IP | Vercel **remplace** `X-PhishGuard-Origin-Auth` (`op: set`) et `X-Real-IP` | `scripts/edge_smoke.sh` |
| une limite de débit commune à tous (IP de Caddy) | `X-Real-IP` devient `X-Forwarded-For`, cru de Caddy seul (`/32`) | test : 31ᵉ requête de A → 429, B → 200 |
| fuite du secret dans un journal | aucun journal d'accès Caddy, en-tête retiré avant l'API | `tests/test_deployment.py` |
| clé SSH de la CI volée | `command="phishguard-deploy",restrict` : ni shell, ni tunnel ; images de `ghcr.io/arixstoo/phishguard-api` seulement, par empreinte | `tests/test_deployment.py` (10 commandes refusées) |
| image remplacée sur le registre | déploiement par empreinte `sha256`, attestation de provenance SLSA | `deploy.yml` |
| injection dans le workflow | aucune expression `${{ }}` dans un script, entrées validées | `tests/test_deployment.py` |
| serveur compromis → sauvegardes lues | chiffrement asymétrique `age` : le serveur n'a que la clé publique | [operations.md](operations.md) |
| connexion SSH par mot de passe, root | désactivées ; fail2ban ; ufw | `check-ports.sh`, `sshd -T` |

## 1. Choisir le serveur (6.1)

Comparatif fait le 18 novembre 2026 ; les offres changent, revérifiez avant de choisir.

| Offre | Prix | Ressources | Remarque |
|---|---|---|---|
| **Oracle Cloud Always Free** (recommandé) | 0 € | jusqu'à 4 cœurs Ampere A1 (arm64), 24 Go | carte bancaire demandée à l'inscription ; l'image est publiée en arm64 |
| Hetzner CX22 / CAX11 | ~4 €/mois | 2 vCPU, 4 Go | le plus simple, facturé |
| Google Cloud e2-micro | 0 € | 2 vCPU partagés, 1 Go | juste pour l'API (1 Go de `mem_limit`) |

Fly.io et Render n'offrent pas de machine où appliquer `ufw`, `fail2ban` et SSH (étape
6.1) : écartés.

**Oracle Cloud** : *Compute > Instances > Create*, image **Ubuntu 24.04**, forme
`VM.Standard.A1.Flex` (1 OCPU, 6 Go suffisent), votre clé publique SSH. Puis *Networking >
Virtual Cloud Networks > (VCN) > Security Lists* : ajoutez des règles d'entrée TCP 80 et
443 depuis `0.0.0.0/0` (22 y est déjà). Notez l'adresse IP publique.

## 2. Nom gratuit de l'origine (DuckDNS)

1. <https://www.duckdns.org>, connexion par votre compte GitHub.
2. Créez un sous-domaine, par exemple `phishguard-origin` → `phishguard-origin.duckdns.org`,
   et mettez l'adresse IP du serveur dans *current ip*.
3. Vérifiez : `nslookup phishguard-origin.duckdns.org` renvoie l'IP du serveur.

Le jeton DuckDNS n'est utile que pour une IP dynamique : une IP fixe de VPS n'en a pas besoin,
il ne va donc pas sur le serveur.

## 3. Durcir le serveur (6.1)

Sur votre poste, une clé dédiée au déploiement (sans phrase de passe : la CI l'utilise
seule, et elle ne peut lancer que `phishguard-deploy`) :

```bash
ssh-keygen -t ed25519 -f ~/.ssh/phishguard_deploy -C github-actions-deploy -N ''
scp -r deploy ubuntu@<ip>:/tmp/phishguard-deploy
ssh ubuntu@<ip>
sudo bash /tmp/phishguard-deploy/server/bootstrap.sh \
  --admin-user <vous> \
  --admin-key "<contenu de ~/.ssh/id_ed25519.pub>" \
  --deploy-key "<contenu de ~/.ssh/phishguard_deploy.pub>" \
  --replace-oracle-iptables
sudo passwd <vous>
```

Les clés publiques se collent telles quelles : la commande tourne sur le serveur, où vos
fichiers `~/.ssh` n'existent pas. `--replace-oracle-iptables` : Oracle Cloud seulement.
`passwd` fixe le mot de passe de `sudo` ; il ne sert jamais pour SSH.

**Gardez la session ouverte** et vérifiez dans un autre terminal :

```bash
ssh <vous>@<ip>              # doit réussir
ssh root@<ip>                # doit échouer
ssh -o PubkeyAuthentication=no <vous>@<ip>   # doit échouer : « Permission denied (publickey) »
ssh -i ~/.ssh/phishguard_deploy deploy@<ip> id   # « commande refusée : id »
```

**Terminé quand** (6.1), depuis votre poste, sur votre propre serveur :

```bash
bash deploy/server/check-ports.sh <ip>
# ports TCP ouverts sur <ip> : 22 80 443
# conforme : seuls 22, 80 et 443 sont joignables
```

Docker contourne `ufw` pour les ports qu'il publie : c'est pourquoi `compose.prod.yml` ne
publie que 80 et 443 (Caddy), Uptime Kuma sur `127.0.0.1` seulement, et pourquoi le
contrôle se fait de l'extérieur avec `nmap`, jamais en se fiant à `ufw status`.

## 4. Fichiers du serveur

```bash
# Depuis votre poste : modèles signés et clé publique (étape 4.12)
scp -r models/* <vous>@<ip>:/tmp/models/ && scp keys/model-signing.pub <vous>@<ip>:/tmp/
# Sur le serveur
sudo install -o deploy -g deploy -m 0644 /tmp/models/* /opt/phishguard/shared/models/
sudo install -o deploy -g deploy -m 0644 /tmp/model-signing.pub /opt/phishguard/shared/keys/
sudo -u deploy nano /opt/phishguard/shared/server.env   # voir deploy/server/server.env.example
```

`server.env` : `PHISHGUARD_ORIGIN_HOST` (le nom DuckDNS), `PHISHGUARD_ORIGIN_SECRET` (le
même que celui du projet Vercel, voir §5), `PHISHGUARD_ACME_EMAIL`. Le fichier `.env.deploy`
à la racine de votre copie du dépôt (ignoré par git, créé lors de la mise en place) contient
le secret déjà enregistré dans Vercel.

## 5. Projet Vercel (6.2)

**Fait le 18 novembre 2026.** Projet `phishguard-api` (équipe
`saidirostom26-gmailcoms-projects`, `prj_f2WLwgqGAU7ZkQJZKQPjESA2kQxS`), nom public
**`api-phishguard.vercel.app`** rattaché au projet (il suit chaque déploiement de
production). `phishguard-api.vercel.app` appartient à un autre compte : Vercel avait
attribué `phishguard-api-nu.vercel.app`, toujours actif mais jamais communiqué. En attendant
le serveur, le proxy est en mode maintenance : 503 JSON, `no-store`, HSTS préchargé.

Commandes utilisées (pour refaire la mise en place ailleurs) :

```bash
npx vercel@65.11.0 login
npx vercel@65.11.0 project add phishguard-api
python scripts/render_edge_config.py maintenance
cd deploy/edge/dist && npx vercel@65.11.0 link --yes --project phishguard-api
rm -f .env.local .gitignore      # créés par « link » : ne pas les publier
# secret lu dans .env.deploy (racine du dépôt, ignoré par git), jamais affiché
grep ^PHISHGUARD_ORIGIN_SECRET= ../../../.env.deploy | cut -d= -f2 | tr -d '\r\n' \
  | npx vercel@65.11.0 env add PHISHGUARD_ORIGIN_SECRET production --sensitive
npx vercel@65.11.0 deploy --prod --yes
npx vercel@65.11.0 domains add api-phishguard.vercel.app phishguard-api
```

Le secret est de type **Sensitive** : illisible après enregistrement, y compris depuis le
tableau de bord ; sa valeur pour `server.env` est celle de `.env.deploy`. Les déploiements
de préversion et les URL de déploiement restent protégés par l'authentification Vercel
(*Deployment Protection*) ; seul le nom de production est public.

Une fois le serveur prêt, passage en relais (ou laisser faire le workflow de l'étape 6.3) :

```bash
python scripts/render_edge_config.py proxy --origin-host <origine>.duckdns.org
cd deploy/edge/dist && npx vercel@65.11.0 deploy --prod --yes
```

**Terminé quand** (6.2) :

```bash
bash scripts/edge_smoke.sh https://api-phishguard.vercel.app
```

et une note A ou A+ sur <https://www.ssllabs.com/ssltest/> pour **les deux** noms :
`api-phishguard.vercel.app` (géré par Vercel) et l'origine (Caddy : TLS 1.2 et 1.3
seulement, suites modernes par défaut). HSTS est envoyé par l'API en production ;
`vercel.app` figure de plus sur la liste de préchargement HSTS des navigateurs.

## 6. Déploiement automatisé (6.3)

Une fois, dans GitHub : *Settings > Environments > New environment* `production`
(*Deployment branches and tags* : tags `v*` seulement ; facultatif : *Required reviewers*).

| Secret de l'environnement | Valeur |
|---|---|
| `DEPLOY_HOST` | IP ou nom du serveur |
| `DEPLOY_SSH_PORT` | port SSH (facultatif, 22 par défaut) |
| `DEPLOY_SSH_KEY` | contenu de `~/.ssh/phishguard_deploy` (clé privée) |
| `DEPLOY_SSH_KNOWN_HOSTS` | `ssh-keyscan -t ed25519 <ip>`, **comparé** à `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` lu sur le serveur |
| `PHISHGUARD_ORIGIN_HOST` | le nom DuckDNS de l'origine |
| `VERCEL_TOKEN` | jeton Vercel limité à l'équipe du projet, avec expiration |

| Variable de l'environnement | Valeur |
|---|---|
| `VERCEL_ORG_ID` | `team_1KYPFznakL2pEcw8k53ojOlY` |
| `VERCEL_PROJECT_ID` | `prj_f2WLwgqGAU7ZkQJZKQPjESA2kQxS` |

Le paquet ghcr.io est privé à sa première publication : *Packages > phishguard-api >
Package settings > Change visibility > Public* (le code est public ; le serveur tire alors
l'image sans identifiant). Sinon, connectez le serveur avec un jeton `read:packages` seul :
`sudo -u deploy docker login ghcr.io`.

**Publier une version :**

```bash
# pyproject.toml : version = "0.6.0" ; CHANGELOG.md à jour
git tag -s v0.6.0 -m "v0.6.0" && git push origin v0.6.0
```

Le workflow refuse une étiquette qui ne correspond pas à `pyproject.toml`
(`v0.6.0-beta.1` ↔ `0.6.0b1`). Ensuite :

1. image construite sur des machines **amd64 et arm64 natives**, trivy bloquant
   (HIGH/CRITICAL corrigeables, secrets), test de démarrage avec des modèles signés ;
2. publication **par empreinte**, index multi-architecture, attestation de provenance
   signée par Sigstore, vérifiable par tous :
   `gh attestation verify oci://ghcr.io/arixstoo/phishguard-api:v0.6.0 --owner arixstoo` ;
3. `ssh deploy@serveur "deploy v0.6.0 ghcr.io/arixstoo/phishguard-api@sha256:…"` : la
   commande forcée valide chaque mot, installe `releases/v0.6.0/`, lance la pile
   (`--wait`), vérifie l'image en cours, la santé à travers Caddy **et** le refus sans
   secret ; en cas d'échec, retour automatique à la version précédente ;
4. proxy Vercel régénéré, puis `scripts/edge_smoke.sh` depuis Internet.

**Terminé quand** (6.3) : pousser `v0.6.0` met à jour le serveur sans intervention.

### Retour arrière

Une commande, depuis n'importe où :

```bash
gh workflow run deploy.yml -f action=rollback                    # version précédente
gh workflow run deploy.yml -f action=rollback -f version=v0.6.0  # version donnée
```

ou sur le serveur : `sudo -u deploy phishguard-deploy rollback`. Les cinq dernières versions
restent installées (`phishguard-deploy status`). Un retour arrière ne touche ni la base ni
les modèles (`shared/`).

### Rotation du secret de l'origine

Annuelle, ou immédiate en cas de doute :

1. `openssl rand -hex 32 > secret.txt` sur votre poste ;
2. serveur : nouvelle valeur dans `/opt/phishguard/shared/server.env`, puis
   `sudo -u deploy phishguard-deploy reload` (Caddy relit le secret, vérification comprise) ;
3. Vercel (la valeur ne s'applique qu'aux nouveaux déploiements) :

   ```bash
   npx vercel@65.11.0 env rm PHISHGUARD_ORIGIN_SECRET production --yes
   npx vercel@65.11.0 env add PHISHGUARD_ORIGIN_SECRET production --sensitive < secret.txt
   npx vercel@65.11.0 redeploy api-phishguard.vercel.app --target production
   ```

4. `bash scripts/edge_smoke.sh`, puis `shred -u secret.txt`.

Entre la mise à jour du serveur et celle de Vercel, l'origine refuse les requêtes (403)
pendant moins d'une minute : l'extension continue son analyse locale.

## Mesures

Testé le 18 novembre 2026 sur Docker Desktop 29.1 (Docker-in-Docker pour le serveur) :

- Caddyfile validé par `caddy validate` 2.11.9 ;
- origine : sans secret, secret faux ou secret préfixe + `*` → 403 ; bon secret → 200 ;
  ni `Server` ni `Via` ; HSTS et `no-store` de l'API conservés ;
- limite de débit par visiteur à travers Caddy : 31ᵉ requête du visiteur A → 429, première
  du visiteur B → 200 ;
- `phishguard-deploy` : déploiement v0.6.0 puis v0.6.1, `status`, `rollback` → v0.6.0,
  déploiement d'une empreinte inexistante → échec, retour automatique à v0.6.0, version
  en échec retirée ;
- conteneurs : système de fichiers en lecture seule (Caddy, API), aucune capacité (API,
  Kuma en `1000:1000`), `NET_BIND_SERVICE` seule pour Caddy.
