# Mises à jour du modèle, sécurisées et planifiées (étape 6.8)

Le phishing change vite : un modèle vieillit en quelques mois (nouveaux TLD, nouvelles
plateformes d'hébergement, nouvelles formes d'URL). Cette étape réentraîne le modèle URL
chaque mois, ne publie le résultat que s'il ne régresse pas, et permet à l'extension de le
recevoir **sans pouvoir être trompée par une compromission de l'hébergement**.

```
 GitHub Actions (mensuel)                Machine de l'auteur              Extension / API
 ─────────────────────────               ───────────────────              ───────────────
 données ─► candidat ─► garde-fou ─┐
                                   ├─► release brouillon ─► publish_model.py ─► models-stable ─► vérifie la
             attestation Sigstore ─┘    (non signée)        vérifie provenance      (signée)       signature Ed25519
                                                            + garde-fou, signe                     avec la clé
                                                                                                   embarquée
```

## 1. Réentraînement mensuel

Workflow [`model-update.yml`](../.github/workflows/model-update.yml), le 2 de chaque mois à
05:00 UTC (après la collecte quotidienne), ou à la main depuis l'onglet *Actions*.

| Étape | Commande | Ce qui est garanti |
|---|---|---|
| données | historique chiffré (release `data-history`) + `scripts/sync_feed_archives.py` | aucune collecte perdue : les artefacts de `fetch-feeds.yml` expirent après 90 jours, l'historique est réenregistré à chaque passage (job `save-history`), même si le candidat est refusé |
| jeu d'URLs | `build_dataset.py`, puis `model_update.py exclude-frozen`, puis `split_dataset.py` | les domaines du test figé sont retirés **avant** le split : le candidat n'est jamais jugé sur des sites qu'il a appris |
| candidat | `train_url.py`, `train_adversarial.py --only url`, `calibrate_url.py` | même recette que `url_v2` (LightGBM, entraînement adversarial, calibration) |
| garde-fou | `model_update.py gate` | voir section 2 ; le modèle en service n'est désérialisé qu'après vérification de sa signature |
| export | `export_model.py` | JSON pour l'extension, vérifié par l'implémentation de référence en Python pur |
| brouillon | `gh release create model-AAAA.MM.JJ --draft` | fichiers, rapport, `SHA256SUMS`, **attestation de provenance** Sigstore |

**Version et publication.** Le nom `url_v2` désigne la *recette* (features, algorithme,
entraînement adversarial) ; la *publication* datée (`2026.12.02`) désigne un réentraînement.
Le code qui charge les modèles (`phishguard.deployment.DEPLOYED_MODELS`) ne change donc pas
chaque mois. Une nouvelle recette (`url_v3`) reste un changement de code relu, jamais
automatique.

## 2. Garde-fou de non-régression

`phishguard.model_update.decide`, testé dans `tests/test_model_update.py`. Le candidat
n'est publié que si **aucune** vérification n'échoue :

| Vérification | Jeu | Règle |
|---|---|---|
| rappel à 1 % de faux positifs | **test figé** : le bloc de test du 25/10/2026 (21 004 URLs), gelé ; empreinte du contenu versionnée dans [`metrics/frozen_test.json`](metrics/frozen_test.json) | ne baisse pas |
| rappel à 1 % de faux positifs | **test récent** : bloc de test du nouveau split (domaines les plus récents de chaque source) | ne baisse pas |
| faux positifs | **106 sites légitimes courants** ([`common_legitimate_urls.json`](../src/phishguard/urls/data/common_legitimate_urls.json)) : pages de connexion et d'accueil de messageries, banques, administrations, commerce, en France, au Maghreb et ailleurs | n'augmentent pas |

La tolérance de rappel est nulle par défaut ; une baisse admise doit être demandée
explicitement au lancement manuel (0,05 au plus) et apparaît dans le rapport.

**Essai réel (18 novembre 2026).** Soumis au garde-fou comme s'il était un candidat,
`url_v1` est **refusé** face à `url_v2`, le modèle en service :

| Vérification | `url_v2` (en service) | `url_v1` (candidat) | |
|---|---:|---:|:---:|
| rappel à 1 % de FPR, test figé | 0,668 | 0,755 | ✅ |
| faux positifs, sites légitimes courants | 3 | 28 | ❌ |

`url_v1` détecte plus de phishing mais signale les pages de connexion de PayPal, LinkedIn,
GitHub, impots.gouv.fr… C'est exactement le compromis qui a fait choisir `url_v2` à
l'étape 3.12 ([robustness-report.md](robustness-report.md)) : le garde-fou l'aurait vu
seul. Le rappel moyen ne suffit pas, et c'est pour cela que la liste des sites courants
existe.

Le rapport (`gate_report.json`, `gate_report.md`) ne contient aucune URL des jeux de
données, seulement celles, publiques, de la liste des sites courants.

## 3. Signature et publication

La clé privée ne va **jamais** sur la CI (règle de l'étape 4.12). Le workflow s'arrête à
une release brouillon ; l'auteur relit le rapport, puis :

```bash
export PHISHGUARD_SIGNING_PASSPHRASE='…'
python scripts/publish_model.py publish 2026.12.02 --dry-run   # tout vérifier
python scripts/publish_model.py publish 2026.12.02             # signer et publier
```

`publish_model.py` refuse de signer si une vérification échoue : empreintes de
`SHA256SUMS` (rien de modifié, rien d'ajouté), **provenance** (`gh attestation verify
--signer-workflow …/model-update.yml` : le modèle sort de ce workflow, pas d'un fichier
déposé à la main dans le brouillon), garde-fou `passed`. Le modèle texte, inchangé, est
repris du canal en service après vérification de sa signature. Le manifeste porte les
chiffres du garde-fou, puis est signé, relu avec la clé publique du dépôt, ajouté à la
release datée, et les fichiers du canal **`models-stable`** sont remplacés (manifeste et
signature en dernier).

## 4. Côté extension

MV3 interdit le code distant, pas les données. L'option **« Recevoir les mises à jour
signées du modèle de détection »** (désactivée par défaut, permission des hôtes de GitHub
demandée à l'activation) télécharge au plus une fois par jour, depuis `models-stable`, la
signature, le manifeste puis le modèle (`extension/src/updates.ts`). Rien n'est envoyé.

Vérification (`extension/src/core/signed-model.ts`), dans l'ordre de
`phishguard.registry`, avec la **clé publique Ed25519 embarquée au build** :

1. tailles bornées (manifeste 1 Mio, signature 4 Kio, modèle 16 Mio) ;
2. signature d'abord, sur les octets exacts ; document de signature validé en entier
   (champs exacts, JSON et base64 canoniques) ;
3. manifeste : format, publication datée, **même extracteur de features** que l'extension,
   un seul artefact `url-export` au nom plat ;
4. taille puis SHA-256 du modèle ;
5. **pas de retour arrière** : publication strictement plus récente que celle du paquet et
   que la dernière acceptée ;
6. contenu revérifié nœud par nœud par `loadUrlModel`.

Le modèle accepté est gardé dans `storage.local` **avec** son manifeste et sa signature,
et revérifié en entier à chaque chargement : `storage.local` est modifiable par le script
de contenu Gmail. En cas d'échec, il est effacé et l'extension revient au modèle de son
paquet. Désactiver l'option efface le modèle reçu et rend la permission.

**Critère de l'étape : un modèle falsifié (un octet modifié) est rejeté.** Vérifié par
`extension/test/signed-model.test.ts` (chaque octet de la signature et du manifeste, et
des positions réparties dans tout le modèle) et `extension/test/updates.test.ts` (modèle
servi modifié d'un octet : refusé, rien de stocké ; modèle stocké modifié : effacé).
Une publication signée par **Python** (fixture `extension/test/fixtures/signed-release/`,
`scripts/make_signed_release_fixture.py`) et le vrai manifeste du dépôt passent la même
vérification TypeScript.

## 5. Mise en place (une fois)

Ces opérations demandent vos accès GitHub et vos données locales ; elles ne sont faites
qu'une fois.

```bash
# 1. Canal en service : les modèles signés actuels (models/).
python scripts/publish_model.py bootstrap

# 2. Test figé : geler le bloc de test, versionner son empreinte, publier le fichier chiffré.
python scripts/model_update.py freeze          # écrit docs/metrics/frozen_test.json
openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:ARCHIVE_PASSPHRASE \
  -in data/frozen/url_test_frozen.parquet -out url_test_frozen.parquet.enc
gh release create frozen-test --prerelease --latest=false --title "Test figé (chiffré)" \
  --notes "Bloc de test gelé du garde-fou de l'étape 6.8, chiffré." url_test_frozen.parquet.enc

# 3. Historique : l'archive de data/raw/ (toutes les collectes locales).
tar -czf - -C data raw | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
  -pass env:ARCHIVE_PASSPHRASE -out feeds-history.tar.gz.enc
gh release create data-history --prerelease --latest=false --title "Historique chiffré des collectes" \
  --notes "Archive chiffrée des collectes, utilisée par model-update.yml." feeds-history.tar.gz.enc
```

`ARCHIVE_PASSPHRASE` est le secret déjà utilisé par `fetch-feeds.yml`. Les fichiers
chiffrés sont visibles de tous (dépôt public) mais illisibles sans lui ; les conditions
d'OpenPhish interdisent de redistribuer ses flux en clair.

## Limites

- **Le test figé vieillit aussi.** Il mesure la non-régression, pas la qualité face aux
  campagnes de 2027. Le test récent compense en partie ; le geler à nouveau (étape 2
  ci-dessus) est une décision humaine, notée dans le CHANGELOG.
- **Le test récent n'est pas parfaitement inédit pour le modèle en service** : quelques
  domaines récents ont pu exister avant son entraînement. Le biais favorise le modèle en
  service, donc rend le garde-fou plus strict, pas plus laxiste.
- **Données de la CI.** Le candidat ne voit que ce que contient l'historique chiffré : la
  première mise en place (section 5) doit partir de toutes les collectes locales.
- **L'API n'est pas mise à jour automatiquement.** Ses modèles sont dans
  `/opt/phishguard/shared/models/` sur le serveur ([deployment.md](deployment.md)) :
  après une publication, y copier les fichiers de `models-stable`
  (`gh release download models-stable`) puis redémarrer le conteneur de l'API, qui lit
  ses modèles une seule fois au démarrage. L'API refuse de démarrer si la signature ne
  correspond pas : une copie incomplète ne passe pas inaperçue. Automatiser cette copie
  est un travail à faire avec le serveur (étape 6.3).
