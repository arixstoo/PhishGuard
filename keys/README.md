# Clés publiques

`model-signing.pub` : clé publique Ed25519 (PEM) qui vérifie le manifeste signé des
modèles (étape 4.12, [docs/model-registry.md](../docs/model-registry.md)). L'API la lit au
démarrage (`PHISHGUARD_API_MODELS_PUBLIC_KEY`), le conteneur la monte en lecture seule, et
l'extension l'embarquera (module 6).

```bash
export PHISHGUARD_SIGNING_PASSPHRASE='…'
make keygen        # une seule fois : ~/.config/phishguard/model-signing.key + ce fichier
make export sign verify
```

**Aucune clé privée ici, jamais** : `keygen` refuse un chemin dans le dépôt, `.gitignore`
ignore `*.key` et `*.pem`, et deux hooks pre-commit refusent un fichier de clé ou un
contenu `PRIVATE KEY`.
