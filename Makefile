# Commandes courantes de PhishGuard. Sous Windows, à lancer dans WSL2.
#
#   make help        liste des cibles
#   make train-url   entraîne et compare les modèles URL (étape 1.6)
#   make evaluate-url && make errors-url   évaluation et analyse d'erreurs (1.7, 1.8)

PYTHON ?= python
DATASET := data/processed/urls.parquet
SPLIT := data/processed/urls_split.parquet
URL_MODEL := models/url_v1.joblib

.DEFAULT_GOAL := help
.PHONY: help install lint format test split train-url evaluate-url errors-url

help: ## Affiche cette aide
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "} {printf "  %-12s %s\n", $$1, $$2}'

install: ## Installe le paquet et les outils de développement
	$(PYTHON) -m pip install -e '.[dev]'

lint: ## Vérifie le style (ruff)
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format: ## Corrige le style (ruff)
	$(PYTHON) -m ruff check --fix .
	$(PYTHON) -m ruff format .

test: ## Lance les tests avec couverture
	$(PYTHON) -m pytest --cov=phishguard

split: $(SPLIT) ## Découpe le jeu d'URLs en entraînement / validation / test (étape 1.4)

$(SPLIT): $(DATASET)
	$(PYTHON) scripts/split_dataset.py

$(DATASET):
	@echo "$(DATASET) introuvable. Collectez les flux puis construisez le jeu :" >&2
	@echo "  python scripts/fetch_feeds.py && python scripts/build_dataset.py" >&2
	@exit 1

train-url: $(SPLIT) ## Entraîne et compare les modèles URL, enregistre le meilleur (étape 1.6)
	$(PYTHON) scripts/train_url.py

evaluate-url: $(URL_MODEL) ## Évalue le modèle URL sur le test, à prévalence réaliste (étape 1.7)
	$(PYTHON) scripts/evaluate_url.py

errors-url: $(URL_MODEL) ## Classe les pires erreurs du modèle URL sur la validation (étape 1.8)
	$(PYTHON) scripts/analyze_url_errors.py

$(URL_MODEL): $(SPLIT)
	$(PYTHON) scripts/train_url.py
