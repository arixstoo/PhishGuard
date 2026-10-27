# Commandes de PhishGuard. Sous Windows, à lancer dans WSL2.
#
#   make help         liste des cibles
#   make data train   construit les jeux, entraîne et évalue tous les modèles, met à jour
#                     les model cards (clôture du module 1)
#   make test         lance les tests
#
# Les données (data/) et les modèles (models/) sont produits localement, jamais versionnés.

PYTHON ?= python
RAW := data/raw
DATASET := data/processed/urls.parquet
SPLIT := data/processed/urls_split.parquet
URL_MODEL := models/url_v1.joblib
EMAIL_CORPORA := data/raw/emails/manifest_corpora.json

.DEFAULT_GOAL := help
.PHONY: help install lint format test \
	collect data dataset split \
	train train-url evaluate-url errors-url train-text email-samples email-corpora train-email \
	cards

help: ## Affiche cette aide
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "} {printf "  %-14s %s\n", $$1, $$2}'

# --------------------------------------------------------------------------- #
# Outils
# --------------------------------------------------------------------------- #

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

# --------------------------------------------------------------------------- #
# Données (étapes 1.1 à 1.4)
# --------------------------------------------------------------------------- #

collect: ## Ajoute la collecte du jour (flux de phishing, Tranco) et, si absente, Common Crawl
	$(PYTHON) scripts/fetch_feeds.py --output-dir $(RAW)
	@if ls $(RAW)/commoncrawl_*.csv >/dev/null 2>&1; then \
		echo "Common Crawl déjà collecté (relancer scripts/fetch_commoncrawl.py à chaque crawl)"; \
	else \
		$(PYTHON) scripts/fetch_commoncrawl.py --output-dir $(RAW); \
	fi

data: ## Construit et découpe le jeu d'URLs à partir de data/raw/ (collecte d'abord si vide)
	@if ! ls $(RAW)/manifest_*.json >/dev/null 2>&1; then $(MAKE) collect; fi
	$(MAKE) dataset split

dataset: ## Reconstruit data/processed/urls.parquet à partir de data/raw/ (étape 1.2)
	$(PYTHON) scripts/build_dataset.py

split: $(SPLIT) ## Découpe le jeu d'URLs en entraînement / validation / test (étape 1.4)

$(SPLIT): $(DATASET)
	$(PYTHON) scripts/split_dataset.py

$(DATASET):
	$(PYTHON) scripts/build_dataset.py

# --------------------------------------------------------------------------- #
# Modèles (étapes 1.6 à 1.11)
# --------------------------------------------------------------------------- #

train: train-url evaluate-url errors-url train-text train-email cards ## Entraîne et évalue tous les modèles

train-url: $(SPLIT) ## Entraîne et compare les modèles URL, enregistre le meilleur (étape 1.6)
	$(PYTHON) scripts/train_url.py

evaluate-url: $(URL_MODEL) ## Évalue le modèle URL sur le test, à prévalence réaliste (étape 1.7)
	$(PYTHON) scripts/evaluate_url.py

errors-url: $(URL_MODEL) ## Classe les pires erreurs du modèle URL sur la validation (étape 1.8)
	$(PYTHON) scripts/analyze_url_errors.py

$(URL_MODEL): $(SPLIT)
	$(PYTHON) scripts/train_url.py

train-text: ## Compare les modèles SMS (UCI + jeu FR/AR) et enregistre le meilleur (étape 1.9)
	$(PYTHON) scripts/train_text.py

email-samples: ## Télécharge des emails de phishing réels (Phishing Pot, non versionnés) (étape 1.10)
	$(PYTHON) scripts/fetch_email_samples.py

email-corpora: ## Télécharge SpamAssassin (légitime) et Nazario (phishing), non versionnés (étape 1.11)
	$(PYTHON) scripts/fetch_email_corpora.py

$(EMAIL_CORPORA):
	$(PYTHON) scripts/fetch_email_corpora.py

train-email: $(EMAIL_CORPORA) ## Compare règles et modèles du score email, enregistre le modèle (étape 1.11)
	$(PYTHON) scripts/train_email.py

# --------------------------------------------------------------------------- #
# Documentation (étape 1.12)
# --------------------------------------------------------------------------- #

cards: ## Met à jour les chiffres des model cards et du README depuis docs/metrics/
	$(PYTHON) scripts/model_cards.py
