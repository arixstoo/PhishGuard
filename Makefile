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
# 200 emails Phishing Pot, comme dans docs/metrics/email_v1.json (le script en prend 50 par défaut).
EMAIL_SAMPLES := data/raw/emails/phishing_pot/manifest.json
EMAIL_SAMPLE_COUNT := 200

.DEFAULT_GOAL := help
.PHONY: help install sync lock audit lint format test fuzz \
	collect data dataset split \
	train train-url evaluate-url errors-url calibrate-url train-text email-samples email-corpora train-email \
	explain-url calibrate-text cards schema robustness train-adversarial robustness-adversarial llm-phishing plot-robustness 	api api-key

help: ## Affiche cette aide
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "} {printf "  %-14s %s\n", $$1, $$2}'

# --------------------------------------------------------------------------- #
# Outils
# --------------------------------------------------------------------------- #

install: ## Installe le paquet et les outils de développement (versions non verrouillées)
	$(PYTHON) -m pip install -e '.[dev]'

sync: ## Environnement reproductible : versions et empreintes exactes de uv.lock (étape 4.8)
	uv sync --locked --extra dev

lock: ## Met à jour uv.lock après une modification des dépendances de pyproject.toml
	uv lock

# Tout uv.lock, extras compris, avec les empreintes : ce que la CI installe.
AUDIT_REQUIREMENTS := $(or $(TMPDIR),/tmp)/phishguard-audit-requirements.txt

audit: ## Dépendances vulnérables (pip-audit), analyse statique (bandit), secrets (gitleaks)
	uv export --locked --all-extras --no-emit-project --no-header --quiet \
		--format requirements-txt -o $(AUDIT_REQUIREMENTS)
	$(PYTHON) -m pip_audit --disable-pip --require-hashes --progress-spinner off \
		-r $(AUDIT_REQUIREMENTS)
	$(PYTHON) -m bandit -q -r src
	gitleaks git . --redact --no-banner

lint: ## Vérifie le style (ruff)
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format: ## Corrige le style (ruff)
	$(PYTHON) -m ruff check --fix .
	$(PYTHON) -m ruff format .

# Seuil de couverture de la suite complète (cahier des charges : 70 % ; mesurée : 97 %).
COVERAGE_MIN := 90

test: ## Lance les tests avec couverture (échoue sous COVERAGE_MIN %)
	$(PYTHON) -m pytest --cov=phishguard --cov-report=term --cov-fail-under=$(COVERAGE_MIN)

fuzz: ## Fuzzing hypothesis des parseurs et de l'API, 1 000 exemples par propriété (étape 4.7)
	$(PYTHON) -m pytest -m fuzz --hypothesis-profile=fuzz --hypothesis-show-statistics -q

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

train: train-url evaluate-url errors-url calibrate-url explain-url train-text calibrate-text train-email cards ## Entraîne et évalue tous les modèles

train-url: $(SPLIT) ## Entraîne et compare les modèles URL, enregistre le meilleur (étape 1.6)
	$(PYTHON) scripts/train_url.py

evaluate-url: $(URL_MODEL) ## Évalue le modèle URL sur le test, à prévalence réaliste (étape 1.7)
	$(PYTHON) scripts/evaluate_url.py

errors-url: $(URL_MODEL) ## Classe les pires erreurs du modèle URL sur la validation (étape 1.8)
	$(PYTHON) scripts/analyze_url_errors.py

calibrate-url: $(URL_MODEL) ## Calibre les probabilités du modèle URL sur la validation (étape 2.10)
	$(PYTHON) scripts/calibrate_url.py

explain-url: $(URL_MODEL) ## Valeurs SHAP du modèle URL : graphique global et exemples (étape 3.1)
	$(PYTHON) scripts/explain_url.py

$(URL_MODEL): $(SPLIT)
	$(PYTHON) scripts/train_url.py

train-text: ## Compare les modèles SMS (UCI + jeu FR/AR) et enregistre le meilleur (étape 1.9)
	$(PYTHON) scripts/train_text.py

calibrate-text: ## Calibre le score du modèle SMS (marge → probabilité) sur la validation (étape 3.3)
	$(PYTHON) scripts/calibrate_text.py

email-samples: ## Télécharge des emails de phishing réels (Phishing Pot, non versionnés) (étape 1.10)
	$(PYTHON) scripts/fetch_email_samples.py --count $(EMAIL_SAMPLE_COUNT)

$(EMAIL_SAMPLES):
	$(PYTHON) scripts/fetch_email_samples.py --count $(EMAIL_SAMPLE_COUNT)

email-corpora: ## Télécharge SpamAssassin (légitime) et Nazario (phishing), non versionnés (étape 1.11)
	$(PYTHON) scripts/fetch_email_corpora.py

$(EMAIL_CORPORA):
	$(PYTHON) scripts/fetch_email_corpora.py

train-email: $(EMAIL_CORPORA) $(EMAIL_SAMPLES) ## Compare règles et modèles du score email, enregistre le modèle (étape 1.11)
	$(PYTHON) scripts/train_email.py

# --------------------------------------------------------------------------- #
# Robustesse adversariale (étapes 3.6 à 3.11)
# --------------------------------------------------------------------------- #

ROBUSTNESS_LABEL ?= baseline
ROBUSTNESS_DESCRIPTION ?= modèles d'origine, avant toute défense

robustness: $(SPLIT) $(URL_MODEL) ## Banc d'essai : rappel et FPR sous chaque perturbation (étape 3.7)
	$(PYTHON) scripts/robustness_benchmark.py --label $(ROBUSTNESS_LABEL) \
		--description "$(ROBUSTNESS_DESCRIPTION)"

train-adversarial: $(SPLIT) $(URL_MODEL) ## Entraînement adversarial : url_v2 et text_v2 (étape 3.9)
	$(PYTHON) scripts/train_adversarial.py

robustness-adversarial: ## Banc d'essai des modèles url_v2 et text_v2 (étape 3.9)
	$(PYTHON) scripts/robustness_benchmark.py --label adversarial --url-host-rule \
		--url-model models/url_v2.joblib --text-model models/text_v2.joblib \
		--description "normalisation de l'étape 3.8 et entraînement adversarial de l'étape 3.9 (url_v2, text_v2), règle d'alerte des hôtes"


llm-phishing: ## Phishing rédigé par un LLM : dégradation des modèles SMS (étape 3.10, jeu local)
	$(PYTHON) scripts/evaluate_llm_phishing.py

plot-robustness: ## Graphique du rapport : rappel et FPR par technique (étape 3.11, matplotlib)
	$(PYTHON) scripts/plot_robustness.py

# --------------------------------------------------------------------------- #
# Documentation (étape 1.12)
# --------------------------------------------------------------------------- #

cards: ## Met à jour les chiffres des model cards et du README depuis docs/metrics/
	$(PYTHON) scripts/model_cards.py

schema: ## Régénère le schéma JSON de la réponse d'analyse (étape 2.11 bis)
	$(PYTHON) scripts/export_schema.py

# --------------------------------------------------------------------------- #
# API (module 4)
# --------------------------------------------------------------------------- #

api: ## Lance l'API sur 127.0.0.1:8000, documentation sur /docs (étape 4.1)
	$(PYTHON) -m phishguard.api

api-key: ## Crée une clé d'API, affichée une seule fois : make api-key NAME=extension-dev (étape 4.4)
	@test -n "$(NAME)" || (echo "usage : make api-key NAME=<usage de la clé>" && exit 1)
	$(PYTHON) -m phishguard.api.keys create --name "$(NAME)"
