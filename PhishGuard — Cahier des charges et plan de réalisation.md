# PhishGuard — Cahier des charges et plan de réalisation

*Projet open source de détection de phishing multi-canal · Version 1.0 · Octobre 2026 · Auteur : arixstoo*

## 1. Vision et objectifs

**Problème.** Le phishing reste l'un des principaux vecteurs d'accès initial (MITRE ATT&CK T1566). Les protections existantes sont soit des solutions entreprise payantes, soit des listes noires réactives (le site est déjà signalé quand il est trop tard). Il manque un outil **open source, explicable, respectueux de la vie privée et multilingue (FR / EN / AR)** pour l'utilisateur non technique.

**Mission.** Protéger une personne au moment précis où elle va cliquer, avec un verdict clair et une explication en une phrase simple.

**Objectifs**

- O1 : détecter le phishing sur 3 types d'entrées : URL, SMS/texte, email (contenu + en-têtes).
- O2 : enrichir le verdict avec de la Threat Intelligence réelle (Google Safe Browsing, VirusTotal, urlscan.io, RDAP/WHOIS, Certificate Transparency).
- O3 : expliquer chaque décision (XAI) : phrase simple pour l'utilisateur, détail technique pour l'analyste.
- O4 : mesurer et améliorer la robustesse face aux techniques d'évasion (adversarial ML).
- O5 : être accessible : extension navigateur, bot de messagerie, page web, API publique.
- O6 : être déployé en open source avec de vrais utilisateurs.
- O7 : te faire monter en compétences en cyber (blue team, threat intel, AppSec, sécurité de l'IA) et produire un projet de portfolio crédible.

**Hors périmètre (non-objectifs).** Ce n'est pas un antivirus, ni une passerelle mail serveur complète, ni un outil offensif. PhishGuard ne stocke pas le contenu des emails des utilisateurs.

## 2. Utilisateurs cibles

| Persona | Besoin | Canal principal |
| --- | --- | --- |
| P1 – Grand public (famille, amis) | Savoir si un lien/message est dangereux, sans jargon | Extension, bot Telegram |
| P2 – Étudiant / petite structure sans SOC | Contrôle rapide + explication pédagogique | Extension, page web |
| P3 – Analyste / contributeur | Verdict détaillé, API, données reproductibles | API, GitHub |

## 3. Exigences fonctionnelles

| ID | Exigence | Priorité |
| --- | --- | --- |
| FR1 | Analyse d'une URL : verdict (sûr / suspect / phishing) + score 0–100 | Must |
| FR2 | Analyse d'un texte (SMS, message) | Must |
| FR3 | Analyse d'un email brut (.eml) : SPF/DKIM/DMARC, Reply-To, lien affiché vs lien réel | Must |
| FR4 | Enrichissement Threat Intel optionnel (opt-in) | Must |
| FR5 | Explication : raisons classées par poids, en langage simple + vue technique | Must |
| FR6 | Mapping MITRE ATT&CK de la détection (T1566.001/.002/.003, T1204) | Should |
| FR7 | Extension Chrome : badge sur la page, bannière dans Gmail/Outlook web, analyse au survol, clic droit | Must |
| FR8 | Bot Telegram : l'utilisateur transfère un message suspect, reçoit un verdict | Should |
| FR9 | Page web « coller et analyser » | Should |
| FR10 | API REST publique documentée (OpenAPI) | Must |
| FR11 | Signalement faux positif / faux négatif (opt-in, sans contenu personnel) | Should |
| FR12 | Liste blanche / noire personnelle | Could |
| FR13 | Interface FR / EN / AR (RTL) | Should |
| FR14 | Port Firefox | Could |

## 4. Exigences non fonctionnelles

- **Vie privée (priorité n°1)** : inférence locale par défaut ; on envoie au maximum une URL ou un domaine, jamais le corps d'un email ; aucune télémétrie sans opt-in ; politique de confidentialité claire.
- **Performance** : < 50 ms pour l'analyse locale d'une URL ; < 300 ms pour l'API hors Threat Intel ; < 3 s avec enrichissement.
- **Qualité de détection (objectif)** : recall ≥ 95 % à un taux de faux positifs ≤ 1 % sur un **jeu de test temporel** (données plus récentes que l'entraînement). Les faux positifs détruisent la confiance : on les mesure autant que les faux négatifs.
- **Sécurité** : validation stricte des entrées, protection SSRF, rate limiting, dépendances auditées, permissions d'extension minimales.
- **Reproductibilité** : pipeline de données et d'entraînement relançable en une commande ; versionnement des modèles ; model card.
- **Qualité logicielle** : tests (couverture > 70 %), CI GitHub Actions, linting, documentation.
- **Licence** : open source (voir module 6).

## 5. Architecture

```
[Extension Chrome]   [Bot Telegram]   [Page web]   [Clients API]
        |                   |              |             |
   modèle local (ONNX)      +--------------+-------------+
   règles + heuristiques                   |
        | (si incertain, opt-in)           v
        +---------------------->  API FastAPI (Docker)
                                           |
        +----------------+-----------------+------------------+
        v                v                 v                  v
  Feature extractor   Modèles ML      Enrichisseurs TI     Explainer
  (URL/texte/email)   (URL, texte)   (SB, VT, urlscan,    (SHAP + règles
                                      RDAP, crt.sh)         lisibles)
                                           |
                                  Cache (SQLite/Redis) + logs sans données perso

Pipeline offline : collecte feeds -> nettoyage -> split temporel -> entraînement
-> évaluation -> export ONNX -> release (GitHub Actions, mise à jour mensuelle)
```

## 6. Stack technique

| Couche | Choix | Pourquoi |
| --- | --- | --- |
| Langage ML / API | Python 3.12 | Écosystème sécurité + ML |
| ML | scikit-learn, LightGBM, (option : petit transformer multilingue) | Rapide, exportable en ONNX |
| Explicabilité | SHAP | Standard de l'industrie |
| API | FastAPI, Pydantic, httpx (async) | Validation + OpenAPI auto |
| Extension | JavaScript/TypeScript, Manifest V3, onnxruntime-web | Obligation MV3, inférence locale |
| Bot | aiogram ou python-telegram-bot | Messagerie accessible à tous |
| Conteneurs | Docker, docker compose | Déploiement reproductible |
| CI/CD | GitHub Actions | Tests, scans, releases, ré-entraînement planifié |
| Qualité sécu | bandit, pip-audit, Trivy, ruff | SAST + audit dépendances/conteneur |
| MLOps léger | DVC ou MLflow | Versionner données et modèles |
| Docs | MkDocs Material | Site de documentation |

## 7. Modèle de menace et vie privée

Un outil de sécurité est lui-même une cible. À documenter dans `docs/threat-model.md` (méthode STRIDE).

| Menace | Exemple | Mitigation |
| --- | --- | --- |
| SSRF | L'API est poussée à requêter `http://169.254.169.254` ou un réseau interne | Liste de blocage des IP privées/link-local, résolution DNS contrôlée, timeouts, jamais de visite directe de l'URL depuis le serveur |
| Évasion du modèle | Homoglyphes, caractères invisibles, texte légitime ajouté | Normalisation Unicode, entraînement adversarial, ensemble + règles |
| Empoisonnement | Faux feedbacks pour fausser le ré-entraînement | Feedback jamais utilisé automatiquement, revue humaine, quarantaine |
| Abus de l'API | Scraping, déni de service | Clés API, rate limiting, quotas |
| Fuite de données | Contenu d'email envoyé à un tiers | Inférence locale, URL seule, opt-in explicite, logs sans PII |
| Supply chain | Dépendance npm/pip piégée, compte développeur compromis | Lockfiles, pip-audit/npm audit, 2FA, releases signées, peu de dépendances |
| Extension malveillante | Permissions excessives | Permissions minimales, pas de code distant, pas d'innerHTML, CSP stricte |

**Principes de vie privée** : privacy by design, minimisation des données, local-first, transparence (politique de confidentialité obligatoire pour le Chrome Web Store), aucun tracking.

## 8. Plan de réalisation par module (≈ 15 semaines)

Chaque module : objectif, étapes, livrables, compétences cyber acquises, ressources. Si le temps manque, coupe en priorité : port Firefox, phishing généré par LLM, bot Telegram.

### Module 0 — Fondations (semaine 1)

**Objectif** : transformer le dépôt en projet professionnel et comprendre l'anatomie d'un phishing.

**Étapes**

1. Restructurer : `src/phishguard/`, `tests/`, `docs/`, `data/` (non versionné), `notebooks/`, `extension/`, `bot/`.
2. `pyproject.toml`, environnement reproductible, `pre-commit` (ruff), GitHub Actions (lint + tests).
3. Fichiers de projet : `README.md` (problème, démo, installation), `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, templates d'issues.
4. Rejouer ton baseline SMS (TF-IDF + LogReg) avec de vraies métriques : précision, recall, F1, matrice de confusion, pas seulement l'accuracy.
5. Étudier l'anatomie d'une attaque : pretext, urgence, faux domaine, page de collecte d'identifiants, exfiltration. Écrire `docs/phishing-101.md` avec tes mots.

**Livrables** : dépôt restructuré avec CI verte, document phishing-101.

**Compétences** : bonnes pratiques de dépôt, kill chain du phishing, vocabulaire (pretexting, BEC, smishing, quishing, spear phishing).

**Ressources**

- TryHackMe, module « Phishing » et parcours « SOC Level 1 » : https://tryhackme.com/
- MITRE ATT&CK T1566 : https://attack.mitre.org/techniques/T1566/
- APWG Phishing Activity Trends (rapports trimestriels) : https://apwg.org/trendsreports/
- Verizon DBIR (part du phishing dans les brèches) : https://www.verizon.com/business/resources/reports/dbir/
- Livre : *Phishing Dark Waters* (Hadnagy, Fincher)
- Guide de dépôt open source : https://opensource.guide/

### Module 1 — Données et détection URL / texte / email (semaines 2–4)

**Objectif** : construire des détecteurs solides avec une méthodologie rigoureuse, c'est ce qui distingue un projet sérieux d'un notebook.

**Étapes**

1. **Collecte** (scripts reproductibles) : URLs de phishing (OpenPhish community feed, URLhaus d'abuse.ch, PhishTank si accessible), URLs légitimes (liste Tranco), dataset UCI PhiUSIIL pour comparer. SMS : UCI SMS Spam Collection + corpus de smishing publics.
2. **Qualité des données** : dédoublonnage par domaine, détection de fuite de données (le même domaine en train et en test), équilibrage réaliste. Dans la vraie vie, le phishing représente une infime fraction du trafic, donc évalue aussi avec un ratio réaliste.
3. **Split temporel** : entraîner sur le passé, tester sur le plus récent. Un split aléatoire donne des scores flatteurs et trompeurs.
4. **Features URL** (statiques d'abord) : longueur, nombre de sous-domaines, présence d'IP, `@`, tirets, entropie, TLD suspect, mots-clés (login, verify, secure), raccourcisseurs, Punycode/IDN, distance de Levenshtein aux marques connues (typosquatting). Utiliser `tldextract` pour séparer domaine et suffixe correctement.
5. **Modèles** : régression logistique (baseline), Random Forest, LightGBM. Métriques : PR-AUC, recall à FPR = 1 %, courbe précision-rappel. Comparer, choisir, justifier.
6. **Texte** : TF-IDF mots vs n-grammes de caractères (plus robustes aux fautes volontaires) ; option : petit transformer multilingue pour FR/AR. Évaluer le gain réel face au coût (taille, latence).
7. **Email** : parser `.eml` avec la stdlib `email` ; extraire les en-têtes d'authentification (SPF, DKIM, DMARC), `From` vs `Return-Path` vs `Reply-To`, liens dont le texte affiché diffère de la cible, pièces jointes à risque, HTML caché.
8. **Model card** : données, métriques, limites, biais connus.

**Livrables** : pipeline `make train`, trois modèles évalués, rapport d'évaluation, model card.

**Compétences** : feature engineering orienté sécurité, évaluation honnête, analyse d'en-têtes email, typosquatting et attaques par homographes.

**Ressources**

- Tranco (liste de domaines fiables) : https://tranco-list.eu/
- URLhaus : https://urlhaus.abuse.ch/ · OpenPhish : https://openphish.com/ · PhishTank : https://phishtank.org/
- UCI PhiUSIIL Phishing URL Dataset : https://archive.ics.uci.edu/
- Unicode UTS #39 (caractères confondables, homographes) : https://www.unicode.org/reports/tr39/
- RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC) : https://www.rfc-editor.org/
- scikit-learn : https://scikit-learn.org/ · LightGBM : https://lightgbm.readthedocs.io/
- Livre : *Hands-On Machine Learning* (Géron) ; *Machine Learning and Security* (Chio, Freeman)
- Pour analyser des en-têtes à la main : outil MessageHeader de Google Admin Toolbox

### Module 2 — Threat Intelligence et fusion de signaux (semaines 5–6)

**Objectif** : travailler comme un analyste qui enrichit un indicateur avant de conclure.

**Étapes**

1. **Enrichisseurs** (un module par source, interface commune) : Google Safe Browsing (Lookup/Update API), VirusTotal (domaine/URL), urlscan.io (recherche des scans existants, scan à la demande en opt-in), RDAP/WHOIS (âge du domaine, registrar), DNS (`dnspython` : MX, NS, TTL), Certificate Transparency via crt.sh (certificat très récent), AbuseIPDB (réputation IP).
2. **Robustesse réseau** : async `httpx`, timeouts, retries avec backoff, gestion des quotas (le palier gratuit de VirusTotal est limité en requêtes et son usage est restreint aux projets non commerciaux, lis ses conditions), cache avec TTL, circuit breaker si une source tombe.
3. **Protection SSRF** : valider le schéma, bloquer IP privées/loopback/link-local, résoudre le DNS toi-même avant la requête, ne jamais suivre aveuglément les redirections. Écris des tests dédiés.
4. **Fusion des signaux** : score final = modèle ML + signaux TI + règles dures (ex : listé Safe Browsing = phishing). Documenter la logique, la rendre configurable et testable.
5. **Mapping MITRE** et schéma de sortie JSON : `verdict`, `score`, `reasons[]`, `signals{}`, `mitre[]`, `model_version`.
6. **Vie privée** : l'enrichissement n'envoie que le domaine/URL et seulement si l'utilisateur l'a activé. Chaque utilisateur peut fournir sa propre clé d'API, ce qui évite de dépendre de tes quotas.

**Livrables** : package `enrichers/`, tests avec mocks, schéma de réponse documenté, note `docs/ssrf.md`.

**Compétences** : Threat Intelligence, indicateurs de compromission (IOC), OSINT d'infrastructure, DNS/RDAP/CT, sécurité applicative (SSRF), conception résiliente.

**Ressources**

- Google Safe Browsing : https://developers.google.com/safe-browsing
- VirusTotal API v3 : https://docs.virustotal.com/reference/overview
- urlscan.io API : https://urlscan.io/docs/api/
- crt.sh (Certificate Transparency) : https://crt.sh/
- RDAP (RFC 7480 et suivants) / `ipwhois` ou `whodap` en Python
- OWASP SSRF Prevention Cheat Sheet : https://cheatsheetseries.owasp.org/
- Pyramid of Pain (David Bianco) : comprendre la valeur des différents IOC
- Cours gratuits Threat Intelligence sur TryHackMe (Cyber Threat Intelligence)

### Module 3 — Explicabilité et robustesse adversariale (semaines 7–8)

**Objectif** : le volet « futur de la cybersécurité » : une IA de défense doit être explicable et résister à des attaquants qui s'adaptent.

**Étapes**

1. **XAI** : SHAP sur LightGBM pour l'URL, poids des n-grammes pour le texte. Traduire en raisons lisibles via des gabarits : « Le domaine a été enregistré il y a 2 jours », « L'adresse imite « paypal » avec un caractère différent ».
2. **Deux niveaux d'explication** : utilisateur (1 phrase + conseil d'action) et analyste (signaux bruts, valeurs SHAP).
3. **Catalogue d'évasions** : URL (typosquatting, homographes, sous-domaines trompeurs, ajout de chemins bénins) ; texte (homoglyphes, caractères de largeur nulle, leetspeak, ajout de texte légitime pour diluer le signal) ; email (HTML caché, texte en image, quishing via QR code).
4. **Banc d'essai défensif** : script qui applique chaque perturbation à des échantillons connus et mesure la baisse de recall. Utilise des cadres existants (TextAttack, Adversarial Robustness Toolbox) et des exemples synthétiques, jamais envoyés à personne.
5. **Défenses** : normalisation Unicode (NFKC), suppression des caractères invisibles, détection d'IDN mixtes, entraînement avec exemples perturbés, ensemble modèle + règles. Mesurer l'amélioration avant/après.
6. **Phishing généré par LLM** : constituer un petit jeu de test de messages synthétiques grammaticalement parfaits (en local, à des fins de détection) et mesurer la dégradation de ton modèle. Documenter honnêtement les limites. Les détecteurs basés sur des fautes d'orthographe sont mis en échec par ce type de contenu, d'où l'importance des signaux d'infrastructure (âge du domaine, TI).
7. **Rapport** : `docs/robustness-report.md` avec tableaux avant/après. Ce document vaut de l'or en entretien.

**Livrables** : explainer intégré à l'API, banc d'essai adversarial, rapport de robustesse.

**Compétences** : sécurité de l'IA (adversarial ML), évasion de détection, IA explicable, esprit red team appliqué à ton propre outil.

**Ressources**

- SHAP : https://shap.readthedocs.io/
- TextAttack : https://github.com/QData/TextAttack
- Adversarial Robustness Toolbox (IBM) : https://github.com/Trusted-AI/adversarial-robustness-toolbox
- MITRE ATLAS (techniques d'attaque contre les systèmes d'IA) : https://atlas.mitre.org/
- NIST AI 100-2, taxonomie du Adversarial Machine Learning : https://www.nist.gov/
- OWASP Machine Learning Security Top 10 et OWASP Top 10 for LLM Applications : https://owasp.org/
- Livre en ligne : *Interpretable Machine Learning* (Christoph Molnar) : https://christophm.github.io/interpretable-ml-book/

### Module 4 — API et backend sécurisés (semaines 9–10)

**Objectif** : livrer un service que d'autres peuvent appeler et qui résiste à l'abus.

**Étapes**

1. Endpoints : `POST /v1/analyze/url`, `/v1/analyze/text`, `/v1/analyze/email`, `GET /v1/health`, `POST /v1/feedback`. Schémas Pydantic stricts (taille max, formats).
2. Sécurité : clés d'API, rate limiting (ex : `slowapi`), CORS restrictif, en-têtes de sécurité, aucune donnée perso dans les logs, gestion d'erreurs sans fuite d'informations.
3. Tests : `pytest` (unitaires + intégration), fuzzing avec `hypothesis` sur les parseurs d'URL et d'emails (très formateur : les parseurs sont la cible classique des attaquants).
4. Pipeline sécurité dans la CI : `bandit` (SAST), `pip-audit` (dépendances), `trivy` (image Docker), Dependabot.
5. Docker : image minimale, utilisateur non-root, `docker compose` pour API + cache.
6. **Export ONNX** des modèles légers pour l'inférence locale dans l'extension ; vérifier que les prédictions ONNX et Python concordent.
7. Versionnement des modèles (DVC ou MLflow) et endpoint `/v1/model` qui expose version et date d'entraînement.

**Livrables** : API dockerisée, documentation OpenAPI, CI avec scans de sécurité, modèle ONNX.

**Compétences** : AppSec, OWASP API Security Top 10, DevSecOps, tests de robustesse des parseurs, durcissement de conteneurs.

**Ressources**

- FastAPI : https://fastapi.tiangolo.com/
- OWASP API Security Top 10 : https://owasp.org/API-Security/
- OWASP ASVS (référentiel de vérification) : https://owasp.org/www-project-application-security-verification-standard/
- Hypothesis : https://hypothesis.readthedocs.io/
- Trivy : https://trivy.dev/ · Bandit : https://bandit.readthedocs.io/
- ONNX / skl2onnx : https://onnx.ai/
- Docker : https://docs.docker.com/get-started/
- PortSwigger Web Security Academy (gratuit, pour comprendre les attaques web) : https://portswigger.net/web-security

### Module 5 — Extension navigateur et canaux de messagerie (semaines 11–13)

**Objectif** : rendre l'outil utilisable par quelqu'un qui n'a aucune connaissance technique. C'est le module qui crée l'adoption.

**Décision clé : comment « se connecter à ton email »**

| Option | Principe | Verdict |
| --- | --- | --- |
| A. Lecture du DOM de Gmail/Outlook web (content script) | L'extension lit l'email ouvert directement dans la page, localement | **Retenue pour la v1** : pas d'OAuth, pas de serveur qui voit les emails, simple à installer |
| B. API Gmail via OAuth | Accès à la boîte mail | À éviter en solo : les scopes de lecture Gmail sont « restreints » et exigent une vérification Google avec évaluation de sécurité annuelle, lourde pour un projet open source |
| C. Transfert manuel (bot, page web, clic droit) | L'utilisateur envoie lui-même le message suspect | **Complément** : fonctionne partout (WhatsApp/SMS copiés-collés), vie privée maximale |

Attention : le DOM de Gmail change souvent, prévois des tests et une dégradation gracieuse. La bibliothèque InboxSDK peut aider mais ajoute une dépendance à évaluer.

**Étapes**

1. **Extension minimale (MV3)** : manifest, service worker, analyse locale de l'URL de l'onglet via le modèle ONNX + règles, badge vert/orange/rouge.
2. **Content script Gmail** : détecter l'ouverture d'un email, extraire liens (texte affiché vs cible), expéditeur, afficher une bannière « PhishGuard : 2 liens suspects ».
3. **Survol de lien** : infobulle avec verdict et raison principale. Choisir `textContent` et jamais `innerHTML` pour injecter du contenu (sinon l'extension devient une faille XSS).
4. **Popup et page d'options** : explication simple, détail technique repliable, réglages de confidentialité (enrichissement TI opt-in, clé API perso, serveur auto-hébergé), liste blanche.
5. **Sécurité de l'extension** : permissions minimales (`activeTab` quand possible, hôtes restreints), pas de code distant (interdit en MV3), CSP stricte, pas de collecte sans consentement, audit de tes dépendances npm.
6. **i18n** : `chrome.i18n` pour FR/EN/AR, test du rendu RTL.
7. **Accessibilité** : couleurs + icônes + texte (daltonisme), navigation clavier, lecteurs d'écran.
8. **Bot Telegram** : l'utilisateur transfère un message, le bot extrait les liens et répond avec verdict + explication. Ne pas conserver les messages.
9. **Page web « coller et analyser »** : une page statique légère qui appelle l'API.
10. **Tests utilisateurs** : 5 à 10 personnes non techniques, observer sans aider, corriger les points de friction. Les retours valent plus que n'importe quelle fonctionnalité.
11. *(Optionnel)* Port Firefox (WebExtensions), puis add-in Outlook.

**Livrables** : extension fonctionnelle (Chrome), bot, page web, rapport de tests utilisateurs.

**Compétences** : sécurité des extensions et du navigateur (modèle de permissions, XSS, CSP), UX de la sécurité (comment faire agir un humain), vie privée.

**Ressources**

- Documentation Chrome Extensions (MV3) : https://developer.chrome.com/docs/extensions/
- Publication Chrome Web Store : https://developer.chrome.com/docs/webstore/
- Vérification OAuth des scopes restreints Google : https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification
- onnxruntime-web : https://onnxruntime.ai/docs/tutorials/web/
- InboxSDK : https://www.inboxsdk.com/
- Firefox WebExtensions : https://developer.mozilla.org/docs/Mozilla/Add-ons/WebExtensions
- aiogram : https://docs.aiogram.dev/
- Livre : *Usable Security* / travaux sur les avertissements de sécurité (Felt et al.) ; recherche « Google Chrome SSL warnings » pour apprendre pourquoi les gens ignorent les alertes

### Module 6 — Déploiement, open source et adoption (semaines 14–15, puis continu)

**Objectif** : passer d'un projet de dépôt à un produit avec de vrais utilisateurs.

**Étapes**

1. **Hébergement de l'API** : un petit VPS ou un palier gratuit/peu cher (vérifie les offres actuelles de Fly.io, Render, Hetzner, Oracle Cloud) ; HTTPS avec Caddy ou Traefik ; supervision (Uptime Kuma) ; sauvegardes ; limites de coût.
2. **Auto-hébergement facile** : `docker compose up` suffit. Beaucoup d'utilisateurs en sécurité préfèrent héberger eux-mêmes, et ça réduit ta charge.
3. **Licence** : MIT ou Apache-2.0 pour maximiser l'adoption ; AGPL-3.0 si tu veux empêcher une version fermée en SaaS. Choisis consciemment et explique-le dans le README.
4. **Publication des stores** : Chrome Web Store (compte développeur avec frais uniques d'environ 5 $, politique de confidentialité, captures d'écran, justification de chaque permission ; la revue peut prendre de quelques jours à plusieurs semaines) puis Firefox Add-ons.
5. **Documentation** : site MkDocs (installation, confidentialité, FAQ, architecture, modèle de menace, model card), GIF de démo, vidéo de 90 secondes.
6. **Gouvernance** : `SECURITY.md` avec divulgation responsable, versionnage sémantique, `CHANGELOG`, issues « good first issue », `CONTRIBUTING`.
7. **Ré-entraînement planifié** : workflow GitHub Actions mensuel qui récupère les feeds, ré-évalue sur données récentes et publie un nouveau modèle seulement si les métriques ne régressent pas (le phishing évolue vite, un modèle vieillit en quelques mois).
8. **Lancement** : article technique (dev.to / Medium / LinkedIn) sur « ce que j'ai appris en construisant un détecteur de phishing », Show HN, r/cybersecurity, r/chrome\_extensions, communautés étudiantes et groupes cyber locaux, famille et amis comme premiers testeurs.
9. **Mesurer** : installations, utilisateurs actifs hebdomadaires, retours, taux de faux positifs signalés. Itérer sur les retours réels.

**Livrables** : API en production, extension publiée, site de docs, article de lancement, première release v1.0.

**Compétences** : déploiement et exploitation, gestion de communauté open source, divulgation de vulnérabilités, MLOps (dérive des données), communication technique.

**Ressources**

- Open Source Guides : https://opensource.guide/
- Choisir une licence : https://choosealicense.com/
- Contributor Covenant : https://www.contributor-covenant.org/
- Semantic Versioning : https://semver.org/
- MkDocs Material : https://squidfunk.github.io/mkdocs-material/
- Caddy : https://caddyserver.com/
- GitHub Actions (workflows planifiés) : https://docs.github.com/actions

## 9. Critères de succès

| Axe | Cible |
| --- | --- |
| Détection | recall ≥ 95 % à FPR ≤ 1 % (test temporel) |
| Robustesse | baisse de recall < 10 points sur le banc d'évasion après défenses |
| Vie privée | 0 contenu d'email envoyé hors de l'appareil par défaut |
| Qualité | CI verte, couverture > 70 %, 0 vulnérabilité critique ouverte |
| Adoption (6 mois) | 100+ installations actives, 50+ étoiles GitHub, 5+ retours d'utilisateurs réels |
| Portfolio | 3 documents phares : threat model, rapport de robustesse, article de lancement |

## 10. Risques et réponses

| Risque | Réponse |
| --- | --- |
| Trop de faux positifs, perte de confiance | Seuils prudents, liste blanche, verdict « suspect » nuancé, feedback |
| Refus du Chrome Web Store | Permissions minimales, justification claire, politique de confidentialité tôt |
| Changement du DOM Gmail | Tests, dégradation gracieuse, canaux alternatifs (clic droit, bot) |
| Dérive du modèle | Ré-entraînement mensuel + garde-fous de non-régression |
| Dépendance aux API tierces | Cache, clés utilisateur, mode dégradé local |
| Dérive du périmètre / épuisement | MVP d'abord : URL + extension + API, le reste est incrémental |
| Aspects légaux | Respecter les conditions des API, ne jamais visiter d'URL suspectes depuis ta machine sans sandbox, n'utiliser que des données publiques |

## 11. Comment valoriser le projet (CV, entretiens)

- **Rôles visés** : analyste SOC N1/N2, Threat Intelligence, AppSec/DevSecOps, sécurité de l'IA.
- **Phrase CV type** : « Conçu et déployé PhishGuard, outil open source de détection de phishing (extension Chrome + API) : modèle LightGBM évalué sur split temporel, enrichissement Threat Intel, explicabilité SHAP, banc d'essai adversarial, N utilisateurs actifs. »
- **Histoires à raconter** : la fuite de données que tu as découverte dans le split aléatoire, la faille SSRF que tu as testée, l'évasion qui a fait chuter ton recall et comment tu l'as corrigée, ce que les utilisateurs non techniques ont mal compris.
- **Certifications complémentaires** : CompTIA Security+, Google Cybersecurity Certificate, BTL1 (Blue Team Level 1), TryHackMe SOC Level 1.

## 12. Ressources transverses

- **Pratique blue team** : TryHackMe, LetsDefend, Blue Team Labs Online, Malware-Traffic-Analysis.net (cas réels).
- **Veille** : blogs Krebs on Security, The DFIR Report, rapports annuels Google Threat Intelligence, CERT locaux.
- **Phishing en pratique** : Anti-Phishing Working Group (apwg.org), PhishTool (analyse d'emails), CISA et ANSSI/CERT-FR (guides de sensibilisation).
- **ML + sécurité** : MITRE ATLAS, NIST AI RMF, OWASP ML/LLM Top 10.

## 13. Première semaine concrète

1. Créer la nouvelle structure du dépôt et la CI.
2. Rejouer le baseline SMS avec précision/recall/F1.
3. Écrire `docs/phishing-101.md`.
4. Télécharger les feeds OpenPhish/URLhaus + Tranco et lancer un premier script de collecte.
5. Ouvrir 15 issues GitHub correspondant aux étapes du module 1 pour suivre ta progression publiquement.

# Partie II — Guide d'exécution pas à pas

*Ce guide détaille, module par module, chaque étape à réaliser dans l'ordre. Une étape = une issue GitHub = une branche = une PR. Ne passe à l'étape suivante que lorsque le critère « Terminé quand » est rempli. Les durées sont approximatives.*

## Mode d'emploi et règles de travail

- **Rythme** : 10 h par semaine environ (1 à 2 h par jour). Si tu avances plus vite, tant mieux ; ne saute pas les critères de fin.
- **Format de chaque étape** : Faire, commandes ou code, Terminé quand, Piège à éviter, Pour apprendre.
- **Journal d'apprentissage** : crée `docs/LEARNING.md`. Pour chaque étape, écris 3 lignes : ce que j'ai fait, ce que j'ai appris, ce qui m'a bloqué. C'est la matière première de ton article de lancement et de tes réponses en entretien.
- **Git** : une branche par étape (`feat/m1-url-features`), commits conventionnels (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), une PR même si tu travailles seul, tag de version à la fin de chaque module (`v0.1.0`, `v0.2.0`...).
- **Outils à installer** : Python 3.12, git, VS Code, Docker Desktop, Node.js 20 LTS, make. Sous Windows, installe WSL2 (Ubuntu) et travaille dedans : tous les exemples de commandes supposent un shell Linux.
- **Comptes à créer (au fur et à mesure)** : GitHub, Telegram, VirusTotal, Google Cloud (Safe Browsing), urlscan.io, Chrome Web Store (module 6).

## Règles de sécurité de ton laboratoire (à lire avant le module 1)

- Traite les URLs de phishing **uniquement comme des chaînes de caractères**. Ne les ouvre jamais dans ton navigateur habituel et n'ouvre jamais de pièce jointe issue d'un corpus de phishing.
- Pour observer une page suspecte, utilise un service de scan tiers (urlscan.io en mode privé) ou une machine virtuelle isolée sans aucun de tes comptes connectés.
- Ne publie jamais les données brutes dans le dépôt (adresses email réelles, informations personnelles) : publie les scripts de collecte, pas les données.
- Ne mets jamais de clé d'API dans Git (voir étape 2.1).
- N'envoie aucun message de test à de vraies personnes.

---

## Module 0 — Fondations (semaine 1)

### Étape 0.1 — Préserver l'ancien projet (15 min)

**Faire** : garde l'historique de ton projet d'il y a 4 ans, c'est la preuve de ta progression.

```
git clone https://github.com/arixstoo/SMS-Spam-Detector-96 phishguard
cd phishguard
git tag v0-legacy && git push --tags
git checkout -b refactor/structure
```

Sur GitHub, renomme le dépôt en `phishguard` (Settings, Repository name) ; GitHub redirige automatiquement les anciens liens.

**Terminé quand** : le tag `v0-legacy` est visible sur GitHub et le dépôt s'appelle `phishguard`.

### Étape 0.2 — Arborescence du projet (30 min)

```
mkdir -p src/phishguard/{urls,text,email,enrichers,fusion,explain,adversarial,security,api}
mkdir -p tests scripts data/{raw,interim,processed} models docs notebooks/legacy extension bot
touch src/phishguard/__init__.py
```

Déplace tes anciens fichiers (notebook, scripts) dans `notebooks/legacy/` avec `git mv`. Rôle des dossiers : `src/phishguard` = le code réutilisable (importé par l'API, le bot et les scripts), `scripts` = commandes de collecte/entraînement, `data` = jamais versionné, `models` = modèles produits, `extension` = l'extension Chrome, `bot` = le bot Telegram.

**Terminé quand** : `tree -L 2` montre cette structure et rien d'important n'est perdu.

### Étape 0.3 — Environnement et `pyproject.toml` (45 min)

**Faire** : un seul fichier décrit le projet et ses dépendances.

```
[project]
name = 'phishguard'
version = '0.0.1'
requires-python = '>=3.11'
dependencies = ['pandas', 'scikit-learn', 'lightgbm', 'tldextract', 'rapidfuzz', 'beautifulsoup4', 'joblib', 'httpx']

[project.optional-dependencies]
dev = ['pytest', 'pytest-cov', 'ruff', 'pre-commit', 'hypothesis']

[tool.ruff]
line-length = 100

[tool.pytest.ini_options]
testpaths = ['tests']
```

```
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

**Piège** : ne commite jamais `.venv`. Crée un `.gitignore` avec au minimum : `.venv/`, `data/`, `__pycache__/`, `.env`, `node_modules/`, `dist/`, `*.joblib`.

**Terminé quand** : `python -c 'import phishguard'` fonctionne depuis n'importe quel dossier du projet.

### Étape 0.4 — Qualité de code automatique (30 min)

Crée `.pre-commit-config.yaml` (vérifie les dernières versions sur les dépôts des outils) :

```
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
```

Puis `pre-commit install`. À chaque commit, le code est formaté et le dépôt est scanné à la recherche de secrets (clés d'API oubliées). Écris aussi un premier test `tests/test_smoke.py` qui importe le paquet.

**Terminé quand** : un commit contenant une fausse clé (essaie avec une chaîne ressemblant à une clé) est bloqué.

### Étape 0.5 — Intégration continue (30 min)

Crée `.github/workflows/ci.yml` :

```
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -e '.[dev]'
      - run: ruff check . && ruff format --check .
      - run: pytest --cov=phishguard
```

**Terminé quand** : la pastille verte apparaît sur ton premier commit. Ajoute le badge CI en haut du README.

### Étape 0.6 — Fichiers de communauté (1 h)

- `README.md` : problème, capture ou GIF (vide pour l'instant), fonctionnalités prévues, installation, avancement par module. Un README honnête (« en construction ») vaut mieux qu'un README vide.
- `LICENSE` : mets MIT pour l'instant ; tu pourras changer tant que tu es seul auteur (décision finale au module 6).
- `SECURITY.md` : comment signaler une vulnérabilité (une adresse email dédiée ou la fonction « Report a vulnerability » de GitHub).
- `CONTRIBUTING.md` : comment installer, lancer les tests, ouvrir une PR (10 lignes suffisent).
- `.github/ISSUE_TEMPLATE/` : un modèle « bug » et un modèle « faux positif / faux négatif ».

**Terminé quand** : l'onglet « Community Standards » de GitHub est au vert.

### Étape 0.7 — Baseline SMS rigoureux (3 h)

**Faire** : reprends ton modèle d'il y a 4 ans, mais évalue-le correctement. Télécharge la UCI SMS Spam Collection (fichier `SMSSpamCollection`, colonnes : étiquette ham/spam, texte, séparées par une tabulation) dans `data/raw/`.

```python
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, average_precision_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

df = pd.read_csv('data/raw/SMSSpamCollection', sep='\t', names=['label', 'text'])
X_tr, X_te, y_tr, y_te = train_test_split(
    df.text, (df.label == 'spam').astype(int), test_size=0.2, stratify=df.label, random_state=42)
model = make_pipeline(TfidfVectorizer(), LogisticRegression(max_iter=1000, class_weight='balanced'))
model.fit(X_tr, y_tr)
print(classification_report(y_te, model.predict(X_te)))
print('PR-AUC', average_precision_score(y_te, model.predict_proba(X_te)[:, 1]))
```

Sauvegarde les métriques dans `docs/metrics/sms_baseline.json`. Note le nombre de faux positifs : c'est lui qui compte pour la confiance des utilisateurs.

**Piège** : 96 % d'accuracy sur un jeu où 87 % des messages sont légitimes est un résultat banal. Regarde la précision et le rappel de la classe spam.

**Terminé quand** : un script `scripts/train_sms_baseline.py` reproduit les métriques d'une seule commande.

### Étape 0.8 — Écrire `docs/phishing-101.md` (3 h)

Rédige avec tes propres mots, sans copier : (1) définition et variantes (phishing, spear phishing, smishing, vishing, quishing, BEC) ; (2) la chaîne d'attaque (prétexte, leurre, domaine ou page trompeuse, collecte d'identifiants, exfiltration) ; (3) techniques de trompe-l'œil sur les URLs (typosquatting, sous-domaines, homographes, raccourcisseurs) ; (4) authentification email (SPF, DKIM, DMARC en une phrase chacun) ; (5) comment un utilisateur peut reconnaître une attaque ; (6) correspondance MITRE ATT&CK (T1566.001, .002, .003, T1204).

**Pour apprendre** : fais la salle « Phishing » et le début du parcours SOC Level 1 sur TryHackMe, lis un rapport trimestriel de l'APWG.

**Terminé quand** : quelqu'un de non technique comprend ton document en 10 minutes (fais-le relire).

### Étape 0.9 — Planifier le travail (1 h)

Dans GitHub, crée un Project (tableau Kanban), un jalon (milestone) par module et un label par module. Transforme chaque étape de ce guide en issue (copie le titre). Cette trace publique d'avancement impressionne les recruteurs.

**Clôture du module 0** : CI verte, README, `phishing-101.md`, baseline reproductible, issues créées. Fusionne la PR et tague `v0.0.1`.

---

## Module 1 — Données et détection URL / texte / email (semaines 2 à 4)

### Étape 1.1 — Scripts de collecte reproductibles (3 h)

**Faire** : crée `scripts/fetch_feeds.py` qui télécharge dans `data/raw/` avec horodatage dans le nom de fichier :

- phishing : le flux communautaire d'OpenPhish (`https://openphish.com/feed.txt`) ; PhishTank si l'inscription est ouverte ; URLhaus (`https://urlhaus.abuse.ch/downloads/csv_recent/`), mais attention : URLhaus recense surtout des URLs de distribution de malwares, filtre sur les étiquettes pertinentes ou garde-les dans une classe séparée ;
- légitimes : la liste Tranco (`https://tranco-list.eu/`) ; télécharge une version datée (identifiant de liste) pour que ton expérience soit reproductible.

Lis les conditions d'utilisation de chaque source et note-les dans `docs/data-sources.md` (licence, fréquence de mise à jour, limites).

**Piège** : les flux de phishing sont éphémères (les sites sont supprimés en heures ou jours). Archive ce que tu collectes avec sa date : c'est ta seule façon de faire un split temporel plus tard. Lance la collecte une fois par jour avec un cron ou un workflow GitHub Actions planifié, dès maintenant.

**Terminé quand** : `python scripts/fetch_feeds.py` produit des fichiers horodatés et `docs/data-sources.md` existe.

### Étape 1.2 — Schéma commun et nettoyage (3 h)

Crée `scripts/build_dataset.py` qui produit `data/processed/urls.parquet` avec les colonnes : `url`, `label` (1 = phishing), `source`, `first_seen`, `host`, `registered_domain`.

- Parse avec `urllib.parse.urlsplit`, mets l'hôte en minuscules.
- Utilise `tldextract` pour obtenir le domaine enregistré. Pour éviter qu'il télécharge la liste des suffixes à chaque exécution : `tldextract.TLDExtract(suffix_list_urls=())` utilise l'instantané embarqué.
- Supprime les doublons exacts, puis limite le nombre d'URLs par domaine enregistré (par exemple 5 max) pour qu'un seul site ne domine pas.

**Terminé quand** : le fichier parquet existe, avec un rapport de `df.groupby('label').size()` et `df.registered_domain.nunique()`.

### Étape 1.3 — Repérer les biais avant d'entraîner (2 h)

C'est l'étape qui distingue un projet sérieux. Vérifie :

- **Biais de chemin** : les domaines Tranco sont des pages d'accueil (sans chemin), les URLs de phishing ont souvent un chemin profond. Un modèle peut apprendre « a un chemin = phishing » et être inutile en vrai. Remède : compare avec un jeu qui contient des URLs légitimes avec chemins (dataset PhiUSIIL) et teste ton modèle avec et sans les features de chemin.
- **Biais de source** : si toutes les URLs de phishing viennent d'une source, le modèle apprend la source. Évalue en entraînant sur une source et en testant sur une autre.
- **Fuite par domaine** : le même domaine ne doit jamais être à la fois dans l'entraînement et dans le test.

Note tes constats dans `docs/data-bias.md`.

**Terminé quand** : tu sais expliquer en 2 phrases chaque biais et ce que tu as fait pour l'atténuer.

### Étape 1.4 — Split temporel et groupé (1 h)

Trie par `first_seen`. Entraînement = les premiers 70 %, validation = les 15 % suivants, test = les 15 % les plus récents, en vérifiant qu'aucun `registered_domain` n'apparaît dans deux blocs. Écris cette logique dans `src/phishguard/data/split.py` avec un test unitaire qui vérifie l'absence de recouvrement.

**Terminé quand** : le test d'absence de fuite passe.

### Étape 1.5 — Extracteur de features URL (6 h)

Crée `src/phishguard/urls/features.py`. Commence simple, avec un test par feature :

```python
import math, re
from urllib.parse import urlsplit
import tldextract

_ext = tldextract.TLDExtract(suffix_list_urls=())
KEYWORDS = ('login', 'verify', 'secure', 'account', 'update', 'bank', 'confirm')

def entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))

def url_features(url: str) -> dict:
    parts = urlsplit(url)
    ext = _ext(url)
    host = parts.hostname or ''
    return {
        'url_len': len(url),
        'host_len': len(host),
        'n_subdomains': len([s for s in ext.subdomain.split('.') if s]),
        'has_ip_host': bool(re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+', host)),
        'has_at': '@' in parts.netloc,
        'n_hyphens': host.count('-'),
        'is_punycode': 'xn--' in host,
        'host_entropy': entropy(host),
        'path_len': len(parts.path),
        'n_digits': sum(ch.isdigit() for ch in url),
        'is_https': parts.scheme == 'https',
        'kw_hits': sum(k in url.lower() for k in KEYWORDS),
    }
```

Ajoute ensuite, une par une, en mesurant chaque fois le gain :

1. **Typosquatting** : distance minimale entre le domaine enregistré et une liste de 100 à 200 marques (`rapidfuzz.distance.Levenshtein`), plus un indicateur « contient le nom d'une marque mais n'est pas son domaine officiel ».
2. **Homographes** : décode le Punycode avec `host.encode('ascii').decode('idna')`, puis vérifie avec `unicodedata.name(c)` si l'hôte mélange plusieurs écritures (latin + cyrillique).
3. **TLD** : fréquence du suffixe côté phishing (attention au biais de collecte).
4. **Raccourcisseurs** : liste de domaines connus (bit.ly et équivalents).

**Piège** : écris tes features comme des fonctions pures, sans accès réseau : elles devront être portées à l'identique en TypeScript pour l'extension (module 5). Garde l'ensemble de features petit et simple dès maintenant.

**Terminé quand** : 25 tests unitaires environ passent, avec des cas pièges (URL sans schéma, IPv6, très longue URL, caractères Unicode, `http://a@b.com`).

### Étape 1.6 — Entraîner et comparer les modèles URL (4 h)

Dans `scripts/train_url.py`, entraîne trois modèles : régression logistique (avec standardisation), Random Forest, LightGBM. Ajoute la fonction de métrique qui compte vraiment :

```python
from sklearn.metrics import roc_curve

def recall_at_fpr(y_true, y_score, max_fpr=0.01):
    fpr, tpr, _ = roc_curve(y_true, y_score)
    return float(tpr[fpr <= max_fpr].max())
```

Rapporte pour chaque modèle : PR-AUC, recall à FPR = 1 %, recall à FPR = 0,1 %, temps d'inférence par URL. Sélectionne les hyperparamètres sur la validation, jamais sur le test. Sauvegarde le meilleur modèle et ses métriques (`models/url_lgbm_v1.joblib`, `docs/metrics/url_v1.json`).

**Terminé quand** : `make train-url` (ajoute un `Makefile`) reproduit les résultats.

### Étape 1.7 — Évaluation réaliste (2 h)

Dans la vraie vie, le phishing représente une infime fraction des URLs visitées (bien moins de 1 %). Rééchantillonne ton test pour simuler 0,1 % et 1 % de phishing, et calcule la **précision** : tu verras qu'un faux positif à 1 % peut produire plus de fausses alertes que de vraies. Documente-le dans `docs/evaluation.md` et justifie ton seuil de décision.

**Terminé quand** : un tableau « prévalence vs précision » est dans la doc.

### Étape 1.8 — Analyse d'erreurs (2 h)

Extrais les 50 pires faux positifs et les 50 pires faux négatifs. Classe-les (service légitime avec long paramètre ? hébergeur gratuit détourné ? domaine neuf mais honnête ?) et écris `docs/error-analysis-url.md`. Les faux négatifs (phishing hébergé sur un domaine réputé, par exemple un service de stockage de fichiers) sont ceux que les features statiques ne verront jamais : cela justifie le module 2.

**Terminé quand** : tu as au moins 3 catégories d'erreurs avec des exemples et des pistes d'amélioration.

### Étape 1.9 — Modèle de texte (SMS / messages) (6 h)

1. Compare TF-IDF mots et TF-IDF caractères (`analyzer='char_wb', ngram_range=(2, 5)`), avec régression logistique et `LinearSVC`.
2. Ajoute des features « smishing » faites à la main : présence d'URL, d'un numéro court, de mots d'urgence, de majuscules, de montants.
3. Pour le français et l'arabe, les données publiques sont rares. Constitue un petit jeu complémentaire à partir d'exemples publics (signalements, sites de sensibilisation des CERT), anonymise tout, et documente la taille et les limites honnêtement.
4. Optionnel : embeddings multilingues (`sentence-transformers`, modèle `paraphrase-multilingual-MiniLM-L12-v2`) + régression logistique. Compare le gain de qualité avec le coût (taille, latence).

**Terminé quand** : un tableau compare au moins 3 approches avec précision, rappel, taille et latence.

### Étape 1.10 — Parseur d'emails (6 h)

Crée `src/phishguard/email/parser.py`. Utilise uniquement la bibliothèque standard `email` pour l'analyse, et `BeautifulSoup` (parseur `html.parser`) pour le HTML.

```python
from email import policy
from email.parser import BytesParser

def parse_eml(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return {
        'from': msg['From'],
        'reply_to': msg['Reply-To'],
        'return_path': msg['Return-Path'],
        'auth_results': msg.get_all('Authentication-Results') or [],
        'subject': msg['Subject'],
        'body': msg.get_body(preferencelist=('html', 'plain')),
    }
```

Puis extrais : le résultat SPF/DKIM/DMARC dans `Authentication-Results` (`pass`, `fail`, `none`), l'écart entre le domaine de `From`, de `Reply-To` et de `Return-Path`, les liens du corps (texte affiché vs `href`), les pièces jointes à extension à risque, le texte masqué (taille de police 0, couleur identique au fond).

**Piège** : un email est une entrée hostile. Ne rends jamais le HTML, n'exécute rien, limite la taille, protège-toi des emails malformés (c'est ce que le fuzzing du module 4 vérifiera).

**Terminé quand** : le parseur gère 10 emails de test variés (crée-les toi-même plus 5 exemples tirés de corpus publics) sans erreur.

### Étape 1.11 — Score email : règles puis modèle (4 h)

Commence par un score à base de règles transparentes (par exemple : DMARC en échec +30, `Reply-To` sur un autre domaine +20, lien dont le domaine affiché diffère de la cible +35). Évalue sur un corpus d'emails de phishing public (Nazario) face à un corpus d'emails légitimes (corpus public SpamAssassin, partie « ham »). Si les données le permettent, entraîne ensuite un petit modèle sur ces signaux et compare-le aux règles.

**Terminé quand** : tu as des métriques règles vs modèle, avec une réserve honnête sur la représentativité de ces corpus anciens.

### Étape 1.12 — Model card, commande unique et release (2 h)

Écris `docs/model-card-url.md` et `docs/model-card-text.md` : usage prévu, données (sources, dates, tailles), métriques, limites connues, biais, ce que le modèle ne fait pas. Ajoute `make data`, `make train` et `make test`.

**Clôture du module 1** : un inconnu peut cloner le dépôt, lancer `make data train` et retrouver tes métriques. Fusionne, tague `v0.1.0`, publie une release GitHub.

---

## Module 2 — Threat Intelligence et fusion des signaux (semaines 5 et 6)

### Étape 2.1 — Comptes, clés d'API et gestion des secrets (1 h)

**Faire** : crée les comptes et récupère les clés : VirusTotal (clé gratuite dans ton profil), Google Cloud (crée un projet, active l'API Safe Browsing, crée une clé d'API restreinte à cette API), urlscan.io (clé dans les paramètres), et éventuellement AbuseIPDB.

- Mets les clés dans un fichier `.env` **jamais commité** et fournis un `.env.example` avec des valeurs vides (`VT_API_KEY=`, `GSB_API_KEY=`, `URLSCAN_API_KEY=`).
- Charge-les avec `pydantic-settings` dans `src/phishguard/config.py`.
- Vérifie que le hook gitleaks de l'étape 0.4 fonctionne toujours.

**Piège** : si tu commites une clé par erreur, supprimer le commit ne suffit pas, la clé est compromise. Révoque-la immédiatement et regénère-en une.

**Terminé quand** : le projet démarre sans clé (les enrichisseurs sont simplement désactivés) et avec clés (ils s'activent).

### Étape 2.2 — Interface commune des enrichisseurs (2 h)

Définis dans `src/phishguard/enrichers/base.py` un contrat unique pour toutes les sources :

```python
from abc import ABC, abstractmethod
from pydantic import BaseModel

class Signal(BaseModel):
    source: str                 # 'virustotal', 'rdap', ...
    status: str                 # 'ok' | 'error' | 'skipped' | 'timeout'
    risk: float = 0.0           # contribution normalisée de 0 à 1
    evidence: dict = {}         # données brutes utiles pour l'analyste
    latency_ms: int = 0

class Enricher(ABC):
    name: str
    @abstractmethod
    async def enrich(self, url: str, domain: str) -> Signal: ...
```

Chaque enrichisseur ne lève jamais d'exception vers l'appelant : il renvoie un `Signal` avec `status='error'`. Un service tiers en panne ne doit jamais faire tomber ton API.

**Terminé quand** : un faux enrichisseur de test respecte l'interface et un test vérifie qu'une exception interne devient un signal `error`.

### Étape 2.3 — Garde-fou réseau anti-SSRF (4 h)

Crée `src/phishguard/security/netguard.py`. Même si tu comptes ne contacter que des API tierces, tout code qui suivra un jour une redirection ou récupérera une page doit passer par ce garde-fou.

1. Autorise uniquement les schémas `http` et `https`.
2. Résous le nom de domaine toi-même (`socket.getaddrinfo`) et refuse si l'une des adresses est privée, de boucle locale, de lien local (dont l'adresse du service de métadonnées cloud 169.254.169.254), réservée ou multicast (module `ipaddress` : `is_private`, `is_loopback`, `is_link_local`, `is_reserved`, `is_multicast`).
3. Connecte-toi à l'adresse déjà validée, pas au nom (sinon un attaquant peut changer la réponse DNS entre la vérification et la connexion : attaque par « DNS rebinding »).
4. Limite le nombre de redirections et revalide chaque saut.
5. Timeouts courts et taille de réponse maximale.

**Décision de conception à documenter dans `docs/ssrf.md`** : ton serveur ne visite jamais l'URL analysée. Il interroge des tiers à son sujet. Si tu ajoutes un jour l'expansion des liens raccourcis, elle passe par le garde-fou, en option.

**Terminé quand** : une batterie de tests refuse `http://127.0.0.1`, `http://localhost`, `http://169.254.169.254`, `http://[::1]`, `http://0x7f000001`, `http://2130706433`, `file:///etc/passwd` et un domaine qui résout vers une IP privée (simule-le avec un mock).

### Étape 2.4 — Enrichisseur Google Safe Browsing (3 h)

Il existe une API de recherche directe (Lookup) et une API à préfixes de hachage (Update) qui préserve mieux la vie privée. Vérifie dans la documentation Google quelle version est recommandée aujourd'hui.

- Version 1 : appel de recherche directe, **uniquement si l'utilisateur a activé l'enrichissement**, car l'URL complète est envoyée à Google.
- Réponse : une liste de correspondances par type de menace (`SOCIAL_ENGINEERING`, `MALWARE`...). Une correspondance donne `risk=1.0` et devient une règle dure.
- Version 2 (plus tard) : base locale de préfixes de hachage, ce qui évite d'envoyer l'URL complète. C'est un excellent sujet d'article.

**Terminé quand** : des tests avec réponses simulées (bibliothèque `respx`) couvrent le cas « trouvé », « non trouvé », « erreur 429 » et « timeout ».

### Étape 2.5 — Enrichisseur VirusTotal (3 h)

- Pour un domaine : `GET /api/v3/domains/{domaine}`. Pour une URL : l'identifiant est l'URL encodée en base64 « url-safe » **sans** les `=` de remplissage : `GET /api/v3/urls/{id}`.
- En-tête d'authentification : `x-apikey`.
- Lis `last_analysis_stats` (nombre de moteurs `malicious`, `suspicious`, `harmless`) ; calcule un risque, par exemple `min(1, (malicious + 0.5 * suspicious) / 5)`.
- Respecte le palier gratuit (environ 4 requêtes par minute et 500 par jour au moment de l'écriture) et lis les conditions : usage non commercial seulement. Implémente un limiteur local (`aiolimiter`) et mets les résultats en cache.

**Terminé quand** : le respect de la limite de débit est testé (le cinquième appel en une minute attend ou renvoie `skipped`).

### Étape 2.6 — Enrichisseur urlscan.io (3 h)

- Recherche de scans existants : `GET https://urlscan.io/api/v1/search/?q=domain:exemple.com` (en-tête `API-Key`).
- Soumission d'un scan : réservée à l'option « analyse approfondie ». **Utilise une visibilité non publique** (`unlisted` ou `private`) : un scan public expose l'URL, qui peut contenir des données personnelles.
- Les résultats utiles : verdict, marques ciblées détectées, adresse IP et pays du serveur, capture d'écran (à afficher avec précaution, jamais à rendre en HTML).

**Terminé quand** : la recherche fonctionne avec cache et le mode soumission est derrière un drapeau de configuration désactivé par défaut.

### Étape 2.7 — Enrichisseurs RDAP et DNS (4 h)

- **RDAP** (successeur moderne de WHOIS, format JSON) : interroge un service d'amorçage comme `https://rdap.org/domain/exemple.com` ou le serveur du registre. Extrais la date d'enregistrement (événement `registration`) pour calculer l'âge du domaine : un domaine de moins de 30 jours est un signal fort (c'est aussi une technique MITRE de préparation d'infrastructure, T1583.001).
- **DNS** (`dnspython`) : enregistrements A, MX, NS, TTL très bas, absence de MX pour un domaine qui prétend envoyer des emails, NS d'un fournisseur d'hébergement gratuit.
- **Certificate Transparency** (optionnel) : `crt.sh` en JSON pour connaître la date du premier certificat. Le service est lent et parfois instable : timeout strict, cache long, jamais bloquant.

**Piège** : certains registres n'exposent pas la date. Un signal manquant n'est pas un signal de risque : renvoie `status='error'` ou `risk=0`, pas `risk=1`.

**Terminé quand** : l'âge du domaine est calculé correctement sur 5 domaines connus de ton choix.

### Étape 2.8 — Client HTTP robuste, cache et limitation (4 h)

Crée un module `src/phishguard/enrichers/http.py` : `httpx.AsyncClient` partagé, timeouts distincts (connexion 2 s, lecture 3 s), tentatives avec backoff exponentiel (`tenacity`) uniquement sur les erreurs temporaires (429, 5xx), cache avec durée de vie (`cachetools.TTLCache` en mémoire pour commencer, SQLite ensuite) et disjoncteur : après 5 échecs consécutifs, la source est mise en pause 60 secondes.

**Terminé quand** : des tests simulent une panne de source et montrent que le disjoncteur s'ouvre, puis se referme.

### Étape 2.9 — Orchestrateur parallèle avec budget de temps (3 h)

Dans `src/phishguard/enrichers/orchestrator.py`, lance tous les enrichisseurs actifs en parallèle avec `asyncio.gather` sous un budget global de 2,5 secondes. Les sources trop lentes sont marquées `timeout`, les autres sont utilisées. L'analyse ne doit **jamais** échouer parce qu'une source échoue : elle dégrade.

**Terminé quand** : un test avec une source lente (sommeil de 10 s) montre une réponse en moins de 3 s avec ce signal marqué `timeout`.

### Étape 2.10 — Fusion du score (4 h)

Dans `src/phishguard/fusion/score.py` :

1. **Calibre** les probabilités du modèle ML (`CalibratedClassifierCV`) pour que 0,9 signifie réellement environ 90 %.
2. **Règles dures** : correspondance Safe Browsing = phishing ; whitelist personnelle = sûr.
3. **Combinaison pondérée** des signaux restants (modèle, âge du domaine, VirusTotal, urlscan, DNS).
4. **Seuils** : sûr < 30, suspect de 30 à 70, phishing > 70 (à ajuster d'après l'étape 1.7).
5. Garde la fonction pure et testable : même entrée, même sortie ; paramètres dans un fichier de configuration versionné.

Écris des tests « table de vérité » : par exemple « modèle 0,2 + domaine de 3 jours + 6 moteurs VirusTotal positifs donne phishing ».

**Terminé quand** : 15 cas de test documentent le comportement et tu peux expliquer chaque pondération en entretien.

### Étape 2.11 — Correspondance MITRE ATT&CK (2 h)

Associe chaque situation à une technique (fichier `src/phishguard/fusion/mitre.py`) :

| Situation détectée | Technique |
| --- | --- |
| Lien malveillant dans un message | T1566.002 Spearphishing Link |
| Pièce jointe à risque | T1566.001 Spearphishing Attachment |
| Phishing via service tiers (messagerie, réseaux sociaux) | T1566.003 Spearphishing via Service |
| L'utilisateur est incité à cliquer ou ouvrir | T1204 User Execution (.001 Malicious Link) |
| Collecte d'informations par message | T1598 Phishing for Information |
| Domaine récent ou typosquatté | T1583.001 Acquire Infrastructure: Domains |

Vérifie ces identifiants sur le site MITRE avant de les figer.

**Terminé quand** : chaque verdict phishing renvoie au moins une technique avec son intitulé.

### Étape 2.11 bis — Schéma de réponse (1 h)

Fixe le contrat JSON de sortie et documente-le : `verdict`, `score`, `confidence`, `reasons` (liste), `signals` (par source), `mitre`, `model_version`, `enrichment` (`used` ou `skipped`), `latency_ms`. Ce schéma ne changera presque plus : l'extension et le bot en dépendront.

### Étape 2.12 — Tests de contrat et de vie privée (3 h)

- Tests avec réponses simulées pour chaque enrichisseur (`respx`).
- **Test de vie privée** : avec l'enrichissement désactivé, vérifie qu'**aucune requête sortante** n'est émise (le mock échoue si une requête part).
- Test de dégradation : toutes les sources en panne, le verdict ML seul est tout de même renvoyé.

**Clôture du module 2** : fusionne et tague `v0.2.0`. Rédige dans le journal : « quelle source m'a le plus surpris et pourquoi ».

---

## Module 3 — Explicabilité et robustesse adversariale (semaines 7 et 8)

### Étape 3.1 — Explicabilité des modèles d'URL avec SHAP (4 h)

```python
import shap
explainer = shap.TreeExplainer(lgbm_model)
values = explainer.shap_values(X_sample)
shap.summary_plot(values, X_sample)
```

Produis le graphique global (quelles features pèsent le plus) et, pour une URL donnée, les 3 features qui ont le plus poussé vers « phishing ». Enregistre le graphique global dans `docs/img/` pour la model card.

**Piège** : selon la version de SHAP et du modèle, les valeurs peuvent être renvoyées par classe (liste de deux tableaux) ou en un seul tableau. Vérifie la forme avant d'indexer.

**Terminé quand** : pour 10 URLs, tu peux nommer les 3 raisons principales, et elles ont du sens.

### Étape 3.2 — Du jargon aux phrases (4 h)

Crée `src/phishguard/explain/reasons.py` et un fichier de gabarits `explain/templates.fr.yml` (puis `en`, `ar`). Pour chaque feature qui compte, un gabarit en langage simple :

- `domain_age_days < 30` : « Ce site a été créé il y a seulement {n} jours. »
- `brand_lookalike` : « L'adresse ressemble à celle de {marque} mais n'est pas la sienne. »
- `mixed_script` : « L'adresse contient des lettres d'alphabets différents pour imiter un site connu. »
- `link_text_mismatch` : « Le lien affiché ne mène pas à l'endroit annoncé. »

Règles : maximum 3 raisons, classées par poids, uniquement les features compréhensibles, ajoute **toujours un conseil d'action** (« N'entrez aucun mot de passe. Ouvrez le site en tapant vous-même son adresse. »).

**Piège** : ne répète pas le contenu d'un message de l'utilisateur dans l'explication sans l'échapper, sinon tu crées toi-même une injection dans l'interface.

**Terminé quand** : une personne non technique comprend l'explication de 5 verdicts sans aide.

### Étape 3.3 — Explications du modèle de texte (3 h)

Pour la régression logistique sur TF-IDF, multiplie les coefficients par les valeurs TF-IDF du message pour obtenir la contribution de chaque terme. Affiche les 3 à 5 termes qui ont le plus pesé, ou signale les catégories (urgence, argent, lien, demande de code).

**Terminé quand** : l'API renvoie des `reasons` pour le texte aussi.

### Étape 3.4 — Deux niveaux de sortie (1 h)

Dans le schéma : `reasons` (pour l'utilisateur) et `analyst` (valeurs SHAP, signaux bruts, seuils, versions). L'extension n'affiche `analyst` que si l'utilisateur déplie « Détails techniques ».

### Étape 3.5 — Catalogue des techniques d'évasion (3 h)

Crée `docs/evasion-catalog.md`. Pour chaque technique : description, vecteur (URL, texte, email), pourquoi elle peut tromper un modèle, ta contre-mesure prévue, et la référence correspondante dans MITRE ATLAS (par exemple la technique « Evade ML Model ») ou ATT&CK. À minima :

- **URL** : typosquatting, homographes, sous-domaines trompeurs (`paypal.com.exemple.xyz`), ajout de chemins ou paramètres bénins, domaine de confiance détourné (hébergeur de fichiers), URL très longue.
- **Texte** : homoglyphes, caractères de largeur nulle, séparation des mots par des symboles, leetspeak, ajout de texte légitime pour diluer le signal, message en image.
- **Email** : texte caché en HTML, lien dans une image, QR code (quishing).

**Terminé quand** : le catalogue contient au moins 12 techniques documentées.

### Étape 3.6 — Bibliothèque de perturbations (4 h)

Crée `src/phishguard/adversarial/perturb.py`, destinée **uniquement à évaluer et renforcer ton détecteur** :

```python
ZW = '\u200b'
HOMOGLYPHS = {'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с'}  # lettres cyrilliques

def insert_zero_width(text: str, every: int = 3) -> str:
    return ''.join(c + (ZW if i % every == 0 else '') for i, c in enumerate(text))

def swap_homoglyphs(text: str, rate: float = 0.3, seed: int = 0) -> str:
    import random
    rnd = random.Random(seed)
    return ''.join(HOMOGLYPHS[c] if c in HOMOGLYPHS and rnd.random() < rate else c for c in text)

def pad_benign(text: str, benign_words: list[str], n: int = 20) -> str:
    return text + ' ' + ' '.join(benign_words[:n])
```

Pour les URLs : ajout de sous-domaines, de chemins bénins, d'un paramètre long, passage en majuscules partielles. Chaque fonction est déterministe (graine fixe) pour que les résultats soient reproductibles.

**Terminé quand** : chaque perturbation a un test qui vérifie qu'elle modifie le texte sans le rendre vide.

### Étape 3.7 — Banc d'essai de robustesse (4 h)

Crée `scripts/robustness_benchmark.py` : pour chaque perturbation, applique-la aux échantillons de phishing du jeu de test, mesure le rappel avant/après (Δ recall) et le taux de faux positifs sur des échantillons légitimes perturbés de la même façon (une défense qui bloque tout n'est pas une défense). Produis un tableau Markdown dans `docs/robustness-report.md`.

Optionnel : lance `TextAttack` sur le modèle de texte pour une attaque automatisée plus agressive que tes perturbations manuelles.

**Terminé quand** : le premier rapport « avant défenses » est publié, avec les chiffres réels, même s'ils sont mauvais. Un rapport honnête vaut plus qu'un résultat parfait.

### Étape 3.8 — Défenses par normalisation (4 h)

Applique, **à l'entraînement comme à l'inférence**, un module `src/phishguard/security/normalize.py` :

1. `unicodedata.normalize('NFKC', s)`.
2. Suppression des caractères de catégorie Unicode « Cf » (formatage, dont la largeur nulle) et des caractères de contrôle.
3. Pliage des caractères confondables vers leur « squelette » selon l'UTS #39 (bibliothèque `confusable_homoglyphs` ou table dédiée).
4. Règle explicite : un nom d'hôte qui mélange plusieurs écritures reçoit un signal d'alerte fort.
5. Journalise quand la normalisation a modifié l'entrée (c'est en soi un indice suspect).

**Terminé quand** : le banc d'essai de l'étape 3.7 est relancé et le rappel sous perturbation s'améliore nettement sans augmenter les faux positifs.

### Étape 3.9 — Entraînement adversarial (3 h)

Augmente l'**ensemble d'entraînement uniquement** avec des versions perturbées des exemples de phishing (même étiquette). Réentraîne, évalue sur le jeu de test non perturbé **et** perturbé. Compare trois lignes dans ton rapport : modèle d'origine, normalisation seule, normalisation + entraînement adversarial.

**Piège** : si tu augmentes aussi le jeu de test, tu triches. Les perturbations du test doivent venir d'un générateur que le modèle n'a pas vu (nouvelle graine, nouvelles techniques).

**Terminé quand** : le tableau avant/après montre l'effet de chaque défense.

### Étape 3.10 — Test sur des messages rédigés par un LLM (4 h)

Les messages générés par des LLM sont grammaticalement parfaits : les détecteurs qui comptent sur les fautes d'orthographe y perdent beaucoup.

- Constitue un jeu de test **défensif et local** : quelques centaines de messages synthétiques (phishing et courriers légitimes d'entreprise, deux familles de même taille) avec des **domaines réservés** (`example.com`, `.test`) et sans coordonnées réelles. Ils ne sortent jamais de ta machine et ne sont jamais envoyés à personne.
- Mesure rappel **et** faux positifs : les messages professionnels bien écrits sont aussi un risque de faux positifs.
- Conclus honnêtement : le texte seul ne suffit plus, d'où l'importance des signaux d'infrastructure du module 2 (âge du domaine, réputation, concordance du lien).

**Terminé quand** : un chapitre « LLM-phishing » du rapport chiffre la dégradation et ce qui la compense.

### Étape 3.11 — Rapport de robustesse final (3 h)

Structure de `docs/robustness-report.md` : modèle de menace, méthodologie, jeux de données, résultats avant défenses, défenses, résultats après, limites, pistes futures. Ajoute un graphique de rappel par technique. C'est le document le plus valorisant du projet pour un recruteur sécurité, soigne-le.

### Étape 3.12 — Intégration et clôture (2 h)

Branche normalisation et explications dans le pipeline principal (`analyze_url`, `analyze_text`, `analyze_email`) avec des tests de bout en bout. Fusionne et tague `v0.3.0`.

---

## Module 4 — API et backend sécurisés (semaines 9 et 10)

### Étape 4.1 — Squelette FastAPI (2 h)

Crée `src/phishguard/api/main.py` avec une fonction `create_app()`, des routeurs séparés (`analyze.py`, `feedback.py`, `meta.py`) et une configuration via `pydantic-settings`. Charge les modèles **une seule fois au démarrage** (gestionnaire `lifespan`), pas à chaque requête.

```
pip install fastapi 'uvicorn[standard]' pydantic-settings slowapi structlog
uvicorn phishguard.api.main:app --reload
```

**Terminé quand** : `GET /v1/health` répond et la documentation interactive `/docs` s'affiche.

### Étape 4.2 — Schémas d'entrée stricts (2 h)

Toute entrée est hostile. Contraintes de taille et de format dès le schéma :

```python
from pydantic import BaseModel, Field

class UrlRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    use_threat_intel: bool = False

class TextRequest(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    use_threat_intel: bool = False
```

Pour l'email : taille maximale d'1 Mo, refus des types de contenu inattendus. Rejette les caractères de contrôle et renvoie une erreur 422 claire.

**Terminé quand** : des tests envoient une URL de 100 000 caractères, un texte vide, un JSON malformé et un octet nul, et obtiennent tous une erreur propre.

### Étape 4.3 — Couche service et endpoints (4 h)

Sépare la logique de la couche HTTP : `service.py` expose `analyze_url`, `analyze_text`, `analyze_email` (déjà écrites aux modules 1 à 3). Endpoints : `POST /v1/analyze/url`, `/v1/analyze/text`, `/v1/analyze/email` (téléversement de fichier `.eml`), `GET /v1/model` (version, date d'entraînement, empreinte SHA-256), `POST /v1/feedback`. Le calcul ML est synchrone : exécute-le dans un pool de threads (`run_in_threadpool`) pour ne pas bloquer la boucle asynchrone.

**Terminé quand** : les 3 endpoints d'analyse renvoient le schéma figé à l'étape 2.11 bis.

### Étape 4.4 — Authentification et limitation de débit (3 h)

- Clé d'API dans l'en-tête `X-API-Key`. Stocke uniquement l'empreinte (SHA-256) des clés en base SQLite, jamais la clé en clair.
- Deux niveaux : anonyme (quota bas, par adresse IP) et avec clé (quota plus élevé). Utilise `slowapi`.
- **Piège** : derrière un proxy inverse, l'IP vue par l'API est celle du proxy. Configure correctement `X-Forwarded-For` et ne fais confiance à cet en-tête que s'il vient de ton proxy, sinon n'importe qui peut contourner la limite en le falsifiant.

**Terminé quand** : un test envoie 100 requêtes rapides et reçoit des 429 après le seuil.

### Étape 4.5 — Durcissement HTTP (2 h)

CORS restrictif (liste explicite d'origines, pas `*` pour les endpoints avec clé), en-têtes de sécurité (`X-Content-Type-Options: nosniff`, `Cache-Control: no-store`), limite de taille de corps de requête, timeouts, messages d'erreur sans trace de pile. Désactive les routes de débogage en production.

**Terminé quand** : l'analyse de tes en-têtes avec l'outil en ligne SecurityHeaders ou avec `curl -I` ne montre aucun défaut évident.

### Étape 4.6 — Journalisation sans données personnelles (2 h)

Avec `structlog`, journalise un identifiant de requête, l'endpoint, le verdict, la latence, la version du modèle. **Ne journalise jamais** le contenu des messages ni les URLs complètes. Écris un test qui analyse une URL contenant un jeton secret et vérifie que ce jeton n'apparaît dans aucune ligne de log.

**Terminé quand** : ce test passe.

### Étape 4.7 — Tests, fuzzing et propriétés (5 h)

- `pytest` + `TestClient` de FastAPI : un test par endpoint et par cas d'erreur.
- **Fuzzing avec `hypothesis`** sur `url_features`, la normalisation et `parse_eml` : propriété « ne lève jamais d'exception inattendue et renvoie une sortie bornée ». C'est un exercice très formateur : les parseurs sont la cible classique des attaquants.
- Tests de non-régression : chaque bug trouvé devient un test.

**Terminé quand** : la couverture dépasse 70 % et `hypothesis` a tourné sans échec sur 1 000 exemples.

### Étape 4.8 — Pipeline de sécurité dans la CI (3 h)

Ajoute au workflow : `bandit -r src` (analyse statique du code Python), `pip-audit` (dépendances vulnérables), `gitleaks` (secrets), `trivy image` (image Docker, voir 4.9). Active Dependabot (`.github/dependabot.yml`) pour Python, npm et GitHub Actions. Épingle les versions avec un fichier de verrouillage (`pip-compile` ou `uv lock`).

**Terminé quand** : la CI échoue volontairement si tu ajoutes une dépendance connue vulnérable (teste-le puis annule).

### Étape 4.9 — Image Docker durcie (3 h)

```
FROM python:3.12-slim AS build
WORKDIR /app
COPY pyproject.toml .
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
RUN useradd --create-home app
COPY --from=build /install /usr/local
COPY models /app/models
USER app
WORKDIR /app
HEALTHCHECK CMD python -c 'import urllib.request; urllib.request.urlopen("http://localhost:8000/v1/health")'
CMD uvicorn phishguard.api.main:app --host 0.0.0.0 --port 8000
```

Points à retenir : build en deux étapes, utilisateur non root, aucune clé dans l'image (variables d'environnement au lancement), image minimale. Ajoute un `docker-compose.yml` avec l'API et un volume pour SQLite.

**Terminé quand** : `docker compose up` fonctionne sur une machine propre et `trivy image` ne signale aucune faille critique.

### Étape 4.10 — Feedback sans risque (2 h)

`POST /v1/feedback` reçoit : domaine (pas l'URL complète), verdict reçu, jugement de l'utilisateur (faux positif ou faux négatif), horodatage. Stocke dans une table de quarantaine. **Aucun réentraînement automatique** : un attaquant pourrait empoisonner le modèle en envoyant de faux retours. Tu relis les signalements toi-même, par lots.

**Terminé quand** : le feedback est limité en débit, validé, et un test vérifie qu'il n'influence pas le modèle en cours d'utilisation.

### Étape 4.11 — Export du modèle pour l'extension (4 h)

L'extension doit faire l'inférence **localement**. Pour un modèle LightGBM, le plus simple et le plus robuste en première version n'est pas ONNX mais l'export des arbres en JSON :

```python
import json
with open('models/url_lgbm_v1.json', 'w') as f:
    json.dump(model.booster_.dump_model(), f)
```

En JavaScript, la prédiction est une courte boucle sur les arbres (voir étape 5.3). ONNX (`onnxmltools`, `onnxruntime-web`) reste une option plus tard si tu veux d'autres types de modèles.

**Fichiers de référence communs** : génère `tests/golden/url_vectors.json` qui contient pour 200 URLs les valeurs de features **et** la probabilité calculée par Python. Les tests TypeScript devront retrouver exactement ces valeurs (à 1e-6 près). Sans ce garde-fou, les deux implémentations divergent en silence.

**Terminé quand** : le fichier JSON du modèle et le fichier de vecteurs de référence sont produits par une commande (`make export`).

### Étape 4.12 — Registre de modèles et signature (3 h)

Chaque modèle publié a un fichier `manifest.json` : version, date, empreinte SHA-256, métriques, version de l'extracteur de features. Signe le manifeste avec une clé Ed25519 (outil `minisign`, ou bibliothèque `cryptography`) : l'extension vérifiera la signature avant d'utiliser un modèle téléchargé (voir module 6). Garde la clé privée hors du dépôt.

**Terminé quand** : un script signe un modèle et un autre script de test vérifie la signature, en échouant si un seul octet est modifié.

### Étape 4.13 — Test de charge et documentation (3 h)

Utilise `locust`, `k6` ou `hey` pour envoyer 50 requêtes par seconde pendant une minute sur l'analyse d'URL sans enrichissement et note la latence médiane et au 95e centile. Documente l'API : exemples `curl`, codes d'erreur, limites, politique de confidentialité de l'API (`docs/api.md`).

**Clôture du module 4** : fusionne et tague `v0.4.0`. Objectif de performance : médiane sous 50 ms sans enrichissement.

---

## Module 5 — Extension navigateur et canaux de messagerie (semaines 11 à 13)

### Étape 5.1 — Choisir l'architecture (1 h)

Relis la décision du module 5 (partie I) et fige-la dans `docs/extension-design.md` :

- **Analyse automatique de toutes les pages** : nécessite les permissions `tabs` ou `webNavigation`, qui provoquent un avertissement effrayant à l'installation (« lire votre historique de navigation »). Décision recommandée : **optionnelle**, demandée au moment où l'utilisateur l'active.
- **Analyse à la demande** (clic sur l'icône, clic droit sur un lien) : permission `activeTab`, aucun avertissement.
- **Gmail** : un script de contenu sur `https://mail.google.com/*` (avertissement « lire et modifier vos données sur mail.google.com », qu'il faudra justifier clairement).

### Étape 5.2 — Projet TypeScript et manifeste (3 h)

Dans `extension/` : Node 20, TypeScript, un outil de build (Vite avec le plugin `@crxjs/vite-plugin`, ou simplement `esbuild`), `vitest` pour les tests. Manifeste minimal :

```
{
  "manifest_version": 3,
  "name": "__MSG_extName__",
  "version": "0.1.0",
  "default_locale": "fr",
  "action": { "default_popup": "popup.html" },
  "background": { "service_worker": "background.js", "type": "module" },
  "permissions": ["storage", "activeTab", "contextMenus"],
  "optional_permissions": ["tabs"],
  "optional_host_permissions": ["https://api.example.org/*"],
  "content_scripts": [{
    "matches": ["https://mail.google.com/*"],
    "js": ["gmail.js"],
    "run_at": "document_idle"
  }]
}
```

**Terminé quand** : l'extension se charge dans `chrome://extensions` (mode développeur, « Charger l'extension non empaquetée ») et affiche une fenêtre contextuelle vide.

### Étape 5.3 — Porter l'extracteur et le modèle en TypeScript (8 h)

C'est l'étape la plus technique. Réécris `url_features` en TypeScript à l'identique (utilise la classe `URL` du navigateur et une liste de suffixes publics embarquée, par exemple la bibliothèque `tldts`). Écris ensuite la prédiction des arbres :

```js
const evalTree = (node, x) => {
  while (node.leaf_value === undefined) {
    node = x[node.split_feature] <= node.threshold ? node.left_child : node.right_child;
  }
  return node.leaf_value;
};
const sigmoid = (z) => 1 / (1 + Math.exp(-z));
export const predict = (model, x) =>
  sigmoid(model.tree_info.reduce((s, t) => s + evalTree(t.tree_structure, x), 0));
```

Vérifie les détails de ton export (gestion des valeurs manquantes, types de décision) et **évite les features catégorielles** dans le modèle destiné à l'extension. Les tests `vitest` chargent `tests/golden/url_vectors.json` et exigent des résultats identiques à ceux de Python.

**Piège** : les différences de découpage d'URL entre Python et JavaScript (cas limites : IDN, ports, URL sans schéma) sont la première source d'écarts. Chaque écart découvert devient un cas dans les vecteurs de référence.

**Terminé quand** : 200 vecteurs de référence passent côté TypeScript.

### Étape 5.4 — Service worker : analyse et badge (4 h)

Dans `background.ts` : une fonction `analyzeUrl(url)` (extracteur + modèle + règles locales : IP en hôte, mélange d'alphabets, marque imitée), un cache en mémoire par URL, l'affichage du verdict via `chrome.action.setBadgeText` et `setBadgeBackgroundColor`, et une entrée de menu contextuel « Analyser ce lien avec PhishGuard » (`chrome.contextMenus`). La liste blanche de l'utilisateur est stockée dans `chrome.storage.local`.

**Piège MV3** : le service worker peut être arrêté à tout moment ; ne garde pas d'état important en variable globale, charge le modèle à la demande et mets en cache dans `chrome.storage.session`.

**Terminé quand** : un clic sur l'icône sur 10 sites variés donne un verdict correct et rapide (moins de 50 ms hors chargement du modèle).

### Étape 5.5 — Fenêtre contextuelle (popup) (4 h)

Contenu : verdict avec icône et couleur **et** texte (pas seulement la couleur), une phrase d'explication et un conseil d'action, un bouton « Détails techniques » déplié à la demande, « Signaler une erreur », « Toujours faire confiance à ce site ». Utilise du HTML/CSS simple ou Preact. Insère le texte avec `textContent`, jamais avec `innerHTML`.

**Terminé quand** : l'interface est utilisable au clavier et un testeur non technique comprend le verdict.

### Étape 5.6 — Script de contenu Gmail (8 h)

1. **Détecter l'ouverture d'un message** avec un `MutationObserver` sur la zone de lecture. Isole tous les sélecteurs CSS dans un seul fichier `selectors.ts` : l'interface de Gmail change, tu ne veux corriger qu'un endroit.
2. **Extraire** les liens du message (texte affiché et `href`) et l'expéditeur. Gmail peut passer par une redirection du type `google.com/url?q=...` : décode le paramètre `q` pour retrouver la vraie cible.
3. **Analyser** chaque lien localement, plus la règle « le domaine du texte affiché diffère du domaine de la cible ».
4. **Afficher** une bannière dans un Shadow DOM (isole ton style de celui de Gmail) : « PhishGuard : 2 liens suspects dans ce message », avec la liste et les raisons. Marque les liens suspects d'une icône.
5. **Ne lis que le message ouvert**, jamais la boîte entière, ne stocke rien, n'envoie rien hors de l'appareil par défaut.
6. Teste sur une **page HTML de maquette** qui imite la structure d'un message, puis sur ton propre compte avec des messages de test que tu t'envoies.

**Piège** : n'injecte jamais le contenu de l'email avec `innerHTML` : tu transformerais ton extension en vecteur d'attaque XSS à l'intérieur de la messagerie.

**Terminé quand** : sur 10 messages de test (légitimes et piégés), la bannière apparaît à bon escient et ne bloque pas l'interface.

### Étape 5.7 — Page d'options et enrichissement optionnel (4 h)

Options : langue, activation de l'analyse automatique (demande la permission `tabs` au moment du clic via `chrome.permissions.request`), activation de l'enrichissement en ligne (demande la permission d'accès à l'hôte de l'API de la même façon, en `optional_host_permissions`), clé d'API personnelle de l'utilisateur, adresse d'un serveur auto-hébergé, liste blanche, gestion du retour d'information. Chaque réglage a une phrase qui explique **quelles données partent où**.

**Terminé quand** : par défaut, l'extension n'émet aucune requête réseau (vérifie dans l'onglet Réseau des outils de développement du service worker).

### Étape 5.8 — Langues et accessibilité (3 h)

Utilise `chrome.i18n` : `_locales/fr/messages.json`, `en`, `ar`. Teste l'arabe en lecture de droite à gauche (`dir='rtl'` sur le popup). Vérifie le contraste (WCAG AA), la navigation au clavier, les attributs ARIA, le fonctionnement avec un lecteur d'écran. Les verdicts utilisent icône, couleur et texte.

### Étape 5.9 — Audit des permissions et de la sécurité de l'extension (3 h)

Liste chaque permission et écris la justification en une phrase (tu devras les fournir au Chrome Web Store). Vérifie : pas de code distant ni de `eval`, politique CSP par défaut conservée, pas de dépendance inutile (`npm audit`), pas de journal de navigation conservé, pas d'identifiant unique de l'utilisateur. Écris `docs/extension-privacy.md` en langage clair.

**Terminé quand** : quelqu'un d'autre peut lire ce document et décrire exactement ce que l'extension fait de ses données.

### Étape 5.10 — Tests de l'extension (5 h)

Tests unitaires `vitest` (extracteur, modèle, décodage des redirections). Tests de bout en bout avec Playwright : lancement de Chromium avec l'extension chargée (contexte persistant et option `--load-extension`), ouverture de ta page de maquette Gmail, vérification que la bannière apparaît. Ajoute-les à la CI.

### Étape 5.11 — Bot Telegram (6 h)

1. Crée le bot avec @BotFather (récupère le jeton, mets-le dans `.env`).
2. Avec `aiogram` (version 3) :

```python
import re
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart

URL_RE = re.compile(r'https?://[^ ]+')
dp = Dispatcher()

@dp.message(CommandStart())
async def start(m: types.Message):
    await m.answer('Transfère-moi un message suspect ou envoie un lien : je te dis ce que j en pense.')

@dp.message()
async def check(m: types.Message):
    urls = URL_RE.findall(m.text or '')[:5]
    # appelle l'API PhishGuard pour chaque URL, puis formate le verdict
```

3. Commandes : `/start`, `/aide`, `/confidentialite` (ce que le bot fait des messages : rien n'est conservé), `/langue`.
4. Limites : 5 liens par message, délai entre messages, taille maximale du texte.
5. Utilise le **mode « long polling »** en développement et le mode webhook en production si tu veux ; ajoute le bot au `docker-compose.yml`.

**Terminé quand** : transférer un message de test dans le bot renvoie un verdict clair en moins de 3 secondes.

### Étape 5.12 — Page web « coller et analyser » (3 h)

Une page statique (HTML + un peu de JavaScript) avec une zone de texte, un bouton, et l'affichage du verdict. Utile pour ceux qui n'installeront jamais d'extension. Avertis clairement : « Ne collez pas de mot de passe ou de données personnelles. »

### Étape 5.13 — Tests utilisateurs (1 semaine, en parallèle)

Recrute 5 à 10 personnes non techniques (famille, amis, étudiants).

1. Donne-leur 3 tâches sans explication : installer l'extension, ouvrir un message piégé de test, comprendre un verdict.
2. **Observe sans aider** ; note où elles hésitent.
3. Fais remplir un questionnaire SUS (System Usability Scale, 10 questions).
4. Corrige les 5 problèmes les plus fréquents et recommence avec de nouvelles personnes.

**Terminé quand** : un score SUS d'au moins 70 sur le dernier groupe et un rapport `docs/user-tests.md` avec les citations marquantes (anonymisées).

### Étape 5.14 — Version bêta (2 h)

Construis l'archive (`npm run build`, puis zip du dossier `dist`), numérote `0.5.0-beta`, distribue-la à tes testeurs. **Clôture du module 5** : tague `v0.5.0`.

---

## Module 6 — Déploiement, open source et adoption (semaines 14 et 15, puis en continu)

### Étape 6.1 — Choisir et préparer le serveur (4 h)

Un petit VPS (quelques euros par mois) ou un palier gratuit suffit pour démarrer ; compare les offres actuelles (Hetzner, Fly.io, Render, Oracle Cloud) car les conditions changent. Une fois la machine créée :

1. Connexion par clé SSH uniquement, désactive l'authentification par mot de passe et la connexion directe en root.
2. Crée un utilisateur non privilégié.
3. Pare-feu : n'ouvre que les ports 22, 80 et 443 (`ufw`).
4. `fail2ban` contre les tentatives de connexion répétées, mises à jour de sécurité automatiques (`unattended-upgrades`).
5. Installe Docker et Docker Compose.

**Terminé quand** : un scan de ports depuis l'extérieur (avec ton accord sur ta propre machine, par exemple `nmap`) ne montre que 22, 80 et 443.

### Étape 6.2 — Nom de domaine et HTTPS (2 h)

Achète un nom de domaine (une dizaine d'euros par an), crée un enregistrement A vers ton serveur et utilise **Caddy** comme proxy inverse : il obtient et renouvelle les certificats automatiquement.

```
api.ton-domaine.org {
    reverse_proxy api:8000
}
```

Ajoute Caddy au `docker-compose.yml` de production. Vérifie ensuite ta note avec un testeur TLS public.

**Terminé quand** : `https://api.ton-domaine.org/v1/health` répond avec un certificat valide.

### Étape 6.3 — Déploiement automatisé (4 h)

Workflow GitHub Actions déclenché par un tag de version : construit l'image, l'analyse avec Trivy, la publie sur GitHub Container Registry (ghcr.io), puis se connecte au serveur en SSH (clé dédiée stockée dans les secrets GitHub) pour faire `docker compose pull && docker compose up -d`. Ajoute un « rollback » documenté : comment revenir à la version précédente en une commande.

**Terminé quand** : pousser un tag `v0.6.0` met à jour le serveur sans intervention manuelle.

### Étape 6.4 — Supervision, sauvegardes et garde-fous de coût (3 h)

- **Uptime Kuma** (outil libre) pour surveiller `/v1/health` et t'alerter sur Telegram.
- Rotation des journaux, espace disque surveillé.
- Sauvegarde quotidienne de la base SQLite (copie chiffrée hors du serveur).
- Limites de débit globales et quotas d'enrichissement pour ne pas épuiser tes API gratuites. Pense à un « mode dégradé » : si les quotas sont épuisés, l'analyse locale continue de fonctionner.
- Option : place Cloudflare (palier gratuit) devant l'API pour absorber les abus.

**Terminé quand** : tu reçois une alerte Telegram quand tu arrêtes volontairement l'API.

### Étape 6.5 — Documents juridiques et de confidentialité (3 h)

Rédige `PRIVACY.md` et une page de politique de confidentialité publique (le Chrome Web Store l'exige) : quelles données, pourquoi, combien de temps, avec qui elles sont partagées (les services tiers si l'enrichissement est activé), comment les supprimer, comment te contacter. Reste factuel et court. Vérifie que ce que tu écris est exactement ce que fait le code.

**Terminé quand** : chaque phrase de la politique correspond à un comportement vérifiable du code.

### Étape 6.6 — Licence et gouvernance (3 h)

1. **Licence définitive** : MIT ou Apache-2.0 (adoption maximale, Apache ajoute une clause de brevets) ; AGPL-3.0 si tu veux obliger quiconque propose ton code comme service en ligne à publier ses modifications. Explique ton choix dans le README.
2. `CODE_OF_CONDUCT.md` (Contributor Covenant).
3. `SECURITY.md` finalisé : adresse de contact, délai de réponse que tu t'engages à tenir, politique de divulgation responsable.
4. Labels (`bug`, `enhancement`, `good first issue`, `help wanted`, `security`), **10 issues « good first issue »** bien décrites (ajouter une marque à la liste de typosquatting, traduire une langue, ajouter un test).
5. Versionnage sémantique et `CHANGELOG.md`.
6. Active les alertes de sécurité GitHub et « Private vulnerability reporting ».

**Terminé quand** : un inconnu peut contribuer sans te poser une seule question.

### Étape 6.7 — Site de documentation (4 h)

Un site MkDocs Material publié sur GitHub Pages : démarrage rapide (installation de l'extension en 3 captures d'écran), FAQ, confidentialité, architecture, modèle de menace, model cards, rapport de robustesse, API, comment contribuer. Ajoute le diagramme d'architecture et une vidéo de démonstration de 90 secondes.

**Terminé quand** : le site est en ligne et un non-technicien installe l'extension en suivant uniquement la page d'accueil.

### Étape 6.8 — Mises à jour du modèle sécurisées et planifiées (6 h)

Le phishing évolue vite : un modèle vieillit en quelques mois.

1. **Workflow planifié mensuel** (GitHub Actions, déclencheur `schedule`) : récupère les nouvelles données, réentraîne, évalue sur un jeu de test récent **et** sur ton jeu de test figé.
2. **Garde-fou de non-régression** : le nouveau modèle n'est publié que si le rappel à FPR 1 % ne baisse pas et si les faux positifs sur une liste de sites légitimes courants n'augmentent pas.
3. Génère le manifeste signé (étape 4.12) et publie le modèle comme asset d'une release GitHub.
4. **Côté extension** : MV3 interdit le code distant, pas les données. L'extension peut télécharger le fichier JSON du modèle, **vérifier la signature Ed25519 avec la clé publique embarquée**, et refuser tout fichier dont la signature ou la version d'extracteur ne correspond pas. Ainsi, une compromission de ton hébergement ne suffit pas à tromper les utilisateurs.

**Terminé quand** : un modèle falsifié (un octet modifié) est rejeté par l'extension dans un test.

### Étape 6.9 — Publication sur le Chrome Web Store (1 à 2 semaines avec la revue)

Checklist :

- Compte développeur Chrome Web Store (frais uniques, environ 5 $), authentification à deux facteurs activée.
- Archive `.zip` du dossier de build, numéro de version.
- Icônes (128 × 128), captures d'écran (1280 × 800), image promotionnelle, description claire en FR, EN, AR.
- Onglet « Pratiques de confidentialité » : déclare exactement les données traitées, indique que tu n'utilises pas de code distant, lien vers la politique de confidentialité.
- Justification de **chaque** permission (une phrase par permission, issue de l'étape 5.9) et déclaration de l'« objectif unique » de l'extension : « détecter et signaler les liens de phishing ».
- Lance d'abord en **visibilité « non répertoriée »** ou en test à accès restreint avec tes testeurs, puis passe en public.

**Piège** : les refus les plus fréquents viennent de permissions trop larges, d'un objectif peu clair, d'une description trompeuse ou d'une politique de confidentialité absente. Réponds calmement aux demandes de précision ; cela prend du temps mais c'est normal.

**Terminé quand** : l'extension est installable depuis le Chrome Web Store.

### Étape 6.10 — Firefox (optionnel, 6 h)

Adapte le manifeste (`browser_specific_settings`, script d'arrière-plan au lieu du service worker selon la version), utilise `web-ext lint` et publie sur Firefox Add-ons (AMO), qui exige aussi une revue.

### Étape 6.11 — Plan de lancement (2 semaines)

**Avant (semaine -2)** : démo vidéo de 90 secondes, GIF en tête du README, 10 testeurs bêta qui s'engagent à laisser un avis, brouillon de l'article, comptes sociaux prêts.

**Jour J** :

1. Publie l'article technique (dev.to, Medium ou LinkedIn) : « Ce que j'ai appris en construisant un détecteur de phishing open source », en y mettant tes vrais chiffres, y compris ceux du rapport de robustesse.
2. Publie sur LinkedIn (un post avec le GIF et le lien du dépôt), r/cybersecurity et r/chrome\_extensions (respecte les règles de chaque communauté), et propose un « Show HN » sur Hacker News.
3. Envoie le projet aux communautés cyber étudiantes, aux CERT et associations de sensibilisation, aux écoles.
4. **Réponds à chaque commentaire et issue dans les 24 h** pendant la première semaine.

**Après (semaines +1 à +4)** : un article par semaine sur un point technique (le garde-fou SSRF, le split temporel, l'évasion par homoglyphes), la mise en avant des contributeurs, une release corrective rapide pour répondre aux premiers retours.

### Étape 6.12 — Mesurer sans pister (en continu)

Sources de mesure respectueuses : statistiques du Chrome Web Store (installations, utilisateurs actifs), étoiles, forks et clones GitHub, issues et retours, nombre d'appels API agrégés (sans identifiants). Si tu veux une télémétrie, rends-la **opt-in**, anonyme et documentée. Chaque semaine, 1 heure de tri des retours : faux positifs signalés, demandes de langues, bugs.

### Étape 6.13 — Feuille de route après la v1.0

Idées classées par valeur : base locale de préfixes de hachage Safe Browsing (confidentialité renforcée), détection des QR codes (quishing), add-in Outlook, bot WhatsApp/Signal selon les possibilités des plateformes, modèle de texte arabe et dialectal, tableau de bord pour petites structures, signalement vers PhishTank/OpenPhish avec accord de l'utilisateur.

### Étape 6.14 — Mettre le projet en valeur dans ton portfolio (1 semaine)

- Le haut du README : le problème, un GIF, les 3 chiffres clés (rappel, faux positifs, latence), le lien d'installation.
- Trois documents phares à épingler : modèle de menace, rapport de robustesse, article de lancement.
- CV : 3 puces chiffrées (modèle et métrique, sécurité de l'API ou de l'extension, utilisateurs réels).
- Prépare **5 histoires** d'entretien (format situation, action, résultat) : la fuite de données trouvée dans un split aléatoire ; la faille SSRF que tu as testée ; l'évasion qui a fait chuter ton rappel et la défense qui l'a corrigée ; la décision de vie privée sur l'accès à Gmail ; ce que les testeurs non techniques ont mal compris.
- Démo en direct de 5 minutes : extension sur un faux message piégé, explication, mode avion pour montrer l'inférence locale.

**Clôture du module 6** : release `v1.0.0`, extension publiée, API en production, site de documentation en ligne.

---

## Calendrier récapitulatif

| Semaine | Module | Résultat attendu |
| --- | --- | --- |
| 1 | M0 Fondations | Dépôt pro, CI, baseline, phishing-101 |
| 2 à 4 | M1 Détection | Modèles URL / texte / email, rapports d'évaluation, `v0.1.0` |
| 5 à 6 | M2 Threat Intel | Enrichisseurs, garde-fou SSRF, fusion, MITRE, `v0.2.0` |
| 7 à 8 | M3 XAI et adversarial | Explications, banc d'essai, rapport de robustesse, `v0.3.0` |
| 9 à 10 | M4 API | API sécurisée, Docker, CI sécurité, export modèle, `v0.4.0` |
| 11 à 13 | M5 Extension et bot | Extension, bot Telegram, tests utilisateurs, `v0.5.0` |
| 14 à 15 | M6 Déploiement | Production, Chrome Web Store, lancement, `v1.0.0` |

Si le temps manque, coupe dans cet ordre : port Firefox, test LLM-phishing, page web « coller et analyser », enrichissement urlscan.io, modèle de texte multilingue avancé. **Ne coupe jamais** : split temporel, garde-fou SSRF, tests de vie privée, rapport de robustesse, tests utilisateurs.

## Définition de « terminé » pour le projet complet

- Un inconnu installe l'extension depuis le store en moins d'une minute et comprend un verdict sans aide.
- Par défaut, aucun contenu d'email ou de page ne quitte l'appareil.
- Les métriques annoncées dans le README sont reproductibles avec `make data train`.
- La CI passe (tests, analyse de code, audit des dépendances, scan de l'image).
- Le rapport de robustesse, le modèle de menace et la politique de confidentialité sont publiés.
- Au moins 10 vraies personnes l'utilisent et tu as traité leurs retours.

## Ta toute prochaine action

Aujourd'hui : fais les étapes 0.1 et 0.2 (45 minutes). Demain : 0.3 à 0.5. Dès que ta CI est verte, reviens me voir avec ton arborescence ou n'importe quelle erreur rencontrée, et on code l'étape suivante ensemble.
