# Textes du lancement (étape 6.11)

Prêts à copier, à relire le jour même. Remplacer `<STORE>` par le lien du Chrome Web Store
et `<ARTICLE>` par celui de l'article. Règles communes :

- toujours dire que l'on est l'auteur ;
- les limites dans le texte, pas seulement les réussites (objectif de rappel non atteint,
  faux positifs sur les courriers d'entreprise) : c'est ce qui rend crédible ;
- aucun lien raccourci, aucun paramètre de suivi (`utm_*`) : ce serait contraire au projet.

## LinkedIn

> 🛡️ Je publie PhishGuard, un détecteur de phishing open source qui prévient **au moment
> où l'on va cliquer**, avec une explication en une phrase, en français, anglais et arabe.
>
> Ce qui le distingue :
> 🔒 l'analyse se fait dans le navigateur : par défaut, aucune adresse ni aucun email ne
> quitte l'ordinateur (vérifié par des tests à chaque modification) ;
> 💬 chaque verdict est expliqué : domaine qui imite une marque, lettres d'un autre
> alphabet, adresse IP à la place d'un nom ;
> 📊 des chiffres honnêtes : modèle évalué sur les URLs les plus récentes qu'il n'a jamais
> vues, robustesse face aux techniques d'évasion mesurée et publiée.
>
> Mon objectif de départ (95 % de phishing détecté pour 1 % de fausses alertes) n'est pas
> atteint : j'en suis à 67 %. J'explique pourquoi dans l'article, et ce que j'ai appris en
> route, dont une fuite de données qui faussait mes premiers chiffres.
>
> 🧩 Extension Chrome : <STORE>
> 💻 Code (MIT) : https://github.com/arixstoo/PhishGuard
> 📝 Article : <ARTICLE>
>
> Vos signalements de faux positifs sont la contribution la plus utile. Merci de partager
> autour de vous, surtout à ceux qui ne sont pas du métier.
>
> #cybersécurité #phishing #opensource #machinelearning #privacy

*Joindre le GIF de démonstration (`docs/img/demo.gif`) ou, à défaut,
`docs/img/extension-verdict.png`.*

## Show HN

**Titre** (80 caractères au plus) :

> Show HN: PhishGuard – open-source phishing detector that runs in your browser

**Lien** : https://github.com/arixstoo/PhishGuard

**Premier commentaire** (à poster aussitôt) :

> Hi HN, I built PhishGuard, a Chrome extension (plus an API and a Telegram bot) that
> flags phishing links before you click, with a one-sentence explanation.
>
> The model (LightGBM, 25 lexical URL features) runs locally in the extension: I ported
> the feature extractor from Python to TypeScript and check parity on 200 reference
> vectors to 1e-6. By default the extension makes no network request at all; a Playwright
> test fails if any request leaves the package. Optional features (online analysis against
> a server you choose, signed model updates verified with Ed25519) are off by default.
>
> Honest numbers, on a temporal and domain-grouped test set of the 21,004 most recent URLs:
> PR-AUC 0.91, 66.8% recall at 1% FPR. My goal was 95%; lexical features can't see
> phishing hosted on reputable platforms. I also benchmarked evasion (homoglyphs,
> zero-width characters, extra subdomains, dilution) and published what the defences cost.
>
> Things I'd love feedback on: the threat model, the privacy guarantees, and false
> positives on sites you use. Write-up: <ARTICLE>

## Reddit

Relire les règles de chaque communauté le jour même (autopromotion, jour dédié, mot-clé
du titre). Rester présent pour répondre pendant plusieurs heures.

### r/cybersecurity

**Titre** : I built an open-source, privacy-first phishing detector and benchmarked how
easily it can be evaded (results inside)

> I'm the author. PhishGuard is a browser extension, API and Telegram bot that flags
> phishing URLs with plain-language reasons. It runs locally by default; nothing leaves
> the device.
>
> What might interest this sub more than the tool itself:
>
> - **Evasion benchmark**: two added subdomains cost the first model 12.5 points of
>   recall. Normalisation plus adversarial training brought homograph detection from 75% to
>   99%, at the cost of 10 points of recall on clean URLs.
> - **LLM-written phishing**: recall holds (90%), but 57–63% of well-written legitimate
>   business emails get flagged. Infrastructure signals (domain age, link consistency,
>   sender authentication) are what still separates them.
> - **Supply chain**: signed model updates (Ed25519, key never on CI), Sigstore
>   provenance on releases, SSRF guard that connects to the validated IP.
>
> Robustness report: https://arixstoo.github.io/PhishGuard/robustness-report/
> Threat model: https://arixstoo.github.io/PhishGuard/threat-model/
> Code (MIT): https://github.com/arixstoo/PhishGuard
>
> Criticism of the threat model is very welcome.

### r/chrome_extensions

**Titre** : PhishGuard: a phishing detector that runs entirely in the browser (MV3, no
remote code, open source)

> Author here. A few MV3 details that might be useful to other extension developers:
>
> - the ML model (LightGBM trees in JSON) runs in the service worker, 2–4 ms per URL;
> - three required permissions (`activeTab`, `contextMenus`, `storage`) plus Gmail;
>   everything else is optional and requested when the user turns the feature on;
> - the build fails on `eval`, `new Function`, `importScripts`, HTML injection, or `fetch`
>   outside three files; Playwright fails if any request leaves the package by default;
> - model updates are data, not code: downloaded from GitHub releases and accepted only if
>   the Ed25519 signature matches a key embedded at build time.
>
> Chrome Web Store: <STORE> — code: https://github.com/arixstoo/PhishGuard

## Message aux communautés, CERT, associations, écoles

> **Objet** : PhishGuard, un outil libre de détection du phishing pour vos publics
>
> Bonjour,
>
> Je m'appelle *[prénom]* et je viens de publier PhishGuard, une extension de navigateur
> libre et gratuite qui prévient l'utilisateur au moment où il va cliquer sur un lien de
> phishing, avec une explication simple, en français, en anglais et en arabe.
>
> Elle a été pensée pour des personnes non techniques : l'analyse se fait sur l'ordinateur,
> sans compte, sans publicité, sans collecte de données. Le code, la politique de
> confidentialité et les limites de l'outil sont publics.
>
> Si elle peut servir dans vos actions de sensibilisation, je serais heureux d'en discuter,
> et surtout de recevoir vos retours sur les cas qu'elle rate ou signale à tort.
>
> - Installation : <STORE>
> - Présentation et confidentialité : https://arixstoo.github.io/PhishGuard/
>
> Bien cordialement,
> *[prénom, nom]*

## Recrutement des testeurs

> Je cherche 10 personnes pour tester PhishGuard, une extension qui repère les liens de
> phishing, pendant une semaine avant sa sortie publique. Pas besoin d'être technique,
> au contraire. Il suffit de l'installer, de s'en servir normalement, puis de me dire en
> 5 minutes ce qui était clair ou pas (et de laisser un avis sur le store si elle vous a
> été utile). L'extension ne collecte rien : tout se passe sur votre ordinateur.
> Intéressé·e ? Répondez-moi, je vous envoie le lien.

## Questions attendues

| Question | Réponse courte | Détail |
|---|---|---|
| « Pourquoi pas Google Safe Browsing, qui est déjà dans Chrome ? » | Complémentaire : Safe Browsing ne connaît un site qu'une fois signalé ; PhishGuard juge la forme de l'adresse dès la première visite, et explique son verdict. Une base locale Safe Browsing est sur la feuille de route. | [roadmap.md](../roadmap.md#3-base-locale-de-préfixes-safe-browsing) |
| « Que voyez-vous de ma navigation ? » | Rien : l'analyse est locale, aucune requête par défaut, testé en CI. | [extension-privacy.md](../extension-privacy.md) |
| « Pourquoi lire Gmail ? » | Pour vérifier les liens du seul message ouvert, sur l'ordinateur ; rien n'est gardé ni envoyé ; désactivable. | [extension-privacy.md](../extension-privacy.md#5-les-autorisations-demandées) |
| « 67 % de rappel, c'est faible. » | Oui, et c'est dit. Seuil choisi pour peu de fausses alertes ; la suite est dans la feuille de route. | [roadmap.md](../roadmap.md) |
| « Un attaquant peut lire votre code et l'éviter. » | Il peut, comme pour tout filtre ; le banc d'évasion mesure ce que ça lui coûte, et l'obscurité n'est pas une défense. | [robustness-report.md](../robustness-report.md) |
| « Et si votre serveur de mises à jour est compromis ? » | Un modèle non signé par la clé intégrée est refusé ; la clé privée n'est jamais en ligne. | [model-updates.md](../model-updates.md) |
| « Comment signaler un faux positif ? » | Bouton « Signaler une erreur » (si un serveur est configuré) ou issue « faux positif » sur GitHub. | [feedback.md](../feedback.md) |
