# Modèle de menace

Ce que PhishGuard protège, contre qui, comment, et ce qui reste ouvert. Chaque parade
renvoie au document qui la décrit et la vérifie. Les failles se signalent en privé :
[politique de sécurité](security.md).

## Ce qui est protégé

| Bien | Pourquoi il compte |
| --- | --- |
| la navigation et les emails de l'utilisateur | un outil anti-phishing qui fuit ces données deviendrait lui-même un risque |
| la justesse du verdict | un verdict « sûr » falsifié pousse à cliquer |
| l'intégrité des modèles | un modèle remplacé peut innocenter une campagne entière |
| le serveur, ses clés d'API et ses quotas de Threat Intelligence | abus, coût, déni de service |
| la chaîne de publication (code, images, modèles) | une compromission toucherait tous les utilisateurs |

## Attaquants considérés

1. **L'auteur d'une campagne de phishing**, qui veut que ses pages passent pour sûres.
2. **Une page web ou un email hostile**, ouvert par l'utilisateur, qui vise l'extension.
3. **Un client abusif de l'API** (robot, concurrent), qui veut épuiser les quotas.
4. **Un attaquant réseau ou un hébergeur compromis** (GitHub, CDN, Vercel), qui sert de
   faux fichiers.
5. **Un contributeur ou une dépendance malveillants** (chaîne d'approvisionnement).

L'utilisateur lui-même, et le système d'exploitation de son appareil, sont de confiance.

## Menaces et parades

| Menace | Attaquant | Parade | Référence |
| --- | --- | --- | --- |
| évasion : homoglyphes, sous-domaines ajoutés, caractères invisibles, typosquatting | 1 | normalisation (NFKC, homoglyphes, invisibles), alerte des hôtes à alphabets mélangés, entraînement adversarial, robustesse mesurée par technique | [catalogue d'évasion](evasion-catalog.md), [normalisation](normalization.md), [rapport](robustness-report.md) |
| phishing hébergé sur une plateforme de confiance (formulaire, document partagé) | 1 | Threat Intelligence en option côté serveur ; **limite assumée** des features lexicales, publiée | [analyse d'erreurs](error-analysis-url.md) |
| empoisonnement des données d'entraînement par les flux publics | 1 | test figé et garde-fou : un candidat qui régresse n'est pas publié ; relecture humaine avant signature | [mises à jour](model-updates.md#2-garde-fou-de-non-régression) |
| faux signalements pour influencer le modèle | 1, 3 | les retours ne modifient jamais le modèle ; quarantaine, quota, déduplication, relecture | [retours](feedback.md) |
| injection dans l'affichage (XSS par une raison, un nom d'expéditeur) | 2 | `textContent` seulement, CSP sans `unsafe-*`, raisons gabaritées, Shadow DOM fermé dans Gmail | [extension](extension-design.md), [raisons](reasons.md) |
| page Gmail compromise qui modifie le stockage de l'extension | 2 | réglages validés champ par champ, modèle reçu revérifié à chaque chargement, aucune requête possible depuis le script Gmail | [données de l'extension](extension-privacy.md#6-ce-que-dautres-pourraient-voir) |
| fuite des données de navigation | 2, 4 | aucune requête par défaut (vérifié par Playwright), options à double accord, URL sans fragment, ni cookie ni `Referer` | [données de l'extension](extension-privacy.md) |
| faux modèle servi à l'extension ou à l'API | 4 | signature Ed25519 vérifiée avec la clé embarquée, empreintes, même extracteur, pas de retour arrière ; clé privée hors CI | [registre](model-registry.md), [mises à jour](model-updates.md) |
| SSRF par une URL analysée | 3 | le serveur ne visite jamais l'URL ; garde réseau pour le code qui doit sortir | [SSRF](ssrf.md) |
| abus de l'API, épuisement des quotas | 3 | limites de débit par niveau de client, quotas par source, Threat Intelligence désactivée par défaut, mode dégradé | [API](api.md), [exploitation](operations.md) |
| contournement du proxy vers l'IP du serveur | 3, 4 | secret de 256 bits exigé par Caddy, 403 sinon | [déploiement](deployment.md) |
| dépendance ou action compromise | 5 | versions et empreintes verrouillées (`uv.lock`, `package-lock.json`), scripts d'installation npm interdits, actions épinglées par SHA, trivy, provenance SLSA, `npm audit signatures` | [sécurité de la CI](ci-security.md) |
| secret publié par erreur | 5 | gitleaks en pré-commit et en CI, clés hors du dépôt | [secrets](secrets.md) |

## Risques résiduels

- **Pas de détection parfaite.** Un modèle lexical manque une partie du phishing, et un
  attaquant qui connaît les features peut les contourner. Les chiffres sont publiés pour
  que personne ne surestime l'outil.
- **La présence de l'extension se voit dans Gmail** (bandeau, icônes), pas sur les autres
  sites.
- **Le serveur choisi par l'utilisateur** voit les adresses qu'il reçoit.
- **Compromission de la machine de signature** : la clé privée est chiffrée par phrase de
  passe ; sa rotation impose une nouvelle version de l'extension
  ([registre](model-registry.md#clé-privée)).
