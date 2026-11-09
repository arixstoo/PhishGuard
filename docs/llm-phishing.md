# Jeu de test « phishing rédigé par un LLM »

*Étape 3.10 du cahier des charges. Code : `src/phishguard/data/llm_phishing.py` (chargeur et règles de sûreté), `scripts/evaluate_llm_phishing.py` (`make llm-phishing`). Tests : `tests/test_llm_phishing.py`. Résultats : [robustness-report.md](robustness-report.md#phishing-rédigé-par-un-llm-étape-310).*

Ce jeu mesure ce que deviennent les modèles de texte face à des leurres **sans faute**, et face à des courriers professionnels légitimes **aussi bien écrits**. Il est **défensif et local** : il sert uniquement à évaluer les détecteurs de PhishGuard. Il ne sort pas de la machine, il n'est envoyé à personne et il n'est pas versionné.

## Ce qui est publié, ce qui ne l'est pas

| Publié (versionné) | Local seulement (`data/llm_phishing/`, ignoré par git) |
| --- | --- |
| ce protocole, le chargeur et ses règles, le script de mesure | `messages.jsonl` : 300 messages |
| l'empreinte SHA-256 de chaque fichier, dans `docs/metrics/llm_phishing.json` | `legit_links_control.jsonl` : 40 messages de contrôle |
| les mesures, sans aucun texte de message | |

Publier des leurres prêts à l'emploi, même fictifs, n'apporterait rien à la mesure, et le plan l'exclut. Pour rejouer l'étape, on rédige un jeu qui suit ce protocole : le chargeur refuse tout fichier qui ne le respecte pas. Les chiffres ne seront pas identiques, mais la méthode et les garde-fous le seront.

## Protocole de rédaction

- **Rédacteur** : un LLM (Claude, modèle `claude-opus-5-5`), le 9 novembre 2026, dans la session de développement de l'étape. La consigne est de rédiger des messages grammaticalement parfaits, au ton d'un service réel, sans faute volontaire ni vocabulaire de spam.
- **Taille** : 150 messages de phishing et 150 messages légitimes d'entreprise. Il y a 15 familles par classe, 10 messages par famille, en alternant SMS et email (151 SMS, 149 emails).
- **Langue** : anglais, comme le corpus d'entraînement du modèle SMS. Le français et l'arabe sont déjà mesurés à part ([robustness-report.md](robustness-report.md#sms-français--arabe--déjà-fragile-sans-perturbation)). Mêler la langue et la qualité de rédaction rendrait les deux effets indiscernables.
- **Familles de phishing** : compte suspendu, mot de passe expiré, demande de code MFA, frais de colis, facture ou changement de RIB, mise à jour de la paie, remboursement d'impôt, gain ou récompense, alerte de fraude bancaire, renouvellement d'abonnement, document partagé, faux dirigeant et cartes cadeaux, messagerie et IT, fausse offre d'emploi, investissement et crypto.
- **Familles légitimes**, choisies pour être des **négatifs difficiles** : elles parlent de comptes, de codes, de paiements et de colis comme le phishing. Ce sont les rappels de réunion, avis de livraison, factures disponibles, codes de connexion, confirmations de changement de mot de passe, annonces RH, maintenance IT, rendez-vous, confirmations de commande, bulletins de paie, voyages, lettres d'information, avis de sécurité, messages de collègues et service client.
- **Organisations fictives**, les **mêmes pour les deux classes** (Northwind, Globex, Acme, Initech, Contoso) : aucune marque ne trahit l'étiquette, et aucune organisation réelle n'est imitée.
- **Domaines réservés seulement** (RFC 2606, RFC 6761) : `example.com`, `example.net`, `example.org`, et les TLD `.test`, `.example`, `.invalid`.
- **Aucune coordonnée réelle** : pas d'adresse email hors de ces domaines, pas de numéro de téléphone (seuls les numéros fictifs `555-01xx` passeraient).

Format : une ligne JSON par message, avec les champs `id`, `label` (1 phishing, 0 légitime), `family`, `channel` (`sms` ou `email`) et `text`.

## Garde-fous du chargeur

`load_llm_messages` refuse le fichier entier, sans recopier le texte fautif dans l'erreur, si :

- un nom d'hôte ou le domaine d'une adresse email n'est pas réservé ;
- une suite de 9 chiffres ou plus ressemble à un numéro de téléphone non fictif (un numéro de facture comme `2026-118` n'en a que 7) ;
- un identifiant est en double, un champ manque, le canal ou l'étiquette sont inconnus, ou un texte est vide ou dépasse 2 000 caractères ;
- les deux classes n'ont pas la même taille. Le jeu de contrôle, d'une seule classe, est chargé avec `balanced=False`.

## Jeu de contrôle

Le premier passage a montré un biais de construction. Seuls 5 % des messages légitimes du jeu principal contiennent un lien, contre 85 % du phishing, et une règle fondée sur les liens y paraît donc précise sans raison. Plutôt que de modifier le jeu principal après la mesure, un **jeu de contrôle** de 40 messages légitimes, qui contiennent **tous** un lien, a été ajouté : relevé de compte, confirmation d'adresse, suivi de colis, document de travail partagé. Il est rédigé selon le même protocole et ne sert qu'à mesurer des faux positifs. Le rapport le signale comme ajouté après la première mesure.

## Limites

- **Un seul rédacteur, une seule session.** Un autre LLM, ou un attaquant qui itère contre le détecteur, écrirait autrement. Les chiffres valent pour ce jeu, la conclusion (le registre ne sépare plus les classes) est plus générale.
- **Le phishing est un peu plus long** que le légitime (202 caractères en médiane, contre 152). Le modèle SMS normalise la longueur (TF-IDF), mais pas les catégories de leurre.
- **10 messages par famille** : les taux par famille sont des ordres de grandeur, pas des mesures précises.
- **Pas de vrais domaines** : les liens ne disent rien de l'infrastructure. Le scénario « domaine récent » du rapport montre ce que la fusion ferait d'un tel signal, il ne mesure pas sa fréquence.
