# Tests utilisateurs (étape 5.13)

> **État : protocole prêt, séances à mener.** Rien dans ce document n'a encore été observé :
> les sections « Résultats » sont à remplir pendant et après les séances. Critère de fin
> de l'étape : **SUS moyen d'au moins 70 sur le dernier groupe**, et ce rapport complété
> avec les citations marquantes, anonymisées.

Ce que l'on cherche : là où une personne **non technique** hésite, se trompe ou abandonne
devant PhishGuard, pas une confirmation que l'outil marche. Une séance réussie est une
séance qui trouve des problèmes.

## 1. Participants

- **5 à 10 personnes par groupe**, non techniques : famille, amis, étudiants hors
  informatique. Viser la diversité : âge (dont des plus de 60 ans), aisance avec
  l'ordinateur, au moins une personne arabophone (l'interface arabe n'a pas encore été
  relue par des locuteurs, [reasons.md](reasons.md)), et si possible une personne qui
  utilise un lecteur d'écran (étape 5.8 : NVDA, JAWS ou VoiceOver jamais essayés).
- **Exclure** : développeurs, personnes de la sécurité informatique, et quiconque a vu
  PhishGuard fonctionner.
- **Deux groupes au moins** : le groupe 1 trouve les problèmes, on corrige les cinq plus
  fréquents, puis un groupe 2 de **nouvelles** personnes vérifie les corrections. Le
  critère SUS porte sur le dernier groupe.

### Consentement et données

Lire au participant, avant de commencer, et obtenir son accord oral (noté sur la fiche) :

> « Je teste un outil, pas vous : il n'y a pas de mauvaise réponse. Je vais prendre des
> notes sur ce que vous faites et dites, sans votre nom. Je n'enregistre ni l'écran ni la
> voix, sauf si vous l'acceptez. Vous pouvez arrêter à tout moment. Les messages que vous
> verrez sont faux : aucun ne vient d'une vraie banque, aucun lien ne mène à un vrai site. »

- Chaque participant reçoit un **identifiant** (`P01`, `P02`…) : c'est le seul qui
  apparaît dans les notes, le fichier SUS et ce rapport. La correspondance nom ↔
  identifiant reste sur papier chez l'animateur et est détruite à la fin de l'étape.
- Profil noté par tranches seulement : âge (18-29, 30-44, 45-59, 60 et plus), aisance
  (débutant, à l'aise, avancé), langue de l'interface.
- Citations : mot pour mot, mais sans rien qui identifie la personne ou un tiers.
- **Poste de test** : un profil Chrome créé pour l'occasion et un compte Gmail de test
  créé par l'animateur. **Jamais la boîte réelle du participant.**

## 2. Préparation

1. Construire la version bêta (étape 5.14, [beta.md](beta.md)) et l'avoir sur une clé USB
   ou en téléchargement.
2. Compte Gmail de test : s'y envoyer les **messages du kit** (section 6) depuis une autre
   adresse de test, la veille.
3. Lancer l'API (`make api`) et le bot (`make bot`) si les tâches facultatives sont au
   programme ; la page « coller et analyser » est à la racine de l'API.
4. Imprimer, par participant : la fiche d'observation (section 4) et le questionnaire SUS
   (section 5).

## 3. Les tâches

Données **une à une, sans explication**. L'animateur lit la consigne, puis **observe sans
aider** : s'il est sollicité, il renvoie la question (« Qu'est-ce que vous feriez chez
vous ? »). Après 5 minutes de blocage, il note « abandon » et passe à la suite. On demande
au participant de penser à voix haute.

| # | Consigne lue au participant | Réussite si… |
|---|---|---|
| T1 | « Un ami vous a envoyé ce fichier : c'est un outil contre les arnaques. Installez-le dans Chrome. » | l'icône PhishGuard est dans la barre, sans aide |
| T2 | « Vous avez reçu des emails. Ouvrez celui de PayPal et dites-moi ce que vous en pensez. » (message K3) | il ne clique pas sur le lien **et** cite l'alerte de PhishGuard |
| T3 | « D'après PhishGuard, que faut-il faire de ce message, et pourquoi ? » | il reformule une raison et le conseil (« ne pas cliquer », « aller sur le vrai site ») |
| T4 *(facultatif)* | « Vous visitez ce site. Demandez son avis à PhishGuard. » (onglet K7 ouvert) | il clique sur l'icône et lit le verdict |
| T5 *(facultatif)* | « Une amie vous transfère ce SMS. Vérifiez-le sans rien installer. » (page ou bot, message K8) | verdict obtenu, avertissement « ne collez pas de mot de passe » remarqué |

Ordre fixe (T1 → T5) : la compréhension (T3) n'a de sens qu'après avoir vu l'alerte.

**Lecteur d'écran** (participant qui en utilise un) : T2 et T3 avec son propre lecteur ;
noter si la bannière est annoncée, si le verdict est compréhensible à l'oreille, si les
boutons ont un nom.

## 4. Fiche d'observation (une par participant)

```text
Participant : P__   Groupe : _   Âge : ____   Aisance : ________   Langue : __
Accord oral : ☐   Enregistrement accepté : ☐ oui ☐ non

T1 installation   ☐ réussie ☐ avec hésitation ☐ abandon   durée : ___ min
   hésitations / erreurs :
T2 message piégé  ☐ alerte vue ☐ alerte ignorée ☐ a cliqué sur le lien
   où il a regardé en premier :
T3 compréhension  ☐ raison reformulée ☐ conseil reformulé ☐ contresens
   ses mots :
T4 / T5           ☐ réussie ☐ avec hésitation ☐ abandon
Citations marquantes (mot pour mot) :
Problèmes observés (un par ligne, avec la tâche) :
```

## 5. Questionnaire SUS

Juste après les tâches, sans l'animateur à côté. Dix affirmations, réponse de 1 (pas du
tout d'accord) à 5 (tout à fait d'accord). Le système est « l'outil PhishGuard ».

| # | Affirmation |
|---|---|
| 1 | Je pense que j'aimerais utiliser cet outil fréquemment. |
| 2 | J'ai trouvé cet outil inutilement compliqué. |
| 3 | J'ai trouvé cet outil facile à utiliser. |
| 4 | Je pense que j'aurais besoin de l'aide d'une personne technique pour pouvoir utiliser cet outil. |
| 5 | J'ai trouvé que les différentes fonctions de cet outil étaient bien intégrées. |
| 6 | J'ai trouvé qu'il y avait trop d'incohérences dans cet outil. |
| 7 | J'imagine que la plupart des gens apprendraient très vite à utiliser cet outil. |
| 8 | J'ai trouvé cet outil très lourd à utiliser. |
| 9 | Je me suis senti(e) très en confiance en utilisant cet outil. |
| 10 | J'ai dû apprendre beaucoup de choses avant de pouvoir utiliser cet outil. |

Traduction des items de Brooke (1996). Pour une publication, préférer une version
française validée (Gronier et Baudet, 2021) ; garder la même version pour tous les
groupes, sinon les scores ne se comparent pas. En anglais, les items originaux ; en
arabe, une traduction relue par un locuteur avant la première séance.

**Saisie** : `docs/user-tests/sus.csv` (copier `sus-template.csv`), une ligne par
participant, identifiant anonyme seulement. Une réponse manquante ne se devine pas : la
ligne est refusée par le script, on la laisse de côté et on le note.

```bash
python scripts/sus_score.py docs/user-tests/sus.csv                 # tableau à coller section 7
python scripts/sus_score.py docs/user-tests/sus.csv --min-score 70   # critère sur le dernier groupe
```

Le script donne, par groupe, la moyenne, son intervalle de confiance à 95 % (avec 5 à 10
personnes, il est large : le dire), le minimum, le maximum, et la lettre de l'échelle de
Sauro et Lewis (68 est la moyenne observée sur des centaines d'études, 70 notre cible).

## 6. Kit de messages de test

Faux par construction : domaines réservés `.example`, adresses IP de documentation
(192.0.2.0/24), homographe construit. Aucun lien ne mène à un vrai site.

| Id | Canal | Contenu | Attendu |
|---|---|---|---|
| K1 | email | Lettre d'information, liens vers `https://www.lemonde.fr/` | rien |
| K2 | email | Notification « Nouveau document » de `impots.gouv.fr`, lien `https://www.impots.gouv.fr/accueil` | rien |
| K3 | email | « Votre compte PayPal est limité », texte du lien `www.paypal.com`, cible `http://paypa1-secure-login.example/verify/account` | bannière **phishing** |
| K4 | email | Nom affiché `service@paypal.com`, adresse `alerts@notice-mail.example` | bannière **suspect** |
| K5 | email | « Vérifiez votre identifiant Apple », lien `http://xn--pple-43d.com/` (homographe) | bannière **phishing** |
| K6 | email | Lien `http://192.0.2.10/paypal/login.php` derrière « Connexion sécurisée » | bannière **phishing** |
| K7 | onglet | `https://appleid.apple.com.verify-account.example/signin` (page factice locale) | icône : phishing |
| K8 | SMS | « Votre colis est bloqué. Payez 1,99 € de frais : http://192.0.2.10/colis » | phishing |

Les emails K3 à K6 reprennent les messages 6 à 10 de la maquette Gmail
(`extension/test/fixtures/gmail-mock.html`), déjà vérifiés de bout en bout. Les envoyer
en HTML (le texte du lien doit différer de sa cible).

## 7. Résultats

*À remplir après chaque groupe.*

### Groupe 1 (date : …)

| Participant | Profil | T1 | T2 | T3 | T4 | T5 | SUS |
|---|---|---|---|---|---|---|---|
| P01 | … | … | … | … | … | … | … |

Tableau SUS (sortie de `sus_score.py`) :

```text
…
```

**Problèmes**, classés par nombre de participants concernés :

| # | Problème | Tâche | Participants | Gravité | Correction |
|---|---|---|---|---|---|
| 1 | … | … | …/… | bloquant / gênant / mineur | … |

Gravité : *bloquant* (tâche échouée), *gênant* (réussie avec hésitation ou contresens),
*mineur* (remarque). On corrige les **cinq problèmes les plus fréquents** avant le
groupe 2 ; à fréquence égale, le plus grave d'abord.

### Groupe 2 (date : …)

Mêmes tableaux, et pour chaque correction du groupe 1 : le problème a-t-il disparu ?

### Citations marquantes

> « … » (P__, T_)

### Comparaison avec PhishTool

Protocole : [external-tools.md](external-tools.md#protocole-de-comparaison-étape-513),
sur les emails de test du kit et de `tests/fixtures/emails/` seulement, jamais sur un
email réel.

| Email de test | Constat | PhishGuard | PhishTool | Écart et suite donnée |
| --- | --- | --- | --- | --- |
| `02_phish_link_mismatch.eml` | Lien trompeur | … | … | … |

## 8. Ce que l'on surveille en particulier

Points connus d'avance, à confirmer ou infirmer :

- **T1 installation** : la bêta s'installe en mode développeur (« Charger l'extension non
  empaquetée »). C'est un obstacle attendu pour des non-techniciens ; il mesure la
  qualité du guide [beta.md](beta.md). La publication sur le Chrome Web Store (module 6)
  le supprimera.
- **Avertissement d'installation** « lire et modifier vos données sur mail.google.com » :
  fait-il renoncer ? Ce que les participants en comprennent.
- **Pages internes légitimes** proches du seuil « suspect » (score 25-28, faiblesse connue
  de `url_v2`, [model-card-url.md](model-card-url.md)) : un participant tombe-t-il sur un
  faux positif ?
- **Lettres d'information** : un lien de suivi (`list-manage.com`) derrière le texte
  `www.boutique.fr` donne « suspect » ([extension-design.md](extension-design.md#limites-connues)) :
  inquiétude inutile ?
- **Les cinq explications** de [reasons.md](reasons.md) : comprises sans aide ?
- **Arabe** : traduction, sens d'écriture, coupures de mots.
