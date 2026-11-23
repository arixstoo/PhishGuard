# Feuille de route après la v1.0 (étape 6.13)

Ce qui viendra après la première version publique, **classé par valeur pour les
utilisateurs**, pas par intérêt technique. Chaque piste dit le problème mesuré qu'elle
résout, son coût, son risque pour la vie privée, et le premier pas concret. Elle devient une
issue (label `roadmap`) quand quelqu'un s'en empare.

Deux règles ne changent pas, quelle que soit la piste :

1. **Par défaut, rien ne quitte l'appareil.** Une fonction qui envoie quelque chose est
   désactivée à l'installation, demande l'autorisation au moment de l'activation, et entre
   dans [PRIVACY.md](../PRIVACY.md) avant d'être livrée.
2. **Aucun modèle n'est publié sans le garde-fou de non-régression**
   ([model-updates.md](model-updates.md)) : test figé, test récent, sites légitimes courants.

## Classement

| Rang | Piste | Valeur | Coût | Risque vie privée |
|---:|---|---|---|---|
| 1 | Correctifs issus des premiers retours (faux positifs, langues) | très haute | faible, continu | aucun |
| 2 | Signaux de confiance dans la fusion | haute | moyen | aucun |
| 3 | Base locale de préfixes de hachage Safe Browsing | haute | élevé | **diminue** le risque |
| 4 | Modèle de texte français, arabe et dialectal | haute (public visé) | élevé (données) | faible si les données sont publiques |
| 5 | Détection des QR codes (quishing) | moyenne à haute | moyen | aucun (sur l'appareil) |
| 6 | Signalement vers PhishTank / OpenPhish, avec accord | moyenne | faible | faible, opt-in |
| 7 | Add-in Outlook | moyenne | élevé | à étudier |
| 8 | Tableau de bord pour petites structures | moyenne | élevé | **élevé** |
| 9 | Bot WhatsApp ou Signal | incertaine | élevé, dépend des plateformes | à étudier |

## 1. Correctifs issus des premiers retours

**Problème.** Les chiffres du modèle viennent de jeux publics ; les vrais utilisateurs
trouveront d'autres erreurs. Pour `url_v2`, le modèle déployé, le taux de faux positifs
mesuré sur le test au seuil de décision est de 4,0 % sur les pages internes légitimes,
contre 0,3 % sur les pages d'accueil
([`metrics/url_v2_test.json`](metrics/url_v2_test.json)).

**Quoi.** L'heure de tri hebdomadaire ([measure.md](measure.md)) alimente des versions
correctives `1.0.x` : sites légitimes ajoutés à la liste de référence (avec le label
`needs-retraining`), libellés mal compris corrigés, langues demandées.

**Premier pas.** Les 10 issues « good first issue » de l'étape 6.6 et la première semaine
de retours après le lancement.

## 2. Signaux de confiance dans la fusion

**Problème.** La fusion ne sait qu'**ajouter** du risque : aucun signal ne peut faire baisser
un faux positif ([robustness-report.md](robustness-report.md#8-limites)). Or le modèle texte
signale 57 à 63 % des courriers légitimes d'entreprise rédigés avec soin.

**Quoi.** Des signaux capables de baisser un score : expéditeur authentifié (SPF, DKIM et
DMARC alignés, déjà extraits par le parseur), domaine ancien (RDAP) et cohérent avec la
marque annoncée. Une table de vérité documentée, comme pour la fusion actuelle
([fusion.md](fusion.md)).

**Garde-fou.** Un attaquant qui contrôle son domaine peut passer SPF et DKIM : un signal
de confiance ne doit jamais annuler une règle dure (homographe, IP, marque imitée).

**Premier pas.** Mesurer sur le corpus email de l'étape 1.11 combien de faux positifs du
modèle texte ont un expéditeur authentifié et aligné.

## 3. Base locale de préfixes Safe Browsing

**Problème.** Le modèle juge la **forme** d'une adresse. Un phishing hébergé sur une
plateforme réputée lui échappe ([error-analysis-url.md](error-analysis-url.md)) ; seule une
liste de réputation le voit. Aujourd'hui, consulter Safe Browsing exige d'envoyer l'URL à
un serveur.

**Quoi.** L'API *Update* de Safe Browsing (v4) : l'extension garde une base locale de
préfixes de hachage (4 octets), vérifie l'URL sur l'appareil, et n'interroge Google que
pour un préfixe qui correspond, avec le seul préfixe, mêlé à d'autres. Confidentialité
renforcée par rapport à l'enrichissement actuel.

**Coût et limites.** Taille de la base (plusieurs Mo), mises à jour régulières, conditions
d'utilisation de l'API (usage non commercial, clé propre au projet), et une requête vers
Google en cas de correspondance : à déclarer dans PRIVACY.md et le formulaire du store.

**Premier pas.** Prototype hors extension (Python) : taille de la base, taux de
correspondances sur le test URL, nombre de requêtes complètes par jour.

## 4. Modèle de texte français, arabe et dialectal

**Problème.** Le public visé parle français et arabe ; le modèle SMS, entraîné sur de
l'anglais, signale 42 % des messages légitimes français et arabes, et la dilution par des
mots anglais fait tomber son rappel à zéro ([robustness-report.md](robustness-report.md)).

**Quoi.** Un jeu de messages publics et étiquetés en français, arabe standard et darija
(campagnes signalées par les CERT, signalements publics, messages légitimes de services
publics et de banques), puis un modèle évalué avec le même protocole (split temporel,
déduplication, banc de robustesse).

**Risque.** Ne jamais collecter de messages privés. Les retours des utilisateurs ne
contiennent que des domaines : ils ne peuvent pas servir ici, et c'est voulu.

**Premier pas.** Recenser les sources publiques et leurs licences dans
[data-sources.md](data-sources.md).

## 5. Détection des QR codes (quishing)

**Problème.** Un QR code dans un email ou une image cache l'URL au lecteur et aux filtres.

**Quoi.** Décoder sur l'appareil les QR codes des images d'un message ouvert dans Gmail et
analyser l'URL obtenue comme un lien. Décodeur en JavaScript pur, embarqué (aucun code
distant), appelé seulement sur les images déjà affichées.

**Premier pas.** Choisir un décodeur à licence compatible MIT, mesurer son poids et son
temps sur une image de 1 Mo, et ajouter des messages à QR code à la maquette Gmail.

## 6. Signalement vers PhishTank et OpenPhish

**Quoi.** Après un verdict « phishing », proposer d'envoyer l'URL à une base publique.
Toujours une action explicite de l'utilisateur, URL montrée avant l'envoi, jamais
automatique ; conditions de chaque service vérifiées (compte, limites).

**Pourquoi au rang 6.** Utile à tous, mais l'URL peut contenir un identifiant personnel
(lien de réinitialisation) : il faut l'élaguer et le montrer avant l'envoi.

## 7. Add-in Outlook

**Quoi.** Le même score email que l'API pour Outlook Web et le client de bureau, avec la
bannière de Gmail. Les add-ins Office tournent dans un cadre web : l'extracteur
TypeScript est réutilisable.

**Coût.** Manifeste, revue de Microsoft AppSource, et des droits de lecture du message à
justifier comme pour Gmail.

## 8. Tableau de bord pour petites structures

**Quoi.** Pour une association ou une petite entreprise qui héberge sa propre API : les
totaux d'usage et les signalements de ses membres, sans données personnelles.

**Pourquoi si bas.** C'est la piste qui pousse le plus vers la surveillance des personnes.
Elle n'a de sens qu'avec les totaux sans identifiant de l'étape 6.12 comme seule source, et
un modèle de menace écrit avant la première ligne de code.

## 9. Bot WhatsApp ou Signal

**Quoi.** Le bot Telegram ([telegram-bot.md](telegram-bot.md)) sur d'autres messageries.

**Pourquoi incertain.** L'API WhatsApp Business est payante et passe par Meta ; Signal n'a
pas d'API officielle de bot. À réévaluer selon les plateformes, sans contourner leurs
conditions.

## Écarté pour l'instant

- **Télémétrie dans l'extension**, même *opt-in* : voir [measure.md](measure.md#ce-que-lon-ne-mesure-pas-volontairement).
- **Visiter la page analysée** (capture, contenu) depuis le serveur : risque SSRF et
  exposition de l'infrastructure ([ssrf.md](ssrf.md)). Si un jour nécessaire, dans un bac à
  sable isolé et jetable, jamais sur le serveur de l'API.
- **Réentraînement automatique sur les retours** : porte ouverte à l'empoisonnement
  ([feedback.md](feedback.md)).
