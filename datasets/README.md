# Jeux de données versionnés

Ce dossier ne contient que des jeux **rédigés pour le projet** : aucun message réel, aucune donnée personnelle. Les corpus publics (UCI, flux de phishing) ne sont jamais versionnés : ils sont téléchargés par les scripts dans `data/` (voir [`docs/data-sources.md`](../docs/data-sources.md)).

## `sms_fr_ar.csv` : SMS français et arabes (étape 1.9)

| | Français | Arabe | Total |
| :--- | ---: | ---: | ---: |
| Smishing | 30 | 20 | 50 |
| Légitime | 30 | 20 | 50 |

Colonnes : `id`, `lang` (`fr`, `ar`), `label` (1 = smishing, 0 = légitime), `category` (`colis`, `banque`, `administration`, `operateur`, `gain`, `famille`, `emploi`, `poste` ; `otp`, `livraison`, `rdv`, `perso`…), `text`.

### Comment il a été constitué

Les données publiques de smishing en français et en arabe sont rares et rarement redistribuables. Les messages ont donc été **rédigés à la main**, sur le modèle des arnaques les plus signalées dans les campagnes de sensibilisation publiques : faux frais de livraison, remboursement Ameli, amende ANTAI, droits CPF, carte Vitale, « maman, j'ai changé de numéro », banque et opérateurs côté français ; Algérie Poste, BaridiMob, carte Edahabia et opérateurs mobiles côté arabe. Les messages légitimes couvrent les cas que le smishing imite : codes à usage unique, livraisons, rendez-vous, messages personnels, et des messages légitimes **avec un lien**, pour qu'un modèle ne puisse pas apprendre « lien = arnaque ».

### Anonymisation (vérifiée par un test)

- Tous les liens utilisent le domaine réservé `.example` (RFC 2606) : aucun ne mène à un vrai site.
- Les numéros français sont pris dans les tranches réservées à la fiction par l'ARCEP (`01 99 00`, `06 39 98`). Les numéros algériens ont la forme `05 50 00 00 xx`, `07 70 00 00 xx`, `06 60 00 00 xx`.
- Aucun nom réel de personne. Les noms d'organismes et d'entreprises sont ceux que les escrocs usurpent : ils ne désignent pas l'expéditeur réel.

### Usage et limites

- **Test hors distribution uniquement.** Aucun modèle ne doit s'entraîner ni régler un seuil sur ce jeu, sinon il ne mesure plus la généralisation. Un futur jeu de validation FR/AR devra être distinct.
- **Rédigé, donc biaisé** : un message écrit par la même personne que le jeu d'entraînement reflète ses idées sur le smishing. Les messages réels ont des fautes, des abréviations et des variantes dialectales (darija algérienne, arabizi en lettres latines) absentes ici.
- **Petit** : un écart de 10 points de rappel représente 2 à 3 messages. Ce jeu donne un ordre de grandeur.
- Licence : comme le reste du dépôt (MIT).
