# Plan de lancement (étape 6.11)

Le lancement n'est pas une date : c'est quatre semaines de travail, dont deux **avant** le
jour J. Ce plan dit quoi faire, dans quel ordre, et à quoi on reconnaît que c'est fait.
Les textes sont prêts dans [posts.md](posts.md), l'article dans [article.md](article.md),
le scénario de la vidéo dans [demo.md](demo.md).

## Conditions pour fixer le jour J

Ne pas lancer avant que **tout** ceci soit vrai : un lancement ne se rejoue pas.

- [ ] Extension **publique** sur le Chrome Web Store ([store.md](../store.md)), installée
      sur un profil Chrome neuf par quelqu'un d'autre que l'auteur.
- [ ] API en production, `make edge-smoke` vert, alerte Telegram reçue lors d'un arrêt
      volontaire ([operations.md](../operations.md)).
- [ ] Site de documentation en ligne, lien d'installation du store sur la page d'accueil.
- [ ] Tests utilisateurs faits, SUS ≥ 70 sur le dernier groupe ([user-tests.md](../user-tests.md)).
- [ ] Tag `v1.0.0` poussé : release GitHub avec archives, empreintes et attestations.
- [ ] Une semaine sans incident sur la version non répertoriée, avec les testeurs.

## Semaine −2 : préparer

| Tâche | Fait quand |
|---|---|
| Vidéo de démonstration de 90 secondes ([demo.md](demo.md)) | publiée (YouTube non répertorié ou fichier de la release), sous-titrée FR et EN |
| GIF en tête du README | 10 à 15 s, moins de 5 Mo, dans `docs/img/demo.gif` ; l'image actuelle du README est une vraie capture de l'extension |
| 10 testeurs bêta qui s'engagent à laisser un avis | noms (pour soi, jamais publiés) et date d'installation notés ; message de recrutement dans [posts.md](posts.md#recrutement-des-testeurs) |
| Brouillon de l'article relu par deux personnes, dont une non technique | chaque chiffre vérifié contre `docs/metrics/` (section « Chiffres » de [article.md](article.md)) |
| Comptes prêts | dev.to ou Medium, LinkedIn à jour, compte Reddit avec un historique (les nouveaux comptes sont filtrés), compte Hacker News |
| Réponses préparées aux questions attendues | section « Questions attendues » de [posts.md](posts.md#questions-attendues) |
| Tableau de suivi | issue épinglée « Lancement » : liens publiés, chiffres J, J+7, J+28 |

## Semaine −1 : répéter

- Relire l'article à voix haute ; couper ce qui ne sert pas l'histoire.
- Installer depuis le store sur trois machines (Windows, macOS ou Linux, Chromebook si
  possible) et sur Firefox si l'extension y est publiée.
- Vérifier les liens de chaque texte de [posts.md](posts.md) : store, dépôt, site, article.
- Vider la file : aucune issue ouverte de plus de 7 jours sans réponse.
- Choisir le jour : un mardi ou un mercredi, le matin heure de la côte est des États-Unis
  pour Hacker News (après-midi en France), jamais une veille de jour férié.

## Jour J

Dans cet ordre, sur une demi-journée, pour pouvoir répondre ensuite :

1. **Article** publié (dev.to, Medium ou LinkedIn) : « Ce que j'ai appris en construisant un
   détecteur de phishing open source ».
2. **LinkedIn** : le post avec le GIF et le lien du dépôt.
3. **Show HN** : titre et premier commentaire de [posts.md](posts.md#show-hn), lien vers le
   dépôt (pas vers l'article).
4. **Reddit** : r/cybersecurity et r/chrome_extensions, en respectant les règles de chaque
   communauté (autopromotion, jour dédié, mot-clé) ; les relire **le jour même**, elles
   changent.
5. **Messages directs** : communautés cyber étudiantes, CERT et associations de
   sensibilisation, écoles ([posts.md](posts.md#message-aux-communautés-cert-associations-écoles)),
   famille et amis.

**Pendant la première semaine, réponse à chaque commentaire et chaque issue en moins de
24 heures.** Un faux positif signalé publiquement reçoit une réponse publique, factuelle,
avec la suite donnée.

## Semaines +1 à +4 : entretenir

| Semaine | Article technique | Autre |
|---|---|---|
| +1 | Le garde-fou SSRF : pourquoi le serveur ne visite jamais l'URL ([ssrf.md](../ssrf.md)) | release corrective `1.0.1` avec les premiers retours |
| +2 | Le split temporel : la fuite de données qui gonflait mes chiffres ([split.md](../split.md)) | mise en avant des premiers contributeurs |
| +3 | L'évasion par homoglyphes et sous-domaines, et ce qui l'a corrigée ([robustness-report.md](../robustness-report.md)) | premier rapport d'adoption public ([measure.md](../measure.md)) |
| +4 | Bilan : chiffres d'adoption, ce que les utilisateurs ont mal compris, suite ([roadmap.md](../roadmap.md)) | mise à jour du README et du portfolio |

## Mesurer le lancement

Uniquement des totaux ([measure.md](../measure.md)) : installations et utilisateurs actifs
du store, étoiles, issues, analyses de l'API, faux positifs signalés. Relevés à J, J+7 et
J+28 dans l'issue « Lancement ». Objectifs du cahier des charges, à six mois : 100
installations actives, 50 étoiles, 5 retours d'utilisateurs réels.

Ne jamais : acheter des étoiles, demander des votes sur Hacker News ou Reddit (interdit et
détecté), publier le même texte en boucle, ajouter un traceur au lien d'installation.
