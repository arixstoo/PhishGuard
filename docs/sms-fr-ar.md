# Jeu complémentaire SMS français / arabe

Fichier : [`datasets/sms_fr_ar.csv`](../datasets/sms_fr_ar.csv) (colonnes `lang`, `label`, `theme`, `text`, `label` = 1 pour smishing).

## Pourquoi

La UCI SMS Spam Collection est en anglais, date de 2011 et parle surtout de spam commercial (« WIN a prize, text 87121 »). Les arnaques actuelles en France et au Maghreb parlent de colis, de carte Vitale, d'amendes, de comptes bancaires bloqués ou de « Maman, j'ai changé de numéro ». Aucun corpus public, propre et sous licence claire n'existe pour ces langues. Ce petit jeu sert **uniquement de test hors distribution** : il mesure si un modèle entraîné sur l'anglais généralise à d'autres langues. Il ne sert jamais à l'entraînement ni au choix des hyperparamètres.

## Taille

| langue | smishing | légitime | total |
|---|---:|---:|---:|
| français | 20 | 20 | 40 |
| arabe (dont 2 en darija écrite en lettres latines) | 15 | 15 | 30 |
| **total** | **35** | **35** | **70** |

## Constitution et anonymisation

- **Aucun message réel n'a été copié.** Les messages ont été rédigés à la main en reprenant les scénarios d'arnaque décrits publiquement dans les campagnes de sensibilisation (thèmes : colis et frais de réexpédition, santé et carte Vitale, compte formation, amendes, remboursement d'impôts, banque, faux proche, gain, emploi à domicile, énergie, télécom, messagerie).
- **Liens** : tous les domaines utilisent le TLD réservé `.example` (RFC 2606). Aucun ne peut résoudre vers un vrai site. Un test vérifie que c'est toujours le cas.
- **Numéros** : fictifs (`01 00 00 00 00`, `0600000000`…). Aucune adresse email, aucun nom de personne réelle.
- **Messages légitimes** : un mélange de messages du quotidien et de **négatifs difficiles**, c'est-à-dire des notifications honnêtes qui ressemblent au smishing : code de vérification à 6 chiffres, confirmation de paiement avec montant, colis livré, « urgent : rappelle-moi ». Ce sont ces messages qui révèlent les faux positifs.

## Limites

- **Trop petit pour des conclusions fines.** Avec 35 positifs, un message mal classé fait bouger le rappel de près de 3 points. Les écarts de quelques points entre deux modèles ne sont pas significatifs, et le « rappel à 1 % de FPR » sur 35 négatifs revient à exiger zéro faux positif.
- **Biais de rédaction** : des messages écrits par une seule personne sont plus propres et plus homogènes que les vrais (moins de fautes, moins de variantes, pas d'emojis). Les vrais SMS frauduleux sont probablement plus faciles sur certains points (liens raccourcis) et plus durs sur d'autres.
- **Arabe** : surtout de l'arabe standard. La darija et l'arabizi (arabe en lettres latines et chiffres) sont presque absents, alors qu'ils dominent les vrais SMS au Maghreb.
- **Vocabulaire recoupé avec les features smishing** : la liste de mots d'urgence a été écrite par la même personne que les messages. Le gain apporté par ces features sur ce jeu est donc probablement surestimé.

## Pistes pour l'agrandir

Collecter des signalements publics (captures diffusées par les CERT nationaux et les sites de sensibilisation), les retranscrire, remplacer chaque lien par un domaine `.example` et chaque numéro par un numéro fictif, puis noter la source et la date dans une colonne supplémentaire. Viser au moins 200 messages par langue avant d'en tirer des conclusions.
