# Phishing 101 : comprendre l'arnaque pour mieux la détecter

*Temps de lecture : 10 minutes. Aucun prérequis technique.*

Ce document explique ce qu'est le phishing, comment une attaque se déroule et comment la
repérer. C'est aussi la base de tout ce que PhishGuard cherche à détecter.

> Tous les exemples utilisent des adresses fictives (`example.com`, `.test`). Les liens sont
> « désamorcés » : `hxxps://` au lieu de `https://` et `[.]` au lieu de `.`, pour qu'on ne
> puisse pas cliquer dessus par erreur.

---

## 1. Qu'est-ce que le phishing ?

Le **phishing** (ou *hameçonnage*) est une arnaque où quelqu'un se fait passer pour une
personne ou une organisation de confiance (banque, livreur, administration, collègue) afin
de vous pousser à faire quelque chose qui l'arrange : donner un mot de passe, un code reçu
par SMS, un numéro de carte, ou ouvrir un fichier piégé.

Le phishing n'attaque pas l'ordinateur, il attaque **la personne**. C'est pour cela qu'il
reste l'une des premières portes d'entrée des cyberattaques : il est plus facile de tromper
un humain pressé que de casser un système bien protégé.

### Les variantes

| Nom | Canal | En une phrase |
| --- | --- | --- |
| **Phishing** | Email | Le message envoyé en masse : « Votre compte sera suspendu, cliquez ici. » |
| **Spear phishing** | Email | Un phishing *ciblé* : l'attaquant connaît votre nom, votre poste, vos collègues, et rédige un message sur mesure. |
| **Smishing** | SMS | Le phishing par SMS : « Votre colis est bloqué, payez 1,99 € de frais. » |
| **Vishing** | Téléphone (voix) | Un faux conseiller bancaire vous appelle et vous demande de « valider une opération ». |
| **Quishing** | QR code | Un QR code (affiche, courrier, email) qui mène vers un faux site. Le lien est invisible tant qu'on n'a pas scanné. |
| **BEC** (*Business Email Compromise*) | Email professionnel | Un faux PDG ou un faux fournisseur demande un virement urgent ou un changement de RIB. Souvent sans aucun lien ni pièce jointe : juste une demande crédible. |

---

## 2. Comment se déroule une attaque

Une attaque de phishing suit presque toujours la même chaîne. La casser à **n'importe
quelle étape** suffit à la faire échouer.

```
 1. Prétexte  ->  2. Leurre  ->  3. Faux site  ->  4. Collecte  ->  5. Exploitation
 (l'histoire)    (le message)    (le piège)       (vos données)     (le vol)
```

1. **Le prétexte** : l'histoire qui rend la demande crédible. Un colis en attente, une
   facture impayée, une connexion suspecte, un remboursement des impôts, un message du
   patron. L'attaquant choisit un sujet qui touche beaucoup de monde, ou qui vous concerne
   personnellement (spear phishing).
2. **Le leurre** : le message lui-même. Il joue sur des émotions qui court-circuitent la
   réflexion :
   - l'**urgence** (« sous 24 h », « dernier rappel ») ;
   - la **peur** (« compte bloqué », « amende ») ;
   - l'**autorité** (« la direction », « la police », « votre banque ») ;
   - l'**appât du gain** (« vous avez gagné », « remboursement de 214 € »).
3. **Le faux site** : le lien mène à une page qui imite parfaitement le vrai site (logo,
   couleurs, formulaire). L'adresse, elle, est différente : c'est souvent le seul indice.
   Ces sites sont créés quelques heures ou jours avant l'attaque et disparaissent vite.
4. **La collecte** : vous tapez votre identifiant, votre mot de passe, votre code SMS ou
   votre carte bancaire. Les informations partent immédiatement chez l'attaquant, parfois
   pendant que la page affiche « Merci, votre compte est vérifié ».
5. **L'exploitation** (ou *exfiltration*) : l'attaquant se connecte à votre compte, vide
   le compte bancaire, revend les identifiants, ou utilise votre messagerie pour piéger
   vos contacts. En entreprise, ce premier accès sert souvent de tremplin vers une
   attaque plus grave (rançongiciel, vol de données).

---

## 3. Les ruses sur les adresses web (URL)

Une adresse web se lit **de droite à gauche** à partir du premier `/` : ce qui compte,
c'est le **nom de domaine principal**, juste avant l'extension (`.com`, `.fr`…).

```
hxxps://paypal.com.secure-login[.]example/connexion
         \_______________/ \______________/
          sous-domaines     domaine réel = secure-login.example  (pas PayPal !)
```

| Ruse | Exemple (fictif, désamorcé) | Ce qui trompe |
| --- | --- | --- |
| **Typosquatting** | `hxxps://paypa1[.]example`, `amazom[.]example` | Une lettre changée, ajoutée ou inversée. L'œil lit ce qu'il s'attend à lire. |
| **Sous-domaine trompeur** | `hxxps://paypal.com.verif-compte[.]example` | Le nom de la marque est au début, mais le vrai domaine est à la fin. |
| **Homographe** | `hxxps://раypal[.]example` | Le « р » et le « а » sont des lettres **cyrilliques** identiques à l'œil. Le navigateur peut afficher `xn--ypal-…` (Punycode). |
| **Mots rassurants** | `secure-`, `login-`, `verify-`, `-officiel` | Des mots qui inspirent confiance ajoutés à un domaine quelconque. |
| **Raccourcisseur** | `hxxps://bit[.]ly/3xYz` | La vraie destination est cachée jusqu'au clic. |
| **Service de confiance détourné** | un formulaire hébergé sur un service de documents ou de stockage connu | Le domaine est légitime ; c'est le contenu qui est piégé. Aucune liste noire de domaines ne le bloque. |
| **Le cadenas** | `https://` avec cadenas | Le cadenas prouve seulement que la connexion est chiffrée, **pas** que le site est honnête. La grande majorité des sites de phishing ont un cadenas. |

---

## 4. L'authentification des emails : SPF, DKIM, DMARC

L'adresse d'expéditeur d'un email peut être falsifiée aussi facilement que celle écrite
au dos d'une enveloppe. Trois mécanismes permettent au serveur qui reçoit l'email de
vérifier son origine :

- **SPF** : le propriétaire d'un domaine publie la liste des serveurs autorisés à envoyer
  des emails en son nom ; un email venant d'un autre serveur est suspect.
- **DKIM** : le serveur d'envoi signe l'email avec une clé cryptographique ; le
  destinataire vérifie la signature pour s'assurer que l'email vient bien du domaine et
  n'a pas été modifié en route.
- **DMARC** : le propriétaire du domaine indique quoi faire si SPF et DKIM échouent
  (laisser passer, mettre en spam, rejeter) et exige que le domaine vérifié corresponde à
  celui affiché dans le champ « De ».

Ces résultats sont inscrits dans les en-têtes de l'email (`Authentication-Results`).
PhishGuard les lit pour repérer un expéditeur usurpé. Attention : un email qui passe ces
trois contrôles peut quand même être du phishing, si l'attaquant a acheté un domaine
ressemblant (`banque-securite[.]example`) et l'a correctement configuré.

---

## 5. Comment reconnaître une attaque (pour tout le monde)

**Les signaux d'alerte**

1. **On vous presse** : délai très court, menace, ton dramatique.
2. **On vous demande un secret** : mot de passe, code reçu par SMS, numéro de carte.
   Votre banque, votre opérateur et l'administration **ne vous demandent jamais** votre
   mot de passe ou un code de validation par message ou par téléphone.
3. **L'adresse ne colle pas** : l'expéditeur ou le lien ne correspond pas exactement au
   site officiel (survolez le lien sans cliquer pour voir la vraie destination).
4. **Le message est inattendu** : un colis que vous n'attendez pas, une facture d'un
   service auquel vous n'êtes pas abonné.
5. **Un changement de coordonnées bancaires** annoncé par email : appelez toujours le
   fournisseur sur un numéro que vous connaissez déjà.

> Les fautes d'orthographe ne sont plus un bon indice : les outils d'IA permettent
> désormais d'écrire des messages de phishing parfaits, dans toutes les langues.

**Les bons réflexes**

- **Ne cliquez pas** : ouvrez l'application officielle ou tapez vous-même l'adresse du
  site.
- **Vérifiez par un autre canal** : rappelez la personne ou l'organisme sur un numéro
  connu, jamais celui donné dans le message.
- **Activez la double authentification** (code ou application) sur vos comptes
  importants : un mot de passe volé ne suffit alors plus.
- **Si vous avez cliqué ou saisi un mot de passe** : changez-le tout de suite (et partout
  où vous l'utilisez), prévenez votre banque si vous avez donné des informations de
  paiement, et signalez l'arnaque (en France : 33700 pour les SMS, signal-spam.fr pour
  les emails, cybermalveillance.gouv.fr pour l'aide aux victimes).

---

## 6. Correspondance avec MITRE ATT&CK

[MITRE ATT&CK](https://attack.mitre.org/) est la référence mondiale qui classe les
techniques des attaquants. Les analystes de sécurité l'utilisent comme vocabulaire
commun. Chaque détection de PhishGuard sera associée à une ou plusieurs de ces
techniques.

| Technique | Nom | Ce que cela recouvre |
| --- | --- | --- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Envoi de messages piégés pour obtenir un accès initial. |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Le piège est une **pièce jointe** (document Office avec macro, archive, fichier HTML). |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link | Le piège est un **lien** vers un faux site ou un téléchargement. Cœur de cible de PhishGuard. |
| [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | Spearphishing via Service | Le message passe par un **service tiers** (réseau social, messagerie instantanée) plutôt que par l'email de l'entreprise. |
| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | L'attaque repose sur **une action de la victime** : cliquer sur un lien (T1204.001) ou ouvrir un fichier (T1204.002). C'est l'étape que PhishGuard veut interrompre. |

Techniques voisines utiles pour la suite du projet : T1598 *Phishing for Information*
(le but est de collecter des informations plutôt que d'obtenir un accès) et T1583.001
*Acquire Infrastructure: Domains* (achat de domaines ressemblants avant l'attaque).

---

## Pour aller plus loin

- MITRE ATT&CK, technique T1566 : <https://attack.mitre.org/techniques/T1566/>
- APWG, rapports trimestriels sur le phishing : <https://apwg.org/trendsreports/>
- Cybermalveillance.gouv.fr, fiches réflexes hameçonnage : <https://www.cybermalveillance.gouv.fr/>
- TryHackMe, salle « Phishing » et parcours SOC Level 1 : <https://tryhackme.com/>
