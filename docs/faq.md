# Questions fréquentes

## Utiliser PhishGuard

**PhishGuard est-il gratuit ?**
Oui, entièrement, et sans publicité. C'est un logiciel libre ([licence MIT](https://github.com/arixstoo/PhishGuard/blob/master/LICENSE)).

**Que veulent dire « sûr », « suspect » et « phishing » ?**
*Sûr* : rien d'inquiétant dans l'adresse. *Suspect* : des signes qui méritent de la
prudence ; ne saisissez rien sans vérifier. *Phishing* : l'adresse a les marques d'une
page piégée ; quittez-la. Le verdict est toujours accompagné d'une phrase qui dit
pourquoi, et la couleur n'est jamais le seul indice (icône et texte aussi).

**Un site « sûr » est-il garanti ?**
Non. PhishGuard juge l'adresse, sans visiter la page. Une page piégée hébergée sur une
plateforme connue (un formulaire en ligne, un document partagé) peut avoir une adresse
banale. Les chiffres, y compris ces cas manqués, sont publiés dans la
[fiche du modèle](model-card-url.md). Restez vigilant : ne donnez jamais un mot de passe
ou un code reçu par SMS à la suite d'un message inattendu.

**Fonctionne-t-il sans Internet ?**
Oui. L'analyse se fait sur votre ordinateur, avec un modèle livré dans l'extension. Elle
prend quelques millisecondes.

**Fonctionne-t-il avec Outlook, Yahoo Mail, le téléphone ?**
Dans le navigateur, le bouclier fonctionne sur tous les sites, donc aussi sur un lien
ouvert depuis n'importe quelle messagerie. L'analyse automatique des messages ouverts
n'existe que pour Gmail. Chrome sur téléphone n'accepte pas les extensions.

**Et Firefox ?**
Pas encore : une version Firefox est envisagée après la publication sur le Chrome Web Store.

## Erreurs

**PhishGuard signale un site que je sais légitime.**
Dans la fenêtre de PhishGuard, choisissez **« Toujours faire confiance à ce site »** : il
ne sera plus signalé, sauf si son adresse imite des lettres d'un autre alphabet (une
technique d'usurpation courante, jamais ignorée). Pour nous aider à corriger l'erreur,
signalez-la avec le [formulaire de signalement](https://github.com/arixstoo/PhishGuard/issues/new?template=detection_feedback.yml),
en écrivant l'adresse sous la forme `hxxps://exemple[.]com` pour qu'elle ne soit pas
cliquable.

**PhishGuard n'a pas vu un site de phishing.**
Même formulaire. Votre signalement est relu par une personne ; il ne modifie jamais le
modèle automatiquement, pour qu'un tiers ne puisse pas l'influencer.

## Données et sécurité

**Que sait PhishGuard de moi ?**
Rien, par défaut : pas de compte, pas d'identifiant, pas d'historique, et aucune donnée
envoyée. Le détail, une ligne par donnée : [confidentialité](privacy.md).

**Pourquoi Chrome dit-il que PhishGuard peut « lire et modifier vos données sur mail.google.com » ?**
C'est l'autorisation qui lui permet de vérifier les liens **du message que vous ouvrez**
dans Gmail et d'afficher un bandeau d'alerte. La lecture se fait sur votre ordinateur ;
rien n'est gardé ni envoyé. Vous pouvez couper cette analyse dans les options. La
justification de chaque autorisation : [données de l'extension](extension-privacy.md#5-les-autorisations-demandées).

**Le modèle de détection se met-il à jour ?**
Si vous le voulez : l'option **« Recevoir les mises à jour signées du modèle »** est
désactivée par défaut. Activée, elle télécharge au plus une fois par jour le dernier
modèle publié, et ne l'installe que si sa signature prouve qu'il vient du projet
([comment](model-updates.md#4-côté-extension)).

**J'ai trouvé une faille de sécurité.**
Merci ! Signalez-la en privé, jamais dans une issue publique : [politique de sécurité](security.md).

## Le projet

**Qui fait PhishGuard ?**
Un développeur, à titre personnel, en public sur [GitHub](https://github.com/arixstoo/PhishGuard).
Toute aide est la bienvenue : [contribuer](contributing.md).

**Comment est-il construit et évalué ?**
Voir l'[architecture](architecture.md), les [fiches des modèles](model-card-url.md) et le
[rapport de robustesse](robustness-report.md) : les chiffres y sont mesurés sur des
attaques postérieures à l'entraînement, et les faux positifs comptent autant que les
détections manquées.
