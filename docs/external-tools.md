# Évaluation d'outils externes

*Décisions prises le 02/11/2026, à la fin du module 2. Un outil n'entre dans PhishGuard que s'il apporte une valeur réelle **et** respecte les principes du projet : vie privée d'abord, analyse locale par défaut, aucun outil offensif, licence compatible avec MIT.*

| Outil | Ce que c'est | Décision |
| --- | --- | --- |
| [EML Analyzer](#eml-analyzer) | Application open source d'analyse de fichiers `.eml` | **Idée reprise, outil non intégré** : analyse du contenu des pièces jointes (étape 2.13) |
| [Format Outlook `.msg`](#format-outlook-msg) | Format des emails enregistrés depuis Outlook pour Windows | **Plus tard** ([issue #124](https://github.com/arixstoo/PhishGuard/issues/124)) |
| [DeHashed](#dehashed) | Moteur de recherche payant dans des fuites de données | **Écarté** |
| [PhishTool](#phishtool) | Plateforme commerciale d'analyse d'emails pour analystes | **Référence de comparaison** pour les tests utilisateurs (étape 5.13), pas d'intégration |

## EML Analyzer

[github.com/ninoseki/eml_analyzer](https://github.com/ninoseki/eml_analyzer), licence MIT.

**Ce qu'il fait** :
- analyse les en-têtes et le corps, et extrait les indicateurs (URLs, domaines, IP, adresses) ;
- interroge VirusTotal et urlscan.io ;
- calcule un score SpamAssassin ;
- lit le format `.msg` ;
- repère les fichiers OLE suspects dans les pièces jointes.

**Pourquoi l'outil n'est pas intégré** :

- c'est une **application** complète (FastAPI, interface Vue, Redis, démon SpamAssassin), pas une bibliothèque : son `pyproject.toml` déclare `package = false` ;
- il exige Python 3.14 uniquement, alors que PhishGuard vise 3.11 et plus ;
- il fait en double ce que PhishGuard fait déjà : en-têtes, authentification et liens (étape 1.10), VirusTotal et urlscan (étapes 2.5 et 2.6) ;
- SpamAssassin (un démon Perl) mesure le spam, pas le phishing ;
- `dkimpy` revérifie les signatures DKIM : le projet lit plutôt le résultat écrit par le serveur de réception (étape 1.10), la bonne pratique, sans requête DNS de plus.

**Ce qui est repris** : l'idée d'**inspecter le contenu des pièces jointes**, que notre parseur jugeait sur leur seul nom. Elle est réalisée à l'étape 2.13 ([issue #123](https://github.com/arixstoo/PhishGuard/issues/123), [`attachments.md`](attachments.md)), sans aucune dépendance à EML Analyzer :

- vrai type par signature ;
- macros VBA (avec `olefile`, licence BSD) et modèles distants ;
- archives listées sans extraction ;
- PDF actifs ;
- pages HTML qui demandent un mot de passe.

## Format Outlook `.msg`

**Valeur** : réelle mais limitée aujourd'hui. Les webmails (Gmail, Outlook web) exportent en `.eml`, et seul Outlook pour Windows enregistre en `.msg`. Le format deviendra utile quand le bot (étape 5.11) recevra des messages transférés.

**Décision : plus tard**, en suivant l'[issue #124](https://github.com/arixstoo/PhishGuard/issues/124). Point à vérifier avant de commencer : la **licence** de la bibliothèque. `extract-msg`, la plus connue, est sous GPL, incompatible avec la licence MIT actuelle du projet. Le `.msg` étant un fichier OLE, `olefile` (déjà ajouté à l'étape 2.13) en lit la structure.

## DeHashed

**Ce que c'est** : un service payant qui cherche une adresse email, un nom d'utilisateur, un téléphone ou une IP dans des bases de données issues de fuites, et peut renvoyer les mots de passe associés.

**Décision : écarté**, pour trois raisons :

1. **Il ne répond pas au problème.** Savoir qu'une adresse figure dans une fuite ne dit rien sur le fait qu'un lien, un SMS ou un email soit du phishing.
2. **Il contredit les principes du projet.** Il renvoie des données personnelles de tiers, parfois des mots de passe. Le cahier des charges place la vie privée en priorité n° 1, et exclut tout outil offensif. Ces données sont à double usage : le même service sert à préparer des attaques.
3. **Il est payant**, avec un usage réservé à des fins de sécurité légitimes. Les tarifs publiés par des tiers sont contradictoires et datés.

**Si l'on veut un jour l'angle « mes identifiants ont-ils fuité ? »**, par exemple un conseil après un clic, l'alternative respectueuse est Have I Been Pwned. Son service *Pwned Passwords* vérifie un mot de passe **sans jamais l'envoyer** (k-anonymat : seuls les 5 premiers caractères de son empreinte SHA-1 partent). Ce serait de la remédiation, pas de la détection : hors du périmètre actuel.

## PhishTool

**Ce que c'est** : une plateforme d'enquête sur les emails pour les analystes SOC. Elle offre une vue analyste des en-têtes, de l'authentification, des liens et des pièces jointes, enrichie par des services tiers. Elle a une offre gratuite (*Community*, un utilisateur, analyses limitées) et des offres payantes ; d'après sa page de tarifs, l'API n'est disponible qu'en payant.

**Décision : pas d'intégration dans le code.**

- L'intégrer voudrait dire **envoyer les emails complets des utilisateurs** à une entreprise tierce. Le cahier des charges l'interdit : « on envoie au maximum une URL ou un domaine, jamais le corps d'un email ».
- Elle s'appuie elle-même sur des sources que PhishGuard interroge déjà (VirusTotal…).
- L'API demande une offre payante.

**Rôle retenu : une référence de comparaison** pendant les tests utilisateurs de l'étape 5.13. PhishTool est un outil d'analyste reconnu : comparer ses constats à ceux de PhishGuard sur les mêmes emails met en évidence ce que PhishGuard rate, ou signale à tort.

### Protocole de comparaison (étape 5.13)

1. **Emails utilisés** : uniquement des emails **de test**. Ce sont les emails rédigés pour le projet (`tests/fixtures/emails/`) et les messages piégés préparés pour les testeurs. **Jamais l'email réel d'une personne** : PhishTool est un service tiers. Ne pas y verser non plus les emails de Phishing Pot (licence CC BY-NC, données de victimes réelles).
2. **Compte** : offre Community, créée par le mainteneur. Relire les conditions d'utilisation avant la première analyse : quota, et droits de PhishTool sur les fichiers soumis.
3. **Pour chaque email**, noter dans le tableau ci-dessous les constats des deux outils sur :
   - l'authentification (SPF, DKIM, DMARC) ;
   - l'expéditeur (`Reply-To`, nom affiché) ;
   - les liens et leur réputation ;
   - les pièces jointes ;
   - le verdict final.
4. **Classer chaque écart** :
   - *PhishGuard rate un indicateur* : créer un cas de test qui le reproduit, puis corriger ;
   - *PhishGuard signale ce que PhishTool ne voit pas* : vérifier qu'il ne s'agit pas d'un faux positif ;
   - *désaccord sur le verdict* : documenter qui a raison, et pourquoi.
5. **Rapport** : une section « Comparaison avec PhishTool » dans `docs/user-tests.md` (livrable de l'étape 5.13), avec le tableau et les corrections qui en découlent.

| Email de test | Constat | PhishGuard | PhishTool | Écart et suite donnée |
| --- | --- | --- | --- | --- |
| `02_phish_link_mismatch.eml` | Lien trompeur | … | … | … |
| … | | | | |

## Méthode pour un prochain outil

Avant d'ajouter un outil, répondre par écrit, dans ce fichier :

1. **Quel problème de détection** résout-il, que le projet ne résout pas encore ?
2. **Qu'envoie-t-il, et à qui ?** Rien de plus qu'une URL ou un domaine, et seulement sur opt-in.
3. **Licence** compatible avec MIT ? Pas de GPL dans le paquet.
4. **Coût et conditions** : gratuit ou payant, usage commercial autorisé ou non ?
5. **Peut-on reprendre l'idée sans la dépendance** ? C'est souvent la meilleure option, comme pour EML Analyzer.
