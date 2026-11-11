# Explications du modèle de texte (SMS et messageries)

*Étape 3.3 du cahier des charges. Code : `src/phishguard/explain/text.py` (contributions), `src/phishguard/explain/reasons.py` (phrases), `src/phishguard/analysis.py` (`TextAnalyzer`). Calibration : `scripts/calibrate_text.py` (`make calibrate-text`). Tests : `tests/test_explain_text.py`.*

Le modèle SMS `text_v1` (étape 1.9, [`model-card-text.md`](model-card-text.md)) est un SVM linéaire sur des n-grammes de caractères. Cette étape lui donne ce que l'URL a depuis les étapes 3.1 et 3.2 : un score utilisable par la fusion, des raisons lisibles et un conseil d'action, dans le même schéma de réponse.

```python
analyzer = TextAnalyzer.from_files(
    Path("models/text_v1.joblib"), Path("models/text_v1_calibration.json")
)
response = analyzer.analyze(sms, channel="sms").to_response("fr")  # aucun appel réseau
```

## Contribution de chaque mot

Un modèle linéaire sur TF-IDF s'additionne exactement :

```
score = constante + somme sur les n-grammes j de (coefficient_j × tfidf_j)
```

La contribution d'un n-gramme est donc `coefficient × tfidf` : pas d'approximation, pas d'échantillonnage. C'est vrai pour la régression logistique (score en log-odds) comme pour le SVM (score = marge).

Un n-gramme de caractères (« `rif` », « `z i` ») ne parle à personne. Chaque contribution est ramenée **aux mots du message** :

- un n-gramme présent plusieurs fois partage sa contribution entre ses occurrences ;
- `char_wb` ne franchit jamais un espace : chaque occurrence appartient à un seul mot, qui la reçoit ;
- pour un modèle sur les mots, un bigramme (« votre compte ») partage la sienne entre ses deux mots.

La somme des contributions des mots est **exactement** celle des n-grammes. Sur les 100 messages du jeu français / arabe, l'écart entre cette somme et la marge du SVM est de 7 × 10⁻¹⁶. Les tests vérifient l'égalité pour le SVM, la régression logistique et le modèle sur les mots, et que les n-grammes reconstruits sont ceux de scikit-learn.

## Catégories de leurre

Les mots seuls ne disent pas tout : « Le message parle d'un code » est plus utile que « le mot *code* a pesé 0,3 ». Cinq catégories sont repérées avec les mots-clés de l'étape 1.9, en français, en anglais et en arabe :

| Catégorie | Repérée par |
| --- | --- |
| `urgency` | mots d'urgence ou de menace (« immédiatement », « bloqué », « فوراً ») |
| `money` | montant avec une devise (« 500 € »), mots de gain ou de remboursement |
| `link` | un lien (schéma, `www.`, domaine nu) |
| `code` | code, OTP, PIN, mot de passe (« رمز ») |
| `account` | compte, carte, identifiant, colis |

Un lien ne compte que comme lien : `caf-verification.example` ne « demande pas de code ». Chaque catégorie reçoit la somme des contributions positives des mots qui l'évoquent (« urgent », « 500 » dans « 500 € », le lien lui-même).

## Les raisons du texte

Mêmes règles que pour l'URL ([`reasons.md`](reasons.md)) : au plus trois raisons, la part du modèle répartie au prorata des contributions, toujours un conseil.

1. **Les catégories** qui ont fait monter le score, par poids.
2. **Puis les mots** : une raison unique cite les trois mots restants les plus influents (« Des mots comme « visiteur, port » reviennent souvent dans les messages frauduleux. »). Seulement pour un verdict suspect ou phishing : dire d'un message jugé sûr que ses mots « reviennent dans les messages frauduleux » serait trompeur.
3. **Puis, à 0 point**, une catégorie présente qui n'a pas fait monter le score, pour un verdict suspect ou phishing.
4. À défaut, « Le style de ce message ressemble à celui de messages frauduleux connus. »

Un mot n'est jamais recopié s'il est un lien (il deviendrait cliquable dans une messagerie), s'il n'a aucune lettre (un code reçu, un numéro de téléphone), si c'est un mot-outil (« votre », « est ») ou s'il fait moins de trois caractères. Les autres passent par le même nettoyage que les fragments d'URL (`safe_fragment`).

## Calibration

La marge d'un SVM n'est pas une probabilité : la fusion de l'étape 2.10 ne peut pas l'utiliser telle quelle. `scripts/calibrate_text.py` apprend la fonction marge → probabilité sur la **validation** de l'étape 1.9 (même corpus, mêmes doublons retirés, même graine, test jamais lu), avec la méthode de l'URL : isotone et Platt comparées en validation croisée, la meilleure au score de Brier.

| Méthode | Brier | ECE | Perte logarithmique |
| --- | ---: | ---: | ---: |
| marge brute (bornée à [0, 1]) | 0,0210 | 0,0338 | 0,1206 |
| isotone | 0,0075 | 0,0052 | 0,0530 |
| **Platt** (retenue) | **0,0063** | **0,0032** | **0,0281** |

774 messages de validation, dont 12,4 % de spam. Détail : [`metrics/text_calibration.json`](metrics/text_calibration.json). Platt l'emporte ici, contrairement à l'URL : avec 96 messages positifs seulement, la fonction en escalier de la régression isotone colle trop aux données. Sans fichier de calibration, `TextAnalyzer` ramène la marge par une sigmoïde centrée sur le seuil du modèle et le signale dans le journal.

## Exemples

Sortie réelle de `text_v1` calibré, sur des messages du jeu [`datasets/sms_fr_ar.csv`](../datasets/sms_fr_ar.csv), rédigés pour le projet (domaines en `.example`).

**« Votre colis est en attente : frais de réexpédition de 1,99 € à régler sous 24h sur https://suivi-colis-livraison.example/r/8F2K »** : phishing, score 75

- [28,8] Le message vous pousse à ouvrir un lien.
- [7,4] Le message parle d'argent : un paiement, un gain ou un remboursement.
- [2,6] Le message parle de votre compte, de votre carte ou d'un colis.
- *Conseil* : Ne cliquez pas sur le lien et ne répondez pas. Contactez l'organisme par son numéro ou son site officiel.

**« Vous êtes notre 1 000 000e visiteur ! Un bon d'achat de 500 € vous attend, frais de port 1 € : bon-cadeau.example »** : phishing, score 93

- [25,1] Le message parle d'argent : un paiement, un gain ou un remboursement.
- [5,8] Le message vous pousse à ouvrir un lien.
- [24,3] Des mots comme « visiteur, 000e, port » reviennent souvent dans les messages frauduleux.

**« Votre code de vérification est 482913. Ne le communiquez à personne, même à un conseiller. »** : sûr, score 13

- [3,0] Le message parle d'un code ou d'un mot de passe : ne le communiquez jamais.
- *Conseil* : Aucun signal inquiétant. Ne communiquez jamais un code reçu par message, même à quelqu'un qui se présente comme votre banque.

**« La réunion de 15h est déplacée en salle B. Merci de prévenir l'équipe. »** : sûr, score 2, aucune raison.

**Message arabe ar-061** (« بريد الجزائر : تم تعليق بطاقتك الذهبية… », carte bloquée, lien de mise à jour) : sûr, score 7, avec une seule raison : « Le message vous pousse à ouvrir un lien. » C'est un **faux négatif** : appris sur un corpus anglais, le modèle n'est pas prêt pour l'arabe. Sur le jeu arabe rédigé, il rate 35 % du smishing et signale 40 % des messages légitimes ([`model-card-text.md`](model-card-text.md#chiffres)). L'explication ne le cache pas : elle montre que seul le lien a pesé.

## Limites

- **Le modèle a appris le spam, pas le phishing.** Le corpus UCI mélange arnaques et publicités ; « visiteur » ou « port » pèsent parce qu'ils ressemblent à des concours publicitaires. Les catégories, écrites à la main, compensent en partie.
- **Les n-grammes de caractères répartissent le crédit au-delà du sens.** « 000e » pèse parce que ses n-grammes (`00`, `0e`) sont fréquents dans les numéros de concours ; c'est fidèle au modèle, pas forcément parlant.
- **Français et arabe** : le modèle n'y est pas prêt ([`model-card-text.md`](model-card-text.md#limites)), et ses explications non plus. Les mots-clés arabes ne reconnaissent pas toutes les formes (« بطاقتك », « ta carte », ne contient pas « بطاقة ») : à enrichir.
- **Vie privée** : une explication contient des mots du message. `TextAnalysis.to_dict()`, la forme journalisable, n'en contient aucun, et le texte lui-même n'est jamais conservé. L'explication n'est renvoyée qu'à celui qui a soumis le message.
- **Les liens du message ne sont pas encore analysés par le modèle URL** : le SMS est jugé sur son texte. Relier les deux est l'objet de l'intégration de l'étape 3.12 et de l'API du module 4.
