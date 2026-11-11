# Du jargon aux phrases : les raisons montrées à l'utilisateur

*Étape 3.2 du cahier des charges. Code : `src/phishguard/explain/reasons.py`. Gabarits : `src/phishguard/explain/templates.fr.yml`, `templates.en.yml`, `templates.ar.yml`. Tests : `tests/test_explain_reasons.py`.*

L'étape 3.1 sait dire quelles features ont poussé une URL vers « phishing » (« `is_typosquat` = 1, +1,9 »). Un utilisateur ne lit pas ça. Cette étape traduit le verdict en **au plus trois phrases simples**, classées par poids, suivies d'**un conseil d'action**, en français, en anglais ou en arabe.

```python
analysis = await analyzer.analyze(url)
response = analysis.to_response("fr")  # ou "en", "ar"
[r.message for r in response.reasons]
response.advice
```

## Cinq verdicts expliqués

Sortie réelle du modèle `url_v1` calibré, sans enrichissement, pour des URLs **fabriquées** pour l'exemple (défangées ici). Le nombre entre crochets est la part du score attribuée à la raison.

**`hxxp://paypa1-secure-login[.]xyz/verify/account`** : phishing, score 100

- [26,9] L'adresse contient des mots comme « connexion » ou « vérifier », typiques des fausses pages de connexion.
- [4,6] L'adresse ressemble à celle de paypal mais n'est pas la sienne.
- *Conseil* : N'entrez aucun mot de passe ni aucune information bancaire. Ouvrez le site en tapant vous-même son adresse.

**`hxxps://www[.]paypal[.]com[.]secure-update-4471[.]top/signin`** : phishing, score 99

- [22,2] L'extension « .top » est très souvent utilisée par des sites de phishing.
- [17,2] L'adresse contient des mots comme « connexion » ou « vérifier », typiques des fausses pages de connexion.
- [5,7] L'adresse contient le nom paypal, mais ce n'est pas un site officiel de paypal.

**`hxxp://203[.]0[.]113[.]9/bank/login.php`** : phishing, score 100

- [14,3] L'adresse contient des mots comme « connexion » ou « vérifier », typiques des fausses pages de connexion.
- [4,2] Le lien mène à une adresse numérique (adresse IP) au lieu d'un nom de site.

**`hxxps://bit[.]ly/3xYz12`** : phishing, score 97

- [96,8] La forme de cette adresse ressemble à celle de liens de phishing connus.
- [0] Le lien passe par un raccourcisseur qui cache sa vraie destination.

**`hxxps://www[.]wikipedia[.]org/`** : sûr, score 1

- *aucune raison*
- *Conseil* : Aucun signal inquiétant. Restez attentif si la page vous demande un mot de passe ou un paiement.

Le deuxième exemple en anglais et en arabe :

- The ".top" extension is very often used by phishing sites. / The address contains words like "login" or "verify", typical of fake sign-in pages. / The address contains the name paypal, but it is not an official paypal site.
- الامتداد «top» تستخدمه مواقع التصيّد الاحتيالي كثيرًا. / يحتوي العنوان على كلمات مثل «تسجيل الدخول» أو «تحقق»، وهي معتادة في صفحات الدخول المزيفة. / يحتوي العنوان على اسم paypal، لكنه ليس موقعًا رسميًا لـ paypal.

**Critère de l'étape** : une personne non technique comprend ces cinq explications sans aide. Il ne se vérifie qu'avec de vrais lecteurs : c'est la dernière chose à faire avant de fermer l'issue. Les tests utilisateurs de l'étape 5.13 le refont à plus grande échelle. Une phrase mal comprise se réécrit dans les gabarits, sans toucher au code.

## Les règles

1. **Au plus trois raisons**, de la plus forte à la plus faible. Au-delà, l'utilisateur ne lit plus.
2. **Uniquement des features compréhensibles.** Seize features ou groupes de features ont une phrase ([liste ci-dessous](#raisons-du-modèle-url)). « Le chemin fait 4 caractères », l'entropie de l'hôte ou le nombre de paramètres n'en ont pas : l'utilisateur ne peut rien en faire, et ils reflètent en partie les biais des données (étape 3.1, [`explain-url.md`](explain-url.md#lecture)).
3. **Une condition et un sens.** Une raison n'est citée que si la valeur est en elle-même un indice (`tld_phish_rate` ≥ 0,5, au moins 3 sous-domaines…) **et** que sa contribution SHAP pousse vers « phishing ». Un hôte court qui fait baisser le score n'est jamais présenté comme un danger.
4. **Des points honnêtes.** La part du modèle dans le score (fusion, étape 2.10) est répartie entre les raisons au prorata de leur contribution SHAP. La part des features non citées n'est attribuée à personne : la somme des points peut être inférieure au score, mais aucune raison n'est gonflée.
5. **Trois niveaux d'affichage** :
   - les **indices précis** (marque, adresse IP, TLD, mots-clés, sources de Threat Intelligence), par points ;
   - puis les indices de **forme** (hôte long, beaucoup de tirets ou de chiffres). Ils sont réels mais peu spécifiques : un tiers des faux positifs de la validation sont des domaines peu connus, longs ou chargés ([`error-analysis-url.md`](error-analysis-url.md)). Ils complètent la liste sans passer devant une marque imitée ;
   - enfin, pour un verdict suspect ou phishing, les **constats** nets qui n'ont pas fait monter le score, avec 0 point. `url_v1` donne un poids nul à `is_shortener` (trop rare à l'entraînement), mais « le lien passe par un raccourcisseur » reste une information utile, et le 0 dit honnêtement qu'il n'a pas compté.
6. **Une seule phrase par marque** : `paypa1-paypal.com` ne dit pas deux fois qu'il imite PayPal.
7. **Une raison générale en dernier recours.** Si aucune feature compréhensible n'explique un verdict suspect ou phishing, la réponse dit « La forme de cette adresse ressemble à celle de liens de phishing connus. » Pour un verdict sûr, aucune raison n'est inventée.
8. **Toujours un conseil d'action**, selon le canal (URL, email, SMS et messageries) et le verdict.

## Les gabarits

Les phrases sont dans un fichier YAML par langue, pas dans le code : les reformuler après les tests utilisateurs ne demande aucune modification Python.

```yaml
reasons:
  url.brand_lookalike: "L'adresse ressemble à celle de {brand} mais n'est pas la sienne."
  signal.domain_age: "Ce site a été créé il y a seulement {n} jours."
advice:
  url.phishing: "N'entrez aucun mot de passe ni aucune information bancaire. Ouvrez le site en tapant vous-même son adresse."
```

Règles d'écriture : une phrase courte, au présent, sans jargon ; un constat vérifiable, jamais une accusation (« ressemble à », pas « est un faux »). Les tests vérifient que les trois langues ont exactement les mêmes clés et les mêmes variables, que chaque code que le programme peut produire a son gabarit, et que chaque canal a un conseil pour chaque verdict.

Les gabarits couvrent aussi les 24 règles du score email (étapes 1.11 et 2.13), dont `email.mismatched_link` : « Le lien affiché ne mène pas à l'endroit annoncé. » `ReasonBuilder.email_rules()` les traduit dès maintenant ; l'analyse d'email complète rejoindra le schéma au module 4.

### Raisons du modèle URL

| Code | Features | Condition | Niveau |
| --- | --- | --- | --- |
| `url.brand_lookalike` | `is_typosquat`, `brand_min_distance` | typosquat d'une marque | indice |
| `url.homograph` | `homograph_brand` | homographe d'une marque | indice |
| `url.mixed_script` | `host_mixed_script` | écritures mélangées | indice |
| `url.brand_in_host` | `brand_in_host` | marque dans l'hôte, hors domaine officiel | indice |
| `url.brand_in_path` | `brand_in_path` | marque dans le chemin, hors domaine officiel | indice |
| `url.ip_host` | `host_is_ip` | adresse IP | indice |
| `url.userinfo` | `has_userinfo` | `@` avant l'hôte | indice |
| `url.port` | `has_port` | port non standard | indice |
| `url.shortener` | `is_shortener` | raccourcisseur connu | indice |
| `url.risky_tld` | `tld_phish_rate` | au moins 50 % de phishing à l'entraînement | indice |
| `url.login_keywords` | `host_kw_hits`, `path_kw_hits` | au moins un mot-clé | indice |
| `url.embedded_url` | `path_has_embedded_url` | URL dans le chemin | indice |
| `url.many_subdomains` | `host_n_subdomains` | au moins 3 | indice |
| `url.long_host` | `host_len` | au moins 30 caractères, hors IP | forme |
| `url.many_hyphens` | `host_n_hyphens` | au moins 3, hors IP | forme |
| `url.many_digits` | `host_n_digits` | au moins 5, hors IP | forme |

Les constats cités à 0 point sont les marques, homographes, écritures mélangées, adresses IP, `@` et raccourcisseurs : des faits nets, que l'utilisateur peut vérifier en lisant l'adresse.

## Sécurité : ne pas créer soi-même une injection

Le piège de l'étape : une explication qui recopie l'entrée devient un vecteur d'attaque. Si une phrase reprenait telle quelle l'extension d'une URL, un attaquant pourrait faire afficher `<img src=x onerror=…>` par l'extension, ou une adresse cliquable dans le bot Telegram. Défenses :

1. **Les phrases ne citent presque rien de l'entrée.** Les marques viennent de notre liste (`brands.json`), les nombres sont des entiers. Seule l'extension (`{tld}`) vient de l'URL.
2. **Tout fragment de texte passe par `safe_fragment`** :
   - forme NFKC ;
   - suppression des caractères invisibles et de contrôle, dont U+202E, qui inverse le sens d'affichage (`evil‮gnp.exe` s'affiche `evilexe.png`) ;
   - suppression des caractères de balisage (`< > & " ' ` \ { } [ ]`) ;
   - désarmement des adresses (`hxxp`, `[.]`, `[@]`) ;
   - au plus 40 caractères.
3. **Les gabarits ne peuvent rien lire d'autre qu'une valeur** : `{x.__class__}`, `{x[0]}`, `{x!r}` et les formats sont refusés au chargement, et le YAML est lu avec `safe_load` (aucun objet Python construit).
4. **Les messages sont du texte brut.** Le contrat (`docs/response-schema.md`) impose aux clients de les insérer comme texte (`textContent`), jamais comme HTML. Le bot du module 5 échappera les caractères de son mode de mise en forme.

## Limites

- **Les phrases décrivent le modèle, avec ses limites.** `url.risky_tld` dit que l'extension « .top » est très utilisée par le phishing, ce qui est vrai dans nos données (étape 1.5), mais c'est une statistique, pas un fait sur ce site.
- **Le poids d'une marque imitée reste faible dans `url_v1`** (étape 3.1) : elle passe devant les indices de forme, mais derrière un TLD à risque ou des mots-clés plus lourds. Un modèle qui leur donne plus de poids (contrainte de monotonie, à l'étude dans la [model card](model-card-url.md#limites)) changerait l'ordre sans changer le code des raisons.
- **Arabe** : traduction relue, mais pas encore par des locuteurs dans les tests utilisateurs (étape 5.13). L'extension est écrite sans point initial, pour éviter un affichage inversé dans un texte de droite à gauche.
- **Le nom de la marque est celui de la liste** (`paypal`, en minuscules, tel qu'il apparaît dans les adresses), pas son nom commercial (« PayPal »).
