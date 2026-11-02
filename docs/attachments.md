# Contenu des pièces jointes

*Étape 2.13 (ajoutée au module 2 après l'évaluation d'EML Analyzer, voir [`external-tools.md`](external-tools.md)). Code : `src/phishguard/email/attachments.py`. Tests : `tests/test_email_attachments.py`.*

Le parseur d'emails (étape 1.10) jugeait une pièce jointe sur son **nom** : extension, double extension, caractère RTLO. Ce contrôle se contourne en un instant. Un exécutable renommé `facture.pdf`, un `.doc` ancien format plein de macros, un `.docx` renommé qui cache un projet VBA, une archive chiffrée dont le mot de passe est dans le corps : aucun n'était vu. C'est T1566.001 (Spearphishing Attachment), l'un des vecteurs les plus courants.

L'inspection regarde maintenant le **contenu**, sur les octets déjà décodés du message.

## Ce qui est détecté

| Constat | Comment | Exemple |
| --- | --- | --- |
| **Vrai type** du fichier | Signature (premiers octets) : PE (`MZ`), ELF, Mach-O, OLE, ZIP, OOXML, ODF, JAR, RAR, 7z, gzip, CAB, RTF, PDF, ISO (`CD001`), LNK, script `#!`, HTML, PNG, JPEG, GIF | `facture.pdf` qui commence par `MZ` |
| **Nom qui ment** (`type_mismatch`) | Contenu exécutable ou actif (exécutable, raccourci, script, HTML, ISO) sous un nom qui ne l'annonce pas | Exécutable déguisé en PDF |
| **Macros VBA** | OLE (Word, Excel 97-2003) : stockages `Macros`, `_VBA_PROJECT_CUR`, `VBA`, lus par `olefile`. OOXML : membre `vbaProject.bin`. ODF : dossier `Basic/` | `contrat.doc` à macros, `.docx` renommé qui en cache |
| **Modèle distant** | Document Word dont `settings.xml.rels` déclare un `attachedTemplate` externe (injection de modèle) | `.docx` qui télécharge un `.dotm` à l'ouverture |
| **Objet OLE dans un RTF** | `\objdata` ou `\objupdate` | Vecteur classique d'exploitation d'Office |
| **Archive qui cache sa charge** | ZIP listé **sans extraction** : drapeau « chiffré », membres exécutables, scripts, raccourcis, images disque | `facture.zip` chiffré contenant `facture.pdf.exe` |
| **PDF actif** | Noms `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile`, `/SubmitForm`, y compris obfusqués (`/J#61vaScript`) | PDF qui lance un script à l'ouverture |
| **Page de connexion jointe** | HTML avec un champ `type="password"` | `connexion.html` qui imite une banque |

La famille de risque retenue pour une pièce jointe (`effective_risk`) est la plus grave entre celle du nom et celle du contenu. Un `.doc` à macros devient donc `macro_document`, comme un `.docm`.

`/OpenAction` seul (zoom ou page à l'ouverture) est très courant dans les PDF légitimes : il est gardé dans les preuves, mais ne déclenche aucune règle.

Les règles du score email qui en découlent sont décrites dans [`email-score.md`](email-score.md#les-règles).

## Règles de sécurité

Le fichier est hostile et peut viser le parseur lui-même :

- **rien n'est exécuté, ouvert dans une application, extrait sur disque ni envoyé à un tiers**. Tout se passe en mémoire, et l'analyse reste entièrement locale ;
- **aucun membre d'archive n'est décompressé**, sauf les petits fichiers XML d'un document OOXML (64 Ko au plus, non chiffrés). Une bombe zip (50 Mo de zéros dans 50 Ko) est inspectée en quelques millisecondes ;
- chaque lecture est bornée : 10 Mo inspectés par pièce jointe, 1 000 membres d'archive, 2 000 entrées OLE, 5 Mo de PDF et 2 Mo de HTML parcourus ;
- `inspect_content()` **ne lève jamais**. Un fichier illisible (OLE corrompu, ZIP tronqué) donne un constat vide et une erreur dans `errors`, et `parse_eml` garde sa garantie « aucune exception ». Un test Hypothesis le vérifie sur des octets aléatoires précédés des signatures OLE, ZIP, PDF et RTF ;
- l'inspection peut être désactivée (`EmailLimits(inspect_attachments=False)`) pour un traitement en masse.

## Tests sans malware

Aucun vrai logiciel malveillant n'est versionné. `tests/attachment_samples.py` fabrique des fichiers qui ne reproduisent que la **structure** reconnue, sans aucun code exécutable :

- un « exécutable » réduit à son en-tête `MZ` ;
- des fichiers OLE synthétiques (format MS-CFB minimal) avec ou sans stockage `Macros/VBA` ;
- des `.docx` construits avec `zipfile` ;
- un PDF dont le JavaScript n'est qu'une chaîne ;
- une archive dont le drapeau « chiffré » est posé dans les en-têtes.

Les mêmes tests vérifient l'absence de faux positif sur des pièces jointes légitimes (document sans macro, image, PDF ordinaire, archive de documents) et sur les emails légitimes de test.

## Limites

- Les **flux compressés des PDF** ne sont pas décompressés : un JavaScript caché dans un flux `FlateDecode` n'est pas vu. Les décompresser demanderait un vrai parseur PDF, avec sa propre surface d'attaque.
- **RAR et 7z** sont reconnus comme archives, mais leur contenu n'est pas listé (il faudrait une dépendance native).
- Les **macros Excel 4.0 (XLM)** et le **VBA des présentations PowerPoint 97-2003** ne sont pas détectés.
- Un ZIP imbriqué dans un ZIP n'est pas ouvert : seul son nom compte.
- Le format Outlook **`.msg`** n'est pas encore lu ([issue #124](https://github.com/arixstoo/PhishGuard/issues/124)).
