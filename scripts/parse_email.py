"""Affiche les signaux de phishing d'un email brut (étape 1.10).

    python scripts/parse_email.py message.eml
    python scripts/parse_email.py message.eml --json      # sortie complète, en JSON

Le message n'est lu que comme une suite d'octets : rien n'est rendu ni téléchargé.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phishguard.email import EmailTooLargeError, ParsedEmail, parse_eml


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("path", type=Path)
    p.add_argument("--json", action="store_true", help="toute l'analyse, en JSON")
    p.add_argument(
        "--trusted-authserv-id",
        action="append",
        dest="trusted",
        help="serveur de réception dont on croit l'en-tête Authentication-Results",
    )
    return p.parse_args(argv)


def summary(result: ParsedEmail) -> list[str]:
    sender = result.from_
    auth = result.auth
    lines = [
        f"Objet        : {result.subject}",
        f"Expéditeur   : {sender.address if sender else '?'} ({sender.display_name if sender else ''})",
        f"SPF/DKIM/DMARC : {auth.spf} / {auth.dkim} / {auth.dmarc} (source : {auth.source})",
        f"Reply-To autre domaine    : {'oui' if result.reply_to_differs else 'non'}",
        f"Return-Path autre domaine : {'oui' if result.return_path_differs else 'non'}",
        f"Nom affiché trompeur      : {'oui' if result.display_name_spoof else 'non'}",
        (
            f"Liens : {len(result.links)}, dont {len(result.mismatched_links)} au texte trompeur ; "
            f"formulaires : {result.forms}"
        ),
    ]
    for link in result.mismatched_links[:5]:
        lines.append(f"  - affiche {link.text_domain}, mène à {link.href_domain or link.scheme}")
    lines.append(
        f"Pièces jointes : {len(result.attachments)}, dont {len(result.risky_attachments)} à risque"
    )
    for attachment in result.risky_attachments:
        flags = [
            f
            for f, on in (
                ("double extension", attachment.double_extension),
                ("RTLO", attachment.rtlo),
            )
            if on
        ]
        lines.append(f"  - {attachment.filename!r} : {attachment.risk or ''} {' '.join(flags)}")
    lines.append(
        f"Texte masqué : {result.hidden_text.elements} élément(s), {result.hidden_text.chars} "
        f"caractères ; caractères invisibles : {result.zero_width_chars}"
    )
    if result.defects:
        lines.append(f"Anomalies : {', '.join(result.defects[:10])}")
    return lines


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    args = parse_args(argv)
    try:
        result = parse_eml(args.path.read_bytes(), trusted_authserv_ids=args.trusted)
    except EmailTooLargeError as exc:
        print(f"Refusé : {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Lecture impossible : {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print("\n".join(summary(result)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
