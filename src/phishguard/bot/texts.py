"""Textes du bot (étape 5.11), en français, anglais et arabe.

Les raisons et le conseil d'action viennent de l'API (mêmes gabarits que l'extension et
l'API, étape 3.2) : seuls l'enveloppe et les commandes sont ici. Les verdicts portent une
icône **et** un mot, jamais l'icône seule.
"""

from __future__ import annotations

from typing import Final

from phishguard.explain.reasons import LANGUAGES, Language

Catalog = dict[str, str]

FR: Final[Catalog] = {
    "start": (
        "Bonjour ! Je vérifie les messages et les liens douteux.\n\n"
        "Transférez-moi un message suspect, ou envoyez-moi un lien : je vous dis ce que "
        "j'en pense, et pourquoi.\n\n"
        "Je ne garde rien de ce que vous m'envoyez : /confidentialite\n"
        "Aide : /aide · Langue : /langue"
    ),
    "help": (
        "Comment m'utiliser :\n"
        "1. Transférez-moi le message suspect (SMS recopié, WhatsApp, Telegram, email…), "
        "ou collez un lien.\n"
        "2. Je réponds par un verdict : ✅ sûr, ⚠️ suspect ou ⛔ phishing probable, avec "
        "les raisons et un conseil.\n\n"
        "Limites : {max_urls} liens par message, {max_chars} caractères, un message toutes "
        "les {interval} secondes.\n"
        "Ne m'envoyez jamais un mot de passe ou un code reçu par SMS."
    ),
    "privacy": (
        "Ce que je fais de vos messages :\n"
        "• Le texte et les liens sont envoyés au serveur d'analyse PhishGuard, analysés, "
        "puis oubliés. Rien n'est conservé, ni par moi ni par le serveur.\n"
        "• Je ne visite jamais les liens : je les analyse comme du texte.\n"
        "• Aucun journal ne contient vos messages, vos liens ou votre identifiant.\n"
        "• Votre choix de langue reste en mémoire jusqu'au redémarrage du bot, pas plus.\n"
        "• Je ne fonctionne qu'en conversation privée : ajouté à un groupe, je ne lis rien."
    ),
    "language_prompt": "Choisissez votre langue :",
    "language_set": "Langue : français.",
    "too_fast": "Doucement : attendez quelques secondes entre deux messages.",
    "too_long": "Ce message est trop long (plus de {max_chars} caractères). Envoyez seulement la partie suspecte.",
    "empty": "Envoyez-moi le texte d'un message ou un lien à vérifier. Je ne lis pas les images.",
    "unavailable": "Le serveur d'analyse ne répond pas. Réessayez dans un moment.",
    "partial": "Une partie de l'analyse n'a pas abouti : ce verdict est incomplet.",
    "verdict_safe": "✅ Aucun signe de phishing",
    "verdict_suspicious": "⚠️ Suspect",
    "verdict_phishing": "⛔ Phishing probable",
    "item_safe": "✅ sûr",
    "item_suspicious": "⚠️ suspect",
    "item_phishing": "⛔ phishing",
    "item_failed": "❔ non analysé",
    "message_line": "Le message : {verdict}",
    "link_line": "Lien vers {host} : {verdict}",
    "hidden_link": "   caché derrière le texte « {shown} »",
    "skipped": "{count} autre(s) lien(s) non analysé(s) (limite de {max_urls} par message).",
    "not_web": "{count} lien(s) ignoré(s) : ce ne sont pas des adresses web.",
    "advice": "Conseil : {advice}",
    "defanged_note": "Les adresses sont écrites avec [.] pour ne pas être cliquables.",
}

EN: Final[Catalog] = {
    "start": (
        "Hello! I check suspicious messages and links.\n\n"
        "Forward me a suspicious message, or send me a link: I'll tell you what I think "
        "of it, and why.\n\n"
        "I keep nothing you send me: /privacy\n"
        "Help: /help · Language: /language"
    ),
    "help": (
        "How to use me:\n"
        "1. Forward me the suspicious message (copied SMS, WhatsApp, Telegram, email…), "
        "or paste a link.\n"
        "2. I reply with a verdict: ✅ safe, ⚠️ suspicious or ⛔ likely phishing, with the "
        "reasons and a piece of advice.\n\n"
        "Limits: {max_urls} links per message, {max_chars} characters, one message every "
        "{interval} seconds.\n"
        "Never send me a password or a code received by SMS."
    ),
    "privacy": (
        "What I do with your messages:\n"
        "• The text and links are sent to the PhishGuard analysis server, analysed, then "
        "forgotten. Nothing is kept, neither by me nor by the server.\n"
        "• I never visit links: I analyse them as text.\n"
        "• No log contains your messages, your links or your identifier.\n"
        "• Your language choice stays in memory until the bot restarts, no longer.\n"
        "• I only work in private chats: added to a group, I read nothing."
    ),
    "language_prompt": "Choose your language:",
    "language_set": "Language: English.",
    "too_fast": "Easy: wait a few seconds between two messages.",
    "too_long": "This message is too long (over {max_chars} characters). Send only the suspicious part.",
    "empty": "Send me the text of a message or a link to check. I don't read images.",
    "unavailable": "The analysis server is not responding. Try again in a moment.",
    "partial": "Part of the analysis failed: this verdict is incomplete.",
    "verdict_safe": "✅ No sign of phishing",
    "verdict_suspicious": "⚠️ Suspicious",
    "verdict_phishing": "⛔ Likely phishing",
    "item_safe": "✅ safe",
    "item_suspicious": "⚠️ suspicious",
    "item_phishing": "⛔ phishing",
    "item_failed": "❔ not analysed",
    "message_line": "The message: {verdict}",
    "link_line": "Link to {host}: {verdict}",
    "hidden_link": "   hidden behind the text “{shown}”",
    "skipped": "{count} more link(s) not analysed (limit of {max_urls} per message).",
    "not_web": "{count} link(s) ignored: they are not web addresses.",
    "advice": "Advice: {advice}",
    "defanged_note": "Addresses are written with [.] so that they cannot be clicked.",
}

AR: Final[Catalog] = {
    "start": (
        "مرحبًا! أتحقق من الرسائل والروابط المريبة.\n\n"
        "أعد توجيه رسالة مريبة إليّ، أو أرسل لي رابطًا: سأخبرك برأيي فيه، ولماذا.\n\n"
        "لا أحتفظ بأي شيء ترسله إليّ: /confidentialite\n"
        "المساعدة: /aide · اللغة: /langue"
    ),
    "help": (
        "طريقة الاستخدام:\n"
        "1. أعد توجيه الرسالة المريبة إليّ (رسالة نصية منسوخة، واتساب، تيليغرام، بريد "
        "إلكتروني…)، أو الصق رابطًا.\n"
        "2. أرد بحكم: ✅ آمن، ⚠️ مريب أو ⛔ تصيد احتيالي محتمل، مع الأسباب ونصيحة.\n\n"
        "الحدود: {max_urls} روابط لكل رسالة، {max_chars} حرفًا، رسالة واحدة كل {interval} ثوانٍ.\n"
        "لا ترسل لي أبدًا كلمة مرور أو رمزًا وصلك في رسالة نصية."
    ),
    "privacy": (
        "ما أفعله برسائلك:\n"
        "• يُرسل النص والروابط إلى خادم التحليل PhishGuard، فتُحلَّل ثم تُنسى. لا يُحتفظ "
        "بأي شيء، لا من قبلي ولا من قبل الخادم.\n"
        "• لا أزور الروابط أبدًا: أحللها كنص.\n"
        "• لا يحتوي أي سجل على رسائلك أو روابطك أو معرّفك.\n"
        "• يبقى اختيارك للغة في الذاكرة حتى إعادة تشغيل البوت، لا أكثر.\n"
        "• أعمل في المحادثات الخاصة فقط: إذا أُضفت إلى مجموعة، لا أقرأ شيئًا."
    ),
    "language_prompt": "اختر لغتك:",
    "language_set": "اللغة: العربية.",
    "too_fast": "على مهل: انتظر بضع ثوانٍ بين رسالتين.",
    "too_long": "هذه الرسالة طويلة جدًا (أكثر من {max_chars} حرفًا). أرسل الجزء المريب فقط.",
    "empty": "أرسل لي نص رسالة أو رابطًا للتحقق منه. لا أقرأ الصور.",
    "unavailable": "خادم التحليل لا يستجيب. أعد المحاولة بعد قليل.",
    "partial": "لم يكتمل جزء من التحليل: هذا الحكم غير مكتمل.",
    "verdict_safe": "✅ لا توجد علامات تصيد احتيالي",
    "verdict_suspicious": "⚠️ مريب",
    "verdict_phishing": "⛔ تصيد احتيالي محتمل",
    "item_safe": "✅ آمن",
    "item_suspicious": "⚠️ مريب",
    "item_phishing": "⛔ تصيد احتيالي",
    "item_failed": "❔ لم يُحلَّل",
    "message_line": "الرسالة: {verdict}",
    "link_line": "رابط إلى {host}: {verdict}",
    "hidden_link": "   مخفي خلف النص «{shown}»",
    "skipped": "{count} رابط (روابط) أخرى لم تُحلَّل (الحد {max_urls} لكل رسالة).",
    "not_web": "{count} رابط (روابط) تم تجاهلها: ليست عناوين ويب.",
    "advice": "نصيحة: {advice}",
    "defanged_note": "العناوين مكتوبة مع [.] حتى لا يمكن النقر عليها.",
}

CATALOGS: Final[dict[Language, Catalog]] = {"fr": FR, "en": EN, "ar": AR}
LANGUAGE_NAMES: Final[dict[Language, str]] = {"fr": "Français", "en": "English", "ar": "العربية"}

if set(CATALOGS) != set(LANGUAGES) or any(c.keys() != FR.keys() for c in CATALOGS.values()):
    raise RuntimeError("textes du bot : chaque langue doit avoir exactement les clés du français")


def text(language: Language, key: str, **values: object) -> str:
    """Texte de ``key`` ; les valeurs substituées ne sont jamais réinterprétées."""
    return CATALOGS[language][key].format_map({k: str(v) for k, v in values.items()})


def language_from_code(code: str | None) -> Language | None:
    """Langue de l'interface Telegram (``fr-FR``, ``ar``…) si le bot la parle."""
    if not code:
        return None
    base = code.split("-")[0].lower()
    return base if base in CATALOGS else None  # type: ignore[return-value]


__all__ = ["CATALOGS", "LANGUAGE_NAMES", "language_from_code", "text"]
