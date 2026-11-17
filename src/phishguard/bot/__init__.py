"""Bot Telegram de PhishGuard (étape 5.11, docs/telegram-bot.md).

Transférez-lui un message suspect ou un lien : il interroge l'API PhishGuard et répond
par un verdict, ses raisons et un conseil, sans rien conserver.

- ``settings.py``   configuration (``PHISHGUARD_BOT_*``) ;
- ``telegram.py``   client minimal de l'API Bot, lecture défensive des mises à jour ;
- ``extract.py``    liens d'un message (entités Telegram, liens cachés, UTF-16) ;
- ``api_client.py`` client de l'API PhishGuard, réponse validée par le contrat ;
- ``report.py``     analyse parallèle sous délai, réponse désarmée en texte brut ;
- ``texts.py``      textes en français, anglais, arabe ;
- ``bot.py``        commandes, limites, boucle de réception.
"""
