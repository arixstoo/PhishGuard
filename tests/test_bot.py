"""Bot Telegram (étape 5.11) : extraction des liens, réponse désarmée, client de l'API,
commandes, limites, délai global, et aucun secret ni contenu dans les journaux.

Telegram et l'API PhishGuard sont simulés (respx) : aucun appel réseau réel. Les URLs de
phishing ne sont que des chaînes (domaines ``.example``, IP de documentation).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time

import httpx
import pytest
import respx

from phishguard.bot.__main__ import SILENCED_LOGGERS, configure_logging
from phishguard.bot.api_client import ApiError, PhishGuardApi
from phishguard.bot.bot import PhishGuardBot, command_of
from phishguard.bot.extract import extract_links, utf16_slice
from phishguard.bot.report import FSI, PDI, analyze_message, clean, defang_host, render
from phishguard.bot.settings import BotSettings
from phishguard.bot.telegram import Entity, IncomingMessage, TelegramClient, parse_update
from phishguard.schema import AnalysisResponse, Reason, TechniqueOut

TOKEN = "123456789:" + "A" * 35
API = "http://api.test"
TG = "https://tg.test"
SEND = f"{TG}/bot{TOKEN}/sendMessage"
API_KEY = "pg_" + "k" * 43

# Tests asynchrones par le greffon pytest d'anyio (installé avec httpx), sous asyncio.
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def response(
    verdict: str, *, channel: str = "url", score: int | None = None, reason: str = ""
) -> dict:
    """Une réponse conforme au contrat de l'API."""
    score = score if score is not None else {"safe": 5, "suspicious": 50, "phishing": 95}[verdict]
    mitre = (
        [
            TechniqueOut(
                id="T1566.002",
                name="Spearphishing Link",
                tactic="initial-access",
                url="https://attack.mitre.org/techniques/T1566/002/",
                reason="lien",
            )
        ]
        if verdict == "phishing"
        else []
    )
    reasons = (
        [Reason(code="url.test", source="url_model", points=50, message=reason)] if reason else []
    )
    return AnalysisResponse(
        channel=channel,
        verdict=verdict,
        score=score,
        confidence="high",
        reasons=reasons,
        signals={},
        mitre=mitre,
        model_version="url_v2",
        fusion_version="1.1.0",
        enrichment="skipped",
        latency_ms=3,
        language="fr",
        advice=f"conseil {channel} {verdict}",
    ).model_dump(mode="json")


def settings(**overrides) -> BotSettings:
    values = {
        "token": TOKEN,
        "api_url": API,
        "telegram_api_url": TG,
        "api_key": API_KEY,
        "min_interval_seconds": 3.0,
        "analysis_timeout_seconds": 1.0,
    }
    return BotSettings(_env_file=None, **{**values, **overrides})


def update(text: str | None = None, *, chat_type: str = "private", user: int = 42, **extra) -> dict:
    message = {
        "message_id": 7,
        "chat": {"id": 1000 + user, "type": chat_type},
        "from": {"id": user, "language_code": "fr"},
        **extra,
    }
    if text is not None:
        message["text"] = text
    return {"update_id": 1, "message": message}


def sent(route: respx.Route) -> list[dict]:
    return [json.loads(call.request.content) for call in route.calls]


async def handle(bot: PhishGuardBot, raw: dict) -> None:
    incoming = parse_update(raw)
    assert incoming is not None
    await bot.handle(incoming)


async def make_bot(clock=time.monotonic, **overrides) -> tuple[PhishGuardBot, httpx.AsyncClient]:
    s = settings(**overrides)
    http = httpx.AsyncClient()
    bot = PhishGuardBot(
        s,
        telegram=TelegramClient(http, token=TOKEN, base_url=TG),
        api=PhishGuardApi(http, base_url=API, api_key=API_KEY),
        clock=clock,
    )
    return bot, http


# --------------------------------------------------------------------------- #
# Extraction des liens
# --------------------------------------------------------------------------- #


class TestExtraction:
    def test_utf16_offsets_after_an_emoji(self):
        # « 📦 » compte pour 2 unités UTF-16 : Telegram place l'entité à 11, pas à 10.
        text = "📦 Colis : paypa1.example/suivi bloqué"
        assert utf16_slice(text, 11, 20) == "paypa1.example/suivi"
        found = extract_links(text, [Entity("url", 11, 20)], limit=5)
        assert [link.url for link in found.links] == ["http://paypa1.example/suivi"]

    def test_hidden_link_behind_text(self):
        text = "Suivre mon colis ici"
        entity = Entity("text_link", 0, 16, url="http://192.0.2.10/colis")
        [link] = extract_links(text, [entity], limit=5).links
        assert (link.url, link.shown_as) == ("http://192.0.2.10/colis", "Suivre mon colis")

    def test_written_url_without_entity_and_trailing_punctuation(self):
        found = extract_links("Voir https://exemple.fr/page). Merci", limit=5)
        assert [link.url for link in found.links] == ["https://exemple.fr/page"]
        wiki = extract_links("https://fr.wikipedia.org/wiki/Phishing_(fraude).", limit=5)
        assert wiki.links[0].url == "https://fr.wikipedia.org/wiki/Phishing_(fraude)"

    def test_limit_dedup_and_non_web_links(self):
        text = " ".join(f"https://site{i}.example/" for i in range(7)) + " https://site0.example/"
        entities = [Entity("text_link", 0, 5, url="tg://resolve?domain=x")]
        found = extract_links(text, entities, limit=5)
        assert len(found.links) == 5
        assert (found.skipped, found.not_web) == (2, 1)

    def test_port_is_not_a_scheme(self):
        found = extract_links("exemple.fr:8080/x", [Entity("url", 0, 17)], limit=5)
        assert found.links[0].url == "http://exemple.fr:8080/x"
        assert extract_links("mailto:a@b.fr", [Entity("url", 0, 13)], limit=5).not_web == 1


# --------------------------------------------------------------------------- #
# Mises à jour hostiles
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        {"update_id": "1"},
        {"update_id": 1},
        {"update_id": 1, "message": "x"},
        {"update_id": 1, "message": {"chat": {"id": "1", "type": "private"}}},
        {"update_id": 1, "callback_query": {"id": 1, "from": {"id": 2}, "data": "lang:fr"}},
        {"update_id": True, "message": {"chat": {"id": 1, "type": "private"}}},
    ],
)
def test_malformed_updates_are_ignored(raw):
    assert parse_update(raw) is None


def test_caption_and_forwarded_message():
    incoming = parse_update(
        update(
            caption="Payez ici",
            caption_entities=[{"type": "url", "offset": 0, "length": 5}],
            forward_origin={"type": "hidden_user"},
            photo=[{}],
        )
    )
    assert isinstance(incoming, IncomingMessage)
    assert (incoming.text, incoming.forwarded, incoming.has_media) == ("Payez ici", True, True)
    assert incoming.entities == (Entity("url", 0, 5),)


# --------------------------------------------------------------------------- #
# Réponse désarmée
# --------------------------------------------------------------------------- #


class TestRender:
    def test_hosts_are_defanged_ascii_and_isolated(self):
        assert defang_host("http://paypa1-secure-login.example/verify?token=SECRET") == (
            f"{FSI}paypa1-secure-login[.]example{PDI}"
        )
        # Homographe : la forme Punycode, pas les lettres trompeuses.
        assert defang_host("http://\u0430pple.com/") == f"{FSI}xn--pple-43d[.]com{PDI}"
        assert "\u202e" not in defang_host("http://evil\u202e.example/")

    def test_reason_text_never_contains_a_clickable_domain(self):
        assert clean("Le site imite paypal.com\u200b !") == "Le site imite paypal[.]com !"
        assert clean("Payez 1.99 € ici") == "Payez 1.99 € ici"

    async def test_reply_has_no_url_path_and_no_clickable_host(self):
        async with respx.mock(assert_all_called=False) as mock:
            mock.post(f"{API}/v1/analyze/text").respond(
                200, json=response("safe", channel="messaging")
            )
            mock.post(f"{API}/v1/analyze/url").respond(
                200, json=response("phishing", reason="Marque imitée : apple.com.")
            )
            text = "Votre identifiant Apple : https://appleid.apple.com.verify.example/signin?session=abc123"
            async with httpx.AsyncClient() as http:
                api = PhishGuardApi(http, base_url=API, api_key=None)
                report = await analyze_message(
                    text,
                    extract_links(text, limit=5),
                    api=api,
                    language="fr",
                    threat_intel=False,
                    timeout=1,
                )
        reply = render(report, "fr", max_urls=5)
        assert reply.startswith("⛔ Phishing probable")
        assert "abc123" not in reply and "/signin" not in reply and "https://" not in reply
        assert "appleid[.]apple[.]com[.]verify[.]example" in reply
        assert "apple[.]com" in reply and "apple.com" not in reply
        assert "conseil url phishing" in reply  # conseil du résultat le plus grave

    async def test_strictest_verdict_wins_and_message_advice_breaks_ties(self):
        async with respx.mock() as mock:
            mock.post(f"{API}/v1/analyze/text").respond(
                200, json=response("suspicious", channel="messaging")
            )
            mock.post(f"{API}/v1/analyze/url").respond(200, json=response("suspicious"))
            async with httpx.AsyncClient() as http:
                api = PhishGuardApi(http, base_url=API, api_key=None)
                text = "Urgent https://a.example/"
                report = await analyze_message(
                    text,
                    extract_links(text, limit=5),
                    api=api,
                    language="en",
                    threat_intel=False,
                    timeout=1,
                )
        assert report.verdict == "suspicious"
        assert "conseil messaging suspicious" in render(report, "en", max_urls=5)


# --------------------------------------------------------------------------- #
# Client de l'API
# --------------------------------------------------------------------------- #


class TestApiClient:
    async def test_request_shape(self):
        async with respx.mock() as mock:
            route = mock.post(f"{API}/v1/analyze/url").respond(200, json=response("safe"))
            async with httpx.AsyncClient() as http:
                api = PhishGuardApi(http, base_url=API, api_key=API_KEY)
                await api.analyze_url("https://exemple.fr/", language="ar", threat_intel=False)
        request = route.calls.last.request
        assert request.headers["X-API-Key"] == API_KEY
        assert json.loads(request.content) == {
            "url": "https://exemple.fr/",
            "language": "ar",
            "use_threat_intel": False,
            "analyst": False,
        }

    async def test_control_characters_are_replaced_not_refused(self):
        async with respx.mock() as mock:
            route = mock.post(f"{API}/v1/analyze/text").respond(
                200, json=response("safe", channel="messaging")
            )
            async with httpx.AsyncClient() as http:
                await PhishGuardApi(http, base_url=API, api_key=None).analyze_text(
                    "a\x00b\ud800c\nd", language="fr"
                )
        assert json.loads(route.calls.last.request.content)["text"] == "a b c\nd"

    @pytest.mark.parametrize(
        ("reply", "code"),
        [
            (httpx.Response(429), "rate_limited"),
            (httpx.Response(400, json={}), "invalid_input"),
            (httpx.Response(302, headers={"Location": "https://ailleurs.example/"}), "http_302"),
            (httpx.Response(200, json={"verdict": "safe"}), "invalid_response"),
            (httpx.Response(200, content=b"x" * 300_000), "invalid_response"),
        ],
    )
    async def test_errors_are_codes(self, reply, code):
        async with respx.mock() as mock:
            mock.post(f"{API}/v1/analyze/url").mock(return_value=reply)
            async with httpx.AsyncClient() as http:
                with pytest.raises(ApiError) as caught:
                    await PhishGuardApi(http, base_url=API, api_key=API_KEY).analyze_url(
                        "https://x.example/", language="fr", threat_intel=False
                    )
        assert caught.value.code == code
        assert "x.example" not in str(caught.value) and API_KEY not in str(caught.value)


# --------------------------------------------------------------------------- #
# Commandes, groupes, limites
# --------------------------------------------------------------------------- #


def test_command_parsing():
    assert command_of("/langue@PhishGuardBot en") == ("language", "en")
    assert command_of("/AIDE") == ("help", "")
    assert command_of("/inconnue") is None
    assert command_of("bonjour /start") is None


class TestBot:
    async def test_commands_reply_in_the_user_language(self):
        bot, http = await make_bot()
        async with http, respx.mock() as mock:
            route = mock.post(SEND).respond(200, json={"ok": True, "result": {}})
            raw = update("/privacy")
            raw["message"]["from"]["language_code"] = "en-GB"
            await handle(bot, raw)
        [reply] = sent(route)
        assert reply["text"].startswith("What I do with your messages")
        assert reply["link_preview_options"] == {"is_disabled": True}
        assert "parse_mode" not in reply  # texte brut : rien n'est interprété

    async def test_language_choice_by_button_is_kept_in_memory(self):
        bot, http = await make_bot()
        async with http, respx.mock() as mock:
            mock.post(f"{TG}/bot{TOKEN}/answerCallbackQuery").respond(
                200, json={"ok": True, "result": True}
            )
            route = mock.post(SEND).respond(200, json={"ok": True, "result": {}})
            await handle(bot, update("/langue"))
            assert sent(route)[0]["reply_markup"]["inline_keyboard"][0][2] == {
                "text": "العربية",
                "callback_data": "lang:ar",
            }
            await handle(
                bot,
                {
                    "update_id": 2,
                    "callback_query": {
                        "id": "c1",
                        "from": {"id": 42},
                        "data": "lang:ar",
                        "message": {"chat": {"id": 1042, "type": "private"}},
                    },
                },
            )
        assert bot.language_for(42, "fr") == "ar"

    async def test_groups_are_never_read(self):
        bot, http = await make_bot()
        async with http, respx.mock(assert_all_called=False) as mock:
            route = mock.post(SEND)
            api = mock.post(url__startswith=API)
            await handle(bot, update("https://paypa1.example/", chat_type="group"))
            await handle(bot, update("/start", chat_type="supergroup"))
        assert not route.called and not api.called

    async def test_rate_limit_warns_once_per_window(self):
        now = [0.0]
        bot, http = await make_bot(clock=lambda: now[0])
        async with http, respx.mock(assert_all_called=False) as mock:
            route = mock.post(SEND).respond(200, json={"ok": True, "result": {}})
            mock.post(f"{API}/v1/analyze/text").respond(
                200, json=response("safe", channel="messaging")
            )
            for _ in range(5):
                await handle(bot, update("bonjour"))
            await handle(bot, update("/start"))  # les commandes aussi
            texts = [m["text"] for m in sent(route)]
            assert len(texts) == 2  # une analyse, un seul avertissement
            assert texts[1].startswith("Doucement")
            now[0] = 3.5  # fenêtre écoulée : de nouveau admis
            await handle(bot, update("bonjour"))
        assert len(sent(route)) == 3

    async def test_too_long_and_empty(self):
        bot, http = await make_bot(min_interval_seconds=0, max_text_chars=64)
        async with http, respx.mock(assert_all_called=False) as mock:
            route = mock.post(SEND).respond(200, json={"ok": True, "result": {}})
            api = mock.post(url__startswith=API)
            await handle(bot, update("x" * 65))
            await handle(bot, update(None, photo=[{}]))
        texts = [m["text"] for m in sent(route)]
        assert texts[0].startswith("Ce message est trop long") and texts[1].startswith(
            "Envoyez-moi"
        )
        assert not api.called

    async def test_forwarded_message_with_hidden_link_in_under_three_seconds(self):
        bot, http = await make_bot(min_interval_seconds=0, analysis_timeout_seconds=2.5)

        async def slow(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(0.2)  # latence de l'API, appels en parallèle
            body = json.loads(request.content)
            if "text" in body:
                return httpx.Response(200, json=response("suspicious", channel="messaging"))
            return httpx.Response(
                200, json=response("phishing", reason="Adresse IP au lieu d'un nom.")
            )

        raw = update(
            "Votre colis est bloqué. Suivre mon colis",
            forward_origin={"type": "hidden_user"},
            entities=[
                {"type": "text_link", "offset": 24, "length": 16, "url": "http://192.0.2.10/colis"}
            ],
        )
        async with http, respx.mock() as mock:
            route = mock.post(SEND).respond(200, json={"ok": True, "result": {}})
            mock.post(url__startswith=API).mock(side_effect=slow)
            start = time.perf_counter()
            await handle(bot, raw)
            elapsed = time.perf_counter() - start
        [reply] = sent(route)
        assert elapsed < 3
        assert reply["reply_parameters"]["message_id"] == 7
        assert reply["text"].startswith("⛔ Phishing probable")
        assert f"{FSI}192[.]0[.]2[.]10{PDI}" in reply["text"]
        assert "caché derrière le texte « \u2068Suivre mon colis\u2069 »" in reply["text"]

    async def test_global_timeout_gives_a_partial_or_unavailable_answer(self):
        bot, http = await make_bot(min_interval_seconds=0, analysis_timeout_seconds=0.2)

        async def hang(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(5)
            return httpx.Response(200)

        # Appels annulés à l'échéance : respx ne les compte pas comme reçus.
        async with http, respx.mock(assert_all_called=False) as mock:
            route = mock.post(SEND).respond(200, json={"ok": True, "result": {}})
            mock.post(url__startswith=API).mock(side_effect=hang)
            start = time.perf_counter()
            await handle(bot, update("https://exemple.example/"))
            assert time.perf_counter() - start < 1
        assert sent(route)[0]["text"].startswith("Le serveur d'analyse ne répond pas")


# --------------------------------------------------------------------------- #
# Secrets et journaux
# --------------------------------------------------------------------------- #


class TestSecrets:
    def test_settings_errors_never_echo_the_token(self):
        with pytest.raises(ValueError) as caught:
            settings(token="pas-un-jeton-SECRET")
        assert "SECRET" not in str(caught.value)
        assert TOKEN not in repr(settings())

    @pytest.mark.parametrize(
        "url", ["http://api.telegram.org", "https://u:p@tg.test", "https://tg.test/?x=1"]
    )
    def test_telegram_server_must_be_https_and_plain(self, url):
        with pytest.raises(ValueError):
            settings(telegram_api_url=url)

    def test_httpx_logs_are_silenced(self):
        configure_logging("DEBUG")
        for name in SILENCED_LOGGERS:
            assert not logging.getLogger(name).isEnabledFor(logging.INFO)

    async def test_log_line_has_no_content_no_ids_no_token(self, caplog):
        bot, http = await make_bot(min_interval_seconds=0)
        caplog.set_level(logging.DEBUG)
        async with http, respx.mock() as mock:
            mock.post(SEND).respond(200, json={"ok": True, "result": {}})
            mock.post(url__startswith=API).respond(
                200, json=response("phishing", channel="messaging")
            )
            await handle(bot, update("Code secret 482913 https://paypa1.example/x", user=987654))
        logged = "\n".join(
            r.getMessage() for r in caplog.records if r.name.startswith("phishguard")
        )
        assert "message analysé : 1 lien(s), verdict phishing" in logged
        for secret in ("482913", "paypa1", "987654", "988654", TOKEN, API_KEY):
            assert secret not in logged

    async def test_telegram_errors_never_contain_the_token(self):
        async with httpx.AsyncClient() as http, respx.mock() as mock:
            mock.post(SEND).mock(side_effect=httpx.ConnectError("échec vers " + SEND))
            client = TelegramClient(http, token=TOKEN, base_url=TG)
            with pytest.raises(Exception) as caught:
                await client.send_message(1, "x")
        assert TOKEN not in str(caught.value) and TOKEN not in repr(caught.value)


async def test_polling_loop_acknowledges_retries_and_stops():
    bot, http = await make_bot(min_interval_seconds=0)
    stop = asyncio.Event()
    offsets: list[object] = []

    def get_updates(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        offsets.append(body.get("offset"))
        assert body["allowed_updates"] == ["message", "callback_query"]
        if len(offsets) == 1:
            return httpx.Response(
                200, json={"ok": True, "result": [{**update("/start"), "update_id": 41}]}
            )
        if len(offsets) == 2:
            return httpx.Response(502)  # panne passagère : nouvel essai
        stop.set()
        return httpx.Response(200, json={"ok": True, "result": []})

    async with http, respx.mock() as mock:
        mock.post(f"{TG}/bot{TOKEN}/getUpdates").mock(side_effect=get_updates)
        route = mock.post(SEND).respond(200, json={"ok": True, "result": {}})
        await asyncio.wait_for(bot.run(stop), timeout=10)
    assert offsets == [None, 42, 42]  # chaque mise à jour acquittée une fois
    assert sent(route)[0]["text"].startswith("Bonjour")


def test_requests_are_accepted_by_the_real_api(api_models_dir, tmp_path):
    """Contre la vraie application (schémas stricts, champ inconnu refusé) : les requêtes du
    bot sont acceptées et les réponses passent la validation du client."""
    import asyncio as aio

    from api_support import api_client, settings_for

    with api_client(settings_for(api_models_dir, tmp_path, rate_limit_enabled=False)) as tc:

        async def scenario() -> tuple[str, str]:
            transport = httpx.ASGITransport(app=tc.app)
            async with httpx.AsyncClient(transport=transport) as http:
                api = PhishGuardApi(http, base_url="http://testserver", api_key=None)
                url = await api.analyze_url(
                    "http://192.0.2.10/paypal/login.php", language="ar", threat_intel=False
                )
                text = await api.analyze_text(
                    "Votre colis est bloqué, payez ici\x07", language="en"
                )
            return url.language, text.channel

        assert aio.run(scenario()) == ("ar", "messaging")


def test_every_language_has_the_same_placeholders():
    import string

    from phishguard.bot.texts import CATALOGS

    def fields(message: str) -> set[str]:
        return {name for _, name, _, _ in string.Formatter().parse(message) if name}

    for language, catalog in CATALOGS.items():
        for key, message in catalog.items():
            assert fields(message) == fields(CATALOGS["fr"][key]), (language, key)
