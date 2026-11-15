"""Authentification et limitation de débit (étape 4.4).

Critère : 100 requêtes rapides reçoivent des 429 après le seuil. Vérifié aussi : les clés
ne sont stockées qu'en empreinte, une clé invalide est refusée (jamais rétrogradée en
anonyme), ``X-Forwarded-For`` n'est cru que d'un proxy de confiance.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from ipaddress import ip_address, ip_network

import pytest
from api_support import api_client, settings_for
from starlette.requests import Request

from phishguard.api import keys as keys_cli
from phishguard.api.security import Client, client_ip, ip_bucket
from phishguard.api.storage import KEY_PATTERN, Database, hash_key

TEXT = {"text": "see you at the station tonight"}


def post_text(client, **headers):
    return client.post("/v1/analyze/text", json=TEXT, headers=headers)


# --------------------------------------------------------------------------- #
# Limites de débit
# --------------------------------------------------------------------------- #


def test_100_fast_requests_get_429_after_the_threshold(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:  # défaut : 30/minute
        responses = [post_text(client) for _ in range(100)]
    codes = [r.status_code for r in responses]
    assert codes[:30] == [200] * 30
    assert codes[30:] == [429] * 70
    limited = responses[30]
    assert limited.json()["error"]["code"] == "rate_limited"
    assert 1 <= int(limited.headers["Retry-After"]) <= 60
    assert limited.headers["X-RateLimit-Limit"] == "30"
    assert limited.headers["X-RateLimit-Remaining"] == "0"
    assert responses[0].headers["X-RateLimit-Remaining"] == "29"


def test_api_key_raises_the_quota(api_models_dir, tmp_path):
    settings = settings_for(
        api_models_dir,
        tmp_path,
        rate_limit_anonymous="5/minute",
        rate_limit_authenticated="50/minute",
    )
    with api_client(settings) as client:
        _, key = client.app.state.phishguard.database.create_key("test")
        codes = [post_text(client, **{"X-API-Key": key}).status_code for _ in range(60)]
        # Le quota de la clé est à part : l'IP, elle, a encore tout son quota anonyme.
        anonymous = [post_text(client).status_code for _ in range(6)]
    assert codes == [200] * 50 + [429] * 10
    assert anonymous == [200] * 5 + [429]


def test_each_route_has_its_own_counter(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path, rate_limit_anonymous="3/minute")
    with api_client(settings) as client:
        assert [post_text(client).status_code for _ in range(4)] == [200, 200, 200, 429]
        assert client.get("/v1/model").status_code == 200


def test_malformed_requests_consume_the_quota(api_models_dir, tmp_path):
    """Le limiteur passe avant la lecture du corps : une rafale invalide est limitée."""
    settings = settings_for(api_models_dir, tmp_path, rate_limit_anonymous="5/minute")
    with api_client(settings) as client:
        headers = {"content-type": "application/json"}
        bad = [client.post("/v1/analyze/text", content=b"{", headers=headers) for _ in range(5)]
        assert [r.status_code for r in bad] == [422] * 5
        assert post_text(client).status_code == 429


def test_unknown_paths_share_one_counter(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path, rate_limit_anonymous="3/minute")
    with api_client(settings) as client:
        codes = [client.get(f"/v1/random-{i}").status_code for i in range(5)]
    assert codes == [404, 404, 404, 429, 429]


def test_storage_failure_lets_requests_through(api_models_dir, tmp_path, monkeypatch):
    from phishguard.api.ratelimit import RateLimiter

    async def broken(self, kind, key, route):
        raise ConnectionError("redis indisponible")

    monkeypatch.setattr(RateLimiter, "hit", broken)
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        response = post_text(client)
    assert response.status_code == 200
    assert "X-RateLimit-Limit" not in response.headers


def test_rate_limit_can_be_disabled(api_models_dir, tmp_path):
    settings = settings_for(
        api_models_dir, tmp_path, rate_limit_anonymous="1/minute", rate_limit_enabled=False
    )
    with api_client(settings) as client:
        assert {post_text(client).status_code for _ in range(5)} == {200}


# --------------------------------------------------------------------------- #
# Clés d'API
# --------------------------------------------------------------------------- #


def test_unknown_key_is_refused_never_downgraded(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        for key in ("pg_" + "A" * 43, "not-a-key", "", "pg_" + "A" * 4000):
            response = post_text(client, **{"X-API-Key": key})
            assert response.status_code == 401, key
            assert response.json()["error"]["code"] == "invalid_api_key"
            assert response.headers["WWW-Authenticate"] == "X-API-Key"
            assert not key or key not in response.text


def test_key_guessing_is_rate_limited_per_ip(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path, rate_limit_rejected="10/minute")
    with api_client(settings) as client:
        codes = [post_text(client, **{"X-API-Key": f"pg_{i:043d}"}).status_code for i in range(12)]
    assert codes == [401] * 10 + [429] * 2


def test_revoked_key_is_refused(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        database = client.app.state.phishguard.database
        record, key = database.create_key("ci")
        assert post_text(client, **{"X-API-Key": key}).status_code == 200
        assert database.revoke_key(record.key_id) is True
        assert database.revoke_key(record.key_id) is False  # déjà révoquée
        assert post_text(client, **{"X-API-Key": key}).status_code == 401


def test_two_key_headers_are_refused(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        _, key = client.app.state.phishguard.database.create_key("a")
        response = client.post(
            "/v1/analyze/text",
            json=TEXT,
            headers=[("X-API-Key", key), ("X-API-Key", key)],
        )
    assert response.status_code == 401


def test_keys_are_stored_as_sha256_fingerprints_only(tmp_path):
    path = tmp_path / "keys.sqlite3"
    database = Database(path)
    record, key = database.create_key("extension-dev")
    assert KEY_PATTERN.fullmatch(key)
    assert database.verify_key(key) == record
    with sqlite3.connect(path) as db:
        rows = db.execute("SELECT key_hash FROM api_keys").fetchall()
    assert rows == [(hashlib.sha256(key.encode()).hexdigest(),)] == [(hash_key(key),)]
    for file in tmp_path.iterdir():  # base, journal WAL : nulle part en clair
        assert key.encode() not in file.read_bytes()
        assert key[3:].encode() not in file.read_bytes()


def test_key_verification_refuses_wrong_formats_without_querying(tmp_path, monkeypatch):
    database = Database(tmp_path / "keys.sqlite3")
    monkeypatch.setattr(database, "_connect", None)  # toute requête échouerait
    for value in ("", "pg_short", "PG_" + "a" * 43, "pg_" + "a" * 43 + "\n", "pg_" + "é" * 43):
        assert database.verify_key(value) is None


def test_key_names_are_validated(tmp_path):
    database = Database(tmp_path / "keys.sqlite3")
    for name in ("", "   ", "a" * 65, "nom\navec\x1bcontrôle"):
        with pytest.raises(ValueError):
            database.create_key(name)


@pytest.mark.skipif(os.name != "posix", reason="droits POSIX")
def test_database_file_is_private(tmp_path):
    database = Database(tmp_path / "sub" / "keys.sqlite3")
    assert stat.S_IMODE(database.path.stat().st_mode) == 0o600


def test_database_refuses_memory(tmp_path):
    with pytest.raises(ValueError):
        Database(":memory:")


def test_keys_command_line(tmp_path, capsys):
    path = tmp_path / "cli.sqlite3"
    assert keys_cli.main(["--database", str(path), "create", "--name", "extension-dev"]) == 0
    out = capsys.readouterr().out
    key = out.strip().splitlines()[-1]
    assert KEY_PATTERN.fullmatch(key)
    record = Database(path).verify_key(key)
    assert record is not None and record.name == "extension-dev"

    assert keys_cli.main(["--database", str(path), "list"]) == 0
    listing = capsys.readouterr().out
    assert record.key_id in listing and key not in listing  # jamais le secret

    assert keys_cli.main(["--database", str(path), "revoke", record.key_id]) == 0
    assert keys_cli.main(["--database", str(path), "revoke", record.key_id]) == 1
    assert Database(path).verify_key(key) is None


# --------------------------------------------------------------------------- #
# IP du client et proxy inverse
# --------------------------------------------------------------------------- #


def request_from(peer: str, *forwarded: str) -> Request:
    headers = [(b"x-forwarded-for", value.encode()) for value in forwarded]
    return Request({"type": "http", "client": (peer, 1234), "headers": headers})


PROXIES = (ip_network("10.0.0.0/8"), ip_network("fd00::/8"))


@pytest.mark.parametrize(
    "peer, forwarded, proxies, expected",
    [
        # Aucun proxy de confiance : l'en-tête est ignoré, quoi qu'il dise.
        ("203.0.113.7", ("198.51.100.1",), (), "203.0.113.7"),
        # Connexion directe d'un client qui n'est pas un proxy : en-tête ignoré.
        ("203.0.113.7", ("198.51.100.1",), PROXIES, "203.0.113.7"),
        # Proxy de confiance : le client est l'adresse qu'il a ajoutée.
        ("10.0.0.2", ("198.51.100.1",), PROXIES, "198.51.100.1"),
        # Le client a falsifié l'en-tête : sa valeur est à gauche, ignorée.
        ("10.0.0.2", ("6.6.6.6, 198.51.100.1",), PROXIES, "198.51.100.1"),
        ("10.0.0.2", ("6.6.6.6", "198.51.100.1"), PROXIES, "198.51.100.1"),
        # Deux proxys de confiance en chaîne.
        ("10.0.0.2", ("6.6.6.6, 198.51.100.1, 10.0.0.9",), PROXIES, "198.51.100.1"),
        # Valeur illisible : on garde la dernière adresse sûre.
        ("10.0.0.2", ("198.51.100.1, garbage",), PROXIES, "10.0.0.2"),
        ("10.0.0.2", (), PROXIES, "10.0.0.2"),
        # IPv4 écrite en IPv6 (::ffff:) : ramenée à l'IPv4.
        ("::ffff:10.0.0.2", ("::ffff:198.51.100.1",), PROXIES, "198.51.100.1"),
        ("fd00::1", ("2001:db8::1",), PROXIES, "2001:db8::1"),
    ],
)
def test_client_ip_behind_a_reverse_proxy(peer, forwarded, proxies, expected):
    assert client_ip(request_from(peer, *forwarded), proxies) == ip_address(expected)


def test_client_ip_without_connection_info():
    request = Request({"type": "http", "client": None, "headers": []})
    assert client_ip(request, PROXIES) is None
    assert ip_bucket(None) == "unknown"


def test_ipv6_clients_are_grouped_by_64():
    a, b, c = (
        ip_address(x) for x in ("2001:db8:1:2::1", "2001:db8:1:2:ffff::9", "2001:db8:1:3::1")
    )
    assert ip_bucket(a) == ip_bucket(b) == "2001:db8:1:2::/64"
    assert ip_bucket(c) != ip_bucket(a)
    assert ip_bucket(ip_address("192.0.2.1")) == "192.0.2.1"
    assert Client("anonymous", "192.0.2.1").rate_key == "anonymous:192.0.2.1"
    assert Client("authenticated", "192.0.2.1", key_id="abc").rate_key == "key:abc"


def test_spoofed_forwarded_for_does_not_reset_the_quota(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path, rate_limit_anonymous="3/minute")
    with api_client(settings, client=("203.0.113.7", 5000)) as client:
        codes = [
            post_text(client, **{"X-Forwarded-For": f"198.51.100.{i}"}).status_code
            for i in range(5)
        ]
    assert codes == [200, 200, 200, 429, 429]


def test_trusted_proxy_gives_each_client_its_quota(api_models_dir, tmp_path):
    settings = settings_for(
        api_models_dir,
        tmp_path,
        rate_limit_anonymous="2/minute",
        trusted_proxies="10.0.0.0/8",
    )
    with api_client(settings, client=("10.0.0.2", 5000)) as client:
        first = [
            post_text(client, **{"X-Forwarded-For": "198.51.100.1"}).status_code for _ in range(3)
        ]
        # Le même client qui falsifie la partie gauche reste compté comme lui-même.
        spoof = post_text(client, **{"X-Forwarded-For": "1.2.3.4, 198.51.100.1"}).status_code
        other = post_text(client, **{"X-Forwarded-For": "198.51.100.2"}).status_code
    assert first == [200, 200, 429]
    assert spoof == 429
    assert other == 200
