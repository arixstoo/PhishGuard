"""Déploiement (étapes 6.1 à 6.4) : configuration du proxy Vercel, compose de production,
Caddy, workflows et commande forcée du serveur.

Ces tests figent les garde-fous de sécurité du déploiement : une régression (port de
l'API publié, image désignée par étiquette, action non épinglée, commande SSH acceptée
sans validation) échoue ici, avant d'atteindre le serveur.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
WORKFLOWS = ROOT / ".github" / "workflows"

_spec = importlib.util.spec_from_file_location(
    "render_edge_config", ROOT / "scripts" / "render_edge_config.py"
)
edge = importlib.util.module_from_spec(_spec)
sys.modules["render_edge_config"] = edge
_spec.loader.exec_module(edge)

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
SHA_PIN_RE = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")


# --------------------------------------------------------------------------- #
# Proxy Vercel (scripts/render_edge_config.py)
# --------------------------------------------------------------------------- #


def test_proxy_config_forwards_everything_with_secret_header():
    config = edge.proxy_config("phishguard-origin.duckdns.org")
    (route,) = config["routes"]
    assert route["src"] == "/(.*)"
    assert route["dest"] == "https://phishguard-origin.duckdns.org/$1"
    (transform,) = route["transforms"]
    assert transform == {
        "type": "request.headers",
        "op": "set",  # remplace toute valeur envoyée par le visiteur
        "target": {"key": "x-phishguard-origin-auth"},
        "args": "$PHISHGUARD_ORIGIN_SECRET",
        "env": ["PHISHGUARD_ORIGIN_SECRET"],
    }
    assert config["framework"] is None and config["buildCommand"] == ""


@pytest.mark.parametrize(
    "host",
    [
        "203.0.113.5",  # pas de certificat public pour une IP
        "https://origin.example.org",
        "origin.example.org:8443",
        "origin.example.org/path",
        "user@origin.example.org",
        "Origin.Example.org",
        "localhost",
        "-bad.example.org",
        "phishguard-api.vercel.app",  # boucle vers le proxy lui-même
        "x" * 64 + ".example.org",
        "",
    ],
)
def test_proxy_config_rejects_invalid_origin(host):
    with pytest.raises(edge.EdgeConfigError):
        edge.proxy_config(host)


def test_maintenance_config_answers_503_without_cache():
    (route,) = edge.maintenance_config()["routes"]
    assert route["status"] == 503
    assert route["headers"]["Cache-Control"] == "no-store"
    assert route["headers"]["X-Content-Type-Options"] == "nosniff"


def test_render_writes_dist_without_leaking_origin(tmp_path, capsys):
    assert edge.main(["--output", str(tmp_path), "proxy", "--origin-host", "o.example.org"]) == 0
    config = json.loads((tmp_path / "vercel.json").read_text(encoding="utf-8"))
    assert config["routes"][0]["dest"].startswith("https://o.example.org/")
    assert json.loads((tmp_path / "public" / "unavailable.json").read_text(encoding="utf-8"))
    # La sortie de la CI est publique : le nom de l'origine n'y apparaît pas.
    assert "o.example.org" not in capsys.readouterr().out


def test_render_refuses_and_writes_nothing(tmp_path):
    assert edge.main(["--output", str(tmp_path), "proxy", "--origin-host", "10.0.0.1"]) == 2
    assert not (tmp_path / "vercel.json").exists()


# --------------------------------------------------------------------------- #
# deploy/compose.prod.yml
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load((DEPLOY / "compose.prod.yml").read_text(encoding="utf-8"))


def test_only_caddy_publishes_public_ports(compose):
    services = compose["services"]
    assert services["caddy"]["ports"] == ["80:80/tcp", "443:443/tcp"]
    assert "ports" not in services["api"]
    for port in services["uptime-kuma"]["ports"]:
        assert port.startswith("127.0.0.1:")


def test_images_pinned_by_digest(compose):
    for name, service in compose["services"].items():
        image = service["image"]
        if name == "api":
            # Empreinte écrite par phishguard-deploy dans release.env ; obligatoire.
            assert image.startswith("${PHISHGUARD_IMAGE:?")
        else:
            assert DIGEST_RE.search(image), name


def test_runtime_hardening(compose):
    services = compose["services"]
    anchor = compose["x-hardening"]
    assert anchor["read_only"] is True and anchor["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in anchor["security_opt"]
    for name, service in services.items():
        assert service["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in service["security_opt"], name
        assert service["mem_limit"] and service["pids_limit"], name
        assert service["logging"]["options"]["max-size"], name
    assert services["caddy"]["cap_add"] == ["NET_BIND_SERVICE"]
    assert services["api"]["read_only"] is True and services["caddy"]["read_only"] is True


def test_api_trusts_only_caddy(compose):
    services = compose["services"]
    caddy_ip = services["caddy"]["networks"]["edge"]["ipv4_address"]
    env = services["api"]["environment"]
    assert env["PHISHGUARD_API_TRUSTED_PROXIES"] == f"{caddy_ip}/32"
    assert env["PHISHGUARD_API_ENVIRONMENT"] == "production"
    mounts = {v["target"]: v for v in services["api"]["volumes"] if isinstance(v, dict)}
    assert mounts["/app/models"]["read_only"] is True


def test_caddy_secrets_are_required(compose):
    env = compose["services"]["caddy"]["environment"]
    for key in ("PHISHGUARD_ORIGIN_HOST", "PHISHGUARD_ORIGIN_SECRET", "PHISHGUARD_ACME_EMAIL"):
        assert env[key].startswith(f"${{{key}:?"), key  # compose échoue si vide


# --------------------------------------------------------------------------- #
# deploy/Caddyfile
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def caddyfile() -> str:
    text = (DEPLOY / "Caddyfile").read_text(encoding="utf-8")
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def test_caddy_requires_origin_secret(caddyfile):
    assert "@from_edge header X-PhishGuard-Origin-Auth {$PHISHGUARD_ORIGIN_SECRET}" in caddyfile
    assert "request_header -X-PhishGuard-Origin-Auth" in caddyfile
    assert re.search(r'respond "forbidden" 403', caddyfile)
    # Une seule route vers l'API, sous le matcher du secret.
    assert caddyfile.count("reverse_proxy") == 1
    assert caddyfile.index("handle @from_edge") < caddyfile.index("reverse_proxy")


def test_caddy_has_no_access_log_nor_admin(caddyfile):
    assert not re.search(r"^\s*log\b", caddyfile, re.MULTILINE)  # IP et clés d'API
    assert re.search(r"^\s*admin off$", caddyfile, re.MULTILINE)
    assert "header_up X-Forwarded-For {http.request.header.X-Real-IP}" in caddyfile


# --------------------------------------------------------------------------- #
# Workflows
# --------------------------------------------------------------------------- #


def _workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "name", ["deploy.yml", "uptime.yml", "extension-release.yml", "adoption.yml"]
)
def test_workflow_least_privilege_and_pinned_actions(name):
    workflow = _workflow(name)
    assert workflow["permissions"] == {}
    for job_name, job in workflow["jobs"].items():
        assert "permissions" in job, job_name
        for step in job["steps"]:
            if "uses" in step:
                assert SHA_PIN_RE.match(step["uses"]), step["uses"]
            # Pas d'expression ${{ }} interpolée dans un script : injection de commande.
            assert "${{" not in step.get("run", ""), (job_name, step.get("name"))


def test_deploy_designates_image_by_digest():
    text = (WORKFLOWS / "deploy.yml").read_text(encoding="utf-8")
    assert '"deploy $VERSION $IMAGE@$DIGEST"' in text
    assert "StrictHostKeyChecking=yes" in text and "StrictHostKeyChecking=no" not in text
    jobs = _workflow("deploy.yml")["jobs"]
    assert jobs["deploy"]["environment"] == "production"
    assert jobs["publish"]["permissions"]["id-token"] == "write"


# --------------------------------------------------------------------------- #
# Scripts du serveur
# --------------------------------------------------------------------------- #

SERVER_SCRIPTS = sorted((DEPLOY / "server").glob("*.sh")) + [ROOT / "scripts" / "edge_smoke.sh"]
BASH = shutil.which("bash") if os.name != "nt" else None

needs_bash = pytest.mark.skipif(BASH is None, reason="bash POSIX (Linux, WSL) requis")


@needs_bash
@pytest.mark.parametrize("script", SERVER_SCRIPTS, ids=lambda p: p.name)
def test_shell_syntax(script):
    subprocess.run([BASH, "-n", str(script)], check=True)


@needs_bash
@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck absent")
def test_shellcheck():
    subprocess.run(["shellcheck", "--severity=warning", *map(str, SERVER_SCRIPTS)], check=True)


def _forced_command(
    tmp_path: Path, request: str, stdin: bytes = b""
) -> subprocess.CompletedProcess:
    (tmp_path / "releases").mkdir(exist_ok=True)
    env = {
        "PATH": os.environ["PATH"],
        "PHISHGUARD_ROOT": str(tmp_path),
        "SSH_ORIGINAL_COMMAND": request,
    }
    return subprocess.run(
        [BASH, str(DEPLOY / "server" / "deploy.sh")],
        input=stdin,
        env=env,
        check=False,  # le code de retour est l'objet du test
        capture_output=True,
        timeout=30,
    )


DIGEST = "sha256:" + "a" * 64


@needs_bash
@pytest.mark.skipif(shutil.which("flock") is None, reason="flock (util-linux) absent")
@pytest.mark.parametrize(
    ("request_", "reason"),
    [
        ("rm -rf /", "commande refusée"),
        ("deploy v0.6.0", "usage"),
        ("deploy v0.6.0 ghcr.io/arixstoo/phishguard-api:latest", "empreinte"),
        (f"deploy v0.6.0 ghcr.io/attacker/image@{DIGEST}", "dépôt d'image refusé"),
        (f"deploy $(id) ghcr.io/arixstoo/phishguard-api@{DIGEST}", "version invalide"),
        (f"deploy v0.6.0;id ghcr.io/arixstoo/phishguard-api@{DIGEST}", "version invalide"),
        ("rollback ../../etc", "version invalide"),
        ("status; id", "commande refusée"),
        ("reload now", "usage"),
        ("deploy a b c d", "usage"),
        ("", "usage"),
    ],
)
def test_forced_command_rejects(tmp_path, request_, reason):
    result = _forced_command(tmp_path, request_)
    assert result.returncode != 0
    assert reason in result.stderr.decode("utf-8")
    # Rien n'a été installé.
    assert list((tmp_path / "releases").iterdir()) == []


@needs_bash
@pytest.mark.skipif(shutil.which("flock") is None, reason="flock (util-linux) absent")
def test_forced_command_requires_server_configuration(tmp_path):
    result = _forced_command(tmp_path, f"deploy v0.6.0 ghcr.io/arixstoo/phishguard-api@{DIGEST}")
    assert result.returncode != 0
    assert "server.env absent" in result.stderr.decode("utf-8")
