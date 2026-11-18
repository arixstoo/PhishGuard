"""La politique de confidentialité dit exactement ce que fait le code (étape 6.5).

Critère de l'étape : « chaque phrase de la politique correspond à un comportement
vérifiable du code ». Ce test vérifie la partie mécanique de cette promesse :

- chaque fichier cité dans le tableau des vérifications de ``PRIVACY.md`` existe ;
- chaque valeur chiffrée de la politique est celle du code (durées, tailles, limites),
  en français **et** en anglais : changer une constante sans changer la politique, ou
  l'inverse, fait échouer ce test.

Les comportements eux-mêmes sont vérifiés par les tests cités dans le tableau.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from phishguard.api.settings import ApiSettings

ROOT = Path(__file__).resolve().parents[1]
POLICY = (ROOT / "PRIVACY.md").read_text(encoding="utf-8")
FRENCH, ENGLISH = POLICY.split("# PhishGuard privacy policy", 1)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def claims() -> list[tuple[str, list[str]]]:
    section = re.search(r"<!-- claims:start -->(.*?)<!-- claims:end -->", POLICY, re.DOTALL)
    assert section, "tableau des vérifications introuvable dans PRIVACY.md"
    rows = []
    for line in section.group(1).splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 2 and "`" in cells[1]:
            rows.append((cells[0], re.findall(r"`([^`]+)`", cells[1])))
    return rows


def test_every_claim_is_backed_by_an_existing_file() -> None:
    rows = claims()
    assert len(rows) >= 10
    for claim, paths in rows:
        assert paths, claim
        for path in paths:
            assert (ROOT / path).is_file(), f"« {claim} » cite {path}, introuvable"


def test_extension_limits_match_the_policy() -> None:
    storage = read("extension/src/storage.ts")
    assert re.search(r"CACHE_SIZE = 100;", storage)
    assert re.search(r"MAX_ALLOWLIST = 1000;", storage)
    assert "100 dernières analyses" in FRENCH and "1 000 au plus" in FRENCH
    assert "last 100 requested analyses" in ENGLISH and "at most\n  1,000" in ENGLISH


def test_model_updates_are_daily_off_by_default_and_send_nothing() -> None:
    updates = read("extension/src/updates.ts")
    settings = read("extension/src/settings.ts")
    assert "CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;" in updates
    assert re.search(r"modelUpdates: false,", settings)
    # Requêtes sans corps ni en-tête : rien d'autre que le fichier demandé.
    assert 'method: "GET"' in updates and 'credentials: "omit"' in updates
    assert "body:" not in updates and "headers:" not in updates
    assert "au plus une fois par jour" in FRENCH and "at most once a day" in ENGLISH


def test_feedback_retention_matches_the_policy() -> None:
    settings = ApiSettings(_env_file=None)
    assert settings.feedback_retention_days == 90
    assert "au plus tard\n  90 jours après réception" in FRENCH
    assert "at the latest 90 days after receipt" in ENGLISH


def test_threat_intelligence_is_off_by_default() -> None:
    assert ApiSettings(_env_file=None).threat_intel_enabled is False
    assert "**jamais par défaut**" in FRENCH and "**never by default**" in ENGLISH


@pytest.mark.parametrize("compose", ["docker-compose.yml", "deploy/compose.prod.yml"])
def test_log_rotation_matches_the_policy(compose: str) -> None:
    text = read(compose)
    assert "max-size: 10m" in text and 'max-file: "3"' in text
    assert "3 fichiers de 10 Mo" in FRENCH and "3 files of\n  10 MB" in ENGLISH


def test_backup_retention_matches_the_policy() -> None:
    assert re.search(r'keep_days="\$\{keep_days:-14\}"', read("deploy/server/backup.sh"))
    assert "14 jours sur le serveur" in FRENCH and "14 days on the server" in ENGLISH
    # La règle de 30 jours hors du serveur est documentée là où on configure le stockage.
    assert "30 jours" in read("docs/operations.md")


def test_policy_is_dated_and_links_to_the_detailed_extension_page() -> None:
    assert re.search(r"\*En vigueur le \d{1,2} \w+ \d{4}\.", FRENCH)
    assert re.search(r"\*Effective \d{1,2} \w+ \d{4}\.", ENGLISH)
    assert "docs/extension-privacy.md" in FRENCH
