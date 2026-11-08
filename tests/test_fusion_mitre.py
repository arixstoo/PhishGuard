"""Tests de la correspondance MITRE ATT&CK (étape 2.11)."""

import importlib.util
import itertools
import json
from pathlib import Path

import pytest

from phishguard.enrichers import Signal
from phishguard.fusion.mitre import (
    CHANNELS,
    Observations,
    catalog,
    domain_observations,
    map_techniques,
    technique,
)

ROOT = Path(__file__).resolve().parents[1]


def ids(verdict, **kwargs):
    return [t.id for t in map_techniques(verdict, Observations(**kwargs))]


# --------------------------------------------------------------------------- #
# Table de correspondance
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("observations", "expected"),
    [
        ({"channel": "email", "has_link": True}, ["T1566.002", "T1204.001"]),
        ({"channel": "email", "risky_attachment": True}, ["T1566.001", "T1204.002"]),
        (
            {"channel": "email", "has_link": True, "risky_attachment": True},
            ["T1566.002", "T1566.001", "T1204.001", "T1204.002"],
        ),
        ({"channel": "sms", "has_link": True}, ["T1566.003", "T1204.001"]),
        ({"channel": "messaging"}, ["T1566.003"]),
        ({"channel": "url"}, ["T1566", "T1204.001"]),
        ({"channel": "url", "requests_information": True}, ["T1204.001", "T1598.003"]),
        ({"channel": "sms", "requests_information": True}, ["T1566.003", "T1598.001"]),
        ({"channel": "email", "requests_information": True}, ["T1598"]),
        (
            {"channel": "email", "risky_attachment": True, "requests_information": True},
            ["T1566.001", "T1204.002", "T1598.002"],
        ),
        ({"channel": "url", "recent_domain": True}, ["T1566", "T1204.001", "T1583.001"]),
        ({"channel": "email"}, ["T1566"]),  # phishing sans vecteur précis
    ],
)
def test_mapping_table(observations, expected):
    assert ids("phishing", **observations) == expected


def test_safe_verdict_has_no_technique():
    assert map_techniques("safe", Observations("email", has_link=True)) == ()


def test_suspicious_verdict_is_mapped_too():
    assert ids("suspicious", channel="sms", has_link=True) == ["T1566.003", "T1204.001"]


def test_full_names_tactics_and_links():
    found = {t.id: t for t in map_techniques("phishing", Observations("email", has_link=True))}
    link = found["T1566.002"]
    assert link.name == "Phishing: Spearphishing Link"
    assert link.tactic == "Initial Access"
    assert link.url == "https://attack.mitre.org/techniques/T1566/002"
    assert link.reason == "lien malveillant dans un email"
    assert found["T1204.001"].name == "User Execution: Malicious Link"
    assert found["T1204.001"].tactic == "Execution"
    assert link.to_dict()["id"] == "T1566.002"


def test_domain_reason_names_both_findings():
    obs = Observations("url", recent_domain=True, lookalike_domain=True)
    domain = next(t for t in map_techniques("phishing", obs) if t.id == "T1583.001")
    assert domain.name == "Acquire Infrastructure: Domains"
    assert domain.tactic == "Resource Development"
    assert domain.reason == "domaine de moins de 30 jours et domaine qui imite une marque"


# --------------------------------------------------------------------------- #
# Critère de l'étape : chaque verdict phishing a au moins une technique nommée
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("channel", CHANNELS)
def test_every_phishing_verdict_has_at_least_one_named_technique(channel):
    flags = ("has_link", "risky_attachment", "requests_information", "recent_domain",
             "lookalike_domain")  # fmt: skip
    for values in itertools.product((False, True), repeat=len(flags)):
        techniques = map_techniques("phishing", Observations(channel, **dict(zip(flags, values))))
        assert techniques, (channel, values)
        assert len({t.id for t in techniques}) == len(techniques)  # pas de doublon
        for t in techniques:
            assert t.id in catalog()["techniques"] and t.name and t.tactic and t.reason


# --------------------------------------------------------------------------- #
# Constats issus des sources et des features URL
# --------------------------------------------------------------------------- #


def test_recent_domain_from_rdap_or_certificates():
    rdap = Signal(source="rdap", status="ok", risk=0.8, evidence={"age_days": 12})
    old = Signal(source="rdap", status="ok", evidence={"age_days": 4000})
    cert = Signal(
        source="certificate_transparency", status="ok", risk=0.6, evidence={"first_seen_days": 2}
    )
    assert domain_observations([rdap])["recent_domain"] is True
    assert domain_observations([old])["recent_domain"] is False
    assert domain_observations([old, cert])["recent_domain"] is True


def test_unusable_or_incomplete_signals_are_ignored():
    signals = [
        Signal(source="rdap", status="error", evidence={"age_days": 1}),
        Signal(source="rdap", status="ok", evidence={"age_days": None}),
        Signal(source="virustotal", status="ok", evidence={"age_days": 1}),
    ]
    assert domain_observations(signals) == {"recent_domain": False, "lookalike_domain": False}


@pytest.mark.parametrize("feature", ["is_typosquat", "homograph_brand", "host_mixed_script"])
def test_lookalike_domain_from_url_features(feature):
    assert domain_observations([], {feature: 1.0, "host_len": 12})["lookalike_domain"] is True
    assert domain_observations([], {feature: 0.0})["lookalike_domain"] is False
    # bool(nan) vaut True : une feature manquante ne doit pas devenir une imitation.
    assert domain_observations([], {feature: float("nan")})["lookalike_domain"] is False


def test_boolean_age_is_not_a_number_of_days():
    signal = Signal(source="rdap", status="ok", evidence={"age_days": True})
    assert domain_observations([signal])["recent_domain"] is False


def test_messaging_information_request_is_spearphishing_service():
    found = {
        t.id: t
        for t in map_techniques("phishing", Observations("messaging", requests_information=True))
    }
    assert found["T1598.001"].name == "Phishing for Information: Spearphishing Service"
    assert found["T1598.001"].tactic == "Reconnaissance"


def test_unknown_channel_and_technique_are_rejected():
    with pytest.raises(ValueError):
        Observations("fax")
    with pytest.raises(KeyError):
        technique("T9999", "x")


# --------------------------------------------------------------------------- #
# Catalogue versionné et script de vérification
# --------------------------------------------------------------------------- #


def test_catalog_is_consistent():
    data = catalog()
    assert data["domain"] == "enterprise-attack" and data["attack_version"]
    for technique_id, entry in data["techniques"].items():
        assert entry["tactic"] in data["tactics"]
        if "." in technique_id:
            assert technique_id.split(".")[0] in data["techniques"]


def _load_script():
    spec = importlib.util.spec_from_file_location("verify_mitre", ROOT / "scripts/verify_mitre.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_stix(version="20.0", rename=None, revoke=None, tactic=None):
    """Paquet STIX minimal, construit à partir du catalogue du projet."""
    objects = [{"type": "x-mitre-collection", "x_mitre_version": version}]
    for technique_id, entry in catalog()["techniques"].items():
        objects.append(
            {
                "type": "attack-pattern",
                "name": (rename or {}).get(technique_id, entry["name"]),
                "revoked": technique_id == revoke,
                "kill_chain_phases": [
                    {"phase_name": (tactic or {}).get(technique_id, entry["tactic"])}
                ],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": technique_id}
                ],
            }
        )
    return {"type": "bundle", "objects": objects}


def run_script(tmp_path, bundle, *extra):
    stix = tmp_path / "enterprise-attack.json"
    stix.write_text(json.dumps(bundle), encoding="utf-8")
    catalog_copy = tmp_path / "mitre_attack.json"
    catalog_copy.write_text(json.dumps(catalog()), encoding="utf-8")
    code = _load_script().main(["--stix", str(stix), "--catalog", str(catalog_copy), *extra])
    return code, json.loads(catalog_copy.read_text(encoding="utf-8"))


def test_script_accepts_an_up_to_date_catalog(tmp_path, capsys):
    code, _ = run_script(tmp_path, fake_stix())
    assert code == 0
    assert f"{len(catalog()['techniques'])} techniques vérifiées" in capsys.readouterr().out


def test_script_detects_a_renamed_technique(tmp_path, capsys):
    code, _ = run_script(tmp_path, fake_stix(rename={"T1566.002": "Link Phishing"}))
    assert code == 1
    assert (
        "T1566.002 : nom 'Spearphishing Link', officiel 'Link Phishing'" in capsys.readouterr().out
    )


def test_script_detects_a_revoked_or_missing_technique(tmp_path, capsys):
    assert run_script(tmp_path, fake_stix(revoke="T1598"))[0] == 1
    bundle = fake_stix()
    bundle["objects"] = [o for o in bundle["objects"] if o.get("name") != "Malicious Link"]
    assert run_script(tmp_path, bundle)[0] == 1
    assert "T1204.001 : absente d'ATT&CK" in capsys.readouterr().out


def test_script_updates_names_and_version(tmp_path):
    code, updated = run_script(
        tmp_path, fake_stix(version="21.0", rename={"T1566.002": "Link Phishing"}), "--write"
    )
    assert code == 0
    assert updated["attack_version"] == "21.0"
    assert updated["techniques"]["T1566.002"]["name"] == "Link Phishing"


def test_script_refuses_to_write_when_a_technique_is_revoked(tmp_path):
    code, unchanged = run_script(tmp_path, fake_stix(revoke="T1598"), "--write")
    assert code == 1 and unchanged == catalog()


def test_script_refuses_to_write_when_a_tactic_changed(tmp_path, capsys):
    # --write ne corrige que les noms : une tactique changée ne doit pas passer en silence.
    bundle = fake_stix(tactic={"T1583.001": "initial-access"})
    code, unchanged = run_script(tmp_path, bundle, "--write")
    assert code == 1 and unchanged == catalog()
    assert "T1583.001 : tactique" in capsys.readouterr().out


def test_script_prefers_the_active_object_over_a_revoked_duplicate():
    bundle = fake_stix()
    revoked_copy = {**bundle["objects"][1], "name": "Old", "revoked": True}
    bundle["objects"].append(revoked_copy)
    stix, _ = _load_script().index_stix(bundle)
    assert stix[revoked_copy["external_references"][0]["external_id"]]["revoked"] is False


def test_written_catalog_keeps_one_technique_per_line(tmp_path):
    _, written = run_script(tmp_path, fake_stix(version="21.0"), "--write")
    text = (tmp_path / "mitre_attack.json").read_text(encoding="utf-8")
    assert written["attack_version"] == "21.0"
    assert '"T1566.002": {"name": "Spearphishing Link", "tactic": "initial-access"}' in text
