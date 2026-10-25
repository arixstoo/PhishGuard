"""Tests de l'audit des biais (étape 1.3), sur de petits jeux synthétiques."""

import hashlib
import importlib.util
import io
import json
import zipfile
from pathlib import Path

import httpx
import numpy as np
import pandas as pd
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from phishguard.data import bias as B
from phishguard.data import phiusiil as P
from phishguard.data.integrity import DatasetIntegrityError, download_zip_member
from phishguard.data.urls import COLUMNS, make_domain_extractor, normalize_url, registered_domain

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_bias.py"
spec = importlib.util.spec_from_file_location("audit_bias", SCRIPT)
audit_script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_script)

EXTRACTOR = make_domain_extractor()
FAST = B.ProbeConfig(min_df=1, max_features=5000, test_size=0.3, min_source_rows=20)


def rows(*entries: tuple[str, int, str, str]) -> pd.DataFrame:
    """Construit un jeu au schéma commun à partir de ``(url, label, source, date)``."""
    records = []
    for raw, label, source, seen in entries:
        url, host = normalize_url(raw)
        records.append(
            {
                "url": url,
                "label": label,
                "source": source,
                "first_seen": pd.Timestamp(seen, tz="UTC"),
                "host": host,
                "registered_domain": registered_domain(host, EXTRACTOR),
            }
        )
    return pd.DataFrame(records, columns=COLUMNS).astype({"label": "int8"})


def random_word(rng: np.random.Generator, size: int = 8) -> str:
    return "".join(rng.choice(list("abcdefghijklmnopqrstuvwxyz"), size))


def biased_dataset(n: int = 300, seed: int = 0) -> pd.DataFrame:
    """Reproduit le biais de Tranco : légitime = page d'accueil, phishing = chemin profond.

    Les domaines des deux classes sont tirés de la même façon : seul le chemin, le schéma
    et les sous-domaines séparent les classes.
    """
    rng = np.random.default_rng(seed)
    entries = []
    for i in range(n):
        entries.append((f"https://{random_word(rng)}.com/", 0, "tranco", "2026-10-22"))
        source, scheme = ("phishtank", "https") if i % 2 else ("openphish", "http")
        url = f"{scheme}://login.{random_word(rng)}.com/{random_word(rng, 5)}/verify.php?id={i}"
        entries.append((url, 1, source, f"2026-{1 + i % 9:02d}-01"))
    return rows(*entries)


# --------------------------------------------------------------------------- #
# Structure
# --------------------------------------------------------------------------- #


def test_url_traits_reads_every_structural_signal():
    df = rows(
        ("https://example.com/", 0, "tranco", "2026-10-22"),
        ("http://user@www.a.b.example.co.uk:8080/x/y/?q=1#f", 1, "phishtank", "2026-10-01"),
        ("http://192.0.2.1/login", 1, "openphish", "2026-10-02"),
        ("https://victim.github.io/", 1, "openphish", "2026-10-02"),
    )
    traits = B.url_traits(df)

    assert list(traits.columns) == list(B.TRAITS)
    home, full, ip, platform = (traits.iloc[i] for i in range(4))
    assert not home[list(B.BOOLEAN_TRAITS)].any()
    assert home["path_depth"] == 0 and home["subdomain_depth"] == 0

    for name in ("is_http", "has_path", "has_query", "has_fragment", "has_userinfo", "has_port"):
        assert full[name], name
    assert full["has_www"] and full["subdomain_depth"] == 3 and full["path_depth"] == 2

    assert ip["is_ip"] and ip["subdomain_depth"] == 0 and not ip["has_subdomain"]
    # Un compte github.io est son propre domaine enregistré : pas de sous-domaine.
    assert platform["subdomain_depth"] == 0


def test_structure_profile_and_trait_auc_expose_the_path_shortcut():
    df = biased_dataset(50)
    profile = B.structure_profile(df, "label")
    assert profile["0"]["has_path"] == 0.0 and profile["1"]["has_path"] == 1.0
    assert profile["0"]["rows"] == profile["1"]["rows"] == 50

    auc = B.trait_auc(df)
    assert auc["has_path"] == 1.0
    assert auc["has_fragment"] == 0.5  # trait absent des deux classes : non informatif


def test_represent_strips_progressively():
    df = rows(("http://www.shop.example.co.uk/a?b=1", 1, "phishtank", "2026-10-01"))
    assert B.represent(df, "url").item() == "http://www.shop.example.co.uk/a?b=1"
    assert B.represent(df, "origin").item() == "http://www.shop.example.co.uk/"
    assert B.represent(df, "host").item() == "www.shop.example.co.uk"
    assert B.represent(df, "registered_domain").item() == "example.co.uk"
    with pytest.raises(ValueError, match="représentation inconnue"):
        B.represent(df, "path")


# --------------------------------------------------------------------------- #
# Protocoles
# --------------------------------------------------------------------------- #


@settings(max_examples=50, deadline=None)
@given(st.lists(st.integers(min_value=0, max_value=15), min_size=4, max_size=60))
def test_grouped_holdout_never_shares_a_domain(domain_ids):
    df = pd.DataFrame({"registered_domain": [f"d{i}.com" for i in domain_ids]})
    if df["registered_domain"].nunique() < 2:
        return
    train, test = B.grouped_holdout(df, 0.3, seed=1)
    assert len(train) + len(test) == len(df)
    train_domains = set(df["registered_domain"].iloc[train])
    assert train_domains.isdisjoint(df["registered_domain"].iloc[test])


def test_ablation_detects_that_the_score_comes_from_the_url_shape():
    result = B.representation_ablation(biased_dataset(), FAST)

    assert set(result) == {*B.REPRESENTATIONS, "structural_traits_only"}
    assert result["url"]["pr_auc"] > 0.99
    assert result["structural_traits_only"]["pr_auc"] > 0.99
    # Les domaines des deux classes sont tirés au hasard de la même façon : sans la forme
    # de l'URL, la sonde n'a plus rien d'utile.
    assert result["registered_domain"]["roc_auc"] < 0.7
    assert result["url"]["train_rows"] + result["url"]["test_rows"] == 600


def test_domain_leakage_counts_shared_domains_only_in_random_split():
    base = biased_dataset(100)
    # Chaque domaine apparaît trois fois : un split aléatoire le coupe forcément.
    df = pd.concat([base, base.assign(url=base["url"] + "a"), base.assign(url=base["url"] + "b")])
    result = B.domain_leakage(df.reset_index(drop=True), FAST)

    assert result["random"]["test_rows_with_domain_in_train"] > 0
    assert result["grouped_by_domain"]["test_rows_with_domain_in_train"] == 0
    assert result["grouped_by_domain"]["test_share_with_domain_in_train"] == 0.0


def test_cross_source_isolates_the_target_source(monkeypatch):
    calls = []

    def fake_score(train, test, level, cfg):
        calls.append((train, test))
        return {"pr_auc": 0.9 if len(calls) % 2 else 0.6}

    monkeypatch.setattr(B, "_probe_score", fake_score)
    df = biased_dataset(120)
    # Un domaine commun aux deux sources et au légitime ne doit jamais fuiter.
    df.loc[df.index[:6], "registered_domain"] = "shared.com"
    result = B.cross_source(df, FAST)

    assert set(result) == {"openphish", "phishtank"}
    assert result["openphish"]["pr_auc_drop"] == pytest.approx(0.3)
    assert len(calls) == 4
    for i, (train, test) in enumerate(calls):
        target = "openphish" if i < 2 else "phishtank"
        test_phishing = test[test["label"] == 1]
        assert set(test_phishing["source"]) == {target}
        assert set(train["registered_domain"]).isdisjoint(test["registered_domain"])
        assert set(test["label"]) == {0, 1}
        if i % 2:  # without_target
            assert target not in set(train["source"])
        else:
            assert target in set(train["source"])


def test_cross_source_skips_small_sources():
    df = biased_dataset(30)  # 15 URLs par source, sous le seuil
    cfg = B.ProbeConfig(min_df=1, min_source_rows=100)
    assert B.cross_source(df, cfg) == {}
    assert B.source_fingerprint(df, cfg) == {}


def test_source_fingerprint_spots_sources_with_a_distinct_style():
    # openphish en http, phishtank en https : les sources sont reconnaissables.
    result = B.source_fingerprint(biased_dataset(), FAST)
    assert list(result) == ["openphish"]
    assert result["openphish"] > 0.95


# --------------------------------------------------------------------------- #
# Temps, domaines partagés, validation externe
# --------------------------------------------------------------------------- #


def test_temporal_profile_shows_naive_split_puts_legit_in_test():
    profile = B.temporal_profile(biased_dataset(100))

    assert profile["by_source"]["tranco"]["min"].startswith("2026-10-22")
    blocks = profile["naive_temporal_split"]
    assert sum(block["rows"] for block in blocks.values()) == 200
    assert blocks["train"]["phishing_rate"] > 0.6
    assert blocks["test"]["phishing_rate"] == 0.0
    assert profile["phishing_share_before_first_legitimate"] == 1.0

    with pytest.raises(ValueError, match="sommer à 1"):
        B.temporal_profile(biased_dataset(10), (0.5, 0.2, 0.2))


def test_shared_domains():
    df = rows(
        ("https://google.com/", 0, "tranco", "2026-10-22"),
        ("https://sites.google.com/view/fake-login", 1, "phishtank", "2026-10-01"),
        ("https://forms.google.com/x", 1, "phishtank", "2026-10-01"),
        ("https://evil.example/", 1, "openphish", "2026-10-01"),
    )
    assert B.shared_domains(df) == {"domains": 1, "rows": 3, "phishing_rows": 2}


def test_external_validation_excludes_known_domains():
    train = biased_dataset(150, seed=1)
    external = pd.concat([biased_dataset(60, seed=2), train.head(10)], ignore_index=True)
    result = B.external_validation(train, external, FAST)

    assert result["rows"] == 130
    assert result["rows_excluded_known_domain"] >= 10
    assert set(result["probe"]) == set(B.REPRESENTATIONS)
    assert result["trait_auc"]["has_path"] == 1.0


def with_internal_pages(df: pd.DataFrame, seed: int = 3) -> pd.DataFrame:
    """Ajoute deux pages internes Common Crawl à chaque domaine légitime.

    Leur chemin a la même forme que celui du phishing de :func:`biased_dataset` : seul
    le domaine les distingue.
    """
    rng = np.random.default_rng(seed)
    entries = [
        (
            f"https://{domain}/{random_word(rng, 5)}/{page}.php?id={k}",
            0,
            "commoncrawl",
            "2026-10-10",
        )
        for k, domain in enumerate(df.loc[df["label"] == 0, "registered_domain"])
        for page in ("verify", "account")
    ]
    return pd.concat([df, rows(*entries)], ignore_index=True)


def test_internal_page_fpr_shows_the_path_shortcut_and_its_fix():
    result = B.internal_page_fpr(with_internal_pages(biased_dataset(200)), FAST)

    before, after = result["without_internal_pages"], result["with_internal_pages"]
    assert before["train_rows"] < after["train_rows"]
    assert before["fpr_homepages"] <= 0.01 and after["fpr_homepages"] <= 0.01
    # Sans pages internes, la sonde a appris « chemin = phishing ».
    assert before["fpr_internal_pages"] > 0.5
    assert after["fpr_internal_pages"] < before["fpr_internal_pages"] / 2
    assert result["test_rows"]["internal_pages"] > 0


def test_internal_page_fpr_is_skipped_without_internal_pages():
    assert B.internal_page_fpr(biased_dataset(50), FAST) == {}


def test_audit_requires_both_labels():
    df = biased_dataset(10)
    with pytest.raises(ValueError, match="deux classes"):
        B.audit(df[df["label"] == 1], FAST)


# --------------------------------------------------------------------------- #
# PhiUSIIL et téléchargement vérifié
# --------------------------------------------------------------------------- #

PHIUSIIL_CSV = (
    "﻿FILENAME,URL,URLLength,label\n"
    "a.txt,https://www.legit-demo.com,25,1\n"
    "b.txt,http://login.phish-demo.com/verify,30,0\n"
    "c.txt,http://login.phish-demo.com/verify,30,0\n"  # doublon
    "d.txt,https://www.conflict-demo.com,20,1\n"
    "e.txt,https://www.conflict-demo.com,20,0\n"  # étiquettes contradictoires
    "f.txt,https://bad url-demo.com,20,0\n"  # invalide
    "g.txt,http://localhost/x,20,0\n"  # suffixe inconnu
)


def test_load_phiusiil_inverts_labels_and_cleans(tmp_path):
    path = tmp_path / P.ZIP_MEMBER
    path.write_bytes(PHIUSIIL_CSV.encode("utf-8"))
    df, stats = P.load_phiusiil(path, EXTRACTOR)

    assert list(df.columns) == COLUMNS
    labels = dict(zip(df["url"], df["label"], strict=True))
    assert labels == {"https://www.legit-demo.com/": 0, "http://login.phish-demo.com/verify": 1}
    assert set(df["source"]) == {"phiusiil"} and df["first_seen"].isna().all()
    assert stats == {
        "rows_raw": 7,
        "invalid_url": 1,
        "unknown_suffix": 1,
        "label_conflicts": 1,
        "duplicates_removed": 1,
        "rows": 2,
    }


def test_load_phiusiil_rejects_unknown_labels(tmp_path):
    path = tmp_path / P.ZIP_MEMBER
    path.write_text("URL,label\nhttps://a-demo.com,2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="inattendues"):
        P.load_phiusiil(path, EXTRACTOR)


def zip_client(member: str, payload: bytes) -> httpx.Client:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member, payload)
    content = buffer.getvalue()
    return httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=content))
    )


def test_download_phiusiil_verifies_digest(tmp_path, monkeypatch):
    payload = PHIUSIIL_CSV.encode("utf-8")
    dest = tmp_path / "phiusiil.csv"
    with pytest.raises(DatasetIntegrityError, match="SHA-256"):
        P.download_phiusiil(dest, client=zip_client(P.ZIP_MEMBER, payload))
    assert not dest.exists()

    monkeypatch.setattr(P, "EXPECTED_SHA256", hashlib.sha256(payload).hexdigest())
    assert P.download_phiusiil(dest, client=zip_client(P.ZIP_MEMBER, payload)) == dest
    assert dest.read_bytes() == payload
    # Fichier déjà présent et intact : aucune requête.
    refusing = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    assert P.download_phiusiil(dest, client=refusing) == dest


@pytest.mark.parametrize(
    ("member", "payload", "limits", "message"),
    [
        ("other.csv", b"x", (10_000, 10_000), "sans data.csv"),
        ("data.csv", b"x" * 5000, (10_000, 100), "anormalement volumineux"),
        (
            "data.csv",
            np.random.default_rng(0).bytes(5000),
            (1000, 10**6),
            "anormalement volumineuse",
        ),
    ],
)
def test_download_zip_member_rejects_bad_archives(tmp_path, member, payload, limits, message):
    with pytest.raises(DatasetIntegrityError, match=message):
        download_zip_member(
            "https://example.test/a.zip",
            "data.csv",
            "0" * 64,
            tmp_path / "data.csv",
            max_download_bytes=limits[0],
            max_member_bytes=limits[1],
            client=zip_client(member, payload),
        )
    assert not (tmp_path / "data.csv").exists()


# --------------------------------------------------------------------------- #
# Script
# --------------------------------------------------------------------------- #


def test_script_writes_a_report_without_any_url(tmp_path, monkeypatch, capsys):
    dataset = biased_dataset(150)
    dataset_path = tmp_path / "urls.parquet"
    dataset.to_parquet(dataset_path, index=False)
    external_path = tmp_path / "phiusiil.csv"
    external_path.write_bytes(PHIUSIIL_CSV.encode("utf-8"))
    monkeypatch.setattr(
        P, "EXPECTED_SHA256", hashlib.sha256(external_path.read_bytes()).hexdigest()
    )
    monkeypatch.setattr(audit_script, "ProbeConfig", lambda **kw: B.ProbeConfig(min_df=1, **kw))
    report_path = tmp_path / "data_bias.json"

    code = audit_script.main(
        [
            "--dataset",
            str(dataset_path),
            "--phiusiil",
            str(external_path),
            "--report",
            str(report_path),
        ]
    )

    assert code == 0
    text = report_path.read_text(encoding="utf-8")
    report = json.loads(text)
    assert report["metadata"]["external_dataset"]["rows"] == 2
    assert {"structure", "source", "domain", "time", "external_validation"} <= set(report)
    # Rapport versionné dans un dépôt public : ni URL ni domaine.
    for value in pd.concat([dataset["url"], dataset["host"], dataset["registered_domain"]]):
        assert value not in text
    assert "Modèle sonde" in capsys.readouterr().out


def test_script_fails_cleanly_without_dataset(tmp_path):
    assert audit_script.main(["--dataset", str(tmp_path / "absent.parquet"), "--no-external"]) == 1
