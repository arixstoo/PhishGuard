"""Tests du split temporel et groupé (étape 1.4)."""

import importlib.util
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from phishguard.data import split as S
from phishguard.data.urls import COLUMNS

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "split_dataset.py"
spec = importlib.util.spec_from_file_location("split_dataset", SCRIPT)
split_script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(split_script)

START = pd.Timestamp("2026-01-01", tz="UTC")


def frame(records: list[tuple[str, int, str, int]]) -> pd.DataFrame:
    """Jeu au schéma commun à partir de ``(domaine, label, source, jour)``."""
    df = pd.DataFrame(
        [
            {
                "url": f"https://{domain}/p{i}",
                "label": label,
                "source": source,
                "first_seen": START + pd.Timedelta(days=day),
                "host": domain,
                "registered_domain": domain,
            }
            for i, (domain, label, source, day) in enumerate(records)
        ],
        columns=COLUMNS,
    )
    return df.astype({"label": "int8"})


def two_epochs(n: int = 400) -> pd.DataFrame:
    """Reproduit le biais du jeu réel : phishing ancien, légitime récent et daté d'un seul jour."""
    records = [(f"phish{i}.com", 1, "phishtank", i) for i in range(n)]
    records += [(f"legit{i}.com", 0, "tranco", 10_000) for i in range(n)]
    return frame(records)


records_strategy = st.lists(
    st.tuples(
        st.integers(0, 25).map(lambda i: f"d{i}.com"),
        st.integers(0, 1),
        st.sampled_from(["phishtank", "openphish", "tranco", "commoncrawl"]),
        st.integers(0, 30),
    ),
    min_size=1,
    max_size=120,
)


# --------------------------------------------------------------------------- #
# Garanties
# --------------------------------------------------------------------------- #


@settings(max_examples=100, deadline=None)
@given(records_strategy)
def test_no_registered_domain_is_in_two_blocks(records):
    df = frame(records)
    split = S.temporal_group_split(df)

    assert split.index.equals(df.index)
    assert split.notna().all()
    assert (split.groupby(df["registered_domain"], observed=True).nunique() == 1).all()
    S.assert_no_domain_leakage(df, split)


@settings(max_examples=50, deadline=None)
@given(records_strategy, st.randoms(use_true_random=False))
def test_split_does_not_depend_on_row_order(records, rnd):
    df = frame(records)
    shuffled = df.sample(frac=1.0, random_state=rnd.randint(0, 2**31))
    expected = S.temporal_group_split(df)
    assert S.temporal_group_split(shuffled).reindex(df.index).equals(expected)


def test_blocks_follow_time_within_a_stratum():
    df = frame([(f"d{i}.com", 1, "phishtank", i) for i in range(100)])
    blocks = S.split_frames(df, S.temporal_group_split(df))

    assert [len(b) for b in blocks.values()] == [70, 15, 15]
    assert blocks["train"]["first_seen"].max() < blocks["validation"]["first_seen"].min()
    assert blocks["validation"]["first_seen"].max() < blocks["test"]["first_seen"].min()


def test_a_domain_shared_with_a_smaller_stratum_follows_that_stratum():
    clean = frame([(f"d{i}.com", 1, "phishtank", i) for i in range(100)])
    assert S.constrained_rows(clean, ("label", "source")) == {"1/phishtank": 0}

    # x.com est le domaine le plus récent d'OpenPhish (petite strate, traitée d'abord) : il
    # va au test. Sa page PhishTank, la plus ancienne de PhishTank, le suit : c'est la seule
    # ligne PhishTank hors de l'ordre temporel.
    records = [(f"o{i}.com", 1, "openphish", i) for i in range(10)] + [
        ("x.com", 1, "openphish", 99)
    ]
    records += [(f"p{i}.com", 1, "phishtank", 1 + i) for i in range(100)] + [
        ("x.com", 1, "phishtank", 0)
    ]
    df = frame(records)
    split = S.temporal_group_split(df)

    assert split[df["registered_domain"] == "x.com"].eq("test").all()
    assert S.constrained_rows(df, ("label", "source")) == {"1/openphish": 0, "1/phishtank": 1}
    phishtank = S.split_frames(df[df["source"] == "phishtank"], split)
    old = phishtank["test"]["first_seen"] < phishtank["train"]["first_seen"].max()
    assert old.sum() == 1


def test_each_stratum_is_split_on_its_own_clock():
    df = two_epochs()
    split = S.temporal_group_split(df)

    for _, stratum in df.groupby("label"):
        counts = split.loc[stratum.index].value_counts()
        assert counts.to_dict() == {"train": 280, "validation": 60, "test": 60}

    # Un tri global aurait mis tout le phishing (plus ancien) à l'entraînement ; ici chaque
    # bloc garde la même part de phishing.
    phishing_rate = df.groupby(split, observed=True)["label"].mean()
    assert phishing_rate.between(0.45, 0.55).all()


def test_ties_are_broken_by_seed_not_by_position():
    df = frame([(f"d{i}.com", 0, "tranco", 0) for i in range(200)])
    a = S.temporal_group_split(df, S.SplitConfig(seed=1))
    b = S.temporal_group_split(df, S.SplitConfig(seed=2))

    assert not a.equals(b)
    # Les lignes 0 à 139 n'ont pas d'avantage : le départage n'est pas l'ordre du fichier.
    assert (a.iloc[:140] == "train").mean() < 0.9


def test_domain_shared_between_classes_keeps_both_classes_together():
    records = [(f"p{i}.com", 1, "phishtank", i) for i in range(50)]
    records += [(f"l{i}.com", 0, "tranco", 100) for i in range(200)]
    records += [("host.com", 1, "phishtank", 49), ("host.com", 0, "tranco", 100)]
    df = frame(records)
    split = S.temporal_group_split(df)

    assert split[df["registered_domain"] == "host.com"].nunique() == 1


def test_a_domain_is_never_cut_even_when_it_overflows_a_quota():
    records = [("big.com", 1, "phishtank", 0)] * 90 + [
        (f"d{i}.com", 1, "phishtank", 1 + i) for i in range(10)
    ]
    split = S.temporal_group_split(frame(records))

    assert (split.iloc[:90] == "train").all()
    S.assert_no_domain_leakage(frame(records), split)


def test_empty_dataset_gives_empty_split():
    split = S.temporal_group_split(frame([]))
    assert split.empty and split.dtype == S.SPLIT_DTYPE


# --------------------------------------------------------------------------- #
# Erreurs
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"fractions": (0.5, 0.5)}, "3 fractions"),
        ({"fractions": (0.8, 0.2, 0.0)}, "strictement positive"),
        ({"fractions": (0.7, 0.2, 0.2)}, "sommer à 1"),
        ({"strata": ()}, "au moins une colonne"),
    ],
)
def test_config_rejects_invalid_parameters(kwargs, message):
    with pytest.raises(ValueError, match=message):
        S.SplitConfig(**kwargs)


def test_split_rejects_missing_columns_and_values():
    df = frame([("a.com", 1, "phishtank", 0)])
    with pytest.raises(ValueError, match="colonnes absentes : first_seen"):
        S.temporal_group_split(df.drop(columns="first_seen"))
    with pytest.raises(ValueError, match="valeurs manquantes dans : registered_domain"):
        S.temporal_group_split(df.assign(registered_domain=None))


def test_leakage_check_catches_a_shared_domain():
    df = frame([("a.com", 1, "phishtank", 0), ("a.com", 1, "phishtank", 1)])
    split = pd.Series(pd.Categorical(["train", "test"], dtype=S.SPLIT_DTYPE), index=df.index)

    with pytest.raises(S.DomainLeakageError, match="1 domaines .*a.com"):
        S.assert_no_domain_leakage(df, split)
    with pytest.raises(ValueError, match="même index"):
        S.assert_no_domain_leakage(df, split.reset_index(drop=True).set_axis([5, 6]))


# --------------------------------------------------------------------------- #
# Rapport et script
# --------------------------------------------------------------------------- #


def test_report_is_aggregated_and_contains_no_url_or_domain():
    df = two_epochs(100)
    cfg = S.SplitConfig()
    report = S.split_report(df, S.temporal_group_split(df, cfg), cfg)

    assert report["rows"] == 200 and report["domains_in_several_blocks"] == 0
    assert sum(b["rows"] for b in report["blocks"].values()) == 200
    assert report["strata"]["1/phishtank"]["target_rows"] == {
        "train": 70,
        "validation": 15,
        "test": 15,
    }
    assert report["blocks"]["test"]["legitimate_with_path"] == 15
    text = json.dumps(report)
    assert ".com" not in text and "https://" not in text


def test_script_writes_split_dataset_and_report(tmp_path):
    dataset = tmp_path / "urls.parquet"
    two_epochs(50).to_parquet(dataset, index=False)
    output, report = tmp_path / "out.parquet", tmp_path / "split.json"

    code = split_script.main(
        ["--dataset", str(dataset), "--output", str(output), "--report", str(report)]
    )

    assert code == 0
    written = pd.read_parquet(output)
    assert list(written.columns) == [*COLUMNS, "split"]
    assert set(written["split"]) == set(S.SPLITS)
    content = json.loads(report.read_text("utf-8"))
    assert content["metadata"]["dataset_sha256"] and content["rows"] == 100


def test_script_fails_cleanly_without_dataset(tmp_path):
    assert split_script.main(["--dataset", str(tmp_path / "absent.parquet")]) == 1


def test_script_rejects_fractions_leaving_no_training_data():
    with pytest.raises(SystemExit):
        split_script.parse_args(["--validation", "0.5", "--test", "0.5"])


def test_quotas_always_sum_to_the_number_of_rows():
    for rows in range(50):
        assert S._quotas(rows, (0.7, 0.15, 0.15)).sum() == rows
    assert np.array_equal(S._quotas(100, (0.7, 0.15, 0.15)), [70, 15, 15])


# --------------------------------------------------------------------------- #
# Lecture des blocs
# --------------------------------------------------------------------------- #


def _split_parquet(tmp_path: Path) -> Path:
    df = frame(
        [(f"d{i}.com", i % 2, "tranco" if i % 2 == 0 else "phishtank", i) for i in range(60)]
    )
    path = tmp_path / "urls_split.parquet"
    df.assign(split=S.temporal_group_split(df)).to_parquet(path, index=False)
    return path


def test_read_split_blocks_loads_only_the_requested_blocks(tmp_path):
    path = _split_parquet(tmp_path)
    blocks = S.read_split_blocks(path, ("train", "validation"), ["url", "source"])
    assert list(blocks) == ["train", "validation"]
    for name, block in blocks.items():
        assert set(block["split"].astype(str)) == {name}
        assert {"url", "source", "label", "split"} == set(block.columns)
        assert block.index.equals(pd.RangeIndex(len(block)))
    full = pd.read_parquet(path)
    assert sum(len(b) for b in blocks.values()) == int((full["split"] != "test").sum())


def test_read_split_blocks_rejects_unknown_or_single_class_blocks(tmp_path):
    path = _split_parquet(tmp_path)
    with pytest.raises(ValueError, match="inconnus"):
        S.read_split_blocks(path, ("holdout",))
    one_class = pd.read_parquet(path)
    one_class.loc[one_class["split"] == "test", "label"] = 0
    one_class.to_parquet(path, index=False)
    with pytest.raises(ValueError, match="deux classes"):
        S.read_split_blocks(path, ("test",))
