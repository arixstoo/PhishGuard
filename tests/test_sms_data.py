import hashlib
import io
import zipfile

import httpx
import pandas as pd
import pytest

from phishguard.data import sms
from phishguard.data.sms import deduplicate, download_sms_collection, load_sms_collection


def write(tmp_path, content: str):
    path = tmp_path / "SMSSpamCollection"
    path.write_text(content, encoding="utf-8")
    return path


def test_load_maps_labels(tmp_path):
    path = write(tmp_path, "ham\tSalut, on se voit ce soir ?\nspam\tWIN a prize! Call now\n")
    df = load_sms_collection(path)
    assert list(df.columns) == ["label", "text"]
    assert df["label"].tolist() == [0, 1]


def test_load_keeps_unbalanced_quotes(tmp_path):
    path = write(tmp_path, 'ham\t"Ok see you\nspam\tFree "gift" inside\n')
    df = load_sms_collection(path)
    assert len(df) == 2
    assert df.loc[0, "text"] == '"Ok see you'


def test_load_rejects_unknown_label(tmp_path):
    path = write(tmp_path, "ham\thello\nphish\tclick here\n")
    with pytest.raises(ValueError, match="étiquettes inconnues"):
        load_sms_collection(path)


def test_deduplicate_removes_exact_and_whitespace_duplicates():
    df = pd.DataFrame({"label": [0, 0, 1, 1, 0], "text": ["hello", "hello ", "win", "win", "bye"]})
    clean, stats = deduplicate(df)
    assert sorted(clean["text"]) == ["bye", "hello", "win"]
    assert stats["duplicates_removed"] == 2
    assert stats["conflicting_texts"] == 0


def test_deduplicate_drops_conflicting_labels():
    df = pd.DataFrame({"label": [0, 1, 0], "text": ["ambigu", "ambigu", "ok"]})
    clean, stats = deduplicate(df)
    assert clean["text"].tolist() == ["ok"]
    assert stats["conflicting_texts"] == 1


def fake_uci(payload: bytes) -> httpx.Client:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(sms.ZIP_MEMBER, payload)
    archive = buf.getvalue()
    return httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, content=archive))
    )


def test_download_rejects_tampered_dataset(tmp_path):
    dest = tmp_path / "SMSSpamCollection"
    with pytest.raises(sms.DatasetIntegrityError):
        download_sms_collection(dest, client=fake_uci(b"spam\tthis is not the real corpus\n"))
    assert not dest.exists()


def test_download_accepts_expected_dataset(tmp_path, monkeypatch):
    payload = b"ham\thello\nspam\twin now\n"
    monkeypatch.setattr(sms, "EXPECTED_SHA256", hashlib.sha256(payload).hexdigest())
    dest = download_sms_collection(tmp_path / "SMSSpamCollection", client=fake_uci(payload))
    assert dest.read_bytes() == payload
