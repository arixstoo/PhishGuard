"""Smoke test initial pour valider l'import du package."""


def test_import_phishguard():
    import phishguard

    assert phishguard is not None
