from app.services.hkdf import hkdf_derive


def test_hkdf_derive_matches_rfc_5869_test_case_3() -> None:
    # RFC 5869 A.3: SHA-256 with zero-length salt and info. A missing salt is
    # the same as a zero-length one, so this pins down the exact derivation the
    # local reversible and irreversible keys depend on.
    okm = hkdf_derive(b"\x0b" * 22, b"", length=42)

    assert okm.hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )


def test_hkdf_derive_separates_keys_by_info() -> None:
    master_key = b"\x01" * 32

    assert hkdf_derive(master_key, b"a") != hkdf_derive(master_key, b"b")
    assert len(hkdf_derive(master_key, b"a")) == 32
