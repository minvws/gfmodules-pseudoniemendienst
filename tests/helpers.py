def assert_key_version_payload(
    body: dict[str, object],
    expected_version: int,
    expected_until_dt: object | None = None,
) -> None:
    assert set(body.keys()) == {"id", "version", "from_dt", "until_dt", "removed"}
    assert isinstance(body["id"], str)
    assert body["version"] == expected_version
    assert body["removed"] is False
    assert body["from_dt"] is not None

    if expected_until_dt is not None:
        assert body["until_dt"] == expected_until_dt
    else:
        assert body["until_dt"] is None
