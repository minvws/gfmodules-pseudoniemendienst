from pathlib import Path

import pytest

from app.utils import version


@pytest.fixture
def reset_version_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(version, "_version_cache", False)


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ('{"version": "1.2", "git_ref": "abc"}', {"version": "1.2", "git_ref": "abc"}),
        ("not json", None),
        ('["a list"]', None),
    ],
)
def test_load_version_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reset_version_cache: None,
    content: str,
    expected: dict[str, str] | None,
) -> None:
    path = tmp_path / "version.json"
    path.write_text(content)
    monkeypatch.setattr(version, "_VERSION_JSON_PATH", path)

    assert version.load_version_json() == expected


def test_load_version_json_missing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reset_version_cache: None
) -> None:
    monkeypatch.setattr(version, "_VERSION_JSON_PATH", tmp_path / "missing.json")

    assert version.load_version_json() is None


def test_load_version_json_caches_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reset_version_cache: None
) -> None:
    path = tmp_path / "version.json"
    content = '{"version": "1.2", "git_ref": "abc"}'
    path.write_text(content)
    monkeypatch.setattr(version, "_VERSION_JSON_PATH", path)

    result1 = version.load_version_json()
    path.write_text('{"version": "2.0"}')

    result2 = version.load_version_json()

    assert result1 == result2 == {"version": "1.2", "git_ref": "abc"}


def test_load_version_json_caches_failed_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reset_version_cache: None
) -> None:
    missing_path = tmp_path / "missing.json"
    monkeypatch.setattr(version, "_VERSION_JSON_PATH", missing_path)

    result1 = version.load_version_json()
    missing_path.write_text('{"version": "1.2"}')

    result2 = version.load_version_json()

    assert result1 is None
    assert result2 is None
