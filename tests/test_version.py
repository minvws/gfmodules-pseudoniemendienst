from pathlib import Path

import pytest

from app.utils import version


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
    content: str,
    expected: dict[str, str] | None,
) -> None:
    path = tmp_path / "version.json"
    path.write_text(content)
    monkeypatch.setattr(version, "_VERSION_JSON_PATH", path)

    assert version.load_version_json() == expected


def test_load_version_json_missing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(version, "_VERSION_JSON_PATH", tmp_path / "missing.json")

    assert version.load_version_json() is None
