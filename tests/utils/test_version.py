import json
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import app.utils.version as version_module


@patch("app.utils.version.Path")
@patch(
    "app.utils.version.open",
    mock_open(read_data=json.dumps({"version": "1.0.0", "git_ref": "abc123"})),
)
def test_load_version_json_should_return_dict_when_valid(mock_path: MagicMock) -> None:
    mock_path.return_value.resolve.return_value.parent.parent.parent = Path("/mock")
    version_module._version_cache = False

    result = version_module.load_version_json()

    assert result == {"version": "1.0.0", "git_ref": "abc123"}


@patch("app.utils.version.Path")
@patch("app.utils.version.open", side_effect=OSError("File not found"))
def test_load_version_json_should_return_none_when_file_not_found(
    mock_path: MagicMock, mock_open_file: MagicMock
) -> None:
    mock_path.return_value.resolve.return_value.parent.parent.parent = Path("/mock")
    version_module._version_cache = False

    result = version_module.load_version_json()

    assert result is None


@patch("app.utils.version.Path")
@patch("app.utils.version.open", mock_open(read_data="not json"))
def test_load_version_json_should_return_none_when_invalid_json(
    mock_path: MagicMock,
) -> None:
    mock_path.return_value.resolve.return_value.parent.parent.parent = Path("/mock")
    version_module._version_cache = False

    result = version_module.load_version_json()

    assert result is None


@patch("app.utils.version.Path")
@patch("app.utils.version.open", mock_open(read_data=json.dumps(["not", "a", "dict"])))
def test_load_version_json_should_return_none_when_not_dict(
    mock_path: MagicMock,
) -> None:
    mock_path.return_value.resolve.return_value.parent.parent.parent = Path("/mock")
    version_module._version_cache = False

    result = version_module.load_version_json()

    assert result is None


@patch("app.utils.version.Path")
@patch("app.utils.version.open", mock_open(read_data=json.dumps({"version": "1.0.0"})))
def test_load_version_json_should_cache_result(mock_path: MagicMock) -> None:
    mock_path.return_value.resolve.return_value.parent.parent.parent = Path("/mock")
    version_module._version_cache = False

    # First call
    result1 = version_module.load_version_json()
    # Second call (should use cache, not read file again)
    result2 = version_module.load_version_json()

    assert result1 == result2 == {"version": "1.0.0"}
    # Verify file was only opened once
    assert version_module.open.call_count == 1
