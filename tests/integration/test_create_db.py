import runpy
from unittest.mock import patch

import pytest


@pytest.mark.usefixtures("unconfigured_container")
def test_create_db_configures_the_container_and_generates_the_tables() -> None:
    with patch("app.db.db.Database.generate_tables") as generate_tables:
        runpy.run_module("app.create_db", run_name="__main__")

    generate_tables.assert_called_once_with()
