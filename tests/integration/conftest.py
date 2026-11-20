from collections.abc import Iterator

import inject
import pytest

import app.container


@pytest.fixture
def unconfigured_container() -> Iterator[None]:
    inject.clear()
    yield
    inject.clear()
    app.container.configure()
