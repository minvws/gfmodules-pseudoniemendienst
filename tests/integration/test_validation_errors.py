import pytest
from fastapi import FastAPI
from pydantic import BaseModel
from starlette.testclient import TestClient

from app.routers.errors import install_validation_error_handler


class _Body(BaseModel):
    value: str


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    install_validation_error_handler(app)

    @app.post("/echo")
    def echo(body: _Body) -> None:
        pass

    return TestClient(app)


def test_validation_error_does_not_echo_the_input(client: TestClient) -> None:
    response = client.post("/echo", json={"value": 950000012})

    assert response.status_code == 422
    assert "950000012" not in response.text


def test_validation_error_keeps_where_and_what_went_wrong(client: TestClient) -> None:
    response = client.post("/echo", json={"value": 950000012})

    assert response.json() == {
        "detail": [
            {
                "type": "string_type",
                "loc": ["body", "value"],
                "msg": "Input should be a valid string",
            }
        ]
    }
