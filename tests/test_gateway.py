from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_benign_energy_question_is_allowed() -> None:
    response = client.post("/v1/chat", json={"prompt": "How does battery storage help the grid?"})
    body = response.json()
    assert response.status_code == 200
    assert body["blocked"] is False
    assert "Battery storage" in body["response"]


def test_extra_request_fields_are_rejected() -> None:
    response = client.post(
        "/v1/chat", json={"prompt": "Explain solar generation", "admin": True}
    )
    assert response.status_code == 422


def test_pii_is_redacted_before_model_processing() -> None:
    response = client.post(
        "/v1/chat",
        json={"prompt": "Explain security and contact me at engineer@example.com"},
    )
    body = response.json()
    assert body["blocked"] is False
    assert body["reason"] == "pii_redacted"
    assert "engineer@example.com" not in body["response"]

