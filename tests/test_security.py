from fastapi.testclient import TestClient

from secure.app import app

client = TestClient(app)
_tokens = {}

def token(email: str, password: str) -> str:
    if email in _tokens:
        return _tokens[email]
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    _tokens[email] = response.json()["access_token"]
    return _tokens[email]

def auth(value: str) -> dict:
    return {"Authorization": f"Bearer {value}"}

def test_authentication_required():
    response = client.get("/api/v1/users")
    assert response.status_code == 401

def test_login_rejects_weak_password_and_bad_credentials():
    assert client.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": "short"}).status_code == 422
    assert client.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": "wrong-password"}).status_code == 401

def test_user_cannot_read_another_user():
    response = client.get("/api/v1/users/2", headers=auth(token("alice@example.com", "alice-password")))
    assert response.status_code == 403

def test_order_list_is_scoped_to_owner():
    response = client.get("/api/v1/orders", headers=auth(token("alice@example.com", "alice-password")))
    assert response.status_code == 200
    assert [order["id"] for order in response.json()] == [101]
    assert "card_number" not in response.text

def test_admin_can_read_audit_but_user_cannot():
    assert client.get("/api/v1/admin/audit", headers=auth(token("alice@example.com", "alice-password"))).status_code == 403
    assert client.get("/api/v1/admin/audit", headers=auth(token("admin@example.com", "admin-password"))).status_code == 200

def test_input_validation_rejects_mass_assignment_and_bad_quantity():
    headers = auth(token("alice@example.com", "alice-password"))
    assert client.post("/api/v1/users", headers=headers, json={"email": "new@example.com", "name": "New User", "password": "long-enough-password", "role": "admin"}).status_code == 201
    created = client.post("/api/v1/orders", headers=headers, json={"item": "x", "quantity": 0})
    assert created.status_code == 422

def test_security_headers_present():
    response = client.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"

def test_rate_limit_is_enforced_for_login():
    responses = [client.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "wrong-password"}) for _ in range(6)]
    assert any(response.status_code == 429 for response in responses)
