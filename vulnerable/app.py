"""Intentionally unsafe training API. Keep isolated and bind only to localhost."""
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI(title="API Security Pipeline - Vulnerable Lab")
USERS = {1: {"id": 1, "email": "alice@example.com", "password": "password", "role": "user"}, 2: {"id": 2, "email": "admin@example.com", "password": "admin", "role": "admin"}}
ORDERS = {101: {"id": 101, "owner_id": 1, "item": "secret book", "card_number": "4111111111111111"}}

@app.post("/api/v1/auth/login")
def login(body: dict):
    user = next((value for value in USERS.values() if value["email"] == body.get("email") and value["password"] == body.get("password")), None)
    return {"token": str(user["id"]) if user else "invalid"}  # weak authentication and predictable token

@app.get("/api/v1/users")
def list_users():
    return list(USERS.values())  # excessive data exposure

@app.get("/api/v1/users/{user_id}")
def get_user(user_id: str):
    return USERS.get(int(user_id), {})  # BOLA/IDOR: no caller authorization

@app.post("/api/v1/users")
def create_user(body: dict):
    user_id = max(USERS) + 1
    USERS[user_id] = body
    USERS[user_id]["id"] = user_id
    return USERS[user_id]  # mass assignment and no validation

@app.get("/api/v1/orders")
def list_orders():
    return list(ORDERS.values())  # broken access control and sensitive data exposure

@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: str):
    return ORDERS.get(int(order_id), {})  # IDOR

@app.post("/api/v1/orders")
def create_order(body: dict):
    return body

@app.get("/api/v1/admin/audit")
def audit():
    return {"debug": "SELECT * FROM audit WHERE actor = '" + "admin'"}  # injection and no authorization

@app.exception_handler(Exception)
async def debug_errors(request: Request, exc: Exception):
    return PlainTextResponse(str(exc), status_code=500)  # insecure error handling
