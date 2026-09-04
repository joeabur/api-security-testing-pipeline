"""Hardened API reference implementation for the security lab."""
from datetime import datetime, timedelta, timezone
import logging
import os
from threading import Lock
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pwdlib import PasswordHash
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

logging.basicConfig(level=logging.INFO, format="%(message)s")
audit_logger = logging.getLogger("security.audit")
password_hash = PasswordHash.recommended()
JWT_SECRET = os.getenv("JWT_SECRET", "local-only-change-me-please-32-bytes")
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must contain at least 32 characters")

limiter = Limiter(key_func=get_remote_address, default_limits=[os.getenv("RATE_LIMIT", "60/minute")])
app = FastAPI(title="API Security Pipeline - Hardened API", docs_url="/docs", redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, lambda request, exc: Response(status_code=429, content="rate limit exceeded"))
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","), allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])

_USERS = {
    1: {"id": 1, "email": "alice@example.com", "name": "Alice", "role": "user", "password": password_hash.hash("alice-password")},
    2: {"id": 2, "email": "bob@example.com", "name": "Bob", "role": "user", "password": password_hash.hash("bob-password")},
    3: {"id": 3, "email": "admin@example.com", "name": "Admin", "role": "admin", "password": password_hash.hash("admin-password")},
}
_ORDERS = {101: {"id": 101, "owner_id": 1, "item": "security book", "quantity": 1}, 102: {"id": 102, "owner_id": 2, "item": "hardware key", "quantity": 2}}
_AUDIT = []
_user_lock = Lock()

class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)

class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z][A-Za-z .'-]*$")
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.lower().strip()
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            raise ValueError("invalid email")
        return value

class OrderCreate(BaseModel):
    item: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9 .'-]*$")
    quantity: int = Field(ge=1, le=20)

class PublicUser(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    name: str
    role: str

bearer = HTTPBearer(auto_error=False)

def audit(action: str, request: Request, user_id: int | None = None, outcome: str = "success") -> None:
    event = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": action, "user_id": user_id, "outcome": outcome, "source_ip": get_remote_address(request)}
    _AUDIT.append(event)
    audit_logger.info("%s", event)

def current_user(request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]) -> dict:
    if not credentials or credentials.scheme.lower() != "bearer":
        audit("authentication", request, outcome="missing_token")
        raise HTTPException(status_code=401, detail="authentication required", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"], options={"require": ["sub", "exp", "iat"]})
        user = _USERS.get(int(claims["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        user = None
    if not user:
        audit("authentication", request, outcome="invalid_token")
        raise HTTPException(status_code=401, detail="invalid credentials", headers={"WWW-Authenticate": "Bearer"})
    return user

def admin_user(user: Annotated[dict, Depends(current_user)]) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="administrator role required")
    return user

def public_user(user: dict) -> PublicUser:
    return PublicUser.model_validate({key: user[key] for key in ("id", "email", "name", "role")})

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'", "Cache-Control": "no-store"})
    return response

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/v1/auth/login")
@limiter.limit("5/minute")
def login(payload: LoginRequest, request: Request, response: Response):
    user = next((candidate for candidate in _USERS.values() if candidate["email"] == payload.email.lower().strip()), None)
    if not user or not password_hash.verify(payload.password, user["password"]):
        audit("login", request, outcome="failure")
        raise HTTPException(status_code=401, detail="invalid credentials")
    now = datetime.now(timezone.utc)
    token = jwt.encode({"sub": str(user["id"]), "iat": now, "exp": now + timedelta(minutes=15)}, JWT_SECRET, algorithm="HS256")
    response.set_cookie("access_token", token, httponly=True, secure=False, samesite="lax", max_age=900)
    audit("login", request, user["id"])
    return {"access_token": token, "token_type": "bearer", "expires_in": 900}

@app.get("/api/v1/users", response_model=list[PublicUser])
def list_users(user: Annotated[dict, Depends(current_user)]):
    return [public_user(candidate) for candidate in _USERS.values()]

@app.get("/api/v1/users/{user_id}", response_model=PublicUser)
def get_user(user_id: int, user: Annotated[dict, Depends(current_user)]):
    if user_id != user["id"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="not authorized for this user")
    target = _USERS.get(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="user not found")
    return public_user(target)

@app.post("/api/v1/users", response_model=PublicUser, status_code=201)
@limiter.limit("10/hour")
def create_user(payload: UserCreate, request: Request):
    with _user_lock:
        if any(user["email"] == payload.email for user in _USERS.values()):
            raise HTTPException(status_code=409, detail="email already registered")
        user_id = max(_USERS) + 1
        _USERS[user_id] = {"id": user_id, "email": payload.email, "name": payload.name, "role": "user", "password": password_hash.hash(payload.password)}
    audit("user_created", request, user_id)
    return public_user(_USERS[user_id])

@app.get("/api/v1/orders")
def list_orders(user: Annotated[dict, Depends(current_user)]):
    return [{key: order[key] for key in ("id", "item", "quantity")} for order in _ORDERS.values() if order["owner_id"] == user["id"] or user["role"] == "admin"]

@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: int, user: Annotated[dict, Depends(current_user)]):
    order = _ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="order not found")
    if order["owner_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="not authorized for this order")
    return {key: order[key] for key in ("id", "item", "quantity")}

@app.post("/api/v1/orders", status_code=201)
def create_order(payload: OrderCreate, request: Request, user: Annotated[dict, Depends(current_user)]):
    order_id = max(_ORDERS) + 1
    _ORDERS[order_id] = {"id": order_id, "owner_id": user["id"], **payload.model_dump()}
    audit("order_created", request, user["id"])
    return {key: _ORDERS[order_id][key] for key in ("id", "item", "quantity")}

@app.get("/api/v1/admin/audit")
def audit_events(user: Annotated[dict, Depends(admin_user)]):
    return {"events": _AUDIT[-100:]}
