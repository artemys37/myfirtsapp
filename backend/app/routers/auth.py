from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel
import hashlib, hmac, json, base64, secrets
from ..db import get_db
from ..config import settings

router = APIRouter()
security = HTTPBearer()

SECRET_KEY = getattr(settings, "SECRET_KEY", "change-this-secret-key-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 60)

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def create_token(username: str, role: str) -> str:
    header = _b64url(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    payload = {
        "sub": username, "role": role,
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }
    body = _b64url(json.dumps(payload, separators=(",",":")).encode())
    sig = _b64url(hmac.new(SECRET_KEY.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"

def decode_token(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token")
    body = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    if body.get("exp", 0) < datetime.now(timezone.utc).timestamp():
        raise ValueError("Token expired")
    return body

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return f"{salt}:{h}"

def verify_password(plain: str, hashed: str) -> bool:
    salt, h = hashed.split(":", 1)
    return hashlib.sha256(f"{salt}:{plain}".encode()).hexdigest() == h

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "auditor"

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = decode_token(credentials.credentials)
        return {"username": payload["sub"], "role": payload.get("role", "auditor")}
    except Exception:
        raise HTTPException(401, "Invalid or expired token")

def require_role(required_role: str):
    async def role_checker(user: dict = Depends(get_current_user)):
        roles_order = {"admin": 3, "auditor": 2, "viewer": 1}
        if roles_order.get(user["role"], 0) < roles_order.get(required_role, 0):
            raise HTTPException(403, "Insufficient permissions")
        return user
    return role_checker

@router.post("/register", summary="Register a new user")
async def register(user: UserCreate):
    db = get_db()
    existing = await db.users.find_one({"username": user.username})
    if existing:
        raise HTTPException(400, "Username already exists")
    doc = {
        "username": user.username,
        "password": hash_password(user.password),
        "role": user.role if user.role in ("admin", "auditor", "viewer") else "auditor",
        "created_at": datetime.now(timezone.utc),
    }
    await db.users.insert_one(doc)
    return {"message": "User created", "username": user.username, "role": doc["role"]}

@router.post("/login", summary="Login and get JWT token")
async def login(user: UserLogin):
    db = get_db()
    doc = await db.users.find_one({"username": user.username})
    if not doc or not verify_password(user.password, doc.get("password", "")):
        raise HTTPException(401, "Invalid credentials")
    token = create_token(doc["username"], doc["role"])
    return TokenResponse(access_token=token, username=doc["username"], role=doc["role"])

@router.get("/me", summary="Get current user info")
async def me(user: dict = Depends(get_current_user)):
    return user
