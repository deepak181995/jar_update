import time as _time
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from fastapi import Depends, HTTPException, Request
from passlib.hash import bcrypt
from sqlalchemy.orm import Session

from . import models
from .config import SECRET_KEY, SESSION_MINUTES, LOCKOUT_THRESHOLD, LOCKOUT_MINUTES
from .db import get_db

ROLE_ADMIN = "administrator"
ROLE_OPS = "operations"
ROLE_READONLY = "readonly"


def hash_password(pw: str) -> str:
    return bcrypt.hash(pw)


def verify_password(pw: str, h: str) -> bool:
    try:
        return bcrypt.verify(pw, h)
    except Exception:
        return False


def issue_token(user: models.AdminUser, scope: str = "session") -> str:
    now = int(_time.time())
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "scope": scope,
        "iat": now,
        "exp": now + SESSION_MINUTES * 60,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token: str, scope: str = "session") -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid session")
    if payload.get("scope") != scope:
        raise HTTPException(401, "Invalid session scope")
    return payload


def current_user(request: Request, db: Session = Depends(get_db)) -> models.AdminUser:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated")
    payload = decode_token(auth[7:])
    user = db.get(models.AdminUser, int(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(401, "Account unavailable")
    request.state.user = user
    return user


def require_role(*roles: str):
    def dep(user: models.AdminUser = Depends(current_user)) -> models.AdminUser:
        if user.role not in roles:
            raise HTTPException(403, "Insufficient permissions")
        return user
    return dep


def register_failed_login(db: Session, user: models.AdminUser):
    user.failed_attempts = (user.failed_attempts or 0) + 1
    if user.failed_attempts >= LOCKOUT_THRESHOLD:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
        user.failed_attempts = 0
    db.commit()


def check_lockout(user: models.AdminUser):
    if user.locked_until:
        lu = user.locked_until
        if lu.tzinfo is None:
            lu = lu.replace(tzinfo=timezone.utc)
        if lu > datetime.now(timezone.utc):
            raise HTTPException(423, "Account temporarily locked. Try again later.")


def totp_uri(user: models.AdminUser, secret: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name="GEC Admin"
    )


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)
