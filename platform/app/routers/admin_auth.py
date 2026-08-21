import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..audit import audit
from ..auth import (
    check_lockout, current_user, decode_token, hash_password, issue_token,
    register_failed_login, totp_uri, verify_password, verify_totp,
)
from ..config import OTP_MAX_ATTEMPTS, OTP_MINUTES, TWO_FA_MODE
from .. import mailer
from ..db import get_db

router = APIRouter(prefix="/admin/api/auth", tags=["admin-auth"])


class LoginIn(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=255)


class TotpIn(BaseModel):
    pre_token: str
    code: str = Field(max_length=8)


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.query(models.AdminUser).filter(models.AdminUser.email == body.email.lower().strip()).first()
    if not user or not user.is_active:
        raise HTTPException(401, "Invalid credentials")
    check_lockout(user)
    if not verify_password(body.password, user.password_hash):
        register_failed_login(db, user)
        audit(db, request, None, "login_failed", "admin_user", user.id)
        raise HTTPException(401, "Invalid credentials")

    user.failed_attempts = 0
    db.commit()

    if TWO_FA_MODE == "off":
        audit(db, request, user, "login", "admin_user", user.id)
        return {"token": issue_token(user), "role": user.role, "email": user.email, "name": user.name}

    pre = issue_token(user, scope="pre-2fa")

    if TWO_FA_MODE == "email":
        import hashlib
        import hmac as hmac_mod
        import secrets as sec
        from datetime import datetime, timedelta, timezone
        from ..config import SECRET_KEY
        # Throttle re-issuance: at most one fresh code per 45 seconds while one is live.
        exp = user.otp_expires_at
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp and exp - timedelta(minutes=OTP_MINUTES) + timedelta(seconds=45) > datetime.now(timezone.utc) \
                and (user.otp_attempts or 0) == 0 and user.otp_hash:
            return {"step": "verify_otp", "pre_token": pre}
        code = f"{sec.randbelow(1000000):06d}"
        user.otp_hash = hmac_mod.new(SECRET_KEY.encode(), code.encode(), hashlib.sha256).hexdigest()
        user.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_MINUTES)
        user.otp_attempts = 0
        db.commit()
        try:
            mailer.send_email(
                user.email, "GEC Console sign in code",
                f"Your sign in code is {code}\n\nIt is valid for {OTP_MINUTES} minutes. "
                "If you did not try to sign in, you can ignore this email.")
        except Exception:
            raise HTTPException(502, "Could not send the sign in code. Try again shortly.")
        audit(db, request, user, "otp_sent", "admin_user", user.id)
        return {"step": "verify_otp", "pre_token": pre}

    if not user.totp_secret:
        # First login: enrol two factor before a session is granted.
        secret = pyotp.random_base32()
        request.session_enroll = secret  # not persisted yet; sent to client
        return {
            "step": "enrol_2fa",
            "pre_token": pre,
            "totp_secret": secret,
            "otpauth_uri": totp_uri(user, secret),
        }
    return {"step": "verify_2fa", "pre_token": pre}


class EnrolIn(BaseModel):
    pre_token: str
    totp_secret: str = Field(max_length=64)
    code: str = Field(max_length=8)


@router.post("/enrol")
def enrol(body: EnrolIn, request: Request, db: Session = Depends(get_db)):
    if TWO_FA_MODE != "totp":
        raise HTTPException(403, "Authenticator enrolment is not enabled")
    payload = decode_token(body.pre_token, scope="pre-2fa")
    user = db.get(models.AdminUser, int(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(401, "Account unavailable")
    if user.totp_secret:
        raise HTTPException(400, "Two factor already enrolled")
    if not verify_totp(body.totp_secret, body.code):
        raise HTTPException(401, "Incorrect code")
    user.totp_secret = body.totp_secret
    db.commit()
    audit(db, request, user, "2fa_enrolled", "admin_user", user.id)
    return {"token": issue_token(user), "role": user.role, "email": user.email, "name": user.name}


@router.post("/verify")
def verify(body: TotpIn, request: Request, db: Session = Depends(get_db)):
    if TWO_FA_MODE != "totp":
        raise HTTPException(403, "Authenticator verification is not enabled")
    payload = decode_token(body.pre_token, scope="pre-2fa")
    user = db.get(models.AdminUser, int(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(401, "Account unavailable")
    check_lockout(user)
    if not user.totp_secret or not verify_totp(user.totp_secret, body.code):
        register_failed_login(db, user)
        audit(db, request, None, "2fa_failed", "admin_user", user.id)
        raise HTTPException(401, "Incorrect code")
    user.failed_attempts = 0
    db.commit()
    audit(db, request, user, "login", "admin_user", user.id)
    return {"token": issue_token(user), "role": user.role, "email": user.email, "name": user.name}


@router.post("/verify-otp")
def verify_otp(body: TotpIn, request: Request, db: Session = Depends(get_db)):
    import hashlib
    import hmac as hmac_mod
    from datetime import datetime, timezone
    from ..config import SECRET_KEY

    payload = decode_token(body.pre_token, scope="pre-2fa")
    user = db.get(models.AdminUser, int(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(401, "Account unavailable")
    check_lockout(user)
    exp = user.otp_expires_at
    if exp is not None and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if not user.otp_hash or not exp or exp < datetime.now(timezone.utc):
        raise HTTPException(401, "Code expired. Sign in again to get a new one.")
    if user.otp_attempts >= OTP_MAX_ATTEMPTS:
        user.otp_hash = None
        db.commit()
        raise HTTPException(429, "Too many attempts. Sign in again to get a new code.")
    given = hmac_mod.new(SECRET_KEY.encode(), body.code.strip().encode(), hashlib.sha256).hexdigest()
    if not hmac_mod.compare_digest(given, user.otp_hash):
        user.otp_attempts += 1
        db.commit()
        audit(db, request, None, "otp_failed", "admin_user", user.id)
        raise HTTPException(401, "Incorrect code")
    user.otp_hash = None
    user.otp_attempts = 0
    db.commit()
    audit(db, request, user, "login", "admin_user", user.id)
    return {"token": issue_token(user), "role": user.role, "email": user.email, "name": user.name}


@router.post("/refresh")
def refresh(user: models.AdminUser = Depends(current_user)):
    """Sliding session: the console calls this on activity to extend the 30 minute window."""
    return {"token": issue_token(user)}


@router.get("/me")
def me(user: models.AdminUser = Depends(current_user)):
    return {"email": user.email, "role": user.role, "name": user.name}
