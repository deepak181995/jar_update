"""Forwarders, partners, users, reports and audit viewer."""
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from passlib.hash import bcrypt
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from ..audit import audit
from ..auth import ROLE_ADMIN, ROLE_OPS, ROLE_READONLY, hash_password, require_role
from ..db import get_db

router = APIRouter(prefix="/admin/api", tags=["admin-misc"])


# ---------- Forwarders ----------

class ForwarderIn(BaseModel):
    name: str = Field(max_length=255)
    contact_name: str = Field(default="", max_length=255)
    contact_email: str = Field(default="", max_length=255)
    contact_phone: str = Field(default="", max_length=64)
    coverage_regions: str = Field(default="", max_length=512)
    service_rating: float = Field(default=0, ge=0, le=5)
    payment_terms: str = Field(default="", max_length=255)
    is_active: bool = True


def fwd_out(f: models.Forwarder) -> dict:
    return {c.name: getattr(f, c.name) for c in models.Forwarder.__table__.columns}


@router.get("/forwarders")
def list_forwarders(user=Depends(require_role(ROLE_ADMIN, ROLE_OPS, ROLE_READONLY)),
                    db: Session = Depends(get_db)):
    return {"items": [fwd_out(f) for f in db.query(models.Forwarder).order_by(models.Forwarder.name).all()]}


@router.post("/forwarders")
def create_forwarder(body: ForwarderIn, request: Request,
                     user=Depends(require_role(ROLE_ADMIN, ROLE_OPS)),
                     db: Session = Depends(get_db)):
    f = models.Forwarder(**body.model_dump())
    db.add(f)
    db.commit()
    audit(db, request, user, "forwarder_created", "forwarder", f.id, new=fwd_out(f))
    return fwd_out(f)


@router.put("/forwarders/{fid}")
def update_forwarder(fid: int, body: ForwarderIn, request: Request,
                     user=Depends(require_role(ROLE_ADMIN, ROLE_OPS)),
                     db: Session = Depends(get_db)):
    f = db.get(models.Forwarder, fid)
    if not f:
        raise HTTPException(404, "Forwarder not found")
    old = fwd_out(f)
    for k, v in body.model_dump().items():
        setattr(f, k, v)
    db.commit()
    audit(db, request, user, "forwarder_updated", "forwarder", f.id, old=old, new=fwd_out(f))
    return fwd_out(f)


# ---------- Partners (administrator only: holds API keys) ----------

class PartnerIn(BaseModel):
    name: str = Field(max_length=255)
    callback_url: str = Field(default="", max_length=512)
    rate_limit: int = Field(default=60, ge=1, le=6000)
    is_active: bool = True

    def validate_callback(self):
        if self.callback_url:
            u = urlparse(self.callback_url)
            if u.scheme != "https" or not u.netloc:
                raise HTTPException(422, "callback_url must be a valid HTTPS URL")


def partner_out(p: models.Partner) -> dict:
    return {
        "id": p.id, "name": p.name, "callback_url": p.callback_url,
        "rate_limit": p.rate_limit, "is_active": p.is_active,
        "has_api_key": bool(p.api_key_hash),
        "has_secondary_key": bool(p.api_key_hash_secondary),
        "created_at": p.created_at,
    }


@router.get("/partners")
def list_partners(user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    return {"items": [partner_out(p) for p in db.query(models.Partner).order_by(models.Partner.name).all()]}


@router.post("/partners")
def create_partner(body: PartnerIn, request: Request,
                   user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    body.validate_callback()
    p = models.Partner(**body.model_dump())
    db.add(p)
    db.commit()
    audit(db, request, user, "partner_created", "partner", p.id, new=partner_out(p))
    return partner_out(p)


@router.put("/partners/{pid}")
def update_partner(pid: int, body: PartnerIn, request: Request,
                   user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    body.validate_callback()
    p = db.get(models.Partner, pid)
    if not p:
        raise HTTPException(404, "Partner not found")
    old = partner_out(p)
    for k, v in body.model_dump().items():
        setattr(p, k, v)
    db.commit()
    audit(db, request, user, "partner_updated", "partner", p.id, old=old, new=partner_out(p))
    return partner_out(p)


@router.post("/partners/{pid}/generate-key")
def generate_key(pid: int, request: Request, rotate: bool = False,
                 user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    """Generate an API key. Shown once, stored as a salted hash.

    With rotate=true the current key stays valid as the secondary key so the
    partner can switch over without downtime.
    """
    p = db.get(models.Partner, pid)
    if not p:
        raise HTTPException(404, "Partner not found")
    key = "gec_live_" + secrets.token_urlsafe(32)
    if rotate and p.api_key_hash:
        p.api_key_hash_secondary = p.api_key_hash
    else:
        p.api_key_hash_secondary = None
    p.api_key_hash = bcrypt.hash(key)
    p.callback_secret = p.callback_secret or secrets.token_urlsafe(32)
    db.commit()
    audit(db, request, user, "partner_key_generated", "partner", p.id,
          new={"rotate": rotate})
    return {"api_key": key, "callback_secret": p.callback_secret,
            "note": "Store this key now. It is not retrievable later."}


@router.post("/partners/{pid}/retire-old-key")
def retire_old_key(pid: int, request: Request,
                   user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    p = db.get(models.Partner, pid)
    if not p:
        raise HTTPException(404, "Partner not found")
    p.api_key_hash_secondary = None
    db.commit()
    audit(db, request, user, "partner_old_key_retired", "partner", p.id)
    return {"ok": True}


# ---------- Admin users (administrator only) ----------

class UserIn(BaseModel):
    email: str = Field(max_length=255)
    name: str = Field(default="", max_length=255)
    role: str = "readonly"
    password: str | None = Field(default=None, max_length=255)
    is_active: bool = True


def user_out(u: models.AdminUser) -> dict:
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role,
            "is_active": u.is_active, "has_2fa": bool(u.totp_secret),
            "created_at": u.created_at}


@router.get("/users")
def list_users(user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    return {"items": [user_out(u) for u in db.query(models.AdminUser).order_by(models.AdminUser.id).all()]}


@router.post("/users")
def create_user(body: UserIn, request: Request,
                user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    if body.role not in (ROLE_ADMIN, ROLE_OPS, ROLE_READONLY):
        raise HTTPException(422, "Invalid role")
    if not body.password or len(body.password) < 10:
        raise HTTPException(422, "Password of at least 10 characters required")
    email = body.email.lower().strip()
    if db.query(models.AdminUser).filter(models.AdminUser.email == email).first():
        raise HTTPException(409, "Email already exists")
    u = models.AdminUser(email=email, name=body.name, role=body.role,
                         password_hash=hash_password(body.password), is_active=body.is_active)
    db.add(u)
    db.commit()
    audit(db, request, user, "user_created", "admin_user", u.id, new=user_out(u))
    return user_out(u)


@router.put("/users/{uid}")
def update_user(uid: int, body: UserIn, request: Request,
                user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    u = db.get(models.AdminUser, uid)
    if not u:
        raise HTTPException(404, "User not found")
    if body.role not in (ROLE_ADMIN, ROLE_OPS, ROLE_READONLY):
        raise HTTPException(422, "Invalid role")
    old = user_out(u)
    u.name = body.name
    u.role = body.role
    u.is_active = body.is_active
    if body.password:
        if len(body.password) < 10:
            raise HTTPException(422, "Password of at least 10 characters required")
        u.password_hash = hash_password(body.password)
        u.totp_secret = None  # force fresh 2FA enrolment after admin reset
    db.commit()
    audit(db, request, user, "user_updated", "admin_user", u.id, old=old, new=user_out(u))
    return user_out(u)


# ---------- Reports ----------

@router.get("/reports/summary")
def reports_summary(user=Depends(require_role(ROLE_ADMIN, ROLE_OPS, ROLE_READONLY)),
                    db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    total_requests = db.query(func.count(models.QuoteRequest.id)).scalar() or 0
    month_requests = db.query(func.count(models.QuoteRequest.id)).filter(
        models.QuoteRequest.created_at >= month_start).scalar() or 0
    quoted = db.query(func.count(models.QuoteRequest.id)).filter(
        models.QuoteRequest.status == "QUOTED").scalar() or 0
    pending = db.query(func.count(models.QuoteRequest.id)).filter(
        models.QuoteRequest.status == "PENDING").scalar() or 0

    responded = db.query(models.QuoteRequest).filter(
        models.QuoteRequest.responded_at.isnot(None),
        models.QuoteRequest.sla_deadline.isnot(None)).all()
    on_time = sum(1 for r in responded if r.responded_at.replace(tzinfo=r.responded_at.tzinfo or timezone.utc)
                  <= r.sla_deadline.replace(tzinfo=r.sla_deadline.tzinfo or timezone.utc))
    sla_pct = round(100.0 * on_time / len(responded), 1) if responded else 100.0

    bookings = db.query(func.count(models.Booking.id)).scalar() or 0
    conversion = round(100.0 * bookings / quoted, 1) if quoted else 0.0

    active_rates = db.query(func.count(models.Rate.id)).filter(models.Rate.is_active.is_(True)).scalar() or 0
    expiring = db.query(func.count(models.Rate.id)).filter(
        models.Rate.is_active.is_(True), models.Rate.valid_until.isnot(None),
        models.Rate.valid_until <= now + timedelta(days=7)).scalar() or 0

    return {
        "total_requests": total_requests, "month_requests": month_requests,
        "quoted": quoted, "pending": pending,
        "sla_compliance_pct": sla_pct, "bookings": bookings,
        "conversion_pct": conversion, "active_rates": active_rates,
        "rates_expiring_7d": expiring,
    }


@router.get("/reports/margin-by-route")
def margin_by_route(user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    """Margin analysis. Administrator only: exposes buy and margin figures."""
    rows = (db.query(
                models.Rate.destination_country,
                func.count(models.Rate.id),
                func.avg(models.Rate.sell_rate - models.Rate.buy_rate))
            .filter(models.Rate.is_active.is_(True))
            .group_by(models.Rate.destination_country).all())
    return {"items": [
        {"destination_country": r[0], "rate_count": int(r[1]), "avg_margin": float(r[2] or 0)}
        for r in rows]}


# ---------- Callback deliveries ----------

@router.get("/callbacks")
def list_callbacks(status: str = "", limit: int = 100,
                   user=Depends(require_role(ROLE_ADMIN, ROLE_OPS, ROLE_READONLY)),
                   db: Session = Depends(get_db)):
    q = db.query(models.CallbackDelivery)
    if status:
        q = q.filter(models.CallbackDelivery.status == status)
    rows = q.order_by(models.CallbackDelivery.id.desc()).limit(min(limit, 300)).all()
    refs = {r.id: r.reference_number for r in db.query(models.QuoteRequest).filter(
        models.QuoteRequest.id.in_([d.quote_request_id for d in rows] or [0])).all()}
    names = dict(db.query(models.Partner.id, models.Partner.name).all())
    return {"items": [{
        "id": d.id, "reference_number": refs.get(d.quote_request_id, d.quote_request_id),
        "partner_name": names.get(d.partner_id, ""), "url": d.url,
        "status": d.status, "attempts": d.attempts, "last_error": d.last_error,
        "next_retry_at": d.next_retry_at, "delivered_at": d.delivered_at,
        "created_at": d.created_at,
    } for d in rows]}


@router.post("/callbacks/{cid}/retry")
def retry_callback(cid: int, request: Request,
                   user=Depends(require_role(ROLE_ADMIN, ROLE_OPS)),
                   db: Session = Depends(get_db)):
    d = db.get(models.CallbackDelivery, cid)
    if not d:
        raise HTTPException(404, "Delivery not found")
    d.status = "PENDING"
    d.attempts = 0
    d.next_retry_at = datetime.now(timezone.utc)
    db.commit()
    audit(db, request, user, "callback_retry", "callback_delivery", d.id)
    return {"ok": True}


# ---------- Audit log (administrator only) ----------

@router.get("/audit")
def audit_view(limit: int = 200, action: str = "",
               user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    q = db.query(models.AuditLog)
    if action:
        q = q.filter(models.AuditLog.action == action)
    rows = q.order_by(models.AuditLog.id.desc()).limit(min(limit, 500)).all()
    return {"items": [{
        "id": a.id, "user_email": a.user_email, "action": a.action,
        "entity_type": a.entity_type, "entity_id": a.entity_id,
        "old_value": a.old_value, "new_value": a.new_value,
        "ip_address": a.ip_address, "timestamp": a.timestamp,
    } for a in rows]}
