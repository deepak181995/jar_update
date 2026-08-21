"""CERT-In alerts, proxied into the admin console.

The console front end only talks to its own origin, so these endpoints
relay to the internal CERT-In alerts service for authenticated console
users of any role.
"""
import json
import os
import re
import secrets
import urllib.parse
import urllib.request

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from passlib.hash import bcrypt
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..audit import audit
from ..auth import ROLE_ADMIN, ROLE_OPS, ROLE_READONLY, require_role
from ..db import get_db

router = APIRouter(prefix="/admin/api/certin", tags=["admin-certin"])

CERTIN_API_BASE = os.environ.get(
    "CERTIN_API_BASE", "https://certin-alerts-production.up.railway.app")


def _relay(path: str) -> dict:
    req = urllib.request.Request(CERTIN_API_BASE + path,
                                 headers={"User-Agent": "gec-platform/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read()).get("detail", "Upstream error")
        except Exception:
            detail = "Upstream error"
        raise HTTPException(e.code, detail)
    except Exception:
        raise HTTPException(502, "CERT-In alerts service unavailable")


@router.get("/stats")
def stats(user=Depends(require_role(ROLE_ADMIN, ROLE_OPS, ROLE_READONLY))):
    return _relay("/v1/stats")


@router.get("/alerts")
def alerts(type: str = "", year: int = Query(default=0, ge=0, le=2100),
           q: str = Query(default="", max_length=200),
           limit: int = Query(default=50, ge=1, le=200),
           offset: int = Query(default=0, ge=0),
           user=Depends(require_role(ROLE_ADMIN, ROLE_OPS, ROLE_READONLY))):
    params = urllib.parse.urlencode(
        {k: v for k, v in [("type", type), ("year", year or ""), ("q", q),
                           ("limit", limit), ("offset", offset)] if v != ""})
    return _relay(f"/v1/alerts?{params}")


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: str,
                 user=Depends(require_role(ROLE_ADMIN, ROLE_OPS, ROLE_READONLY))):
    if not re.fullmatch(r'(?i)(CIVN|CIAD)-\d{4}-\d+', alert_id.strip()):
        raise HTTPException(422, "Invalid alert id")
    return _relay(f"/v1/alerts/{urllib.parse.quote(alert_id.strip().upper())}")


# ---------- Usage log (administrator only) ----------

@router.get("/usage")
def usage(customer_id: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=500),
          user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    q = db.query(models.CertinAccessLog)
    if customer_id:
        q = q.filter(models.CertinAccessLog.customer_id == customer_id)
    rows = q.order_by(models.CertinAccessLog.id.desc()).limit(limit).all()
    names = dict(db.query(models.CertinCustomer.id, models.CertinCustomer.name).all())
    return {"items": [{
        "id": r.id, "customer": names.get(r.customer_id, "unknown"),
        "customer_id": r.customer_id, "resource": r.resource,
        "status_code": r.status_code, "response_summary": r.response_summary,
        "ip_address": r.ip_address, "timestamp": r.timestamp,
    } for r in rows]}


# ---------- CERT-In customer management (administrator only) ----------

class CustomerIn(BaseModel):
    name: str = Field(max_length=255)
    contact_email: str = Field(default="", max_length=255)
    rate_limit: int = Field(default=120, ge=1, le=6000)
    is_active: bool = True


def customer_out(c: models.CertinCustomer) -> dict:
    return {"id": c.id, "name": c.name, "contact_email": c.contact_email,
            "rate_limit": c.rate_limit, "is_active": c.is_active,
            "has_api_key": bool(c.api_key_hash),
            "has_secondary_key": bool(c.api_key_hash_secondary),
            "created_at": c.created_at}


@router.get("/customers")
def list_customers(user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    return {"items": [customer_out(c) for c in
                      db.query(models.CertinCustomer).order_by(models.CertinCustomer.name).all()]}


@router.post("/customers")
def create_customer(body: CustomerIn, request: Request,
                    user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    c = models.CertinCustomer(**body.model_dump())
    db.add(c)
    db.commit()
    audit(db, request, user, "certin_customer_created", "certin_customer", c.id, new=customer_out(c))
    return customer_out(c)


@router.put("/customers/{cid}")
def update_customer(cid: int, body: CustomerIn, request: Request,
                    user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    c = db.get(models.CertinCustomer, cid)
    if not c:
        raise HTTPException(404, "Customer not found")
    old = customer_out(c)
    for k, v in body.model_dump().items():
        setattr(c, k, v)
    db.commit()
    audit(db, request, user, "certin_customer_updated", "certin_customer", c.id, old=old, new=customer_out(c))
    return customer_out(c)


@router.post("/customers/{cid}/generate-key")
def generate_customer_key(cid: int, request: Request, rotate: bool = False,
                          user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    c = db.get(models.CertinCustomer, cid)
    if not c:
        raise HTTPException(404, "Customer not found")
    key = "gec_certin_" + secrets.token_urlsafe(32)
    if rotate and c.api_key_hash:
        c.api_key_hash_secondary = c.api_key_hash
    else:
        c.api_key_hash_secondary = None
    c.api_key_hash = bcrypt.hash(key)
    db.commit()
    audit(db, request, user, "certin_key_generated", "certin_customer", c.id, new={"rotate": rotate})
    return {"api_key": key, "note": "Store this key now. It is not retrievable later."}


@router.post("/customers/{cid}/retire-old-key")
def retire_customer_key(cid: int, request: Request,
                        user=Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    c = db.get(models.CertinCustomer, cid)
    if not c:
        raise HTTPException(404, "Customer not found")
    c.api_key_hash_secondary = None
    db.commit()
    audit(db, request, user, "certin_old_key_retired", "certin_customer", c.id)
    return {"ok": True}
