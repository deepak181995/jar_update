"""Customer-facing CERT-In alerts API.

A standalone data product with its own customers and keys, entirely
separate from the freight partner API. Keys are issued in the console's
CERT-In Customers section and carry the gec_certin_ prefix. Content is
relayed from the internal alerts index and belongs to CERT-In; responses
carry attribution.
"""
import json
import os
import re
import time
import urllib.parse
import urllib.request

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from passlib.hash import bcrypt
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db

router = APIRouter(prefix="/v1/certin", tags=["certin-customers"])

CERTIN_API_BASE = os.environ.get(
    "CERTIN_API_BASE", "https://certin-alerts-production.up.railway.app")

_rate_windows: dict[int, list] = {}


def certin_auth(request: Request, x_api_key: str = Header(default=""),
                db: Session = Depends(get_db)) -> models.CertinCustomer:
    key = x_api_key or ""
    auth = request.headers.get("Authorization", "")
    if not key and auth.startswith("Bearer "):
        key = auth[7:]
    if not key:
        raise HTTPException(401, "Missing API key. Send it in the X-API-Key header.")
    for c in db.query(models.CertinCustomer).filter(models.CertinCustomer.is_active.is_(True)).all():
        for h in (c.api_key_hash, c.api_key_hash_secondary):
            try:
                if h and bcrypt.verify(key, h):
                    _enforce_rate_limit(c)
                    return c
            except HTTPException:
                raise
            except Exception:
                continue
    raise HTTPException(401, "Invalid API key")


def _enforce_rate_limit(c: models.CertinCustomer):
    now = int(time.time() // 60)
    win = _rate_windows.get(c.id)
    if not win or win[0] != now:
        _rate_windows[c.id] = [now, 1]
        return
    win[1] += 1
    if win[1] > max(c.rate_limit or 120, 1):
        raise HTTPException(429, "Rate limit exceeded. Retry in a minute.",
                            headers={"Retry-After": "60"})


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
        raise HTTPException(502, "Alerts service unavailable; try again shortly")


@router.get("/alerts")
def alerts(type: str = "", year: int = Query(default=0, ge=0, le=2100),
           q: str = Query(default="", max_length=200),
           limit: int = Query(default=50, ge=1, le=200),
           offset: int = Query(default=0, ge=0),
           customer: models.CertinCustomer = Depends(certin_auth)):
    params = urllib.parse.urlencode(
        {k: v for k, v in [("type", type), ("year", year or ""), ("q", q),
                           ("limit", limit), ("offset", offset)] if v != ""})
    return _relay(f"/v1/alerts?{params}")


@router.get("/alerts/latest")
def latest(limit: int = Query(default=20, ge=1, le=100),
           customer: models.CertinCustomer = Depends(certin_auth)):
    return _relay(f"/v1/alerts/latest?limit={limit}")


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: str, customer: models.CertinCustomer = Depends(certin_auth)):
    if not re.fullmatch(r'(?i)(CIVN|CIAD)-\d{4}-\d+', alert_id.strip()):
        raise HTTPException(422, "Alert id must look like CIVN-2026-0416 or CIAD-2026-0042")
    return _relay(f"/v1/alerts/{urllib.parse.quote(alert_id.strip().upper())}")


@router.get("/stats")
def stats(customer: models.CertinCustomer = Depends(certin_auth)):
    return _relay("/v1/stats")
