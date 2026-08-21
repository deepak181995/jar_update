"""CERT-In alerts, proxied into the admin console.

The console front end only talks to its own origin, so these endpoints
relay to the internal CERT-In alerts service for authenticated console
users of any role.
"""
import json
import os
import re
import urllib.parse
import urllib.request

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth import ROLE_ADMIN, ROLE_OPS, ROLE_READONLY, require_role

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
