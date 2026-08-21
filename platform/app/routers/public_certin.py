"""Customer-facing CERT-In alerts API.

Served under the GEC API domain with the same API key authentication,
per customer rate limits and (for production keys) signed requests as
the freight endpoints. Content is relayed from the internal alerts
index and belongs to CERT-In; responses carry attribution.
"""
import json
import os
import re
import urllib.parse
import urllib.request

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import models
from .public_quotes import partner_auth

router = APIRouter(prefix="/v1/certin", tags=["partner-certin"])

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
        raise HTTPException(502, "Alerts service unavailable; try again shortly")


@router.get("/alerts")
def alerts(type: str = "", year: int = Query(default=0, ge=0, le=2100),
           q: str = Query(default="", max_length=200),
           limit: int = Query(default=50, ge=1, le=200),
           offset: int = Query(default=0, ge=0),
           partner: models.Partner = Depends(partner_auth)):
    params = urllib.parse.urlencode(
        {k: v for k, v in [("type", type), ("year", year or ""), ("q", q),
                           ("limit", limit), ("offset", offset)] if v != ""})
    return _relay(f"/v1/alerts?{params}")


@router.get("/alerts/latest")
def latest(limit: int = Query(default=20, ge=1, le=100),
           partner: models.Partner = Depends(partner_auth)):
    return _relay(f"/v1/alerts/latest?limit={limit}")


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: str, partner: models.Partner = Depends(partner_auth)):
    if not re.fullmatch(r'(?i)(CIVN|CIAD)-\d{4}-\d+', alert_id.strip()):
        raise HTTPException(422, "Alert id must look like CIVN-2026-0416 or CIAD-2026-0042")
    return _relay(f"/v1/alerts/{urllib.parse.quote(alert_id.strip().upper())}")


@router.get("/stats")
def stats(partner: models.Partner = Depends(partner_auth)):
    return _relay("/v1/stats")
