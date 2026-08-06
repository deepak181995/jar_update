"""Partner-facing quote API.

Authentication: X-API-Key header carrying the key issued in the admin
console. Responses never contain buy rates, margins or forwarder details;
the serialisation guard in main.py enforces this a second time.
"""
import json
import secrets
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from passlib.hash import bcrypt
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..sla import deadline_for_tier

router = APIRouter(prefix="/v1", tags=["partner"])

MODES = {"air", "sea_fcl", "sea_lcl", "multimodal"}

# Sliding per-minute rate limit counters: partner_id -> [window_start, count]
_rate_windows: dict[int, list] = {}


def partner_auth(request: Request, x_api_key: str = Header(default=""),
                 db: Session = Depends(get_db)) -> models.Partner:
    key = x_api_key or ""
    auth = request.headers.get("Authorization", "")
    if not key and auth.startswith("Bearer "):
        key = auth[7:]
    if not key:
        raise HTTPException(401, "Missing API key. Send it in the X-API-Key header.")
    for p in db.query(models.Partner).filter(models.Partner.is_active.is_(True)).all():
        for h in (p.api_key_hash, p.api_key_hash_secondary):
            try:
                if h and bcrypt.verify(key, h):
                    _enforce_rate_limit(p)
                    return p
            except Exception:
                continue
    raise HTTPException(401, "Invalid API key")


def _enforce_rate_limit(p: models.Partner):
    now = int(time.time() // 60)
    win = _rate_windows.get(p.id)
    if not win or win[0] != now:
        _rate_windows[p.id] = [now, 1]
        return
    win[1] += 1
    if win[1] > max(p.rate_limit or 60, 1):
        raise HTTPException(429, "Rate limit exceeded. Retry in a minute.",
                            headers={"Retry-After": "60"})


class QuoteIn(BaseModel):
    origin_port: str = Field(min_length=2, max_length=128, description="Port or city of departure, e.g. Nhava Sheva")
    origin_country: str = Field(default="India", max_length=64)
    destination_port: str = Field(min_length=2, max_length=128, description="Port or city of arrival, e.g. Mombasa")
    destination_country: str = Field(min_length=2, max_length=64)
    mode: str = Field(description="air, sea_fcl, sea_lcl or multimodal")
    weight_kg: float = Field(gt=0, le=10_000_000, description="Gross weight in kilograms")
    volume_cbm: float = Field(default=0, ge=0, le=100_000, description="Volume in cubic metres")
    cargo_description: str = Field(min_length=3, max_length=2000)
    hs_code: str = Field(default="", max_length=16, description="HS tariff code if known")
    incoterm: str = Field(default="CIF", max_length=8)
    ready_date: str = Field(default="", max_length=32, description="Date cargo is ready, YYYY-MM-DD")
    hazardous_or_oversized: bool = Field(default=False, description="True for hazardous, oversized or project cargo")
    partner_reference: str = Field(default="", max_length=128, description="Your own reference for this enquiry")


def _match_rate(db: Session, q: QuoteIn) -> models.Rate | None:
    now = datetime.now(timezone.utc)
    rows = (db.query(models.Rate)
            .filter(models.Rate.is_active.is_(True),
                    models.Rate.mode == q.mode,
                    models.Rate.destination_country.ilike(q.destination_country.strip()))
            .all())
    best = None
    for r in rows:
        vu = r.valid_until
        if vu is not None:
            if vu.tzinfo is None:
                vu = vu.replace(tzinfo=timezone.utc)
            if vu < now:
                continue
        if r.weight_max and not (r.weight_min <= q.weight_kg <= r.weight_max):
            continue
        if r.volume_max and q.volume_cbm and not (r.volume_min <= q.volume_cbm <= r.volume_max):
            continue
        port_bonus = 0 if r.destination_port.strip().lower() == q.destination_port.strip().lower() else 1
        rank = (port_bonus, float(r.sell_rate))
        if best is None or rank < best[0]:
            best = (rank, r)
    return best[1] if best else None


def _sla_tier(db: Session, q: QuoteIn) -> str:
    if q.hazardous_or_oversized:
        return "project_cargo_48h"
    known = (db.query(models.Rate.id)
             .filter(models.Rate.destination_country.ilike(q.destination_country.strip()))
             .first())
    return "standard_4h" if known else "new_destination_24h"


@router.post("/quotes")
def request_quote(body: QuoteIn, partner: models.Partner = Depends(partner_auth),
                  db: Session = Depends(get_db)):
    if body.mode not in MODES:
        raise HTTPException(422, f"mode must be one of {sorted(MODES)}")

    now = datetime.now(timezone.utc)
    ref = f"GECQ-{now:%y%m%d}-{secrets.token_hex(3).upper()}"
    rate = _match_rate(db, body)

    qr = models.QuoteRequest(
        partner_id=partner.id,
        reference_number=ref,
        origin_port=body.origin_port, origin_country=body.origin_country,
        destination_port=body.destination_port, destination_country=body.destination_country,
        mode=body.mode, weight_kg=body.weight_kg, volume_cbm=body.volume_cbm,
        cargo_description=body.cargo_description, hs_code=body.hs_code,
        incoterm=body.incoterm, ready_date=body.ready_date,
        partner_reference=body.partner_reference,
    )

    if rate is not None:
        qr.status = "QUOTED"
        qr.sla_tier = "immediate"
        qr.sla_deadline = now
        qr.responded_at = now
        db.add(qr)
        db.flush()
        quote = models.Quote(
            quote_request_id=qr.id, rate_id=rate.id,
            sell_rate=rate.sell_rate, currency=rate.sell_currency,
            transit_days=rate.transit_days, valid_until=rate.valid_until,
            charge_breakdown=json.dumps([{"label": "Consolidated freight and handling",
                                          "amount": float(rate.sell_rate)}]),
            surcharge_notes=rate.surcharge_notes, status="ISSUED",
        )
        db.add(quote)
        db.commit()
        return {
            "reference_number": ref,
            "status": "QUOTED",
            "quote": {
                "sell_rate": float(rate.sell_rate),
                "currency": rate.sell_currency,
                "transit_days": rate.transit_days,
                "valid_until": rate.valid_until,
                "incoterm": body.incoterm,
                "surcharge_notes": rate.surcharge_notes,
            },
        }

    tier = _sla_tier(db, body)
    qr.sla_tier = tier
    qr.sla_deadline = deadline_for_tier(tier, now)
    db.add(qr)
    db.commit()
    return {
        "reference_number": ref,
        "status": "PENDING",
        "sla_response_by": qr.sla_deadline,
        "message": "Your quotation is being prepared by the GEC desk and will be "
                   "delivered by the committed time.",
    }


@router.get("/quotes/{reference_number}")
def quote_status(reference_number: str, partner: models.Partner = Depends(partner_auth),
                 db: Session = Depends(get_db)):
    qr = (db.query(models.QuoteRequest)
          .filter(models.QuoteRequest.reference_number == reference_number.strip(),
                  models.QuoteRequest.partner_id == partner.id)
          .first())
    if not qr:
        raise HTTPException(404, "Unknown reference")
    out = {"reference_number": qr.reference_number, "status": qr.status,
           "partner_reference": qr.partner_reference or "",
           "sla_response_by": qr.sla_deadline}
    quote = (db.query(models.Quote)
             .filter(models.Quote.quote_request_id == qr.id)
             .order_by(models.Quote.id.desc()).first())
    if quote:
        out["quote"] = {
            "sell_rate": float(quote.sell_rate), "currency": quote.currency,
            "transit_days": quote.transit_days, "valid_until": quote.valid_until,
            "surcharge_notes": quote.surcharge_notes,
            "charge_breakdown": json.loads(quote.charge_breakdown or "[]"),
        }
    return out
