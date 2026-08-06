import json
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..audit import audit
from ..auth import ROLE_ADMIN, ROLE_OPS, ROLE_READONLY, require_role
from ..db import get_db
from ..sla import SLA_TIERS, deadline_for_tier
from .admin_rates import compute_sell

router = APIRouter(prefix="/admin/api/quotes", tags=["admin-quotes"])


def new_reference(prefix: str) -> str:
    return f"{prefix}-{datetime.now(timezone.utc):%y%m%d}-{secrets.token_hex(3).upper()}"


class QuoteRequestIn(BaseModel):
    partner_id: int | None = None
    origin_port: str = Field(max_length=128)
    origin_country: str = Field(default="India", max_length=64)
    destination_port: str = Field(max_length=128)
    destination_country: str = Field(max_length=64)
    mode: str = "sea_fcl"
    weight_kg: float = 0
    volume_cbm: float = 0
    cargo_description: str = Field(default="", max_length=2000)
    hs_code: str = Field(default="", max_length=16)
    incoterm: str = Field(default="CIF", max_length=8)
    ready_date: str = Field(default="", max_length=32)
    sla_tier: str = "standard_4h"


def qr_out(q: models.QuoteRequest, partner_names: dict | None = None) -> dict:
    d = {c.name: getattr(q, c.name) for c in models.QuoteRequest.__table__.columns}
    d["partner_name"] = (partner_names or {}).get(q.partner_id, "") if q.partner_id else ""
    return d


def _partner_names(db: Session) -> dict:
    return dict(db.query(models.Partner.id, models.Partner.name).all())


@router.get("/pending")
def pending(user=Depends(require_role(ROLE_ADMIN, ROLE_OPS, ROLE_READONLY)),
            db: Session = Depends(get_db)):
    rows = (db.query(models.QuoteRequest)
            .filter(models.QuoteRequest.status == "PENDING")
            .order_by(models.QuoteRequest.sla_deadline.asc().nullslast())
            .limit(500).all())
    names = _partner_names(db)
    return {"items": [qr_out(q, names) for q in rows]}


@router.get("")
def list_requests(status: str = "", limit: int = 200,
                  user=Depends(require_role(ROLE_ADMIN, ROLE_OPS, ROLE_READONLY)),
                  db: Session = Depends(get_db)):
    query = db.query(models.QuoteRequest)
    if status:
        query = query.filter(models.QuoteRequest.status == status)
    rows = query.order_by(models.QuoteRequest.id.desc()).limit(min(limit, 500)).all()
    quotes = {q.quote_request_id: q for q in db.query(models.Quote).filter(
        models.Quote.quote_request_id.in_([r.id for r in rows] or [0])).all()}
    names = _partner_names(db)
    out = []
    for r in rows:
        d = qr_out(r, names)
        qt = quotes.get(r.id)
        if qt:
            d["quote"] = {
                "sell_rate": float(qt.sell_rate), "currency": qt.currency,
                "transit_days": qt.transit_days, "valid_until": qt.valid_until,
                "status": qt.status,
            }
        out.append(d)
    return {"items": out}


@router.post("")
def create_request(body: QuoteRequestIn, request: Request,
                   user=Depends(require_role(ROLE_ADMIN, ROLE_OPS)),
                   db: Session = Depends(get_db)):
    if body.sla_tier not in SLA_TIERS:
        raise HTTPException(422, f"sla_tier must be one of {sorted(SLA_TIERS)}")
    now = datetime.now(timezone.utc)
    q = models.QuoteRequest(
        **body.model_dump(),
        reference_number=new_reference("GECQ"),
        status="PENDING",
        sla_deadline=deadline_for_tier(body.sla_tier, now),
    )
    db.add(q)
    db.commit()
    audit(db, request, user, "quote_request_created", "quote_request", q.id, new=qr_out(q))
    return qr_out(q)


class QuoteEntryIn(BaseModel):
    forwarder_id: int | None = None
    buy_rate: float = Field(ge=0)
    buy_currency: str = Field(default="USD", max_length=8)
    margin_type: str = "percentage"
    margin_value: float = Field(ge=0)
    sell_currency: str = Field(default="USD", max_length=8)
    transit_days: int = Field(ge=0)
    validity_days: int = Field(default=14, ge=1, le=90)
    charge_breakdown: list[dict] = []
    surcharge_notes: str = Field(default="", max_length=2000)
    save_to_rates: bool = False


@router.post("/{request_id}/quote")
def enter_quote(request_id: int, body: QuoteEntryIn, request: Request,
                user=Depends(require_role(ROLE_ADMIN, ROLE_OPS)),
                db: Session = Depends(get_db)):
    qr = db.get(models.QuoteRequest, request_id)
    if not qr:
        raise HTTPException(404, "Quote request not found")
    if qr.status != "PENDING":
        raise HTTPException(409, f"Request is {qr.status}, not PENDING")
    if body.margin_type not in ("fixed", "percentage"):
        raise HTTPException(422, "margin_type must be fixed or percentage")

    sell = compute_sell(body.buy_rate, body.margin_type, body.margin_value)
    now = datetime.now(timezone.utc)
    quote = models.Quote(
        quote_request_id=qr.id,
        sell_rate=sell,
        currency=body.sell_currency,
        transit_days=body.transit_days,
        valid_until=now + timedelta(days=body.validity_days),
        charge_breakdown=json.dumps(body.charge_breakdown)[:4000],
        surcharge_notes=body.surcharge_notes,
        status="ISSUED",
    )
    db.add(quote)
    qr.status = "QUOTED"
    qr.responded_at = now
    qr.assigned_to = user.id

    if body.save_to_rates:
        r = models.Rate(
            origin_port=qr.origin_port, origin_country=qr.origin_country,
            destination_port=qr.destination_port, destination_country=qr.destination_country,
            mode=qr.mode, incoterm=qr.incoterm,
            forwarder_id=body.forwarder_id,
            buy_rate=body.buy_rate, buy_currency=body.buy_currency,
            margin_type=body.margin_type, margin_value=body.margin_value,
            sell_rate=sell, sell_currency=body.sell_currency,
            transit_days=body.transit_days,
            valid_from=now, valid_until=now + timedelta(days=body.validity_days),
            surcharge_notes=body.surcharge_notes, is_active=True,
        )
        db.add(r)

    db.commit()
    on_time = qr.sla_deadline is None or now <= (
        qr.sla_deadline if qr.sla_deadline.tzinfo else qr.sla_deadline.replace(tzinfo=timezone.utc))
    audit(db, request, user, "quote_issued", "quote", quote.id,
          new={"request": qr.reference_number, "sell_rate": sell, "on_time": on_time})
    from .. import callbacks
    callback_queued = callbacks.schedule(db, qr, quote)
    return {"reference_number": qr.reference_number, "sell_rate": sell,
            "currency": body.sell_currency, "on_time": on_time,
            "callback_queued": callback_queued}


@router.post("/{request_id}/cancel")
def cancel_request(request_id: int, request: Request,
                   user=Depends(require_role(ROLE_ADMIN, ROLE_OPS)),
                   db: Session = Depends(get_db)):
    qr = db.get(models.QuoteRequest, request_id)
    if not qr:
        raise HTTPException(404, "Quote request not found")
    old = qr.status
    qr.status = "CANCELLED"
    db.commit()
    audit(db, request, user, "quote_request_cancelled", "quote_request", qr.id, old=old, new="CANCELLED")
    return {"ok": True}
