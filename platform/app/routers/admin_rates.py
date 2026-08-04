import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..audit import audit
from ..auth import ROLE_ADMIN, ROLE_OPS, ROLE_READONLY, require_role
from ..config import MAX_CSV_BYTES
from ..db import get_db

router = APIRouter(prefix="/admin/api/rates", tags=["admin-rates"])

MODES = {"air", "sea_fcl", "sea_lcl", "multimodal"}
MARGIN_TYPES = {"fixed", "percentage"}


def compute_sell(buy: float, margin_type: str, margin_value: float) -> float:
    if margin_type == "fixed":
        return round(buy + margin_value, 2)
    return round(buy * (1 + margin_value / 100.0), 2)


class RateIn(BaseModel):
    origin_port: str = Field(max_length=128)
    origin_country: str = Field(max_length=64)
    destination_port: str = Field(max_length=128)
    destination_country: str = Field(max_length=64)
    mode: str
    weight_min: float = 0
    weight_max: float = 0
    volume_min: float = 0
    volume_max: float = 0
    incoterm: str = Field(default="CIF", max_length=8)
    forwarder_id: int | None = None
    buy_rate: float = 0
    buy_currency: str = Field(default="USD", max_length=8)
    margin_type: str = "percentage"
    margin_value: float = 0
    sell_currency: str = Field(default="USD", max_length=8)
    transit_days: int = 0
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    surcharge_notes: str = Field(default="", max_length=2000)
    is_active: bool = True

    def validate_business(self):
        if self.mode not in MODES:
            raise HTTPException(422, f"mode must be one of {sorted(MODES)}")
        if self.margin_type not in MARGIN_TYPES:
            raise HTTPException(422, "margin_type must be fixed or percentage")
        if self.buy_rate < 0 or self.margin_value < 0:
            raise HTTPException(422, "Rates and margins must not be negative")


def rate_out(r: models.Rate) -> dict:
    return {c.name: getattr(r, c.name) for c in models.Rate.__table__.columns}


@router.get("")
def list_rates(
    q: str = "", active_only: bool = False, expiring_days: int = 0,
    limit: int = 200, offset: int = 0,
    user=Depends(require_role(ROLE_ADMIN, ROLE_OPS, ROLE_READONLY)),
    db: Session = Depends(get_db),
):
    query = db.query(models.Rate)
    if q:
        like = f"%{q}%"
        query = query.filter(
            models.Rate.origin_port.ilike(like)
            | models.Rate.destination_port.ilike(like)
            | models.Rate.destination_country.ilike(like)
        )
    if active_only:
        query = query.filter(models.Rate.is_active.is_(True))
    if expiring_days:
        cutoff = datetime.now(timezone.utc) + timedelta(days=expiring_days)
        query = query.filter(models.Rate.valid_until.isnot(None), models.Rate.valid_until <= cutoff)
    total = query.count()
    rows = query.order_by(models.Rate.id.desc()).offset(offset).limit(min(limit, 500)).all()
    return {"total": total, "items": [rate_out(r) for r in rows]}


@router.post("")
def create_rate(body: RateIn, request: Request,
                user=Depends(require_role(ROLE_ADMIN, ROLE_OPS)),
                db: Session = Depends(get_db)):
    body.validate_business()
    r = models.Rate(**body.model_dump())
    r.sell_rate = compute_sell(body.buy_rate, body.margin_type, body.margin_value)
    db.add(r)
    db.commit()
    audit(db, request, user, "rate_created", "rate", r.id, new=rate_out(r))
    return rate_out(r)


@router.put("/{rate_id}")
def update_rate(rate_id: int, body: RateIn, request: Request,
                user=Depends(require_role(ROLE_ADMIN, ROLE_OPS)),
                db: Session = Depends(get_db)):
    body.validate_business()
    r = db.get(models.Rate, rate_id)
    if not r:
        raise HTTPException(404, "Rate not found")
    old = rate_out(r)
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    r.sell_rate = compute_sell(body.buy_rate, body.margin_type, body.margin_value)
    db.commit()
    audit(db, request, user, "rate_updated", "rate", r.id, old=old, new=rate_out(r))
    return rate_out(r)


@router.delete("/{rate_id}")
def deactivate_rate(rate_id: int, request: Request,
                    user=Depends(require_role(ROLE_ADMIN, ROLE_OPS)),
                    db: Session = Depends(get_db)):
    r = db.get(models.Rate, rate_id)
    if not r:
        raise HTTPException(404, "Rate not found")
    r.is_active = False
    db.commit()
    audit(db, request, user, "rate_deactivated", "rate", r.id)
    return {"ok": True}


CSV_COLUMNS = [
    "origin_port", "origin_country", "destination_port", "destination_country",
    "mode", "weight_min", "weight_max", "volume_min", "volume_max", "incoterm",
    "forwarder_id", "buy_rate", "buy_currency", "margin_type", "margin_value",
    "sell_currency", "transit_days", "valid_from", "valid_until", "surcharge_notes",
]


@router.post("/upload-csv")
async def upload_csv(request: Request, file: UploadFile,
                     user=Depends(require_role(ROLE_ADMIN, ROLE_OPS)),
                     db: Session = Depends(get_db)):
    if file.content_type not in ("text/csv", "application/vnd.ms-excel", "application/octet-stream"):
        raise HTTPException(415, "Upload a CSV file")
    raw = await file.read()
    if len(raw) > MAX_CSV_BYTES:
        raise HTTPException(413, "CSV too large (2 MB limit)")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(422, "CSV must be UTF-8 encoded")

    reader = csv.DictReader(io.StringIO(text))
    created, errors = 0, []
    for i, row in enumerate(reader, start=2):
        try:
            data = {k: (row.get(k) or "").strip() for k in CSV_COLUMNS}
            body = RateIn(
                origin_port=data["origin_port"], origin_country=data["origin_country"],
                destination_port=data["destination_port"], destination_country=data["destination_country"],
                mode=data["mode"] or "sea_fcl",
                weight_min=float(data["weight_min"] or 0), weight_max=float(data["weight_max"] or 0),
                volume_min=float(data["volume_min"] or 0), volume_max=float(data["volume_max"] or 0),
                incoterm=data["incoterm"] or "CIF",
                forwarder_id=int(data["forwarder_id"]) if data["forwarder_id"] else None,
                buy_rate=float(data["buy_rate"] or 0), buy_currency=data["buy_currency"] or "USD",
                margin_type=data["margin_type"] or "percentage",
                margin_value=float(data["margin_value"] or 0),
                sell_currency=data["sell_currency"] or "USD",
                transit_days=int(data["transit_days"] or 0),
                valid_from=datetime.fromisoformat(data["valid_from"]) if data["valid_from"] else None,
                valid_until=datetime.fromisoformat(data["valid_until"]) if data["valid_until"] else None,
                surcharge_notes=data["surcharge_notes"],
            )
            body.validate_business()
            if not body.origin_port or not body.destination_port:
                raise ValueError("origin_port and destination_port are required")
            r = models.Rate(**body.model_dump())
            r.sell_rate = compute_sell(body.buy_rate, body.margin_type, body.margin_value)
            db.add(r)
            created += 1
        except HTTPException as e:
            errors.append({"line": i, "error": e.detail})
        except Exception as e:
            errors.append({"line": i, "error": str(e)[:200]})
    db.commit()
    audit(db, request, user, "rates_csv_upload", "rate", "", new={"created": created, "errors": len(errors)})
    return {"created": created, "errors": errors[:50], "template_columns": CSV_COLUMNS}
