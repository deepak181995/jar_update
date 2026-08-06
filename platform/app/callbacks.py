"""Signed callback delivery to partner platforms.

When the desk completes a quote for a partner-submitted request, the
completed quotation is pushed to the partner's registered HTTPS callback
URL. Payloads are signed with the partner's callback secret:

    X-GEC-Timestamp: unix seconds
    X-GEC-Signature: hex HMAC-SHA256(secret, "{timestamp}.{raw_body}")

Partners should reject requests older than five minutes to prevent replay.

Deliveries are recorded in callback_deliveries and retried by a background
worker with exponential backoff for up to five attempts, after which the
delivery is flagged FAILED for the console.
"""
import hashlib
import hmac
import json
import logging
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from . import models
from .db import SessionLocal

log = logging.getLogger("gec.callback")

# Minutes until the next attempt, indexed by attempts already made.
BACKOFF_MINUTES = [0, 2, 10, 30, 120]
MAX_ATTEMPTS = 5


def build_payload(qr: models.QuoteRequest, quote: models.Quote) -> dict:
    return {
        "event": "quote.completed",
        "reference_number": qr.reference_number,
        "partner_reference": qr.partner_reference or "",
        "status": "QUOTED",
        "quote": {
            "sell_rate": float(quote.sell_rate),
            "currency": quote.currency,
            "transit_days": quote.transit_days,
            "valid_until": quote.valid_until.isoformat() if quote.valid_until else None,
            "surcharge_notes": quote.surcharge_notes,
            "charge_breakdown": json.loads(quote.charge_breakdown or "[]"),
        },
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }


def schedule(db: Session, qr: models.QuoteRequest, quote: models.Quote) -> bool:
    """Queue a delivery if the request came from a partner with a callback URL."""
    if not qr.partner_id:
        return False
    partner = db.get(models.Partner, qr.partner_id)
    if not partner or not partner.callback_url or not partner.callback_secret:
        return False
    u = urlparse(partner.callback_url)
    if u.scheme != "https":
        log.warning("Refusing non-HTTPS callback for partner %s", partner.id)
        return False
    db.add(models.CallbackDelivery(
        quote_request_id=qr.id, partner_id=partner.id,
        url=partner.callback_url,
        payload=json.dumps(build_payload(qr, quote)),
        next_retry_at=datetime.now(timezone.utc),
    ))
    db.commit()
    return True


def _deliver(d: models.CallbackDelivery, secret: str) -> None:
    body = d.payload.encode()
    ts = str(int(time.time()))
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        d.url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "gec-platform/1.0",
            "X-GEC-Timestamp": ts,
            "X-GEC-Signature": sig,
        })
    with urllib.request.urlopen(req, timeout=20) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"HTTP {resp.status}")


def process_due(db: Session) -> int:
    now = datetime.now(timezone.utc)
    due = (db.query(models.CallbackDelivery)
           .filter(models.CallbackDelivery.status == "PENDING",
                   models.CallbackDelivery.next_retry_at <= now)
           .limit(20).all())
    handled = 0
    for d in due:
        partner = db.get(models.Partner, d.partner_id)
        try:
            if not partner or not partner.callback_secret:
                raise RuntimeError("Partner or secret missing")
            _deliver(d, partner.callback_secret)
            d.status = "DELIVERED"
            d.delivered_at = datetime.now(timezone.utc)
            d.last_error = ""
            log.info("Callback delivered for %s to partner %s", d.quote_request_id, d.partner_id)
        except Exception as e:
            d.attempts += 1
            d.last_error = f"{type(e).__name__}: {str(e)[:200]}"
            if d.attempts >= MAX_ATTEMPTS:
                d.status = "FAILED"
                log.error("Callback FAILED after %s attempts for request %s: %s",
                          d.attempts, d.quote_request_id, d.last_error)
            else:
                minutes = BACKOFF_MINUTES[min(d.attempts, len(BACKOFF_MINUTES) - 1)]
                d.next_retry_at = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        db.commit()
        handled += 1
    return handled


def _worker_loop(interval_seconds: int):
    while True:
        try:
            db = SessionLocal()
            try:
                process_due(db)
            finally:
                db.close()
        except Exception as e:
            log.error("Callback worker error: %s", str(e)[:200])
        time.sleep(interval_seconds)


def start_worker(interval_seconds: int = 30):
    t = threading.Thread(target=_worker_loop, args=(interval_seconds,), daemon=True,
                         name="callback-worker")
    t.start()
    log.info("Callback worker started")
