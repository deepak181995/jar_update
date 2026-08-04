import json

from fastapi import Request
from sqlalchemy.orm import Session

from . import models


def _clean(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:4000]
    try:
        return json.dumps(value, default=str)[:4000]
    except Exception:
        return str(value)[:4000]


def audit(db: Session, request: Request | None, user: models.AdminUser | None,
          action: str, entity_type: str = "", entity_id="", old=None, new=None):
    ip = ""
    if request is not None:
        ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "")
        ip = ip.split(",")[0].strip()[:64]
    db.add(models.AuditLog(
        user_id=user.id if user else None,
        user_email=user.email if user else "",
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        old_value=_clean(old),
        new_value=_clean(new),
        ip_address=ip,
    ))
    db.commit()
