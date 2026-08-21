import json
import logging

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import models  # noqa: F401  (register tables)
from .auth import hash_password
from .config import ADMIN_EMAIL, ADMIN_INITIAL_PASSWORD, CONFIDENTIAL_KEYS, ENV, MAX_BODY_BYTES
from .db import Base, SessionLocal, engine
from .routers import (admin_auth, admin_certin, admin_misc, admin_quotes,
                      admin_rates, public_certin, public_quotes)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("gec")

app = FastAPI(
    title="GEC Freight Platform",
    version="0.1.0",
    docs_url="/admin/api/docs" if ENV != "production" else None,
    redoc_url=None,
)


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    # Additive migrations for columns introduced after first release.
    if engine.dialect.name == "postgresql":
        from sqlalchemy import text
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS otp_hash VARCHAR(128)"))
            conn.execute(text("ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS otp_expires_at TIMESTAMPTZ"))
            conn.execute(text("ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS otp_attempts INTEGER DEFAULT 0"))
            conn.execute(text("ALTER TABLE quote_requests ADD COLUMN IF NOT EXISTS partner_reference VARCHAR(128) DEFAULT ''"))
            conn.execute(text("ALTER TABLE partners ADD COLUMN IF NOT EXISTS environment VARCHAR(16) DEFAULT 'uat'"))
            conn.execute(text("ALTER TABLE partners ADD COLUMN IF NOT EXISTS api_signing_secret VARCHAR(255)"))
    from . import callbacks
    callbacks.start_worker()
    db = SessionLocal()
    try:
        if not db.query(models.AdminUser).first():
            db.add(models.AdminUser(
                email=ADMIN_EMAIL.lower(), name="Administrator",
                password_hash=hash_password(ADMIN_INITIAL_PASSWORD),
                role="administrator",
            ))
            db.commit()
            log.info("Seeded initial administrator account")
    finally:
        db.close()


def _find_confidential(obj) -> bool:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in CONFIDENTIAL_KEYS:
                return True
            if _find_confidential(v):
                return True
    elif isinstance(obj, list):
        return any(_find_confidential(i) for i in obj)
    return False


@app.middleware("http")
async def security_headers(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl:
        try:
            if int(cl) > MAX_BODY_BYTES:
                return JSONResponse({"detail": "Payload too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "Bad request"}, status_code=400)

    if ENV == "production" and request.headers.get("x-forwarded-proto", "https") == "http":
        return RedirectResponse(str(request.url).replace("http://", "https://", 1), status_code=308)

    response = await call_next(request)

    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    )

    # Serialisation guard: no partner-facing /v1 response may carry
    # confidential commercial fields, regardless of endpoint code.
    if request.url.path.startswith("/v1") and response.headers.get("content-type", "").startswith("application/json"):
        body = b""
        async for chunk in response.body_iterator:
            body += chunk
        try:
            leaked = _find_confidential(json.loads(body or b"{}"))
        except Exception:
            leaked = False
        if leaked:
            log.error("Blocked /v1 response carrying confidential fields on %s", request.url.path)
            return JSONResponse({"detail": "Internal error"}, status_code=500)
        headers = dict(response.headers)
        headers.pop("content-length", None)
        return Response(content=body, status_code=response.status_code,
                        headers=headers, media_type="application/json")
    return response


# Partner-facing endpoints (Phase 2 expands this surface)
@app.get("/v1/health", tags=["public"])
def health():
    return {"status": "ok", "service": "gec-freight-api"}


app.include_router(public_quotes.router)
app.include_router(public_certin.router)
app.include_router(admin_auth.router)
app.include_router(admin_rates.router)
app.include_router(admin_quotes.router)
app.include_router(admin_misc.router)
app.include_router(admin_certin.router)

# Admin console static build
app.mount("/admin/assets", StaticFiles(directory="static/admin/assets"), name="admin-assets")


@app.get("/admin{path:path}", include_in_schema=False)
def admin_spa(path: str):
    return FileResponse("static/admin/index.html")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/admin")
