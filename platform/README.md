# GEC Freight Platform

Freight quotation and shipment management system for Global Export Consultancy.

## Components (Phase 1)

- **FastAPI backend** (`app/`): admin API, SLA engine, audit log, security middleware.
- **React admin console** (`admin-ui/`): served at `/admin` from the same service.
- **PostgreSQL** on Railway (`DATABASE_URL`).

## Security highlights

- Admin login: bcrypt password hashing, mandatory TOTP two factor, 30 minute sliding sessions, lockout after 5 failed attempts.
- Roles: administrator, operations, readonly. Operations cannot view partner API keys, users or system settings.
- Partner API keys generated once, stored as bcrypt hashes, with zero-downtime rotation (two active keys).
- Serialisation guard middleware: any `/v1` response carrying `buy_rate`, `margin_*` or `forwarder*` fields is blocked with a 500 before it leaves the process.
- Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options), 2 MB payload cap, HTTPS enforcement.
- Full audit log of logins, rate changes, quote issuance, key generation, with user, IP and timestamp.

## SLA engine

Working hours 09:30 to 18:30 IST, Monday to Saturday, excluding Indian public
holidays (`app/sla.py`, `HOLIDAYS` set maintained yearly). Tiers: immediate,
4 working hours, 24 working hours, 48 working hours.

## Environment variables

`DATABASE_URL`, `SECRET_KEY`, `ADMIN_EMAIL`, `ADMIN_INITIAL_PASSWORD`, `ENV=production`.

## Local development

```
pip install -r requirements.txt
uvicorn app.main:app --reload           # backend on :8000
cd admin-ui && npm install && npm run dev  # UI on :5173 proxying /admin/api
```

## Deploy

Docker image (multi-stage: Vite build then Python). On Railway:
`railway up ./platform --service gec-platform`.

## Roadmap

- Phase 2: public partner API (`POST /v1/quotes`, `GET /v1/quotes/{ref}`), HMAC-signed callback service with retries, sandbox environment, OpenAPI + Postman pack.
- Phase 3: bookings and shipment tracking milestones.
