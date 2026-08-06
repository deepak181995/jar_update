import os

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./dev.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-secret")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
ADMIN_INITIAL_PASSWORD = os.environ.get("ADMIN_INITIAL_PASSWORD", "changeme")
ENV = os.environ.get("ENV", "development")

REQUIRE_2FA = os.environ.get("REQUIRE_2FA", "true").lower() == "true"
# Two factor mode: "off", "totp" (authenticator app) or "email" (OTP by email).
TWO_FA_MODE = os.environ.get("TWO_FA_MODE", "totp" if REQUIRE_2FA else "off").lower()

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", os.environ.get("ADMIN_EMAIL", ""))
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM = os.environ.get("RESEND_FROM", "GEC Console <onboarding@resend.dev>")
# Optional per-recipient key overrides, JSON object of {email: api_key}.
# Used while sender accounts are in test mode and can only reach their owner.
try:
    import json as _json
    RESEND_KEY_MAP = {k.lower(): v for k, v in _json.loads(
        os.environ.get("RESEND_KEY_MAP", "{}")).items()}
except Exception:
    RESEND_KEY_MAP = {}

OTP_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
SESSION_MINUTES = 30          # inactivity expiry
LOCKOUT_THRESHOLD = 5         # failed logins before lockout
LOCKOUT_MINUTES = 15
MAX_BODY_BYTES = 2 * 1024 * 1024   # 2 MB request cap
MAX_CSV_BYTES = 2 * 1024 * 1024

# Fields that must never leave the system through any partner-facing response.
CONFIDENTIAL_KEYS = {
    "buy_rate", "buy_currency", "margin_type", "margin_value",
    "forwarder_id", "forwarder", "forwarder_name",
}
