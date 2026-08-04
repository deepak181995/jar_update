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
