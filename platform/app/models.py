from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, Numeric, String, Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow():
    return datetime.now(timezone.utc)


class AdminUser(Base):
    __tablename__ = "admin_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role: Mapped[str] = mapped_column(String(32), default="readonly")  # administrator | operations | readonly
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    otp_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    otp_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    otp_attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Forwarder(Base):
    __tablename__ = "forwarders"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    contact_name: Mapped[str] = mapped_column(String(255), default="")
    contact_email: Mapped[str] = mapped_column(String(255), default="")
    contact_phone: Mapped[str] = mapped_column(String(64), default="")
    coverage_regions: Mapped[str] = mapped_column(String(512), default="")
    service_rating: Mapped[float] = mapped_column(Float, default=0)
    payment_terms: Mapped[str] = mapped_column(String(255), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Rate(Base):
    __tablename__ = "rates"
    id: Mapped[int] = mapped_column(primary_key=True)
    origin_port: Mapped[str] = mapped_column(String(128), index=True)
    origin_country: Mapped[str] = mapped_column(String(64), index=True)
    destination_port: Mapped[str] = mapped_column(String(128), index=True)
    destination_country: Mapped[str] = mapped_column(String(64), index=True)
    mode: Mapped[str] = mapped_column(String(16))  # air | sea_fcl | sea_lcl | multimodal
    weight_min: Mapped[float] = mapped_column(Float, default=0)
    weight_max: Mapped[float] = mapped_column(Float, default=0)
    volume_min: Mapped[float] = mapped_column(Float, default=0)
    volume_max: Mapped[float] = mapped_column(Float, default=0)
    incoterm: Mapped[str] = mapped_column(String(8), default="CIF")
    forwarder_id: Mapped[int | None] = mapped_column(ForeignKey("forwarders.id"), nullable=True)
    buy_rate: Mapped[float] = mapped_column(Numeric(14, 2), default=0)
    buy_currency: Mapped[str] = mapped_column(String(8), default="USD")
    margin_type: Mapped[str] = mapped_column(String(16), default="percentage")  # fixed | percentage
    margin_value: Mapped[float] = mapped_column(Numeric(14, 2), default=0)
    sell_rate: Mapped[float] = mapped_column(Numeric(14, 2), default=0)
    sell_currency: Mapped[str] = mapped_column(String(8), default="USD")
    transit_days: Mapped[int] = mapped_column(Integer, default=0)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    surcharge_notes: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Partner(Base):
    __tablename__ = "partners"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    api_key_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    api_key_hash_secondary: Mapped[str | None] = mapped_column(String(255), nullable=True)  # rotation window
    callback_url: Mapped[str] = mapped_column(String(512), default="")
    callback_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment: Mapped[str] = mapped_column(String(16), default="uat")  # uat | production
    api_signing_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rate_limit: Mapped[int] = mapped_column(Integer, default=60)  # requests per minute
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class QuoteRequest(Base):
    __tablename__ = "quote_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    partner_id: Mapped[int | None] = mapped_column(ForeignKey("partners.id"), nullable=True)
    reference_number: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    origin_port: Mapped[str] = mapped_column(String(128), default="")
    origin_country: Mapped[str] = mapped_column(String(64), default="")
    destination_port: Mapped[str] = mapped_column(String(128), default="")
    destination_country: Mapped[str] = mapped_column(String(64), default="")
    mode: Mapped[str] = mapped_column(String(16), default="sea_fcl")
    weight_kg: Mapped[float] = mapped_column(Float, default=0)
    volume_cbm: Mapped[float] = mapped_column(Float, default=0)
    cargo_description: Mapped[str] = mapped_column(Text, default="")
    hs_code: Mapped[str] = mapped_column(String(16), default="")
    incoterm: Mapped[str] = mapped_column(String(8), default="CIF")
    ready_date: Mapped[str] = mapped_column(String(32), default="")
    partner_reference: Mapped[str] = mapped_column(String(128), default="")
    sla_tier: Mapped[str] = mapped_column(String(32), default="standard_4h")
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)  # PENDING | QUOTED | EXPIRED | CANCELLED
    sla_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("admin_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Quote(Base):
    __tablename__ = "quotes"
    id: Mapped[int] = mapped_column(primary_key=True)
    quote_request_id: Mapped[int] = mapped_column(ForeignKey("quote_requests.id"), index=True)
    rate_id: Mapped[int | None] = mapped_column(ForeignKey("rates.id"), nullable=True)
    sell_rate: Mapped[float] = mapped_column(Numeric(14, 2), default=0)
    currency: Mapped[str] = mapped_column(String(8), default="USD")
    transit_days: Mapped[int] = mapped_column(Integer, default=0)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    charge_breakdown: Mapped[str] = mapped_column(Text, default="")  # JSON list of {label, amount}
    surcharge_notes: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="ISSUED")  # ISSUED | ACCEPTED | EXPIRED
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Booking(Base):
    __tablename__ = "bookings"
    id: Mapped[int] = mapped_column(primary_key=True)
    quote_id: Mapped[int] = mapped_column(ForeignKey("quotes.id"))
    booking_reference: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    partner_reference: Mapped[str] = mapped_column(String(128), default="")
    shipper_details: Mapped[str] = mapped_column(Text, default="")
    consignee_details: Mapped[str] = mapped_column(Text, default="")
    cargo_details: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(24), default="CONFIRMED")  # CONFIRMED | IN_TRANSIT | DELIVERED | CANCELLED
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ShipmentEvent(Base):
    __tablename__ = "shipment_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    booking_id: Mapped[int] = mapped_column(ForeignKey("bookings.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(64))
    event_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    location: Mapped[str] = mapped_column(String(255), default="")
    remarks: Mapped[str] = mapped_column(Text, default="")


class CallbackDelivery(Base):
    __tablename__ = "callback_deliveries"
    id: Mapped[int] = mapped_column(primary_key=True)
    quote_request_id: Mapped[int] = mapped_column(ForeignKey("quote_requests.id"), index=True)
    partner_id: Mapped[int] = mapped_column(ForeignKey("partners.id"))
    url: Mapped[str] = mapped_column(String(512))
    payload: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)  # PENDING | DELIVERED | FAILED
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(String(512), default="")
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_email: Mapped[str] = mapped_column(String(255), default="")
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity_type: Mapped[str] = mapped_column(String(64), default="")
    entity_id: Mapped[str] = mapped_column(String(64), default="")
    old_value: Mapped[str] = mapped_column(Text, default="")
    new_value: Mapped[str] = mapped_column(Text, default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
