import json
import logging
import smtplib
import urllib.request
from email.mime.text import MIMEText

from .config import (
    RESEND_API_KEY, RESEND_FROM, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_USER,
)

log = logging.getLogger("gec.mail")


def send_email(to: str, subject: str, body: str) -> None:
    try:
        if RESEND_API_KEY:
            _send_resend(to, subject, body)
        else:
            _send_smtp(to, subject, body)
        log.info("Sent mail to %s: %s", to, subject)
    except Exception as e:
        log.error("Mail send failed (%s): %s", type(e).__name__, str(e)[:200])
        raise


def _send_resend(to: str, subject: str, body: str) -> None:
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps({
            "from": RESEND_FROM, "to": [to],
            "subject": subject, "text": body,
        }).encode(),
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"Resend HTTP {resp.status}")


def _send_smtp(to: str, subject: str, body: str) -> None:
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASSWORD)
        s.send_message(msg)
