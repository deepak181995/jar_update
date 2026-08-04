"""SLA deadline calculation on the Indian working calendar.

Working hours are 09:30 to 18:30 IST, Monday to Saturday, excluding Indian
public holidays. Deadlines are computed in working hours, not clock hours,
and returned as UTC datetimes.
"""
from datetime import datetime, timedelta, timezone, date, time

IST = timezone(timedelta(hours=5, minutes=30))
DAY_START = time(9, 30)
DAY_END = time(18, 30)

# National public holidays. Maintained by the operations team, extend yearly.
HOLIDAYS = {
    date(2026, 1, 26),   # Republic Day
    date(2026, 3, 4),    # Holi
    date(2026, 4, 3),    # Good Friday
    date(2026, 5, 1),    # May Day
    date(2026, 8, 15),   # Independence Day
    date(2026, 10, 2),   # Gandhi Jayanti
    date(2026, 11, 8),   # Diwali
    date(2026, 12, 25),  # Christmas
    date(2027, 1, 26),
}

SLA_TIERS = {
    "immediate": 0,
    "standard_4h": 4,
    "new_destination_24h": 24,
    "project_cargo_48h": 48,
}


def is_working_day(d: date) -> bool:
    return d.weekday() != 6 and d not in HOLIDAYS  # Sunday is weekday 6


def add_working_hours(start_utc: datetime, hours: float) -> datetime:
    """Add working hours to a UTC datetime, respecting the IST calendar."""
    t = start_utc.astimezone(IST)
    remaining = timedelta(hours=hours)

    while True:
        day_start = datetime.combine(t.date(), DAY_START, tzinfo=IST)
        day_end = datetime.combine(t.date(), DAY_END, tzinfo=IST)

        if not is_working_day(t.date()) or t >= day_end:
            t = datetime.combine(t.date() + timedelta(days=1), DAY_START, tzinfo=IST)
            continue
        if t < day_start:
            t = day_start

        available = day_end - t
        if remaining <= available:
            return (t + remaining).astimezone(timezone.utc)
        remaining -= available
        t = datetime.combine(t.date() + timedelta(days=1), DAY_START, tzinfo=IST)


def deadline_for_tier(tier: str, start_utc: datetime) -> datetime | None:
    hours = SLA_TIERS.get(tier)
    if hours is None:
        hours = 4
    if hours == 0:
        return start_utc
    return add_working_hours(start_utc, hours)
