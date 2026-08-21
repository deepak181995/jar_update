"""CERT-In Alerts API.

A read-only JSON API over the public advisories (CIAD) and vulnerability
notes (CIVN) published by CERT-In, the Indian Computer Emergency Response
Team, at https://www.cert-in.org.in.

The service maintains a local index of every alert year by year, refreshes
the current and previous year on a schedule, and fetches full alert detail
on demand with caching. All content belongs to CERT-In; this API is a
convenience layer and every response links back to the official source.
"""
import http.cookiejar
import json
import logging
import os
import re
import sqlite3
import threading
import time
import urllib.request
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query, Response

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("certin")

BASE = "https://www.cert-in.org.in"
DB_PATH = os.environ.get("CERTIN_DB", "/srv/certin.db")
FIRST_YEAR = 2003
REFRESH_SECONDS = 1800          # current + previous year, every 30 minutes
FETCH_TIMEOUT = 30
UA = "gec-certin-alerts/1.0 (public alert aggregation; contact curegloballlp@gmail.com)"

SOURCES = {
    "vulnerability_note": {
        "list": "/s2cMainServlet?pageid=VLNLIST02&year={year}",
        "pager": "VulNotesList.jsp",
        "detail": "/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE={code}",
        "prefix": "CIVN",
    },
    "advisory": {
        "list": "/s2cMainServlet?pageid=PUBADVLIST02&year={year}",
        "pager": "Advisories.jsp",
        "detail": "/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE={code}",
        "prefix": "CIAD",
    },
}
MAX_PAGES_PER_YEAR = 100

app = FastAPI(
    title="CERT-In Alerts API",
    description="JSON access to CERT-In security advisories and vulnerability notes. "
                "Unofficial convenience API; all content is published by and belongs to "
                "CERT-In (https://www.cert-in.org.in).",
    version="1.0.0",
    docs_url="/docs",
)

_state = {"last_refresh": None, "backfill_done": False}


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            title TEXT DEFAULT '',
            date TEXT DEFAULT '',
            year INTEGER,
            source_url TEXT,
            fetched_at TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS details (
            id TEXT PRIMARY KEY,
            severity TEXT DEFAULT '',
            cves TEXT DEFAULT '[]',
            software_affected TEXT DEFAULT '',
            overview TEXT DEFAULT '',
            description TEXT DEFAULT '',
            solution TEXT DEFAULT '',
            fetched_at TEXT
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_alerts_year ON alerts(year)")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_alerts_type ON alerts(type)")


def fetch(path: str) -> str:
    req = urllib.request.Request(BASE + path, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return resp.read().decode("utf-8", "replace")


MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"


def parse_list(html: str, alert_type: str) -> list[dict]:
    prefix = SOURCES[alert_type]["prefix"]
    anchors = [(m.start(), m.group(1)) for m in
               re.finditer(rf'VLCODE=({prefix}-\d{{4}}-\d+)', html)]
    items, seen = [], set()
    for i, (pos, code) in enumerate(anchors):
        if code in seen:
            continue
        seen.add(code)
        end = anchors[i + 1][0] if i + 1 < len(anchors) else min(len(html), pos + 4000)
        chunk = html[pos:end]
        dm = re.search(rf'\(\s*({MONTHS})\s+(\d{{1,2}}),?\s*(\d{{4}})\s*\)', chunk)
        date_iso = ""
        if dm:
            try:
                date_iso = datetime.strptime(
                    f"{dm.group(1)} {dm.group(2)} {dm.group(3)}", "%B %d %Y").date().isoformat()
            except ValueError:
                pass
        title = ""
        tm = re.search(r'<span[^>]*padding-left[^>]*>(.*?)</span>', chunk, re.S)
        if tm:
            title = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', tm.group(1))).strip()[:300]
        if not title:
            # fall back: first plausible text line that is not the heading or the date
            text = re.sub(r'&nbsp;?', ' ', re.sub(r'<[^>]+>', '\n', chunk))
            for line in (l.strip() for l in text.splitlines()):
                if (line and code not in line and 'CERT-In' not in line
                        and not re.match(r'^\(', line)
                        and not re.search(rf'\(\s*(?:{MONTHS})', line)):
                    title = line[:300]
                    break
        items.append({
            "id": code, "type": alert_type, "title": title, "date": date_iso,
            "year": int(code.split("-")[1]),
            "source_url": BASE + SOURCES[alert_type]["detail"].format(code=code),
        })
    return items


def upsert_alerts(items: list[dict]):
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        for a in items:
            conn.execute("""INSERT INTO alerts(id, type, title, date, year, source_url, fetched_at)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET title=excluded.title, date=excluded.date,
                    source_url=excluded.source_url, fetched_at=excluded.fetched_at""",
                (a["id"], a["type"], a["title"], a["date"], a["year"], a["source_url"], now))


def refresh_year(year: int) -> int:
    """Walk every page of both list types for a year.

    CERT-In paginates through a session bound JSP: the year page seeds the
    session, then <pager>.jsp?next=N serves subsequent pages, and requires
    the session cookie plus a Referer header.
    """
    total = 0
    for alert_type in SOURCES:
        src = SOURCES[alert_type]
        try:
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            seed_url = BASE + src["list"].format(year=year)

            def get(url, referer=None):
                req = urllib.request.Request(url, headers={"User-Agent": UA})
                if referer:
                    req.add_header("Referer", referer)
                with opener.open(req, timeout=FETCH_TIMEOUT) as resp:
                    return resp.read().decode("utf-8", "replace")

            html = get(seed_url)
            seen_ids: set[str] = set()
            offset = 0
            for _ in range(MAX_PAGES_PER_YEAR):
                items = [i for i in parse_list(html, alert_type) if i["id"] not in seen_ids]
                if not items and seen_ids:
                    break
                upsert_alerts(items)
                seen_ids.update(i["id"] for i in items)
                total += len(items)
                nexts = [int(n) for n in re.findall(rf'{src["pager"]}\?next=(\d+)', html)]
                forward = [n for n in nexts if n > offset]
                if not forward:
                    break
                offset = min(forward)
                time.sleep(0.5)
                html = get(f"{BASE}/{src['pager']}?next={offset}", referer=seed_url)
        except Exception as e:
            log.warning("List fetch failed %s %s: %s", alert_type, year, str(e)[:120])
        time.sleep(0.5)
    return total


def refresh_recent():
    year = datetime.now(timezone.utc).year
    n = refresh_year(year) + refresh_year(year - 1)
    _state["last_refresh"] = datetime.now(timezone.utc).isoformat()
    log.info("Refreshed recent years, %s alerts indexed", n)


def backfill_all_years():
    year = datetime.now(timezone.utc).year - 2
    for y in range(year, FIRST_YEAR - 1, -1):
        refresh_year(y)
    _state["backfill_done"] = True
    log.info("Backfill of all years complete")


def _refresh_loop():
    while True:
        try:
            refresh_recent()
        except Exception as e:
            log.error("Refresh error: %s", str(e)[:150])
        time.sleep(REFRESH_SECONDS)


SECTION_STOPS = r'(?:Software Affected|Overview|Target Audience|Risk Assessment|Impact Assessment|Description|Solution|Vendor Information|References|CVE Name|Disclaimer|$)'


def parse_detail(html: str) -> dict:
    text = re.sub(r'<script.*?</script>|<style.*?</style>', ' ', html, flags=re.S)
    text = re.sub(r'<[^>]+>', '\n', text)
    text = re.sub(r'&nbsp;?', ' ', text)
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n\s*\n+', '\n', text).strip()

    def section(name):
        m = re.search(rf'{name}\s*:?\s*\n(.*?)\n\s*{SECTION_STOPS}', text, re.S)
        return re.sub(r'\s+', ' ', m.group(1)).strip()[:4000] if m else ""

    sev = ""
    sm = re.search(r'Severity Rating\s*:?\s*([A-Za-z]+)', text, re.I)
    if sm:
        sev = sm.group(1).upper()
    return {
        "severity": sev,
        "cves": sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', html))),
        "software_affected": section("Software Affected"),
        "overview": section("Overview"),
        "description": section("Description"),
        "solution": section("Solution"),
    }


def alert_out(row, detail=None) -> dict:
    d = {"id": row["id"], "type": row["type"], "title": row["title"],
         "date": row["date"], "year": row["year"], "source_url": row["source_url"],
         "source": "CERT-In (cert-in.org.in)"}
    if detail is not None:
        d.update(detail)
    return d


@app.on_event("startup")
def startup():
    init_db()
    threading.Thread(target=_refresh_loop, daemon=True).start()
    threading.Thread(target=backfill_all_years, daemon=True).start()


@app.middleware("http")
async def headers_mw(request, call_next):
    resp = await call_next(request)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


@app.get("/v1/health")
def health():
    return {"status": "ok", "service": "certin-alerts-api"}


@app.get("/v1/stats")
def stats():
    with db() as conn:
        total = conn.execute("SELECT count(*) c FROM alerts").fetchone()["c"]
        by_type = {r["type"]: r["c"] for r in
                   conn.execute("SELECT type, count(*) c FROM alerts GROUP BY type")}
        years = {str(r["year"]): r["c"] for r in
                 conn.execute("SELECT year, count(*) c FROM alerts GROUP BY year ORDER BY year DESC")}
    return {"total_alerts": total, "by_type": by_type, "by_year": years,
            "last_refresh": _state["last_refresh"],
            "all_years_indexed": _state["backfill_done"]}


@app.get("/v1/alerts")
def list_alerts(
    type: str = Query(default="", description="advisory or vulnerability_note"),
    year: int = Query(default=0, ge=0, le=2100),
    q: str = Query(default="", max_length=200, description="Search in title and id"),
    severity: str = Query(default="", max_length=20, description="Filter by severity; only matches alerts whose detail has been fetched"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    if type and type not in SOURCES:
        raise HTTPException(422, "type must be advisory or vulnerability_note")
    sql = """SELECT a.* FROM alerts a {join} WHERE 1=1"""
    join, args = "", []
    if severity:
        join = "JOIN details d ON d.id = a.id"
        sql += " AND upper(d.severity) = ?"
        args.append(severity.upper())
    sql = sql.format(join=join)
    if type:
        sql += " AND a.type = ?"; args.append(type)
    if year:
        sql += " AND a.year = ?"; args.append(year)
    if q:
        sql += " AND (a.title LIKE ? OR a.id LIKE ?)"; args += [f"%{q}%", f"%{q}%"]
    count_sql = sql.replace("SELECT a.*", "SELECT count(*) c", 1)
    sql += " ORDER BY a.date DESC, a.id DESC LIMIT ? OFFSET ?"
    with db() as conn:
        total = conn.execute(count_sql, args).fetchone()["c"]
        rows = conn.execute(sql, args + [limit, offset]).fetchall()
    return {"total": total, "count": len(rows), "offset": offset,
            "items": [alert_out(r) for r in rows]}


@app.get("/v1/alerts/latest")
def latest(limit: int = Query(default=20, ge=1, le=100)):
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY date DESC, id DESC LIMIT ?", (limit,)).fetchall()
    return {"count": len(rows), "items": [alert_out(r) for r in rows]}


@app.get("/v1/alerts/{alert_id}")
def alert_detail(alert_id: str, response: Response):
    alert_id = alert_id.strip().upper()
    if not re.fullmatch(r'(CIVN|CIAD)-\d{4}-\d+', alert_id):
        raise HTTPException(422, "Alert id must look like CIVN-2026-0416 or CIAD-2026-0042")
    with db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        det = conn.execute("SELECT * FROM details WHERE id = ?", (alert_id,)).fetchone()

    alert_type = "vulnerability_note" if alert_id.startswith("CIVN") else "advisory"
    if det is None:
        try:
            html = fetch(SOURCES[alert_type]["detail"].format(code=alert_id))
        except Exception:
            raise HTTPException(502, "CERT-In did not respond; try again shortly")
        if alert_id not in html:
            raise HTTPException(404, "Alert not found at CERT-In")
        parsed = parse_detail(html)
        with db() as conn:
            conn.execute("""INSERT OR REPLACE INTO details
                (id, severity, cves, software_affected, overview, description, solution, fetched_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (alert_id, parsed["severity"], json.dumps(parsed["cves"]),
                 parsed["software_affected"], parsed["overview"], parsed["description"],
                 parsed["solution"], datetime.now(timezone.utc).isoformat()))
            if row is None:
                tm = re.search(r'{}\s*\n(.*?)\n'.format(alert_id),
                               re.sub(r'<[^>]+>', '\n', html))
                title = tm.group(1).strip()[:300] if tm else ""
                upsert_alerts([{"id": alert_id, "type": alert_type, "title": title,
                                "date": "", "year": int(alert_id.split("-")[1]),
                                "source_url": BASE + SOURCES[alert_type]["detail"].format(code=alert_id)}])
                row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        det = {"severity": parsed["severity"], "cves": json.dumps(parsed["cves"]),
               "software_affected": parsed["software_affected"], "overview": parsed["overview"],
               "description": parsed["description"], "solution": parsed["solution"]}

    detail = {"severity": det["severity"], "cves": json.loads(det["cves"]),
              "software_affected": det["software_affected"], "overview": det["overview"],
              "description": det["description"], "solution": det["solution"]}
    return alert_out(row, detail)


@app.get("/", include_in_schema=False)
def root():
    return {"service": "CERT-In Alerts API",
            "docs": "/docs",
            "endpoints": ["/v1/alerts", "/v1/alerts/latest", "/v1/alerts/{id}", "/v1/stats", "/v1/health"],
            "attribution": "All alert content is published by CERT-In, https://www.cert-in.org.in"}
