#!/usr/bin/env python3
"""
Drishti CLI - IP and host intelligence from 13 sources.

Standard library only. No pip install. Runs in a-Shell on iPhone.

    python3 Drishti_cli.py 8.8.8.8
    python3 Drishti_cli.py --me
    python3 Drishti_cli.py -f targets.txt --json
    python3 Drishti_cli.py --keys
    python3 Drishti_cli.py --ai 45.155.205.233

The --ai flag adds a plain English reading of the report. It talks to a local
Ollama first and falls back to GLM in the cloud if Ollama is not running.
"""

import argparse
import base64
import concurrent.futures as futures
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

APP = "Drishti"
VERSION = "1.0"
HTTP_TIMEOUT = 8
SOURCE_TIMEOUT = 12
CACHE_TTL = 24 * 3600
TOR_TTL = 6 * 3600
UA = "Drishti/1.0 (+ip-intel-cli)"

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATHS = [
    os.path.join(HERE, "drishti_config.json"),
    os.path.expanduser("~/drishti_config.json"),
    os.path.expanduser("~/.drishti/drishti_config.json"),
]
CACHE_PATH = os.path.join(HERE, "drishti_cache.db")

KEY_FIELDS = [
    ("abuseipdb", "AbuseIPDB", "https://www.abuseipdb.com/account/api"),
    ("greynoise", "GreyNoise", "https://viz.greynoise.io/account"),
    ("virustotal", "VirusTotal", "https://www.virustotal.com/gui/my-apikey"),
    ("shodan", "Shodan", "https://account.shodan.io"),
    ("censys", "Censys (id:secret)", "https://search.censys.io/account/api"),
    ("securitytrails", "SecurityTrails", "https://securitytrails.com/app/account"),
]

# The plain English summary layer. Ollama runs locally and needs no key, GLM is
# the cloud fallback. Preference lives in cfg["ai_backend"]: auto, ollama, glm, off.
AI_FIELDS = [
    ("glm", "GLM API key (cloud AI)", "https://open.bigmodel.cn/usercenter/apikeys"),
]
AI_SETTINGS = [
    ("ai_backend", "AI backend: auto, ollama, glm or off", "auto"),
    ("ollama_host", "Ollama host", "http://127.0.0.1:11434"),
    ("ollama_model", "Ollama model", "llama3.2"),
    ("glm_model", "GLM model", "glm-4-flash"),
]

DNSBL_ZONES = [
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("Barracuda", "b.barracudacentral.org"),
    ("SORBS", "dnsbl.sorbs.net"),
    ("s5h", "all.s5h.net"),
]

RISKY_PORTS = {
    23: "Telnet", 445: "SMB", 3389: "RDP", 1433: "MSSQL", 5900: "VNC",
    3306: "MySQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
    11211: "Memcached", 5432: "PostgreSQL", 21: "FTP", 512: "rexec",
    2375: "Docker API", 161: "SNMP",
}

# ---------------------------------------------------------------- colour

class C:
    on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[38;5;203m"; ORANGE = "\033[38;5;208m"; YELLOW = "\033[38;5;220m"
    GREEN = "\033[38;5;114m"; BLUE = "\033[38;5;75m"; GREY = "\033[38;5;245m"
    NIDO = "\033[38;5;166m"
    BG_RED = "\033[48;5;52m"; BG_ORANGE = "\033[48;5;94m"; BG_GREEN = "\033[48;5;22m"
    BG_BLUE = "\033[48;5;24m"

    @classmethod
    def p(cls, code, text):
        return f"{code}{text}{cls.RESET}" if cls.on else str(text)


def paint(code, text):
    return C.p(code, text)


# ---------------------------------------------------------------- config

def load_config():
    for path in CONFIG_PATHS:
        if os.path.exists(path):
            try:
                with open(path, "r") as fh:
                    data = json.load(fh)
                data["_path"] = path
                return data
            except Exception:
                pass
    return {"_path": CONFIG_PATHS[0]}


def save_config(cfg):
    path = cfg.get("_path") or CONFIG_PATHS[0]
    out = {k: v for k, v in cfg.items() if not k.startswith("_")}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return path


def key(cfg, name):
    val = cfg.get(name) or os.environ.get("DRISHTI_" + name.upper()) or ""
    return val.strip()


# ---------------------------------------------------------------- cache

def cache_open():
    conn = sqlite3.connect(CACHE_PATH, timeout=10)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache "
        "(k TEXT PRIMARY KEY, v TEXT NOT NULL, ts REAL NOT NULL)"
    )
    conn.commit()
    return conn


def cache_get(k, ttl=CACHE_TTL):
    try:
        conn = cache_open()
        row = conn.execute("SELECT v, ts FROM cache WHERE k=?", (k,)).fetchone()
        conn.close()
        if row and (time.time() - row[1]) < ttl:
            return json.loads(row[0]), row[1]
    except Exception:
        pass
    return None, None


def cache_put(k, value):
    try:
        conn = cache_open()
        conn.execute(
            "INSERT OR REPLACE INTO cache (k, v, ts) VALUES (?,?,?)",
            (k, json.dumps(value), time.time()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ---------------------------------------------------------------- http

_SSL = ssl.create_default_context()


def http_json(url, headers=None, timeout=HTTP_TIMEOUT, data=None, method=None):
    body, status = http_raw(url, headers, timeout, data, method)
    if body is None:
        return None, status
    try:
        return json.loads(body), status
    except Exception:
        return None, status


def http_raw(url, headers=None, timeout=HTTP_TIMEOUT, data=None, method=None):
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json, text/plain, */*")
    for hk, hv in (headers or {}).items():
        req.add_header(hk, hv)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as resp:
            return resp.read().decode("utf-8", "replace"), resp.status
    except urllib.error.HTTPError as exc:
        try:
            return exc.read().decode("utf-8", "replace"), exc.code
        except Exception:
            return None, exc.code
    except Exception:
        return None, 0


# ---------------------------------------------------------------- targets

def classify_private(ip):
    obj = ipaddress.ip_address(ip)
    if obj.is_loopback:
        return "Loopback"
    if obj.is_link_local:
        return "Link local"
    if obj.is_private:
        return "Private (RFC1918/ULA)"
    if obj.is_multicast:
        return "Multicast"
    if obj.is_reserved or obj.is_unspecified:
        return "Reserved"
    return None


def resolve_target(target):
    """Return (ip, hostname_or_None, error_or_None)."""
    target = target.strip()
    if not target:
        return None, None, "empty target"
    target = re.sub(r"^\w+://", "", target).split("/")[0]
    if target.startswith("[") and "]" in target:
        target = target[1:target.index("]")]
    elif target.count(":") == 1 and not target.replace(".", "").isdigit():
        host, _, port = target.partition(":")
        if port.isdigit():
            target = host
    try:
        ipaddress.ip_address(target)
        return target, None, None
    except ValueError:
        pass
    try:
        info = socket.getaddrinfo(target, None)
        ip = info[0][4][0]
        return ip, target, None
    except Exception:
        return None, target, "could not resolve %s" % target


# ---------------------------------------------------------------- sources

def src_rdap(ip, cfg):
    data, status = http_json("https://rdap.org/ip/%s" % ip, timeout=10)
    if not data:
        return {"ok": False, "status": status}
    out = {
        "ok": True,
        "handle": data.get("handle"),
        "name": data.get("name"),
        "type": data.get("type"),
        "country": data.get("country"),
        "range": "%s - %s" % (data.get("startAddress", "?"), data.get("endAddress", "?")),
        "abuse": [],
        "org": None,
        "registry": None,
        "events": {},
    }
    for ev in data.get("events") or []:
        if ev.get("eventAction"):
            out["events"][ev["eventAction"]] = (ev.get("eventDate") or "")[:10]
    for ent in _flatten_entities(data.get("entities") or []):
        roles = [r.lower() for r in (ent.get("roles") or [])]
        name, emails = _vcard(ent.get("vcardArray"))
        if "abuse" in roles:
            for em in emails:
                if em not in out["abuse"]:
                    out["abuse"].append(em)
        if ("registrant" in roles or "administrative" in roles) and name and not out["org"]:
            out["org"] = name
    remarks = []
    for rm in data.get("remarks") or []:
        remarks.extend(rm.get("description") or [])
    out["remarks"] = [r for r in remarks if r][:3]
    for ln in data.get("links") or []:
        if ln.get("rel") == "self" and ln.get("href"):
            host = urllib.parse.urlparse(ln["href"]).netloc
            out["registry"] = host.replace("rdap.", "").replace(".net", "").upper()
            break
    return out


def _flatten_entities(entities):
    stack = list(entities)
    seen = []
    while stack:
        ent = stack.pop(0)
        if not isinstance(ent, dict):
            continue
        seen.append(ent)
        stack.extend(ent.get("entities") or [])
    return seen


def _vcard(vcard):
    name, emails = None, []
    if not vcard or len(vcard) < 2:
        return name, emails
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        if item[0] == "fn" and not name:
            name = item[3]
        elif item[0] == "email":
            val = item[3]
            if isinstance(val, str) and "@" in val:
                emails.append(val)
    return name, emails


def src_geo(ip, cfg):
    data, status = http_json("https://ipwho.is/%s" % ip)
    if not data or not data.get("success"):
        return {"ok": False, "status": status}
    conn = data.get("connection") or {}
    return {
        "ok": True,
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "flag": (data.get("flag") or {}).get("emoji"),
        "region": data.get("region"),
        "city": data.get("city"),
        "lat": data.get("latitude"),
        "lon": data.get("longitude"),
        "timezone": (data.get("timezone") or {}).get("id"),
        "asn": conn.get("asn"),
        "org": conn.get("org"),
        "isp": conn.get("isp"),
        "domain": conn.get("domain"),
    }


def src_rdns(ip, cfg):
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        return {"ok": True, "ptr": host, "aliases": aliases}
    except Exception:
        return {"ok": True, "ptr": None, "aliases": []}


def src_internetdb(ip, cfg):
    data, status = http_json("https://internetdb.shodan.io/%s" % ip)
    if status == 404:
        # InternetDB answers 404 when it has simply never seen the address.
        return {"ok": True, "ports": [], "vulns": [], "tags": [],
                "hostnames": [], "cpes": [], "unseen": True}
    if not isinstance(data, dict) or "ports" not in data:
        return {"ok": False, "status": status}
    return {
        "ok": True,
        "ports": sorted(data.get("ports") or []),
        "vulns": sorted(data.get("vulns") or []),
        "tags": data.get("tags") or [],
        "hostnames": data.get("hostnames") or [],
        "cpes": data.get("cpes") or [],
    }


def src_dnsbl(ip, cfg):
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False}
    if obj.version != 4:
        return {"ok": True, "listed": [], "checked": 0, "note": "IPv4 only"}
    rev = ".".join(reversed(ip.split(".")))
    listed, checked = [], 0

    def probe(item):
        label, zone = item
        try:
            answer = socket.gethostbyname("%s.%s" % (rev, zone))
            return label, answer
        except Exception:
            return label, None

    with futures.ThreadPoolExecutor(max_workers=5) as pool:
        for label, answer in pool.map(probe, DNSBL_ZONES):
            checked += 1
            if answer and answer.startswith("127."):
                listed.append({"list": label, "code": answer})
    return {"ok": True, "listed": listed, "checked": checked}


_TOR_LOCK = threading.Lock()
_TOR_MEM = {"set": None}


def tor_exit_set():
    """Fetch the bulk exit list once per process, cached on disk for 6 hours."""
    if _TOR_MEM["set"] is not None:
        return _TOR_MEM["set"]
    with _TOR_LOCK:
        if _TOR_MEM["set"] is not None:
            return _TOR_MEM["set"]
        cached, _ = cache_get("torbulkexitlist", TOR_TTL)
        if cached is None:
            body, _ = http_raw("https://check.torproject.org/torbulkexitlist", timeout=10)
            if not body:
                return None
            cached = [ln.strip() for ln in body.splitlines()
                      if ln.strip() and not ln.startswith("#")]
            cache_put("torbulkexitlist", cached)
        _TOR_MEM["set"] = frozenset(cached)
        return _TOR_MEM["set"]


def src_tor(ip, cfg):
    nodes = tor_exit_set()
    if nodes is None:
        return {"ok": False}
    return {"ok": True, "exit_node": ip in nodes, "list_size": len(nodes)}


def src_urlscan(ip, cfg):
    query = urllib.parse.quote('page.ip:"%s"' % ip)
    data, status = http_json(
        "https://urlscan.io/api/v1/search/?q=%s&size=10" % query, timeout=10
    )
    if not data or "results" not in data:
        return {"ok": False, "status": status}
    results, malicious = [], 0
    for res in data.get("results") or []:
        page = res.get("page") or {}
        verdicts = res.get("verdicts") or {}
        bad = bool(verdicts.get("malicious"))
        malicious += 1 if bad else 0
        results.append({
            "url": (page.get("url") or "")[:110],
            "domain": page.get("domain"),
            "date": (res.get("task") or {}).get("time", "")[:10],
            "malicious": bad,
        })
    return {
        "ok": True,
        "total": data.get("total", len(results)),
        "malicious": malicious,
        "results": results[:8],
    }


def src_abuseipdb(ip, cfg):
    api = key(cfg, "abuseipdb")
    if not api:
        return {"ok": False, "nokey": True}
    data, status = http_json(
        "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose="
        % urllib.parse.quote(ip),
        headers={"Key": api},
    )
    node = (data or {}).get("data")
    if not node:
        return {"ok": False, "status": status, "error": _api_err(data)}
    reports = node.get("reports") or []
    cats = {}
    for rep in reports[:50]:
        for cid in rep.get("categories") or []:
            cats[cid] = cats.get(cid, 0) + 1
    return {
        "ok": True,
        "score": node.get("abuseConfidenceScore", 0),
        "reports": node.get("totalReports", 0),
        "distinct": node.get("numDistinctUsers", 0),
        "last": node.get("lastReportedAt"),
        "tor": node.get("isTor"),
        "whitelisted": node.get("isWhitelisted"),
        "usage": node.get("usageType"),
        "isp": node.get("isp"),
        "domain": node.get("domain"),
        "categories": sorted(
            ({"id": k, "name": ABUSE_CATS.get(k, "cat %s" % k), "n": v} for k, v in cats.items()),
            key=lambda x: -x["n"],
        )[:6],
    }


ABUSE_CATS = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH",
    23: "IoT Targeted",
}


def _api_err(data):
    if not isinstance(data, dict):
        return None
    errs = data.get("errors")
    if isinstance(errs, list) and errs:
        return (errs[0] or {}).get("detail")
    return data.get("error") or data.get("message")


def src_greynoise(ip, cfg):
    api = key(cfg, "greynoise")
    if not api:
        return {"ok": False, "nokey": True}
    data, status = http_json(
        "https://api.greynoise.io/v3/community/%s" % ip,
        headers={"key": api},
    )
    if not data or "ip" not in data:
        return {"ok": False, "status": status, "error": (data or {}).get("message")}
    return {
        "ok": True,
        "noise": data.get("noise"),
        "riot": data.get("riot"),
        "classification": data.get("classification"),
        "name": data.get("name"),
        "last_seen": data.get("last_seen"),
        "message": data.get("message"),
    }


def src_virustotal(ip, cfg):
    api = key(cfg, "virustotal")
    if not api:
        return {"ok": False, "nokey": True}
    data, status = http_json(
        "https://www.virustotal.com/api/v3/ip_addresses/%s" % ip,
        headers={"x-apikey": api},
    )
    attrs = ((data or {}).get("data") or {}).get("attributes")
    if not attrs:
        return {"ok": False, "status": status, "error": _vt_err(data)}
    stats = attrs.get("last_analysis_stats") or {}
    flaggers = [
        name for name, res in (attrs.get("last_analysis_results") or {}).items()
        if res.get("category") in ("malicious", "suspicious")
    ]
    return {
        "ok": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner"),
        "network": attrs.get("network"),
        "vendors": sorted(flaggers)[:10],
        "votes": attrs.get("total_votes") or {},
    }


def _vt_err(data):
    err = (data or {}).get("error") or {}
    return err.get("message") or err.get("code")


def src_shodan(ip, cfg):
    api = key(cfg, "shodan")
    if not api:
        return {"ok": False, "nokey": True}
    data, status = http_json(
        "https://api.shodan.io/shodan/host/%s?key=%s&minify=false"
        % (ip, urllib.parse.quote(api))
    )
    if not data or "ip_str" not in data:
        return {"ok": False, "status": status, "error": (data or {}).get("error")}
    services = []
    for item in (data.get("data") or [])[:12]:
        services.append({
            "port": item.get("port"),
            "transport": item.get("transport"),
            "product": item.get("product"),
            "version": item.get("version"),
            "banner": (item.get("data") or "").strip().splitlines()[:1],
        })
    return {
        "ok": True,
        "ports": sorted(data.get("ports") or []),
        "vulns": sorted(list(data.get("vulns") or [])),
        "tags": data.get("tags") or [],
        "os": data.get("os"),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "hostnames": data.get("hostnames") or [],
        "last_update": (data.get("last_update") or "")[:10],
        "services": services,
    }


def src_censys(ip, cfg):
    api = key(cfg, "censys")
    if not api or ":" not in api:
        return {"ok": False, "nokey": True}
    token = base64.b64encode(api.encode()).decode()
    data, status = http_json(
        "https://search.censys.io/api/v2/hosts/%s" % ip,
        headers={"Authorization": "Basic %s" % token},
    )
    result = ((data or {}).get("result") or {})
    if not result:
        return {"ok": False, "status": status, "error": (data or {}).get("error")}
    services = []
    for svc in result.get("services") or []:
        services.append({
            "port": svc.get("port"),
            "service": svc.get("service_name"),
            "transport": svc.get("transport_protocol"),
            "software": ", ".join(
                filter(None, [
                    (s.get("product") or "") + " " + (s.get("version") or "")
                    for s in (svc.get("software") or [])
                ])
            ).strip(),
        })
    loc = result.get("location") or {}
    autosys = result.get("autonomous_system") or {}
    return {
        "ok": True,
        "services": services[:14],
        "service_count": len(result.get("services") or []),
        "country": loc.get("country"),
        "city": loc.get("city"),
        "asn": autosys.get("asn"),
        "as_name": autosys.get("name"),
        "as_desc": autosys.get("description"),
        "os": (result.get("operating_system") or {}).get("product"),
        "dns": ((result.get("dns") or {}).get("reverse_dns") or {}).get("names") or [],
    }


def src_securitytrails(ip, cfg):
    api = key(cfg, "securitytrails")
    if not api:
        return {"ok": False, "nokey": True}
    payload = json.dumps({"filter": {"ipv4": ip}}).encode()
    data, status = http_json(
        "https://api.securitytrails.com/v1/domains/list?include_ips=false&page=1",
        headers={"APIKEY": api, "Content-Type": "application/json"},
        data=payload,
        method="POST",
    )
    if not data or "records" not in data:
        return {"ok": False, "status": status, "error": (data or {}).get("message")}
    domains = []
    for rec in (data.get("records") or [])[:25]:
        domains.append(rec.get("hostname") or rec.get("host_provider") or "")
    return {
        "ok": True,
        "total": data.get("record_count", {}).get("value") if isinstance(
            data.get("record_count"), dict) else data.get("record_count", len(domains)),
        "domains": [d for d in domains if d][:20],
    }


SOURCES = [
    ("rdap", "RDAP registry", src_rdap, False),
    ("geo", "ipwho.is geo/ASN", src_geo, False),
    ("rdns", "Reverse DNS", src_rdns, False),
    ("internetdb", "Shodan InternetDB", src_internetdb, False),
    ("dnsbl", "DNSBL x5", src_dnsbl, False),
    ("tor", "Tor exit list", src_tor, False),
    ("urlscan", "URLScan", src_urlscan, False),
    ("abuseipdb", "AbuseIPDB", src_abuseipdb, True),
    ("greynoise", "GreyNoise", src_greynoise, True),
    ("virustotal", "VirusTotal", src_virustotal, True),
    ("shodan", "Shodan full", src_shodan, True),
    ("censys", "Censys", src_censys, True),
    ("securitytrails", "SecurityTrails", src_securitytrails, True),
]


# ---------------------------------------------------------------- verdict

def score_target(res):
    """Return dict with score 0-100, verdict, reasons list."""
    score = 0
    reasons = []
    src = res["sources"]

    abuse = src.get("abuseipdb") or {}
    if abuse.get("ok"):
        conf = abuse.get("score") or 0
        if conf:
            add = round(conf * 0.45)
            score += add
            cats = ", ".join(c["name"] for c in abuse.get("categories") or [])
            reasons.append((add, "AbuseIPDB confidence %d%% from %d reports%s"
                            % (conf, abuse.get("reports", 0),
                               " (%s)" % cats if cats else "")))
        if abuse.get("whitelisted"):
            score -= 15
            reasons.append((-15, "AbuseIPDB whitelisted"))

    vt = src.get("virustotal") or {}
    if vt.get("ok"):
        mal, susp = vt.get("malicious", 0), vt.get("suspicious", 0)
        if mal:
            add = min(30, mal * 8)
            score += add
            named = ", ".join((vt.get("vendors") or [])[:3])
            reasons.append((add, "VirusTotal %d vendors flag malicious%s"
                            % (mal, " (%s)" % named if named else "")))
        if susp:
            add = min(10, susp * 3)
            score += add
            reasons.append((add, "VirusTotal %d vendors flag suspicious" % susp))
        if (vt.get("reputation") or 0) < -10:
            score += 5
            reasons.append((5, "VirusTotal community reputation %d" % vt["reputation"]))

    dnsbl = src.get("dnsbl") or {}
    hits = dnsbl.get("listed") or []
    if hits:
        add = min(30, 10 * len(hits))
        score += add
        reasons.append((add, "Listed on %d blocklist(s): %s"
                        % (len(hits), ", ".join(h["list"] for h in hits))))

    tor = src.get("tor") or {}
    if tor.get("exit_node"):
        score += 15
        reasons.append((15, "Active Tor exit node"))

    gn = src.get("greynoise") or {}
    riot = False
    if gn.get("ok"):
        cls = (gn.get("classification") or "").lower()
        if cls == "malicious":
            score += 30
            reasons.append((30, "GreyNoise classifies as malicious scanner (%s)"
                            % (gn.get("name") or "unknown actor")))
        elif cls == "suspicious":
            score += 12
            reasons.append((12, "GreyNoise classifies as suspicious"))
        elif cls == "benign" or gn.get("riot"):
            score -= 25
            riot = True
            reasons.append((-25, "GreyNoise benign/RIOT: %s" % (gn.get("name") or "known good service")))
        elif gn.get("noise"):
            score += 5
            reasons.append((5, "GreyNoise sees internet background noise from this IP"))

    idb = src.get("internetdb") or {}
    shodan = src.get("shodan") or {}
    vulns = sorted(set((idb.get("vulns") or []) + (shodan.get("vulns") or [])))
    if vulns:
        add = min(20, 5 * len(vulns))
        score += add
        reasons.append((add, "%d known CVE(s) on exposed services: %s"
                        % (len(vulns), ", ".join(vulns[:4]))))

    ports = sorted(set((idb.get("ports") or []) + (shodan.get("ports") or [])))
    risky = [p for p in ports if p in RISKY_PORTS]
    if risky:
        add = min(16, 4 * len(risky))
        score += add
        reasons.append((add, "Risky services exposed: %s"
                        % ", ".join("%d/%s" % (p, RISKY_PORTS[p]) for p in risky[:6])))

    tags = set((idb.get("tags") or []) + (shodan.get("tags") or []))
    for bad in ("malware", "c2", "compromised", "honeypot", "phishing"):
        if bad in {t.lower() for t in tags}:
            score += 20
            reasons.append((20, "Shodan tag '%s'" % bad))
            break

    us = src.get("urlscan") or {}
    if us.get("ok") and us.get("malicious"):
        add = min(12, 6 * us["malicious"])
        score += add
        reasons.append((add, "URLScan: %d recent page(s) judged malicious on this IP"
                        % us["malicious"]))

    rdns = src.get("rdns") or {}
    if rdns.get("ok") and not rdns.get("ptr") and ports:
        score += 3
        reasons.append((3, "No reverse DNS on a host with open services"))

    if riot:
        score = min(score, 20)

    score = max(0, min(100, int(score)))
    if score >= 60:
        verdict = "MALICIOUS"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    reasons.sort(key=lambda r: -abs(r[0]))
    return {
        "score": score,
        "verdict": verdict,
        "reasons": [{"weight": w, "text": t} for w, t in reasons],
    }


# ---------------------------------------------------------------- runner

def analyse(target, cfg, fresh=False, on_source=None):
    started = time.time()
    ip, hostname, err = resolve_target(target)
    res = {
        "target": target,
        "ip": ip,
        "hostname": hostname,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sources": {},
        "cached": False,
        "errors": [],
    }
    if err or not ip:
        res["errors"].append(err or "resolution failed")
        res["verdict"] = "ERROR"
        res["score"] = 0
        res["reasons"] = [{"weight": 0, "text": err or "resolution failed"}]
        res["elapsed"] = round(time.time() - started, 2)
        return res

    internal = classify_private(ip)
    if internal:
        res["verdict"] = "INTERNAL"
        res["score"] = 0
        res["internal_kind"] = internal
        res["reasons"] = [{"weight": 0,
                           "text": "%s address, no external lookups performed" % internal}]
        res["elapsed"] = round(time.time() - started, 2)
        return res

    ck = "v1|%s" % ip
    if not fresh:
        cached, ts = cache_get(ck)
        if cached:
            cached["cached"] = True
            cached["cache_age_h"] = round((time.time() - ts) / 3600, 1)
            cached["target"] = target
            cached["hostname"] = hostname or cached.get("hostname")
            return cached

    pool = futures.ThreadPoolExecutor(max_workers=13)
    pending = {}
    for name, label, fn, keyed in SOURCES:
        if keyed and not key(cfg, "censys" if name == "censys" else name):
            res["sources"][name] = {"ok": False, "nokey": True}
            continue
        pending[pool.submit(fn, ip, cfg)] = (name, label)

    done, not_done = futures.wait(list(pending), timeout=SOURCE_TIMEOUT)
    for fut in done:
        name, label = pending[fut]
        try:
            res["sources"][name] = fut.result()
        except Exception as exc:
            res["sources"][name] = {"ok": False, "error": str(exc)[:120]}
            res["errors"].append("%s failed: %s" % (label, str(exc)[:80]))
        if on_source:
            on_source(name, label)
    for fut in not_done:
        name, label = pending[fut]
        fut.cancel()
        res["sources"][name] = {"ok": False, "timeout": True}
        res["errors"].append("%s timed out after %ds" % (label, SOURCE_TIMEOUT))
        if on_source:
            on_source(name, label)
    pool.shutdown(wait=False)

    res.update(score_target(res))
    res["elapsed"] = round(time.time() - started, 2)
    cache_put(ck, res)
    return res


# ---------------------------------------------------------------- ai

AI_TIMEOUT = 45
OLLAMA_DEFAULT_HOST = "http://127.0.0.1:11434"
OLLAMA_DEFAULT_MODEL = "llama3.2"
GLM_DEFAULT_ENDPOINT = "https://open.bigmodel.cn/api/paas/v4/chat/completions"
GLM_FALLBACK_ENDPOINT = "https://api.z.ai/api/paas/v4/chat/completions"
GLM_DEFAULT_MODEL = "glm-4-flash"

AI_SYSTEM = (
    "You explain IP reputation reports to people who are not security "
    "analysts. Use only the facts you are given. Never invent a detail, a "
    "number or a source. If the report is thin, say the evidence is thin. "
    "Write plain English. No jargon unless you define it in the same "
    "sentence. No markdown, no bullet characters, no headings."
)

AI_INSTRUCTION = (
    "Write three short paragraphs, each two sentences at most, separated by "
    "a blank line.\n"
    "1. What this address is and who runs it.\n"
    "2. What the sources found and why that produced the verdict.\n"
    "3. What the reader should do about it, concretely.\n"
    "Do not repeat the raw numbers back as a list. Explain what they mean."
)


def ai_digest(res):
    """Compact, factual brief for the model. Never send the raw source blob."""
    src = res.get("sources") or {}
    geo = src.get("geo") or {}
    rdap = src.get("rdap") or {}
    rdns = src.get("rdns") or {}
    idb = src.get("internetdb") or {}
    shodan = src.get("shodan") or {}
    abuse = src.get("abuseipdb") or {}
    vt = src.get("virustotal") or {}
    gn = src.get("greynoise") or {}
    dnsbl = src.get("dnsbl") or {}
    tor = src.get("tor") or {}
    urlscan = src.get("urlscan") or {}

    ports = sorted(set((idb.get("ports") or []) + (shodan.get("ports") or [])))
    vulns = sorted(set((idb.get("vulns") or []) + (shodan.get("vulns") or [])))
    risky = [(p, RISKY_PORTS[p]) for p in ports if p in RISKY_PORTS]

    lines = ["Address: %s" % (res.get("ip") or res.get("target"))]
    if res.get("hostname"):
        lines.append("Resolved from hostname: %s" % res["hostname"])
    lines.append("Verdict: %s at %d out of 100 risk"
                 % (res.get("verdict"), res.get("score", 0)))
    if res.get("internal_kind"):
        lines.append("This is a %s address, so no external source was queried."
                     % res["internal_kind"])

    if geo.get("ok"):
        where = ", ".join(filter(None, [geo.get("city"), geo.get("country")]))
        lines.append("Location: %s" % (where or "unknown"))
        if geo.get("asn"):
            lines.append("Network: AS%s %s" % (geo["asn"], geo.get("org") or ""))
    if rdap.get("ok"):
        if rdap.get("name"):
            lines.append("Registry netname: %s" % rdap["name"])
        if rdap.get("abuse"):
            lines.append("Abuse contact: %s" % ", ".join(rdap["abuse"][:2]))
    if rdns.get("ok"):
        lines.append("Reverse DNS: %s" % (rdns.get("ptr") or "none set"))

    if ports:
        lines.append("Open ports: %s" % ", ".join(str(p) for p in ports[:20]))
    if risky:
        lines.append("Sensitive services exposed: %s"
                     % ", ".join("%d %s" % (p, n) for p, n in risky[:8]))
    if vulns:
        lines.append("Known vulnerabilities on those services: %s"
                     % ", ".join(vulns[:8]))

    if abuse.get("ok"):
        lines.append("AbuseIPDB: %d%% abuse confidence from %d reports by %d "
                     "reporters%s"
                     % (abuse.get("score", 0), abuse.get("reports", 0),
                        abuse.get("distinct", 0),
                        ", categories " + ", ".join(
                            c["name"] for c in abuse.get("categories") or [])
                        if abuse.get("categories") else ""))
    if vt.get("ok"):
        lines.append("VirusTotal: %d vendors call it malicious, %d suspicious, "
                     "%d harmless"
                     % (vt.get("malicious", 0), vt.get("suspicious", 0),
                        vt.get("harmless", 0)))
    if gn.get("ok"):
        lines.append("GreyNoise: %s%s"
                     % (gn.get("classification") or ("known good service"
                                                     if gn.get("riot") else "not seen"),
                        ", identified as %s" % gn["name"] if gn.get("name") else ""))
    if dnsbl.get("ok"):
        hits = dnsbl.get("listed") or []
        lines.append("Blocklists: listed on %d of %d checked%s"
                     % (len(hits), dnsbl.get("checked", 0),
                        " (" + ", ".join(h["list"] for h in hits) + ")" if hits else ""))
    if tor.get("ok"):
        lines.append("Tor: %s"
                     % ("this is a published Tor exit node" if tor.get("exit_node")
                        else "not a Tor exit node"))
    if urlscan.get("ok"):
        lines.append("URLScan: %d pages scanned on this address, %d judged malicious"
                     % (urlscan.get("total", 0), urlscan.get("malicious", 0)))

    if res.get("reasons"):
        lines.append("Scoring breakdown:")
        for reason in res["reasons"]:
            lines.append("  %+d %s" % (reason["weight"], reason["text"]))

    skipped = [label for name, label, _fn, keyed in SOURCES
               if keyed and (src.get(name) or {}).get("nokey")]
    if skipped:
        lines.append("Sources with no API key configured, so not consulted: %s"
                     % ", ".join(skipped))
    return "\n".join(lines)


def ollama_host(cfg):
    return (cfg.get("ollama_host") or os.environ.get("OLLAMA_HOST")
            or OLLAMA_DEFAULT_HOST).rstrip("/")


def ollama_up(cfg, timeout=2):
    data, _status = http_json("%s/api/tags" % ollama_host(cfg), timeout=timeout)
    return isinstance(data, dict) and "models" in data


def ollama_models(cfg):
    data, _status = http_json("%s/api/tags" % ollama_host(cfg), timeout=4)
    if not isinstance(data, dict):
        return []
    return [m.get("name") for m in data.get("models") or [] if m.get("name")]


def ai_ollama(prompt, cfg):
    model = (cfg.get("ollama_model") or OLLAMA_DEFAULT_MODEL).strip()
    available = ollama_models(cfg)
    if available and model not in available:
        base = [m for m in available if m.split(":")[0] == model.split(":")[0]]
        model = base[0] if base else available[0]
    body = json.dumps({
        "model": model,
        "stream": False,
        "options": {"temperature": 0.2},
        "messages": [
            {"role": "system", "content": AI_SYSTEM},
            {"role": "user", "content": prompt},
        ],
    }).encode()
    data, status = http_json("%s/api/chat" % ollama_host(cfg), timeout=AI_TIMEOUT,
                             data=body, headers={"Content-Type": "application/json"})
    if not isinstance(data, dict):
        return None, "ollama did not answer (HTTP %s)" % status
    if data.get("error"):
        return None, "ollama: %s" % str(data["error"])[:140]
    text = ((data.get("message") or {}).get("content") or "").strip()
    if not text:
        return None, "ollama returned an empty answer"
    return {"text": text, "backend": "ollama", "model": model}, None


def _glm_jwt(kid, secret):
    def seg(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    now = int(time.time() * 1000)
    head = seg(json.dumps({"alg": "HS256", "sign_type": "SIGN"},
                          separators=(",", ":")).encode())
    load = seg(json.dumps({"api_key": kid, "exp": now + 3600000, "timestamp": now},
                          separators=(",", ":")).encode())
    sig = seg(hmac.new(secret.encode(), ("%s.%s" % (head, load)).encode(),
                       hashlib.sha256).digest())
    return "%s.%s.%s" % (head, load, sig)


def ai_glm(prompt, cfg):
    api = key(cfg, "glm")
    if not api:
        return None, "no GLM API key"
    model = (cfg.get("glm_model") or GLM_DEFAULT_MODEL).strip()
    endpoints = [cfg.get("glm_endpoint") or GLM_DEFAULT_ENDPOINT]
    if GLM_FALLBACK_ENDPOINT not in endpoints:
        endpoints.append(GLM_FALLBACK_ENDPOINT)
    body = json.dumps({
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": AI_SYSTEM},
            {"role": "user", "content": prompt},
        ],
    }).encode()

    tokens = [api]
    if "." in api:
        kid, secret = api.split(".", 1)
        tokens.append(_glm_jwt(kid, secret))

    last = "GLM refused the request"
    for endpoint in endpoints:
        for token in tokens:
            data, status = http_json(
                endpoint, timeout=AI_TIMEOUT, data=body,
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer %s" % token})
            choices = (data or {}).get("choices") or []
            if choices:
                text = ((choices[0].get("message") or {}).get("content") or "").strip()
                if text:
                    return {"text": text, "backend": "glm", "model": model}, None
            err = ((data or {}).get("error") or {})
            detail = err.get("message") or (data or {}).get("message")
            last = "GLM %s: %s" % (status, detail or "no answer")
            if status and status not in (401, 403):
                return None, last
    return None, last


def ai_backends(cfg):
    """Which backend to try, in order, for the configured preference."""
    pref = (cfg.get("ai_backend") or os.environ.get("DRISHTI_AI_BACKEND")
            or "auto").strip().lower()
    if pref == "off":
        return []
    if pref in ("ollama", "glm"):
        return [pref]
    order = []
    if ollama_up(cfg):
        order.append("ollama")
    if key(cfg, "glm"):
        order.append("glm")
    if not order:
        order.append("ollama")
    return order


def explain(res, cfg, fresh=False):
    """Plain English reading of a finished report. Returns the result dict."""
    order = ai_backends(cfg)
    if not order:
        return {"ok": False, "error": "AI summary is switched off"}

    prompt = "%s\n\n%s" % (ai_digest(res), AI_INSTRUCTION)
    ck = "ai|%s|%s|%s" % (",".join(order), res.get("ip") or res.get("target"),
                          res.get("score", 0))
    if not fresh:
        cached, ts = cache_get(ck)
        if cached:
            cached["cached"] = True
            cached["cache_age_h"] = round((time.time() - ts) / 3600, 1)
            return cached

    problems = []
    for backend in order:
        started = time.time()
        out, err = (ai_ollama if backend == "ollama" else ai_glm)(prompt, cfg)
        if out:
            out["ok"] = True
            out["cached"] = False
            out["elapsed"] = round(time.time() - started, 2)
            if problems:
                out["fell_back_from"] = problems
            cache_put(ck, out)
            return out
        problems.append(err)
    return {"ok": False, "error": "; ".join(problems),
            "hint": "start Ollama with 'ollama serve' and pull a model, "
                    "or add a GLM key with --keys"}


# ---------------------------------------------------------------- render

VERDICT_COLOUR = {
    "MALICIOUS": (C.RED, C.BG_RED),
    "SUSPICIOUS": (C.ORANGE, C.BG_ORANGE),
    "BENIGN": (C.GREEN, C.BG_GREEN),
    "INTERNAL": (C.BLUE, C.BG_BLUE),
    "ERROR": (C.GREY, C.BG_RED),
}


def width():
    try:
        return min(100, max(60, os.get_terminal_size().columns))
    except Exception:
        return 78


def rule(char="-"):
    return paint(C.GREY, char * width())


def head(text):
    return paint(C.NIDO + C.BOLD, text)


def kv(label, value, colour=None):
    if value in (None, "", [], {}):
        return
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    lab = paint(C.GREY, ("%-13s" % label)[:13])
    print("  %s %s" % (lab, paint(colour, value) if colour else value))


def bar(score):
    span = min(30, max(12, width() // 3))
    filled = int(round(span * score / 100.0))
    if score >= 60:
        col = C.RED
    elif score >= 25:
        col = C.ORANGE
    else:
        col = C.GREEN
    return paint(col, "#" * filled) + paint(C.GREY, "." * (span - filled))


def render(res, cfg):
    print()
    print(rule("="))
    title = res.get("ip") or res["target"]
    if res.get("hostname") and res.get("ip"):
        title = "%s  ->  %s" % (res["hostname"], res["ip"])
    print(" %s  %s" % (head("DRISHTI"), paint(C.BOLD, title)))
    print(rule("="))

    verdict = res.get("verdict", "ERROR")
    fg, bg = VERDICT_COLOUR.get(verdict, (C.GREY, C.BG_RED))
    badge = paint(bg + C.BOLD, " %s " % verdict)
    print()
    print("  %s   score %s/100  %s" % (badge, paint(fg + C.BOLD, res.get("score", 0)), bar(res.get("score", 0))))
    if res.get("cached"):
        print("  %s" % paint(C.GREY, "cached result, %.1fh old, use --fresh to re-query"
                             % res.get("cache_age_h", 0)))
    print()

    for reason in res.get("reasons", []):
        weight = reason["weight"]
        if weight > 0:
            mark, col = "+%-3d" % weight, C.RED if weight >= 15 else C.YELLOW
        elif weight < 0:
            mark, col = "%-4d" % weight, C.GREEN
        else:
            mark, col = "    ", C.GREY
        print("  %s %s" % (paint(col, mark), reason["text"]))
    if res.get("reasons"):
        print()

    if res.get("ai"):
        render_ai(res["ai"])

    if verdict in ("INTERNAL", "ERROR"):
        print(rule())
        return

    src = res["sources"]

    geo = src.get("geo") or {}
    rdap = src.get("rdap") or {}
    if geo.get("ok") or rdap.get("ok"):
        print(head("  OWNERSHIP AND LOCATION"))
        if geo.get("ok"):
            loc = ", ".join(filter(None, [geo.get("city"), geo.get("region"), geo.get("country")]))
            kv("Location", "%s %s" % (geo.get("flag") or "", loc))
            kv("ASN", "AS%s  %s" % (geo.get("asn"), geo.get("org") or ""))
            kv("ISP", geo.get("isp"))
            kv("Timezone", geo.get("timezone"))
        if rdap.get("ok"):
            kv("Registry", rdap.get("registry"))
            kv("Netname", rdap.get("name"))
            if rdap.get("handle") and rdap.get("handle") != rdap.get("range"):
                kv("Handle", rdap.get("handle"))
            kv("Range", rdap.get("range"))
            kv("Allocated", (rdap.get("events") or {}).get("registration"))
            kv("Abuse", rdap.get("abuse"), C.ORANGE)
        print()

    rdns = src.get("rdns") or {}
    idb = src.get("internetdb") or {}
    shodan = src.get("shodan") or {}
    censys = src.get("censys") or {}
    names = set(filter(None, [rdns.get("ptr")]))
    names.update(idb.get("hostnames") or [])
    names.update(shodan.get("hostnames") or [])
    names.update(censys.get("dns") or [])
    ports = sorted(set((idb.get("ports") or []) + (shodan.get("ports") or [])))
    vulns = sorted(set((idb.get("vulns") or []) + (shodan.get("vulns") or [])))
    if names or ports or vulns:
        print(head("  SURFACE"))
        kv("Reverse DNS", rdns.get("ptr") or paint(C.GREY, "none"))
        if names - {rdns.get("ptr")}:
            kv("Hostnames", sorted(names - {rdns.get("ptr")})[:6])
        if ports:
            shown = []
            for port in ports[:24]:
                shown.append(paint(C.RED, "%d" % port) if port in RISKY_PORTS else str(port))
            kv("Open ports", "%s%s" % (" ".join(shown), " ..." if len(ports) > 24 else ""))
        if vulns:
            kv("CVEs", vulns[:10], C.RED)
        tags = sorted(set((idb.get("tags") or []) + (shodan.get("tags") or [])))
        kv("Tags", tags)
        if shodan.get("ok"):
            for svc in shodan.get("services") or []:
                desc = " ".join(filter(None, [svc.get("product"), svc.get("version")]))
                if desc:
                    kv("  %d/%s" % (svc["port"], svc.get("transport") or "tcp"), desc)
        elif censys.get("ok"):
            for svc in censys.get("services") or []:
                if svc.get("software"):
                    kv("  %s/%s" % (svc.get("port"), svc.get("service") or ""), svc["software"])
        print()

    print(head("  REPUTATION"))
    abuse = src.get("abuseipdb") or {}
    if abuse.get("ok"):
        conf = abuse.get("score", 0)
        col = C.RED if conf >= 50 else (C.YELLOW if conf else C.GREEN)
        kv("AbuseIPDB", "%d%% confidence, %d reports from %d sources"
           % (conf, abuse.get("reports", 0), abuse.get("distinct", 0)), col)
        if abuse.get("categories"):
            kv("  categories", ["%s x%d" % (c["name"], c["n"]) for c in abuse["categories"]])
        kv("  last report", abuse.get("last") or "")
        kv("  usage type", abuse.get("usage"))
    else:
        kv("AbuseIPDB", _skip(abuse), C.GREY)

    vt = src.get("virustotal") or {}
    if vt.get("ok"):
        col = C.RED if vt.get("malicious") else (C.YELLOW if vt.get("suspicious") else C.GREEN)
        kv("VirusTotal", "%d malicious / %d suspicious / %d harmless, reputation %d"
           % (vt.get("malicious", 0), vt.get("suspicious", 0), vt.get("harmless", 0),
              vt.get("reputation", 0)), col)
        kv("  flagged by", vt.get("vendors"))
    else:
        kv("VirusTotal", _skip(vt), C.GREY)

    gn = src.get("greynoise") or {}
    if gn.get("ok"):
        cls = gn.get("classification") or ("riot" if gn.get("riot") else "unseen")
        col = C.RED if cls == "malicious" else (C.GREEN if cls in ("benign", "riot") else C.YELLOW)
        kv("GreyNoise", "%s%s%s" % (cls,
                                    " - %s" % gn["name"] if gn.get("name") else "",
                                    ", last seen %s" % gn["last_seen"] if gn.get("last_seen") else ""), col)
    else:
        kv("GreyNoise", _skip(gn), C.GREY)

    dnsbl = src.get("dnsbl") or {}
    if dnsbl.get("ok"):
        hits = dnsbl.get("listed") or []
        kv("DNSBL", "%d of %d lists" % (len(hits), dnsbl.get("checked", 0)) +
           (": " + ", ".join(h["list"] for h in hits) if hits else " clean"),
           C.RED if hits else C.GREEN)
    tor = src.get("tor") or {}
    if tor.get("ok"):
        kv("Tor", "EXIT NODE" if tor.get("exit_node") else "not an exit node",
           C.RED if tor.get("exit_node") else C.GREEN)
    us = src.get("urlscan") or {}
    if us.get("ok"):
        kv("URLScan", "%d scan(s) on this IP, %d malicious" % (us.get("total", 0), us.get("malicious", 0)),
           C.RED if us.get("malicious") else C.GREY)
        for item in (us.get("results") or [])[:4]:
            kv("  %s" % (item.get("date") or ""), item.get("url"),
               C.RED if item.get("malicious") else None)
    st = src.get("securitytrails") or {}
    if st.get("ok"):
        kv("Hosted domains", "%s: %s" % (st.get("total"), ", ".join(st.get("domains") or [])[:200]))
    for name, label in (("shodan", "Shodan"), ("censys", "Censys"),
                        ("securitytrails", "SecurityTrails")):
        node = src.get(name) or {}
        if not node.get("ok") and not node.get("nokey"):
            kv(label, _skip(node), C.GREY)
    print()

    missing = [label for name, label, _, keyed in SOURCES
               if keyed and (src.get(name) or {}).get("nokey")]
    ran = sum(1 for name, *_ in SOURCES if (src.get(name) or {}).get("ok"))
    print(rule())
    line = "  %d of %d sources answered in %ss" % (ran, len(SOURCES), res.get("elapsed", 0))
    print(paint(C.GREY, line))
    if missing:
        print(paint(C.GREY, "  no API key: %s   (run --keys to add)" % ", ".join(missing)))
    if res.get("errors"):
        print(paint(C.GREY, "  notes: %s" % "; ".join(res["errors"][:4])))
    print()


def wrap(text, indent="  "):
    limit = max(40, width() - len(indent) - 2)
    out = []
    for para in text.split("\n"):
        para = para.strip()
        if not para:
            out.append("")
            continue
        line = ""
        for word in para.split():
            if line and len(line) + 1 + len(word) > limit:
                out.append(indent + line)
                line = word
            else:
                line = "%s %s" % (line, word) if line else word
        if line:
            out.append(indent + line)
    return "\n".join(out)


def render_ai(node):
    print(head("  IN PLAIN ENGLISH"))
    if not node.get("ok"):
        print(paint(C.GREY, wrap(node.get("error") or "no summary available")))
        if node.get("hint"):
            print(paint(C.GREY, wrap(node["hint"])))
        print()
        return
    print(wrap(node.get("text") or ""))
    tail = "%s via %s" % (node.get("model", "?"), node.get("backend", "?"))
    if node.get("cached"):
        tail += ", cached %.1fh ago" % node.get("cache_age_h", 0)
    elif node.get("elapsed"):
        tail += ", %ss" % node["elapsed"]
    print()
    print(paint(C.GREY, "  %s" % tail))
    print()


def _skip(node):
    if node.get("nokey"):
        return "no API key"
    if node.get("timeout"):
        return "timed out"
    if node.get("error"):
        err = str(node["error"])
        return "error: %s" % (err[:90] + "..." if len(err) > 90 else err)
    if node.get("status"):
        return "unavailable (HTTP %s)" % node["status"]
    return "unavailable"


def render_summary(results):
    order = {"MALICIOUS": 0, "SUSPICIOUS": 1, "ERROR": 2, "INTERNAL": 3, "BENIGN": 4}
    rows = sorted(results, key=lambda r: (order.get(r.get("verdict"), 9), -r.get("score", 0)))
    print()
    print(rule("="))
    print(" %s  %d targets" % (head("SUMMARY"), len(rows)))
    print(rule("="))
    print(paint(C.GREY, "  %-3s %-19s %-11s %5s  %-8s %s"
                % ("#", "IP", "VERDICT", "SCORE", "COUNTRY", "TOP REASON")))
    for i, res in enumerate(rows, 1):
        fg, _ = VERDICT_COLOUR.get(res.get("verdict"), (C.GREY, ""))
        geo = (res.get("sources") or {}).get("geo") or {}
        country = geo.get("country_code") or ("-" if res.get("verdict") != "INTERNAL" else "LAN")
        reasons = res.get("reasons") or []
        top = reasons[0]["text"] if reasons else "nothing notable"
        avail = max(20, width() - 52)
        print("  %-3d %-19s %s %5s  %-8s %s"
              % (i, (res.get("ip") or res["target"])[:19],
                 paint(fg + C.BOLD, "%-11s" % res.get("verdict", "?")),
                 res.get("score", 0), country, top[:avail]))
    print(rule())
    counts = {}
    for res in rows:
        counts[res.get("verdict")] = counts.get(res.get("verdict"), 0) + 1
    parts = []
    for verdict in ("MALICIOUS", "SUSPICIOUS", "BENIGN", "INTERNAL", "ERROR"):
        if counts.get(verdict):
            fg, _ = VERDICT_COLOUR[verdict]
            parts.append(paint(fg, "%d %s" % (counts[verdict], verdict.lower())))
    print("  " + "   ".join(parts))
    print()


# ---------------------------------------------------------------- keys ui

def manage_keys(cfg):
    print()
    print(rule("="))
    print(" %s  %s" % (head("API KEYS"), paint(C.GREY, cfg.get("_path"))))
    print(rule("="))
    print(paint(C.GREY, "  Enter to keep current, '-' to clear, then Enter through the rest."))
    print()
    stopped = False
    for name, label, url in KEY_FIELDS + AI_FIELDS:
        if name == AI_FIELDS[0][0]:
            print(head("  AI SUMMARY"))
        current = cfg.get(name) or ""
        shown = (current[:4] + "*" * max(0, len(current) - 8) + current[-4:]) if len(current) > 8 \
            else ("set" if current else paint(C.GREY, "not set"))
        print("  %s  %s" % (paint(C.BOLD, "%-26s" % label), shown))
        print("  %s" % paint(C.GREY, url))
        try:
            entered = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            stopped = True
            break
        if entered == "-":
            cfg[name] = ""
        elif entered:
            cfg[name] = entered
        print()

    if not stopped:
        for name, label, default in AI_SETTINGS:
            current = cfg.get(name) or ""
            print("  %s  %s" % (paint(C.BOLD, "%-26s" % label),
                                current or paint(C.GREY, "default %s" % default)))
            try:
                entered = input("  > ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if entered == "-":
                cfg.pop(name, None)
            elif entered:
                cfg[name] = entered
            print()

    path = save_config(cfg)
    print(paint(C.GREEN, "  Saved to %s" % path))
    active = [lbl for nm, lbl, _ in KEY_FIELDS if cfg.get(nm)]
    print(paint(C.GREY, "  Sources: %s" % (", ".join(active) if active else "none, keyless tier only")))
    if ollama_up(cfg):
        models = ollama_models(cfg)
        print(paint(C.GREY, "  Ollama:  up at %s, models %s"
                    % (ollama_host(cfg), ", ".join(models[:6]) or "none pulled yet")))
    else:
        print(paint(C.GREY, "  Ollama:  not reachable at %s" % ollama_host(cfg)))
    print(paint(C.GREY, "  AI:      %s" % (", ".join(ai_backends(cfg)) or "off")))
    print()


def my_ip():
    for url, field in (("https://ipwho.is/", "ip"),
                       ("https://api.ipify.org?format=json", "ip")):
        data, _ = http_json(url, timeout=6)
        if data and data.get(field):
            return data[field]
    return None


# ---------------------------------------------------------------- main

def read_targets(path):
    out = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.split("#")[0].strip()
            if not line:
                continue
            out.extend(p for p in re.split(r"[,\s]+", line) if p)
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="Drishti_cli.py",
        description="Drishti %s - IP and host intelligence from 13 sources." % VERSION,
        epilog="Keyless sources always run. Add keys with --keys for the full picture.",
    )
    parser.add_argument("targets", nargs="*", help="IP addresses or hostnames")
    parser.add_argument("--me", action="store_true", help="look up your own public IP")
    parser.add_argument("--keys", action="store_true", help="add or update API keys")
    parser.add_argument("--json", action="store_true", help="raw JSON output, no colour")
    parser.add_argument("--fresh", action="store_true", help="bypass the 24 hour cache")
    parser.add_argument("--ai", action="store_true",
                        help="add a plain English summary from Ollama or GLM")
    parser.add_argument("--ai-backend", choices=["auto", "ollama", "glm", "off"],
                        help="force which AI backend --ai uses")
    parser.add_argument("-f", "--file", help="file of targets, one per line")
    parser.add_argument("--no-colour", action="store_true", help="disable ANSI colour")
    parser.add_argument("--version", action="version", version="%s %s" % (APP, VERSION))
    args = parser.parse_args(argv)

    if args.no_colour or args.json:
        C.on = False

    cfg = load_config()

    if args.keys:
        manage_keys(cfg)
        return 0

    targets = list(args.targets)
    if args.file:
        try:
            targets.extend(read_targets(args.file))
        except OSError as exc:
            print(paint(C.RED, "cannot read %s: %s" % (args.file, exc)), file=sys.stderr)
            return 2
    if args.me:
        mine = my_ip()
        if not mine:
            print(paint(C.RED, "could not determine your public IP"), file=sys.stderr)
            return 2
        targets.insert(0, mine)
    if not targets:
        parser.print_help()
        return 1

    seen, ordered = set(), []
    for tgt in targets:
        if tgt not in seen:
            seen.add(tgt)
            ordered.append(tgt)

    results = []
    if not args.json and len(ordered) > 1:
        print(paint(C.GREY, "\n  querying %d targets ..." % len(ordered)))
    workers = min(6, len(ordered))
    if workers > 1:
        with futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda t: analyse(t, cfg, args.fresh), ordered))
    else:
        results = [analyse(ordered[0], cfg, args.fresh)]

    if args.ai:
        if args.ai_backend:
            cfg["ai_backend"] = args.ai_backend
        if not args.json:
            print(paint(C.GREY, "  writing the plain English summary ..."))
        explainable = [r for r in results if r.get("verdict") not in ("ERROR",)]
        if explainable:
            with futures.ThreadPoolExecutor(max_workers=min(4, len(explainable))) as pool:
                for res, node in zip(explainable,
                                     pool.map(lambda r: explain(r, cfg, args.fresh),
                                              explainable)):
                    res["ai"] = node

    if args.json:
        payload = results[0] if len(results) == 1 else results
        print(json.dumps(payload, indent=2, default=str))
        return 0

    for res in results:
        render(res, cfg)
    if len(results) > 1:
        render_summary(results)

    if any(r.get("verdict") == "ERROR" for r in results):
        return 3
    worst = max((r.get("score", 0) for r in results), default=0)
    return 0 if worst < 25 else (1 if worst < 60 else 2)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
