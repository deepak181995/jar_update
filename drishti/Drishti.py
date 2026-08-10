#!/usr/bin/env python3
"""
Drishti - IP and host intelligence, 13 sources, one screen.

Single file Flask app for macOS. Start it and it opens itself:

    pip3 install flask
    python3 Drishti.py

Serves on http://127.0.0.1:5055 and walks forward if that port is busy.
API keys live in drishti_config.json next to this file. Results are cached
in drishti_cache.db for 24 hours.

Every report has an Explain button that turns the findings into plain English
using a local Ollama model, or GLM in the cloud when Ollama is not running.
"""

import base64
import concurrent.futures as futures
import csv
import hashlib
import hmac
import io
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
import webbrowser

try:
    from flask import Flask, Response, jsonify, request
except ImportError:
    sys.stderr.write(
        "Drishti needs Flask.\n\n    pip3 install flask\n\n"
        "Then run this file again.\n"
    )
    raise SystemExit(1)

APP = "Drishti"
VERSION = "1.0"
HTTP_TIMEOUT = 8
SOURCE_TIMEOUT = 12
CACHE_TTL = 24 * 3600
TOR_TTL = 6 * 3600
UA = "Drishti/1.0 (+ip-intel-web)"

DEFAULT_PORT = 5055
PORT_TRIES = 20
BULK_LIMIT = 256
BULK_WORKERS = 8

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


# ---------------------------------------------------------------- key check

# A benign, always-present address to validate a key against. Cheap for every
# provider and never itself interesting.
PROBE_IP = "8.8.8.8"


# Two providers answer their lookup endpoint without checking the key at all:
# Shodan serves /shodan/host and GreyNoise serves the v3 community tier openly.
# Validating against those would call any string a working key, so the check
# uses an endpoint that genuinely authenticates instead.
VALIDATE_VIA = {
    "shodan": lambda cfg: http_raw(
        "https://api.shodan.io/api-info?key=%s"
        % urllib.parse.quote(key(cfg, "shodan")), timeout=12),
    "greynoise": lambda cfg: http_raw(
        "https://api.greynoise.io/v2/riot/%s" % PROBE_IP,
        headers={"key": key(cfg, "greynoise")}, timeout=12),
}


def classify_key_result(node):
    """Turn a source result into a verdict about the key behind it."""
    if node.get("nokey"):
        return "unset", "no key configured"
    if node.get("ok"):
        return "works", "authenticated and returned data"
    if node.get("timeout"):
        return "unknown", "timed out, try again"
    status = node.get("status")
    detail = str(node.get("error") or "")[:110]
    if status in (401, 403):
        return "bad", detail or "rejected, HTTP %s" % status
    if status == 429:
        return "limited", detail or "rate limited, the key itself may be fine"
    if status:
        return "unknown", detail or "HTTP %s" % status
    return "unknown", detail or "no response"


def _auth_detail(body):
    """Pull a human message out of a validation response, JSON or HTML."""
    if not body:
        return ""
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            for field in ("message", "error", "detail"):
                if data.get(field):
                    return str(data[field])[:110]
    except Exception:
        pass
    match = re.search(r"<title>(.*?)</title>", body, re.S | re.I)
    if match:
        return match.group(1).strip()[:110]
    return body.strip().splitlines()[0][:110] if body.strip() else ""


def check_keys(cfg):
    """Validate every configured credential against its own API.

    Uses the real source function wherever that endpoint authenticates, and a
    dedicated endpoint for the two providers that answer without a key.
    """
    keyed = [(name, label, fn) for name, label, fn, is_keyed in SOURCES if is_keyed]
    out = []

    def probe(item):
        name, label, fn = item
        started = time.time()
        try:
            if not key(cfg, name):
                node = {"ok": False, "nokey": True}
            elif name in VALIDATE_VIA:
                body, status = VALIDATE_VIA[name](cfg)
                node = ({"ok": True} if status == 200
                        else {"ok": False, "status": status,
                              "error": _auth_detail(body)})
            else:
                node = fn(PROBE_IP, cfg)
        except Exception as exc:
            node = {"ok": False, "error": str(exc)[:110]}
        state, detail = classify_key_result(node)
        return {"id": name, "label": label, "state": state, "detail": detail,
                "elapsed": round(time.time() - started, 2)}

    with futures.ThreadPoolExecutor(max_workers=len(keyed)) as pool:
        out.extend(pool.map(probe, keyed))

    # The AI credentials are not sources, so they are checked separately.
    if ollama_up(cfg):
        models = ollama_models(cfg)
        out.append({"id": "ollama", "label": "Ollama (local AI)",
                    "state": "works" if models else "limited",
                    "detail": "%d model(s) at %s" % (len(models), ollama_host(cfg))
                              if models else "running but no model pulled, "
                                             "run: ollama pull llama3.2",
                    "elapsed": 0})
    else:
        out.append({"id": "ollama", "label": "Ollama (local AI)", "state": "unset",
                    "detail": "not running at %s" % ollama_host(cfg), "elapsed": 0})

    if key(cfg, "glm"):
        started = time.time()
        node, err = ai_glm("Reply with the single word: ok", cfg)
        if node:
            state, detail = "works", "answered with %s" % node.get("model")
        elif err and ("401" in err or "403" in err or "Authentication" in err):
            state, detail = "bad", err[:110]
        elif err and "429" in err:
            state, detail = "limited", err[:110]
        else:
            state, detail = "unknown", (err or "no answer")[:110]
        out.append({"id": "glm", "label": "GLM (cloud AI)", "state": state,
                    "detail": detail, "elapsed": round(time.time() - started, 2)})
    else:
        out.append({"id": "glm", "label": "GLM (cloud AI)", "state": "unset",
                    "detail": "no key configured", "elapsed": 0})
    return out


# ---------------------------------------------------------------- page

PAGE = r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Drishti</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270 0 32 32%27%3E%3Crect width=%2732%27 height=%2732%27 rx=%277%27 fill=%27%230c0d0f%27/%3E%3Ccircle cx=%2716%27 cy=%2716%27 r=%279%27 fill=%27none%27 stroke=%27%23C94B22%27 stroke-width=%272.5%27/%3E%3Ccircle cx=%2716%27 cy=%2716%27 r=%273%27 fill=%27%23C94B22%27/%3E%3C/svg%3E">
<style>
:root{
  --bg:#0c0d0f; --panel:#141619; --panel2:#1b1e23; --panel3:#22262c;
  --line:#2b3038; --line2:#3a404a;
  --ink:#e9e7e4; --ink2:#a8aeb8; --ink3:#767d88;
  --nido:#C94B22; --nido-soft:rgba(201,75,34,.16); --nido-line:rgba(201,75,34,.45);
  --bad:#e45a45; --warn:#d9922b; --good:#43b581; --info:#4f8ff0;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Helvetica,Arial,sans-serif;
  --r:10px;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--ink); font-family:var(--sans);
  font-size:14px; line-height:1.5; -webkit-font-smoothing:antialiased;
}
a{color:var(--nido); text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1180px; margin:0 auto; padding:0 22px 70px}

header.top{
  border-bottom:1px solid var(--line); background:linear-gradient(180deg,#131519,#0c0d0f);
  position:sticky; top:0; z-index:20;
}
.topin{max-width:1180px;margin:0 auto;padding:14px 22px;display:flex;align-items:center;gap:14px}
.brand{display:flex;align-items:baseline;gap:10px}
.mark{
  font-size:21px;font-weight:700;letter-spacing:.16em;color:var(--nido);
}
.mark span{color:var(--ink)}
.tag{color:var(--ink3);font-size:12px;letter-spacing:.04em}
.spacer{flex:1}
button,.btn{
  font:inherit; cursor:pointer; border-radius:8px; border:1px solid var(--line2);
  background:var(--panel2); color:var(--ink); padding:8px 14px; transition:.14s;
}
button:hover,.btn:hover{background:var(--panel3);border-color:var(--ink3)}
button:disabled{opacity:.45;cursor:not-allowed}
button.primary{background:var(--nido);border-color:var(--nido);color:#fff;font-weight:600}
button.primary:hover{background:#dd5527;border-color:#dd5527}
button.ghost{background:transparent}
button.sm{padding:6px 11px;font-size:12.5px}

nav.tabs{display:flex;gap:2px;border-bottom:1px solid var(--line);margin:22px 0 24px}
nav.tabs button{
  background:none;border:none;border-bottom:2px solid transparent;border-radius:0;
  color:var(--ink3);padding:11px 18px;font-size:14px;font-weight:500;
}
nav.tabs button:hover{color:var(--ink2);background:none}
nav.tabs button.on{color:var(--ink);border-bottom-color:var(--nido)}
.panel{display:none}
.panel.on{display:block}

.searchbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input[type=text],textarea{
  font:inherit;background:var(--panel);border:1px solid var(--line);color:var(--ink);
  border-radius:8px;padding:11px 13px;outline:none;width:100%;
}
input[type=text]:focus,textarea:focus{border-color:var(--nido-line);box-shadow:0 0 0 3px var(--nido-soft)}
input[type=text]{flex:1;min-width:260px;font-family:var(--mono);font-size:13.5px}
textarea{font-family:var(--mono);font-size:13px;min-height:170px;resize:vertical}
.check{display:flex;align-items:center;gap:7px;color:var(--ink2);font-size:13px;cursor:pointer;user-select:none;white-space:nowrap}
.check input{accent-color:var(--nido);width:15px;height:15px}
.hint{color:var(--ink3);font-size:12.5px;margin-top:9px}

.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);margin-top:20px;overflow:hidden}
.card > h3{
  margin:0;padding:11px 16px;font-size:11.5px;letter-spacing:.13em;text-transform:uppercase;
  color:var(--ink3);border-bottom:1px solid var(--line);background:var(--panel2);font-weight:600;
}
.card .body{padding:16px}

.verdictbar{display:flex;align-items:center;gap:18px;flex-wrap:wrap;padding:18px 16px}
.badge{
  font-weight:700;letter-spacing:.1em;font-size:13px;padding:9px 18px;border-radius:8px;
  border:1px solid; white-space:nowrap;
}
.v-MALICIOUS{color:var(--bad);background:rgba(228,90,69,.13);border-color:rgba(228,90,69,.45)}
.v-SUSPICIOUS{color:var(--warn);background:rgba(217,146,43,.13);border-color:rgba(217,146,43,.45)}
.v-BENIGN{color:var(--good);background:rgba(67,181,129,.13);border-color:rgba(67,181,129,.42)}
.v-INTERNAL{color:var(--info);background:rgba(79,143,240,.13);border-color:rgba(79,143,240,.42)}
.v-ERROR{color:var(--ink3);background:var(--panel2);border-color:var(--line2)}
.scorewrap{flex:1;min-width:220px}
.scorenum{font-family:var(--mono);font-size:24px;font-weight:700;line-height:1}
.scorenum small{font-size:12px;color:var(--ink3);font-weight:400}
.meter{height:7px;border-radius:4px;background:var(--panel3);overflow:hidden;margin-top:9px}
.meter i{display:block;height:100%;border-radius:4px;transition:width .35s}
.m-MALICIOUS{background:var(--bad)} .m-SUSPICIOUS{background:var(--warn)}
.m-BENIGN{background:var(--good)} .m-INTERNAL{background:var(--info)} .m-ERROR{background:var(--line2)}
.title{font-family:var(--mono);font-size:17px;font-weight:600;word-break:break-all}
.subtle{color:var(--ink3);font-size:12.5px}

ul.reasons{list-style:none;margin:0;padding:0}
ul.reasons li{display:flex;gap:12px;padding:8px 0;border-bottom:1px solid var(--line)}
ul.reasons li:last-child{border-bottom:none}
.w{font-family:var(--mono);font-size:12.5px;font-weight:700;min-width:46px;text-align:right}
.w.plus{color:var(--bad)} .w.small{color:var(--warn)} .w.minus{color:var(--good)} .w.zero{color:var(--ink3)}

table.kv{width:100%;border-collapse:collapse}
table.kv td{padding:6px 0;vertical-align:top;border-bottom:1px solid var(--line)}
table.kv tr:last-child td{border-bottom:none}
table.kv td:first-child{color:var(--ink3);width:150px;font-size:12.5px;padding-right:14px;white-space:nowrap}
table.kv td:last-child{font-family:var(--mono);font-size:13px;word-break:break-word}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:0 26px}
@media (max-width:820px){.cols{grid-template-columns:1fr}}

.chip{
  display:inline-block;font-family:var(--mono);font-size:12px;padding:2px 8px;border-radius:5px;
  background:var(--panel3);border:1px solid var(--line2);margin:0 5px 5px 0;
}
.chip.risk{color:var(--bad);border-color:rgba(228,90,69,.5);background:rgba(228,90,69,.1)}
.chip.cve{color:var(--warn);border-color:rgba(217,146,43,.5);background:rgba(217,146,43,.1)}
.chip.ok{color:var(--good);border-color:rgba(67,181,129,.4);background:rgba(67,181,129,.09)}
.chip.off{color:var(--ink3)}

table.grid{width:100%;border-collapse:collapse;font-size:13px}
table.grid th{
  text-align:left;padding:9px 10px;border-bottom:1px solid var(--line2);color:var(--ink3);
  font-size:11.5px;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;user-select:none;white-space:nowrap;
}
table.grid th:hover{color:var(--ink)}
table.grid td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
table.grid tbody tr{cursor:pointer}
table.grid tbody tr:hover{background:var(--panel2)}
table.grid tbody tr.sel{background:var(--nido-soft)}
.mono{font-family:var(--mono)}
.vpill{font-family:var(--sans);font-weight:700;font-size:11px;letter-spacing:.06em;padding:3px 8px;border-radius:5px;border:1px solid}
.truncate{max-width:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:20px 0 6px}
.prog{height:5px;background:var(--panel3);border-radius:3px;overflow:hidden;flex:1;min-width:150px}
.prog i{display:block;height:100%;background:var(--nido);width:0;transition:width .25s}

dialog{
  border:1px solid var(--line2);background:var(--panel);color:var(--ink);border-radius:12px;
  padding:0;max-width:560px;width:calc(100% - 40px);box-shadow:0 24px 70px rgba(0,0,0,.6);
}
dialog::backdrop{background:rgba(0,0,0,.66);backdrop-filter:blur(2px)}
dialog h2{margin:0;padding:16px 20px;border-bottom:1px solid var(--line);font-size:15px;font-weight:600}
dialog .body{padding:18px 20px;max-height:64vh;overflow:auto}
dialog footer{padding:14px 20px;border-top:1px solid var(--line);display:flex;gap:10px;justify-content:flex-end;align-items:center}
.field{margin-bottom:16px}
.field label{display:block;font-size:12.5px;color:var(--ink2);margin-bottom:6px;font-weight:600}
.field .src{font-size:11.5px;color:var(--ink3);margin-top:5px}
.field input{font-family:var(--mono);font-size:12.5px}

.ai{white-space:pre-wrap;line-height:1.65;font-size:14px}
.ai p{margin:0 0 12px}
.aihead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
select{font:inherit;background:var(--panel2);border:1px solid var(--line2);color:var(--ink);
  border-radius:8px;padding:7px 10px;outline:none}
select:focus{border-color:var(--nido-line)}
.spin{display:inline-block;width:13px;height:13px;border:2px solid var(--line2);border-top-color:var(--nido);border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px}
@keyframes sp{to{transform:rotate(360deg)}}
.empty{color:var(--ink3);padding:34px 10px;text-align:center;font-size:13.5px}
.err{color:var(--bad);background:rgba(228,90,69,.1);border:1px solid rgba(228,90,69,.35);padding:11px 14px;border-radius:8px;margin-top:16px;font-size:13px}

@media print{
  @page{margin:14mm}
  body{background:#fff;color:#111;font-size:11pt}
  header.top,nav.tabs,.searchbar,.bar,dialog,button,.hint,#bulk-input-card{display:none !important}
  .summarybar{display:flex !important;gap:8px;margin-bottom:8pt}
  .summarybar button{display:none !important}
  .wrap{max-width:none;padding:0}
  .card{border:1px solid #bbb;break-inside:avoid;page-break-inside:avoid;margin-top:12pt;background:#fff}
  .card>h3{background:#f2f2f2;color:#444;border-bottom:1px solid #ccc}
  table.kv td{border-bottom:1px solid #e2e2e2}
  table.kv td:first-child{color:#555}
  table.grid th{color:#444;border-bottom:1px solid #999}
  table.grid td{border-bottom:1px solid #e2e2e2}
  .chip{background:#f4f4f4;border-color:#ccc;color:#222}
  .subtle,.scorenum small{color:#666}
  .meter{background:#eee}
  ul.reasons li{border-bottom:1px solid #e8e8e8}
  .v-MALICIOUS{color:#a32b18;background:#fbeceb;border-color:#e0b3ab}
  .v-SUSPICIOUS{color:#8a5a10;background:#fdf4e6;border-color:#e3cda1}
  .v-BENIGN{color:#1d6b45;background:#ecf7f1;border-color:#a9d5be}
  .v-INTERNAL{color:#1d4c8a;background:#eaf1fc;border-color:#a9c2e6}
  .ai{color:#111}
  .aihead button,.aihead select{display:none !important}
  .printhead{display:block !important}
}
.printhead{display:none;border-bottom:2px solid #C94B22;padding-bottom:6pt;margin-bottom:10pt}
.printhead b{color:#C94B22;letter-spacing:.14em}
</style>
</head>
<body>

<header class="top">
  <div class="topin">
    <div class="brand">
      <div class="mark">DRISHTI</div>
      <div class="tag">13 source IP and host intelligence</div>
    </div>
    <div class="spacer"></div>
    <button class="ghost sm" id="btn-cache">Clear cache</button>
    <button class="sm" id="btn-settings">Settings</button>
  </div>
</header>

<div class="wrap">
  <div class="printhead"><b>DRISHTI</b> &nbsp; IP and host intelligence report</div>

  <nav class="tabs">
    <button class="on" data-tab="single">Single lookup</button>
    <button data-tab="bulk">Bulk analysis</button>
  </nav>

  <section class="panel on" id="panel-single">
    <div class="searchbar">
      <input type="text" id="q" placeholder="8.8.8.8, 2606:4700::1111 or example.com" autocomplete="off" spellcheck="false">
      <label class="check"><input type="checkbox" id="fresh1"> Skip cache</label>
      <button class="primary" id="go1">Analyse</button>
    </div>
    <div class="hint">Hostnames resolve to an IP first. Private, loopback, link local and reserved ranges short circuit as internal without burning API calls.</div>
    <div id="single-out"></div>
  </section>

  <section class="panel" id="panel-bulk">
    <div class="card" id="bulk-input-card">
      <h3>Targets</h3>
      <div class="body">
        <textarea id="bulk" placeholder="One per line, or comma separated.&#10;8.8.8.8&#10;1.1.1.1&#10;example.com&#10;192.168.1.1"></textarea>
        <div class="bar">
          <input type="file" id="file" accept=".txt,.csv,.log" style="display:none">
          <button class="sm" id="btn-file">Load file</button>
          <label class="check"><input type="checkbox" id="fresh2"> Skip cache</label>
          <span class="subtle" id="count">0 targets</span>
          <div class="spacer" style="flex:1"></div>
          <button class="primary" id="go2">Run analysis</button>
        </div>
        <div class="bar" id="progwrap" style="display:none">
          <div class="prog"><i id="progbar"></i></div>
          <span class="subtle mono" id="progtxt"></span>
        </div>
      </div>
    </div>
    <div id="bulk-out"></div>
  </section>
</div>

<dialog id="dlg">
  <h2>API keys</h2>
  <div class="body" id="dlg-body"></div>
  <footer>
    <span class="subtle mono" id="dlg-path" style="flex:1;font-size:11px;overflow:hidden;text-overflow:ellipsis"></span>
    <button class="ghost" id="dlg-test">Test keys</button>
    <button class="ghost" id="dlg-close">Cancel</button>
    <button class="primary" id="dlg-save">Save</button>
  </footer>
</dialog>

<script>
const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const RISKY = [23,445,3389,1433,5900,3306,6379,27017,9200,11211,5432,21,512,2375,161];
const ORDER = {MALICIOUS:0, SUSPICIOUS:1, ERROR:2, INTERNAL:3, BENIGN:4};
let BULK = [];
const CUR = {};
let SORT = {col:"verdict", dir:1};

async function api(path, opts){
  const res = await fetch(path, Object.assign({headers:{"Content-Type":"application/json"}}, opts||{}));
  if(!res.ok){
    let msg = "HTTP " + res.status;
    try { const j = await res.json(); if(j.error) msg = j.error; } catch(e){}
    throw new Error(msg);
  }
  return res.json();
}

/* ---------------------------------------------------------------- tabs */
$$("nav.tabs button").forEach(b => b.onclick = () => {
  $$("nav.tabs button").forEach(x => x.classList.toggle("on", x === b));
  $$(".panel").forEach(p => p.classList.toggle("on", p.id === "panel-" + b.dataset.tab));
});

/* ---------------------------------------------------------------- render */
function row(label, value){
  if(value === null || value === undefined || value === "" ||
     (Array.isArray(value) && !value.length)) return "";
  const v = Array.isArray(value) ? value.join(", ") : value;
  return `<tr><td>${esc(label)}</td><td>${v}</td></tr>`;
}
function chips(items, cls){
  return (items||[]).map(t => `<span class="chip ${cls||""}">${esc(t)}</span>`).join("");
}
function why(node){
  if(node && node.nokey) return "no API key";
  if(node && node.timeout) return "timed out";
  if(node && node.error){
    const e = String(node.error);
    return "error: " + (e.length > 90 ? e.slice(0, 90) + "..." : e);
  }
  if(node && node.status) return "unavailable (HTTP " + node.status + ")";
  return "unavailable";
}

function renderResult(r, scope){
  scope = scope || "single";
  const v = r.verdict || "ERROR", sc = r.score || 0, s = r.sources || {};
  const head = (r.hostname && r.ip) ? `${esc(r.hostname)} <span class="subtle">&rarr;</span> ${esc(r.ip)}`
                                    : esc(r.ip || r.target);
  let out = `<div class="card"><div class="verdictbar">
    <div class="badge v-${v}">${v}</div>
    <div class="scorewrap">
      <div class="title">${head}</div>
      <div class="scorenum">${sc}<small> / 100 risk</small></div>
      <div class="meter"><i class="m-${v}" style="width:${Math.max(sc,2)}%"></i></div>
    </div>
    <div class="subtle" style="text-align:right">${esc(r.generated||"")}<br>
      ${r.cached ? "cached " + (r.cache_age_h||0) + "h ago" : (r.elapsed||0) + "s live"}</div>
  </div>`;

  if((r.reasons||[]).length){
    out += `<div class="body" style="border-top:1px solid var(--line)"><ul class="reasons">` +
      r.reasons.map(x => {
        const w = x.weight;
        const cls = w >= 15 ? "plus" : (w > 0 ? "small" : (w < 0 ? "minus" : "zero"));
        const txt = w === 0 ? "" : (w > 0 ? "+" + w : String(w));
        return `<li><span class="w ${cls}">${txt}</span><span>${esc(x.text)}</span></li>`;
      }).join("") + `</ul></div>`;
  }
  out += `</div>`;

  CUR[scope] = r;
  out += `<div class="card" id="ai-${scope}"><h3>In plain English</h3>
    <div class="body">
      <div class="aihead">
        <button class="sm" onclick="aiExplain('${scope}')">Explain this report</button>
        <span class="subtle">A local Ollama model, or GLM if Ollama is not running.</span>
      </div>
    </div></div>`;

  if(v === "ERROR") return out;

  if(v === "INTERNAL") return out;

  const geo = s.geo||{}, rdap = s.rdap||{}, rdns = s.rdns||{},
        idb = s.internetdb||{}, sho = s.shodan||{}, cen = s.censys||{},
        ab = s.abuseipdb||{}, vt = s.virustotal||{}, gn = s.greynoise||{},
        bl = s.dnsbl||{}, tor = s.tor||{}, us = s.urlscan||{}, st = s.securitytrails||{};

  /* ownership */
  let own = "";
  if(geo.ok){
    own += row("Location", esc([geo.city, geo.region, geo.country].filter(Boolean).join(", ")) +
                            (geo.flag ? " " + geo.flag : ""));
    own += row("ASN", geo.asn ? esc("AS" + geo.asn + "  " + (geo.org||"")) : "");
    own += row("ISP", esc(geo.isp||""));
    own += row("Timezone", esc(geo.timezone||""));
    own += row("Coordinates", geo.lat ? esc(geo.lat + ", " + geo.lon) : "");
  }
  if(rdap.ok){
    own += row("Registry", esc(rdap.registry||""));
    own += row("Netname", esc(rdap.name||""));
    own += row("Handle", (rdap.handle && rdap.handle !== rdap.range) ? esc(rdap.handle) : "");
    own += row("Range", esc(rdap.range||""));
    own += row("Allocated", esc((rdap.events||{}).registration||""));
    own += row("Last changed", esc((rdap.events||{})["last changed"]||""));
    own += row("Abuse contact", (rdap.abuse||[]).map(a =>
      `<a href="mailto:${esc(a)}">${esc(a)}</a>`).join("<br>"));
    own += row("Remarks", esc((rdap.remarks||[]).join(" ")));
  }
  if(own) out += `<div class="card"><h3>Ownership and location</h3><div class="body"><table class="kv">${own}</table></div></div>`;

  /* surface */
  const names = Array.from(new Set([].concat(rdns.ptr ? [rdns.ptr] : [],
    idb.hostnames||[], sho.hostnames||[], cen.dns||[]))).filter(Boolean);
  const ports = Array.from(new Set([].concat(idb.ports||[], sho.ports||[]))).sort((a,b)=>a-b);
  const vulns = Array.from(new Set([].concat(idb.vulns||[], sho.vulns||[]))).sort();
  const tags  = Array.from(new Set([].concat(idb.tags||[], sho.tags||[])));
  if(names.length || ports.length || vulns.length){
    let sur = "";
    sur += row("Reverse DNS", rdns.ptr ? esc(rdns.ptr) : `<span class="subtle">none</span>`);
    sur += row("Other names", names.filter(n => n !== rdns.ptr).map(esc).join("<br>"));
    sur += row("Open ports", ports.map(p =>
      `<span class="chip ${RISKY.includes(p)?"risk":""}">${p}</span>`).join(""));
    sur += row("Known CVEs", chips(vulns, "cve"));
    sur += row("Tags", chips(tags));
    (sho.services||[]).forEach(x => {
      const d = [x.product, x.version].filter(Boolean).join(" ");
      if(d) sur += row(x.port + "/" + (x.transport||"tcp"), esc(d));
    });
    if(!sho.ok) (cen.services||[]).forEach(x => {
      if(x.software) sur += row(x.port + "/" + (x.service||""), esc(x.software));
    });
    sur += row("OS", esc(sho.os || cen.os || ""));
    out += `<div class="card"><h3>Attack surface</h3><div class="body"><table class="kv">${sur}</table></div></div>`;
  }

  /* reputation */
  let rep = "";
  rep += row("AbuseIPDB", ab.ok
    ? `<b style="color:${ab.score>=50?"var(--bad)":(ab.score?"var(--warn)":"var(--good)")}">${ab.score}%</b> confidence, ${ab.reports||0} reports from ${ab.distinct||0} sources` +
      ((ab.categories||[]).length ? "<br>" + chips(ab.categories.map(c => c.name + " x" + c.n)) : "") +
      (ab.last ? `<br><span class="subtle">last report ${esc(ab.last)}</span>` : "") +
      (ab.usage ? `<br><span class="subtle">${esc(ab.usage)}</span>` : "")
    : `<span class="subtle">${esc(why(ab))}</span>`);
  rep += row("VirusTotal", vt.ok
    ? `<b style="color:${vt.malicious?"var(--bad)":(vt.suspicious?"var(--warn)":"var(--good)")}">${vt.malicious||0} malicious</b> / ${vt.suspicious||0} suspicious / ${vt.harmless||0} harmless, reputation ${vt.reputation||0}` +
      ((vt.vendors||[]).length ? "<br>" + chips(vt.vendors, "risk") : "")
    : `<span class="subtle">${esc(why(vt))}</span>`);
  rep += row("GreyNoise", gn.ok
    ? (() => {
        const c = gn.classification || (gn.riot ? "riot" : "unseen");
        const col = c === "malicious" ? "var(--bad)" : ((c === "benign" || c === "riot") ? "var(--good)" : "var(--ink2)");
        return `<b style="color:${col}">${esc(c)}</b>` + (gn.name ? " &middot; " + esc(gn.name) : "") +
               (gn.last_seen ? `<br><span class="subtle">last seen ${esc(gn.last_seen)}</span>` : "");
      })()
    : `<span class="subtle">${esc(why(gn))}</span>`);
  rep += row("Blocklists", bl.ok
    ? ((bl.listed||[]).length
        ? chips(bl.listed.map(h => h.list + " " + h.code), "risk")
        : `<span class="chip ok">clean on ${bl.checked||0} lists</span>`)
    : `<span class="subtle">${esc(why(bl))}</span>`);
  rep += row("Tor", tor.ok
    ? (tor.exit_node ? `<span class="chip risk">active exit node</span>`
                     : `<span class="chip ok">not an exit node</span>`)
    : `<span class="subtle">${esc(why(tor))}</span>`);
  rep += row("URLScan", us.ok
    ? `${us.total||0} scans on this IP, <b${us.malicious?' style="color:var(--bad)"':""}>${us.malicious||0} malicious</b>` +
      (us.results||[]).slice(0,5).map(x =>
        `<br><span class="subtle">${esc(x.date||"")}</span> <a href="${esc(x.url)}" target="_blank" rel="noreferrer noopener" style="${x.malicious?"color:var(--bad)":""}">${esc(x.url)}</a>`).join("")
    : `<span class="subtle">${esc(why(us))}</span>`);
  if(st.ok || !st.nokey)
    rep += row("Hosted domains", st.ok
      ? `${esc(String(st.total||0))} total<br>` + chips(st.domains||[])
      : `<span class="subtle">${esc(why(st))}</span>`);
  if(!sho.ok && !sho.nokey) rep += row("Shodan", `<span class="subtle">${esc(why(sho))}</span>`);
  if(!cen.ok && !cen.nokey) rep += row("Censys", `<span class="subtle">${esc(why(cen))}</span>`);
  out += `<div class="card"><h3>Reputation</h3><div class="body"><table class="kv">${rep}</table></div></div>`;

  /* sources */
  const ran = Object.values(s).filter(x => x && x.ok).length;
  const miss = Object.entries(s).filter(([k,x]) => x && x.nokey).map(([k]) => k);
  out += `<div class="card"><h3>Sources</h3><div class="body">
    <div class="subtle" style="margin-bottom:9px">${ran} of ${Object.keys(s).length} answered in ${r.elapsed||0}s</div>` +
    Object.entries(s).map(([k,x]) =>
      `<span class="chip ${x&&x.ok?"ok":"off"}">${esc(k)}${x&&x.ok?"":" &middot; " + esc(why(x))}</span>`).join("") +
    ((r.errors||[]).length ? `<div class="subtle" style="margin-top:10px">${esc(r.errors.join("; "))}</div>` : "") +
    `</div></div>`;
  return out;
}

/* ---------------------------------------------------------------- single */
async function runSingle(){
  const t = $("#q").value.trim();
  if(!t) return;
  $("#go1").disabled = true;
  $("#single-out").innerHTML = `<div class="empty"><span class="spin"></span> &nbsp;querying 13 sources for ${esc(t)}</div>`;
  try{
    const r = await api("/api/lookup", {method:"POST",
      body: JSON.stringify({target:t, fresh: $("#fresh1").checked})});
    $("#single-out").innerHTML = renderResult(r) + `
      <div class="bar">
        <button class="sm" onclick="exportOne('json')">Export JSON</button>
        <button class="sm" onclick="exportOne('csv')">Export CSV</button>
        <button class="sm" onclick="window.print()">Print / PDF</button>
      </div>`;
    window.LAST = r;
  }catch(e){
    $("#single-out").innerHTML = `<div class="err">${esc(e.message)}</div>`;
  }finally{ $("#go1").disabled = false; }
}
$("#go1").onclick = runSingle;
$("#q").addEventListener("keydown", e => { if(e.key === "Enter") runSingle(); });

async function exportOne(fmt){ await download(fmt, [window.LAST]); }

async function aiExplain(scope, fresh){
  const card = $("#ai-" + scope);
  const result = CUR[scope];
  if(!card || !result) return;
  const body = card.querySelector(".body");
  body.innerHTML = `<span class="spin"></span> &nbsp;<span class="subtle">reading the report</span>`;
  try{
    const r = await api("/api/explain", {method:"POST",
      body: JSON.stringify({result, fresh: !!fresh})});
    if(!r.ok){
      body.innerHTML = `<div class="subtle">${esc(r.error || "no summary available")}</div>` +
        (r.hint ? `<div class="subtle" style="margin-top:6px">${esc(r.hint)}</div>` : "") +
        `<div class="aihead" style="margin-top:12px">
           <button class="sm" onclick="aiExplain('${scope}')">Try again</button></div>`;
      return;
    }
    const meta = `${esc(r.model||"")} via ${esc(r.backend||"")}` +
      (r.cached ? `, cached ${r.cache_age_h||0}h ago` : (r.elapsed ? `, ${r.elapsed}s` : ""));
    body.innerHTML = `<div class="ai">` +
      String(r.text).split(/\n\s*\n/).map(x => `<p>${esc(x.trim())}</p>`).join("") +
      `</div><div class="aihead" style="margin-top:6px">
         <span class="subtle">${meta}</span>
         <button class="sm" onclick="aiExplain('${scope}', true)">Rewrite</button>
       </div>`;
  }catch(e){
    body.innerHTML = `<div class="err">${esc(e.message)}</div>`;
  }
}

/* ---------------------------------------------------------------- bulk */
function parseTargets(text){
  const out = [];
  String(text).split(/\r?\n/).forEach(line => {
    line.split("#")[0].split(/[\s,;]+/).forEach(t => {
      const v = t.trim();
      if(v) out.push(v);
    });
  });
  return out;
}
function updateCount(){
  const n = new Set(parseTargets($("#bulk").value)).size;
  $("#count").textContent = n + (n === 1 ? " target" : " targets");
}
$("#bulk").addEventListener("input", updateCount);
$("#btn-file").onclick = () => $("#file").click();
$("#file").onchange = e => {
  const f = e.target.files[0]; if(!f) return;
  const fr = new FileReader();
  fr.onload = () => {
    const cur = $("#bulk").value.trim();
    $("#bulk").value = (cur ? cur + "\n" : "") + parseTargets(fr.result).join("\n");
    updateCount();
  };
  fr.readAsText(f);
  e.target.value = "";
};

async function runBulk(){
  const all = Array.from(new Set(parseTargets($("#bulk").value)));
  if(!all.length) return;
  $("#go2").disabled = true;
  $("#progwrap").style.display = "flex";
  BULK = [];
  const chunk = 8, fresh = $("#fresh2").checked;
  try{
    for(let i = 0; i < all.length; i += chunk){
      const slice = all.slice(i, i + chunk);
      const r = await api("/api/bulk", {method:"POST",
        body: JSON.stringify({targets: slice, fresh})});
      BULK = BULK.concat(r.results || []);
      const pct = Math.round(BULK.length / all.length * 100);
      $("#progbar").style.width = pct + "%";
      $("#progtxt").textContent = BULK.length + " / " + all.length;
      drawBulk();
    }
    $("#progtxt").textContent = BULK.length + " done";
  }catch(e){
    $("#bulk-out").innerHTML = `<div class="err">${esc(e.message)}</div>`;
  }finally{ $("#go2").disabled = false; }
}
$("#go2").onclick = runBulk;

function sortRows(rows){
  const dir = SORT.dir;
  return rows.slice().sort((a,b) => {
    let x, y;
    if(SORT.col === "verdict"){
      x = [ORDER[a.verdict] ?? 9, -(a.score||0)];
      y = [ORDER[b.verdict] ?? 9, -(b.score||0)];
      return dir * (x[0] - y[0] || x[1] - y[1]);
    }
    if(SORT.col === "score") return dir * ((b.score||0) - (a.score||0));
    if(SORT.col === "ip") return dir * String(a.ip||a.target).localeCompare(String(b.ip||b.target));
    if(SORT.col === "country"){
      const ca = ((a.sources||{}).geo||{}).country || "", cb = ((b.sources||{}).geo||{}).country || "";
      return dir * ca.localeCompare(cb);
    }
    return 0;
  });
}

function drawBulk(){
  if(!BULK.length){ $("#bulk-out").innerHTML = ""; return; }
  const counts = {};
  BULK.forEach(r => counts[r.verdict] = (counts[r.verdict]||0) + 1);
  const summary = ["MALICIOUS","SUSPICIOUS","BENIGN","INTERNAL","ERROR"]
    .filter(v => counts[v])
    .map(v => `<span class="vpill v-${v}">${counts[v]} ${v}</span>`).join(" ");

  const rows = sortRows(BULK).map((r,i) => {
    const geo = (r.sources||{}).geo || {};
    const top = (r.reasons||[])[0];
    return `<tr data-i="${i}" onclick="showDetail(${i})">
      <td class="mono">${esc(r.ip || r.target)}${r.hostname ? `<br><span class="subtle">${esc(r.hostname)}</span>` : ""}</td>
      <td><span class="vpill v-${r.verdict}">${r.verdict}</span></td>
      <td class="mono" style="text-align:right">${r.score||0}</td>
      <td>${esc(geo.country_code || (r.verdict === "INTERNAL" ? "LAN" : "-"))}</td>
      <td class="subtle">${esc(geo.org || "")}</td>
      <td class="truncate" style="width:38%">${esc(top ? top.text : "nothing notable")}</td>
    </tr>`;
  }).join("");

  $("#bulk-out").innerHTML = `
    <div class="bar summarybar">
      ${summary}
      <div style="flex:1"></div>
      <button class="sm" onclick="download('json', BULK)">Export JSON</button>
      <button class="sm" onclick="download('csv', BULK)">Export CSV</button>
      <button class="sm" onclick="window.print()">Print / PDF</button>
    </div>
    <div class="card"><h3>Results</h3><div class="body" style="padding:4px 8px">
      <table class="grid"><thead><tr>
        <th onclick="setSort('ip')">Target</th>
        <th onclick="setSort('verdict')">Verdict</th>
        <th onclick="setSort('score')" style="text-align:right">Score</th>
        <th onclick="setSort('country')">Country</th>
        <th>Network</th>
        <th>Top reason</th>
      </tr></thead><tbody>${rows}</tbody></table>
    </div></div>
    <div id="detail"></div>`;
}
function setSort(col){
  SORT.dir = (SORT.col === col) ? -SORT.dir : 1;
  SORT.col = col;
  drawBulk();
}
function showDetail(i){
  const r = sortRows(BULK)[i];
  $$("table.grid tbody tr").forEach(tr => tr.classList.toggle("sel", +tr.dataset.i === i));
  $("#detail").innerHTML = renderResult(r, "detail");
  $("#detail").scrollIntoView({behavior:"smooth", block:"start"});
}

async function download(fmt, results){
  if(!results || !results.length) return;
  const res = await fetch("/api/export/" + fmt, {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({results})
  });
  if(!res.ok){ alert("Export failed"); return; }
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") || "";
  const m = cd.match(/filename=([^;]+)/);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = m ? m[1].trim() : ("drishti." + fmt);
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

/* ---------------------------------------------------------------- settings */
const dlg = $("#dlg");
$("#btn-settings").onclick = async () => {
  const cfg = await api("/api/config");
  $("#dlg-path").textContent = cfg.path;
  const ai = cfg.ai || {};
  const aiBlock = `
    <div style="margin:6px 0 18px;padding:12px 14px;border:1px solid var(--line);border-radius:8px;background:var(--panel2)">
      <div style="font-size:12.5px;font-weight:600;color:var(--ink2);margin-bottom:8px">Plain English summary</div>
      <div class="subtle" style="margin-bottom:12px">
        Ollama at ${esc(ai.ollama_host||"")} is
        ${ai.ollama_up ? `<span class="chip ok">running</span>` : `<span class="chip off">not reachable</span>`}
        ${(ai.ollama_models||[]).length ? "&nbsp;" + chips(ai.ollama_models.slice(0,6)) : ""}
        <br>Order in use: ${esc((ai.backends||[]).join(" then ") || "off")}
      </div>
      ${(ai.settings||[]).map(x => `
        <div class="field" style="margin-bottom:11px">
          <label>${esc(x.label)}</label>
          ${x.id === "ai_backend"
            ? `<select data-set="${esc(x.id)}">` +
                ["auto","ollama","glm","off"].map(o =>
                  `<option value="${o}"${(x.value||"auto")===o?" selected":""}>${o}</option>`).join("") +
              `</select>`
            : `<input type="text" data-set="${esc(x.id)}" value="${esc(x.value)}"
                      placeholder="${esc(x.default)}" autocomplete="off" spellcheck="false">`}
        </div>`).join("")}
    </div>`;
  $("#dlg-body").innerHTML = aiBlock + cfg.keys.map(k => `
    <div class="field">
      <label>${esc(k.label)} ${k.set ? '<span class="chip ok">set</span>' : ""}
        ${k.from_env ? '<span class="chip">from environment</span>' : ""}</label>
      <input type="text" data-key="${esc(k.id)}" placeholder="${k.set ? esc(k.hint) : "paste key"}"
             autocomplete="off" spellcheck="false">
      <div class="src"><a href="${esc(k.url)}" target="_blank" rel="noreferrer noopener">${esc(k.url)}</a></div>
    </div>`).join("") +
    `<div class="subtle">Leave blank to keep the stored key. Type a single dash to clear one.
     Keys are written to drishti_config.json with owner only permissions.</div>`;
  dlg.showModal();
};
const KEY_STATE = {works:"ok", bad:"risk", limited:"cve", unset:"off", unknown:"cve"};
$("#dlg-test").onclick = async () => {
  const btn = $("#dlg-test");
  const was = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Testing";
  let box = $("#keycheck");
  if(!box){
    box = document.createElement("div");
    box.id = "keycheck";
    $("#dlg-body").prepend(box);
  }
  box.innerHTML = `<div class="subtle" style="margin-bottom:14px">
    <span class="spin"></span> &nbsp;checking each key against an endpoint that authenticates</div>`;
  try{
    const r = await api("/api/checkkeys", {method:"POST", body:"{}"});
    box.innerHTML = `<div style="margin:0 0 18px;padding:12px 14px;border:1px solid var(--line);
        border-radius:8px;background:var(--panel2)">
      <div style="font-size:12.5px;font-weight:600;color:var(--ink2);margin-bottom:8px">Key check</div>
      <table class="kv">` +
      r.results.map(x => `<tr><td>${esc(x.label)}</td><td>
        <span class="chip ${KEY_STATE[x.state]||"off"}">${esc(x.state)}</span>
        <span class="subtle">${esc(x.detail)}</span></td></tr>`).join("") +
      `</table></div>`;
  }catch(e){
    box.innerHTML = `<div class="err">${esc(e.message)}</div>`;
  }finally{
    btn.disabled = false;
    btn.textContent = was;
  }
};
$("#dlg-close").onclick = () => { const b = $("#keycheck"); if(b) b.remove(); dlg.close(); };
$("#dlg-save").onclick = async () => {
  const body = {};
  $$("#dlg-body input[data-key]").forEach(inp => {
    const v = inp.value.trim();
    if(v === "-") body[inp.dataset.key] = "";
    else if(v) body[inp.dataset.key] = v;
  });
  $$("#dlg-body [data-set]").forEach(inp => { body[inp.dataset.set] = inp.value.trim(); });
  await api("/api/config", {method:"POST", body: JSON.stringify(body)});
  dlg.close();
};
$("#btn-cache").onclick = async () => {
  await fetch("/api/cache", {method:"DELETE"});
  $("#btn-cache").textContent = "Cache cleared";
  setTimeout(() => $("#btn-cache").textContent = "Clear cache", 1600);
};

$("#q").focus();
updateCount();
</script>
</body>
</html>
"""

# ---------------------------------------------------------------- export

CSV_COLUMNS = [
    "target", "ip", "hostname", "verdict", "score", "country", "city",
    "asn", "org", "reverse_dns", "open_ports", "cves", "dnsbl_hits",
    "tor_exit", "abuseipdb_score", "abuseipdb_reports", "vt_malicious",
    "greynoise", "urlscan_malicious", "abuse_contacts", "top_reason",
    "all_reasons", "sources_ok", "generated",
]


def flatten(res):
    src = res.get("sources") or {}
    geo = src.get("geo") or {}
    rdap = src.get("rdap") or {}
    idb = src.get("internetdb") or {}
    shodan = src.get("shodan") or {}
    abuse = src.get("abuseipdb") or {}
    vt = src.get("virustotal") or {}
    gn = src.get("greynoise") or {}
    dnsbl = src.get("dnsbl") or {}
    tor = src.get("tor") or {}
    us = src.get("urlscan") or {}
    reasons = res.get("reasons") or []
    ports = sorted(set((idb.get("ports") or []) + (shodan.get("ports") or [])))
    vulns = sorted(set((idb.get("vulns") or []) + (shodan.get("vulns") or [])))
    return {
        "target": res.get("target"),
        "ip": res.get("ip") or "",
        "hostname": res.get("hostname") or "",
        "verdict": res.get("verdict"),
        "score": res.get("score", 0),
        "country": geo.get("country") or rdap.get("country") or "",
        "city": geo.get("city") or "",
        "asn": "AS%s" % geo.get("asn") if geo.get("asn") else "",
        "org": geo.get("org") or rdap.get("name") or "",
        "reverse_dns": (src.get("rdns") or {}).get("ptr") or "",
        "open_ports": " ".join(str(p) for p in ports),
        "cves": " ".join(vulns),
        "dnsbl_hits": " ".join(h["list"] for h in (dnsbl.get("listed") or [])),
        "tor_exit": "yes" if tor.get("exit_node") else "no",
        "abuseipdb_score": abuse.get("score", "") if abuse.get("ok") else "",
        "abuseipdb_reports": abuse.get("reports", "") if abuse.get("ok") else "",
        "vt_malicious": vt.get("malicious", "") if vt.get("ok") else "",
        "greynoise": gn.get("classification") or ("riot" if gn.get("riot") else "") if gn.get("ok") else "",
        "urlscan_malicious": us.get("malicious", "") if us.get("ok") else "",
        "abuse_contacts": " ".join(rdap.get("abuse") or []),
        "top_reason": reasons[0]["text"] if reasons else "",
        "all_reasons": " | ".join(
            "%+d %s" % (r["weight"], r["text"]) for r in reasons),
        "sources_ok": sum(1 for v in src.values() if isinstance(v, dict) and v.get("ok")),
        "generated": res.get("generated", ""),
    }


def to_csv(results):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for res in results:
        writer.writerow(flatten(res))
    return buf.getvalue()


# ---------------------------------------------------------------- routes

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.after_request
def _local_only(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html; charset=utf-8")


@app.route("/api/status")
def api_status():
    cfg = load_config()
    return jsonify({
        "app": APP,
        "version": VERSION,
        "config_path": cfg.get("_path"),
        "cache_path": CACHE_PATH,
        "sources": [
            {"id": name, "label": label, "keyed": keyed,
             "ready": (not keyed) or bool(key(cfg, name))}
            for name, label, _fn, keyed in SOURCES
        ],
    })


@app.route("/api/lookup", methods=["POST"])
def api_lookup():
    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"error": "no target given"}), 400
    cfg = load_config()
    return jsonify(analyse(target, cfg, fresh=bool(body.get("fresh"))))


@app.route("/api/bulk", methods=["POST"])
def api_bulk():
    body = request.get_json(silent=True) or {}
    targets = [t.strip() for t in (body.get("targets") or []) if str(t).strip()]
    if not targets:
        return jsonify({"error": "no targets given"}), 400
    targets = targets[:BULK_LIMIT]
    cfg = load_config()
    fresh = bool(body.get("fresh"))
    workers = min(BULK_WORKERS, len(targets))
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda t: analyse(t, cfg, fresh), targets))
    return jsonify({"results": results})


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    cfg = load_config()
    if request.method == "GET":
        up = ollama_up(cfg)
        return jsonify({
            "path": cfg.get("_path"),
            "ai": {
                "backends": ai_backends(cfg),
                "ollama_up": up,
                "ollama_host": ollama_host(cfg),
                "ollama_models": ollama_models(cfg) if up else [],
                "settings": [
                    {"id": name, "label": label, "default": default,
                     "value": cfg.get(name) or ""}
                    for name, label, default in AI_SETTINGS
                ],
            },
            "keys": [
                {"id": name, "label": label, "url": url,
                 "set": bool(key(cfg, name)),
                 "hint": mask(cfg.get(name) or ""),
                 "from_env": bool(not cfg.get(name)
                                  and os.environ.get("DRISHTI_" + name.upper()))}
                for name, label, url in KEY_FIELDS + AI_FIELDS
            ],
        })
    body = request.get_json(silent=True) or {}
    for name, _label, _url in KEY_FIELDS + AI_FIELDS:
        if name in body:
            value = (body.get(name) or "").strip()
            if value == "":
                cfg.pop(name, None)
            elif not value.startswith("•"):
                cfg[name] = value
    for name, _label, _default in AI_SETTINGS:
        if name in body:
            value = (body.get(name) or "").strip()
            if value:
                cfg[name] = value
            else:
                cfg.pop(name, None)
    path = save_config(cfg)
    return jsonify({"saved": True, "path": path})


@app.route("/api/checkkeys", methods=["POST"])
def api_check_keys():
    return jsonify({"results": check_keys(load_config())})


@app.route("/api/explain", methods=["POST"])
def api_explain():
    body = request.get_json(silent=True) or {}
    result = body.get("result")
    if not isinstance(result, dict) or not result.get("verdict"):
        return jsonify({"ok": False, "error": "no report to explain"}), 400
    cfg = load_config()
    backend = (body.get("backend") or "").strip().lower()
    if backend in ("auto", "ollama", "glm", "off"):
        cfg["ai_backend"] = backend
    return jsonify(explain(result, cfg, fresh=bool(body.get("fresh"))))


@app.route("/api/export/<fmt>", methods=["POST"])
def api_export(fmt):
    body = request.get_json(silent=True) or {}
    results = body.get("results") or []
    if not results:
        return jsonify({"error": "nothing to export"}), 400
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if fmt == "csv":
        return Response(
            to_csv(results),
            mimetype="text/csv",
            headers={"Content-Disposition":
                     "attachment; filename=drishti-%s.csv" % stamp},
        )
    if fmt == "json":
        payload = {"app": APP, "version": VERSION,
                   "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "count": len(results), "results": results}
        return Response(
            json.dumps(payload, indent=2, default=str),
            mimetype="application/json",
            headers={"Content-Disposition":
                     "attachment; filename=drishti-%s.json" % stamp},
        )
    return jsonify({"error": "unknown format"}), 400


@app.route("/api/cache", methods=["DELETE"])
def api_cache_clear():
    try:
        conn = cache_open()
        conn.execute("DELETE FROM cache")
        conn.commit()
        conn.close()
        return jsonify({"cleared": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def mask(value):
    if not value:
        return ""
    if len(value) <= 8:
        return "•" * len(value)
    return value[:3] + "•" * 8 + value[-3:]


# ---------------------------------------------------------------- boot

def pick_port(start=DEFAULT_PORT, tries=PORT_TRIES):
    for offset in range(tries):
        port = start + offset
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Werkzeug binds with SO_REUSEADDR, so probe the same way. Without it a
        # socket left in TIME_WAIT by the previous run looks like a busy port
        # and Drishti walks off 5055 for no reason.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            sock.close()
    raise SystemExit("No free port between %d and %d." % (start, start + tries - 1))


def open_later(url, delay=1.0):
    def go():
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=go, daemon=True).start()


def main():
    port = pick_port()
    url = "http://127.0.0.1:%d" % port
    cfg = load_config()
    ready = [label for name, label, _url in KEY_FIELDS if key(cfg, name)]
    print("")
    print("  %s %s" % (APP, VERSION))
    print("  %s" % url)
    print("  config  %s" % cfg.get("_path"))
    print("  cache   %s" % CACHE_PATH)
    print("  keys    %s" % (", ".join(ready) if ready else "none, keyless tier only"))
    print("  ai      %s" % (", ".join(ai_backends(cfg)) or "off"))
    if port != DEFAULT_PORT:
        print("  note    %d was busy, moved to %d" % (DEFAULT_PORT, port))
    print("")
    if "--no-browser" not in sys.argv:
        open_later(url)
    app.run(host="127.0.0.1", port=port, threaded=True, debug=False)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  stopped\n")
