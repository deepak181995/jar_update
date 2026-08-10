#!/usr/bin/env python3
"""
Drishti self-test. Run this once on any new machine:

    python3 selftest.py

It proves the environment can actually run Drishti: Python version, module
imports, outbound reachability of every keyless source, a real end to end
lookup, the web app's routes served from a live server, and whether the AI
layer has a backend to talk to. Standard library only, safe to run anywhere,
touches nothing outside this folder except the network probes.
"""

import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PASS, FAIL, WARN = "pass", "FAIL", "warn"
RESULTS = []


def report(status, name, detail=""):
    RESULTS.append(status)
    mark = {"pass": "\033[32m  ok\033[0m", "FAIL": "\033[31mFAIL\033[0m",
            "warn": "\033[33mwarn\033[0m"}[status] if sys.stdout.isatty() else status
    print("  %s  %-38s %s" % (mark, name, detail))


def section(title):
    print("\n%s" % title)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    print("Drishti self-test on %s, Python %s"
          % (sys.platform, sys.version.split()[0]))

    section("Environment")
    if sys.version_info >= (3, 9):
        report(PASS, "Python version", sys.version.split()[0])
    else:
        report(FAIL, "Python version", "%s is too old, need 3.9+" % sys.version.split()[0])
        return summary()

    cli_path = os.path.join(HERE, "Drishti_cli.py")
    web_path = os.path.join(HERE, "Drishti.py")
    for path in (cli_path, web_path):
        if not os.path.exists(path):
            report(FAIL, os.path.basename(path), "not found next to selftest.py")
            return summary()

    section("CLI build (runs anywhere, including a-Shell)")
    try:
        cli = load(cli_path, "drishti_cli_test")
        report(PASS, "imports on stdlib alone")
    except Exception as exc:
        report(FAIL, "imports on stdlib alone", str(exc)[:90])
        return summary()

    for label, fn in (("private range short circuit",
                       lambda: cli.classify_private("192.168.1.1") is not None),
                      ("loopback short circuit",
                       lambda: cli.classify_private("127.0.0.1") == "Loopback"),
                      ("public IP not misclassified",
                       lambda: cli.classify_private("8.8.8.8") is None),
                      ("verdict engine loaded",
                       lambda: callable(cli.score_target)),
                      ("ai layer loaded",
                       lambda: callable(cli.explain) and callable(cli.ai_digest))):
        try:
            report(PASS if fn() else FAIL, label)
        except Exception as exc:
            report(FAIL, label, str(exc)[:90])

    section("Outbound reachability, keyless sources")
    probes = [
        ("rdap.org", "https://rdap.org/ip/8.8.8.8"),
        ("ipwho.is", "https://ipwho.is/8.8.8.8"),
        ("internetdb.shodan.io", "https://internetdb.shodan.io/8.8.8.8"),
        ("check.torproject.org", "https://check.torproject.org/torbulkexitlist"),
        ("urlscan.io", "https://urlscan.io/api/v1/search/?q=page.ip%3A%228.8.8.8%22&size=1"),
    ]
    reachable = 0
    for name, url in probes:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": cli.UA})
            with urllib.request.urlopen(req, timeout=10) as resp:
                ok = resp.status in (200, 301, 302)
        except Exception:
            ok = False
        reachable += 1 if ok else 0
        report(PASS if ok else WARN, name, "" if ok else "unreachable, source will be skipped")
    try:
        socket.getaddrinfo("2.0.0.127.bl.spamcop.net", None)
        report(PASS, "DNSBL resolution")
    except Exception:
        report(WARN, "DNSBL resolution",
               "resolver blocks blocklist zones, DNSBL source will read clean")

    section("End to end lookup")
    if reachable == 0:
        report(FAIL, "live lookup", "no source reachable, check your network")
    else:
        try:
            started = time.time()
            res = cli.analyse("8.8.8.8", cli.load_config(), fresh=True)
            answered = sum(1 for v in res["sources"].values()
                           if isinstance(v, dict) and v.get("ok"))
            good = res.get("verdict") in ("BENIGN", "SUSPICIOUS", "MALICIOUS") and answered >= 3
            report(PASS if good else FAIL, "live lookup of 8.8.8.8",
                   "%s %d/100, %d sources, %.1fs"
                   % (res.get("verdict"), res.get("score", 0), answered,
                      time.time() - started))
        except Exception as exc:
            report(FAIL, "live lookup of 8.8.8.8", str(exc)[:90])
        try:
            res = cli.analyse("10.0.0.1", cli.load_config())
            report(PASS if res.get("verdict") == "INTERNAL" else FAIL,
                   "internal address burns no API calls",
                   res.get("verdict", "?"))
        except Exception as exc:
            report(FAIL, "internal address burns no API calls", str(exc)[:90])

    section("Web build")
    if importlib.util.find_spec("flask") is None:
        report(WARN, "flask", "not installed, run: pip3 install flask")
    else:
        env = dict(os.environ)
        env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
        proc = subprocess.Popen([sys.executable, web_path, "--no-browser"],
                                cwd=HERE, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        port = None
        try:
            deadline = time.time() + 15
            while time.time() < deadline and port is None:
                line = proc.stdout.readline().decode("utf-8", "replace")
                if "http://127.0.0.1:" in line:
                    port = int(line.rsplit(":", 1)[1].strip())
            if port is None:
                report(FAIL, "server starts", "no URL printed within 15s")
            else:
                # the URL is printed before Flask binds, so wait for the socket
                bound = False
                deadline = time.time() + 15
                while time.time() < deadline:
                    try:
                        socket.create_connection(("127.0.0.1", port), timeout=1).close()
                        bound = True
                        break
                    except OSError:
                        time.sleep(0.3)
                report(PASS if bound else FAIL, "server starts",
                       "port %d" % port if bound else "printed port %d but never bound" % port)
                base = "http://127.0.0.1:%d" % port

                def get(path, payload=None):
                    req = urllib.request.Request(
                        base + path,
                        data=json.dumps(payload).encode() if payload else None,
                        headers={"Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        return resp.status, resp.read()

                def route(name, fn):
                    try:
                        ok, detail = fn()
                        report(PASS if ok else FAIL, name, detail)
                    except Exception as exc:
                        report(FAIL, name, str(exc)[:90])

                if bound:
                    def _page():
                        status, body = get("/")
                        return status == 200 and b"DRISHTI" in body, "%d bytes" % len(body)

                    def _status():
                        _s, body = get("/api/status")
                        srcs = json.loads(body).get("sources", [])
                        return len(srcs) == 13, "%d listed" % len(srcs)

                    def _lookup():
                        _s, body = get("/api/lookup", {"target": "1.1.1.1"})
                        verdict = json.loads(body).get("verdict")
                        return bool(verdict), verdict or "no verdict"

                    def _config():
                        _s, body = get("/api/config")
                        ai = json.loads(body).get("ai", {})
                        return "backends" in ai, \
                            "order: %s" % (", ".join(ai.get("backends", [])) or "off")

                    route("UI page serves", _page)
                    route("13 sources registered", _status)
                    route("lookup route", _lookup)
                    route("AI config route", _config)
        finally:
            proc.terminate()

    section("AI summary backends")
    try:
        cfg = cli.load_config()
        if cli.ollama_up(cfg):
            models = cli.ollama_models(cfg)
            report(PASS, "Ollama", "up at %s, %d model(s)"
                   % (cli.ollama_host(cfg), len(models)))
            if not models:
                report(WARN, "Ollama models", "none pulled, run: ollama pull llama3.2")
        else:
            report(WARN, "Ollama", "not running, start with: ollama serve")
        if cli.key(cfg, "glm"):
            report(PASS, "GLM key", "configured")
        else:
            report(WARN, "GLM key", "not set, cloud fallback unavailable")
    except Exception as exc:
        report(FAIL, "AI backend check", str(exc)[:90])

    return summary()


def summary():
    fails = RESULTS.count(FAIL)
    warns = RESULTS.count(WARN)
    print("\n%d checks: %d passed, %d warnings, %d failures"
          % (len(RESULTS), RESULTS.count(PASS), warns, fails))
    if fails:
        print("Something above needs fixing before Drishti will work here.")
    elif warns:
        print("Drishti works here. Warnings only reduce coverage, nothing is broken.")
    else:
        print("Everything works here.")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
