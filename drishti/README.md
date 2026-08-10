# Drishti

IP and host intelligence from 13 sources. Two builds, one shared engine.

Everything lives in this folder and the folder is the whole install. Copy it
anywhere, run it there. Config and cache are created next to the scripts and
stay out of git, so this repo is always a clean working backup of the code.

New machine, first thing:

```
python3 selftest.py
```

22 checks in about twenty seconds: environment, imports, reachability of
every keyless source, a real end to end lookup, the web routes on a live
server, and the AI backends. Zero failures means Drishti works there.
Warnings only mean reduced coverage, a missing key or Ollama not running.

| | Drishti.py | Drishti_cli.py |
|---|---|---|
| Runs on | macOS, browser UI | a-Shell on iPhone, any terminal |
| Needs | `pip3 install flask` | nothing, standard library only |
| Output | dark web UI, JSON, CSV, print to PDF | colour coded terminal report, JSON |

## Web build

```
pip3 install flask
python3 Drishti.py
```

Serves on http://127.0.0.1:5055 and opens your browser. If 5055 is taken it
walks forward to the next free port and tells you which one. Pass
`--no-browser` to skip the auto open.

Two tabs. Single lookup takes one IP, IPv6 address, hostname or URL. Bulk
analysis takes a pasted list or a loaded file, runs eight at a time with a
progress bar, and gives you a sortable table. Click any row for the full
report. Export JSON, export CSV, or print to PDF with the print stylesheet.

Settings holds the six API keys. They are written to `drishti_config.json`
next to the script with owner only permissions and shown masked afterwards.

## CLI build

```
python3 Drishti_cli.py 8.8.8.8
python3 Drishti_cli.py --me
python3 Drishti_cli.py -f targets.txt
python3 Drishti_cli.py --json 1.1.1.1 | jq .
python3 Drishti_cli.py --keys
```

| Flag | What it does |
|---|---|
| `--me` | look up your own public IP |
| `--keys` | add or update API keys interactively |
| `--json` | raw JSON, no colour |
| `--fresh` | bypass the 24 hour cache |
| `-f FILE` | read targets from a file, one per line, `#` comments allowed |
| `--ai` | add a plain English summary of the report |
| `--ai-backend` | force `auto`, `ollama`, `glm` or `off` for that run |
| `--no-colour` | plain text |

More than one target prints a sorted summary table after the individual
reports. Exit code is 0 for benign, 1 for suspicious, 2 for malicious, 3 if
any target failed to resolve, so it drops straight into a shell pipeline.

## The 13 sources

Keyless, always runs:

1. RDAP registry, ownership and abuse contacts
2. ipwho.is, geolocation and ASN
3. Reverse DNS
4. Shodan InternetDB, open ports and CVEs
5. Five DNSBL blocklists (Spamhaus ZEN, SpamCop, Barracuda, SORBS, s5h)
6. Tor exit node list
7. URLScan

Keyed, add in settings or `--keys`:

8. AbuseIPDB
9. GreyNoise
10. VirusTotal
11. Shodan full
12. Censys, key format `id:secret`
13. SecurityTrails

All 13 fire in parallel through a ThreadPoolExecutor with a 12 second cap on
the whole set. A slow or dead source is marked and the report still lands.
Keys can also come from the environment as `DRISHTI_ABUSEIPDB` and so on.

## Verdict engine

Scores 0 to 100 and returns BENIGN under 25, SUSPICIOUS from 25, MALICIOUS
from 60, with every contributing reason listed and weighted.

| Signal | Weight |
|---|---|
| AbuseIPDB confidence | up to +45 |
| GreyNoise malicious | +30 |
| VirusTotal malicious vendors | +8 each, cap 30 |
| DNSBL listings | +10 each, cap 30 |
| Shodan malware or C2 tag | +20 |
| Known CVEs on exposed services | +5 each, cap 20 |
| Tor exit node | +15 |
| GreyNoise suspicious | +12 |
| URLScan malicious pages | +6 each, cap 12 |
| Risky exposed services | +4 each, cap 16 |
| No reverse DNS with open ports | +3 |
| GreyNoise benign or RIOT | -25 and the total is capped at 20 |
| AbuseIPDB whitelisted | -15 |

Private, loopback, link local, multicast and reserved ranges short circuit as
INTERNAL before any request goes out, so scanning your own subnet costs
nothing in API quota. Hostnames and URLs resolve to an IP first.

## Plain English summary

A report tells you an address scored 25 and sits on one blocklist. It does not
tell you what to do about it. The summary layer closes that gap. In the web UI
every report has an Explain button. On the CLI it is the `--ai` flag.

```
python3 Drishti_cli.py --ai 45.155.205.233
```

Two backends. Ollama runs on your own machine and needs no key, so nothing
about the address you looked up leaves the box. GLM is the cloud fallback for
when Ollama is not running. The default is `auto`: use Ollama if it answers,
otherwise GLM, otherwise say so and carry on.

```
ollama serve
ollama pull llama3.2
```

Set the backend, host, model and GLM key in Settings in the web UI, or with
`--keys` on the CLI. `ai_backend` accepts `auto`, `ollama`, `glm` or `off`.
A GLM key can also come from the environment as `DRISHTI_GLM`. Both raw bearer
and JWT signed authentication are attempted, and both the bigmodel.cn and
z.ai endpoints are tried, so whichever form your key takes will work.

The model never sees the raw source payload. It gets a compact factual brief
built from the finished report: ownership, surface, each source's finding, the
weighted scoring breakdown, and an explicit list of the sources that had no
API key so it cannot imply coverage that did not happen. It is instructed to
use only those facts. Summaries are cached alongside the report, keyed on the
address and its score, so a re-read is instant and a changed score gets a
fresh summary. Rewrite in the UI and `--fresh` on the CLI force a new one.

Everything else works unchanged when no AI backend is available. The summary
is an addition to the report, never a replacement for it.

## Cache

SQLite at `drishti_cache.db` next to the script, 24 hour TTL, keyed by IP.
The Tor exit list is cached separately for 6 hours and fetched once per
process. Skip it with `--fresh`, or Skip cache in the UI. Clear cache in the
web header empties the table.
