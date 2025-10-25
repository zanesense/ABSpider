# ABSpider — Vulnerability Scanner (v1.0)

## Overview

ABSpider is a lightweight reconnaissance and reporting dashboard with a Flask backend and a Tailwind JS frontend.
Features: DNS & HTTP checks, subdomain enumeration, WHOIS, WordPress detection, passive XSS surface analysis, proxy support, Discord webhook summary, threaded module execution, and PDF report generation.

> ⚠️ Only scan systems you own or have explicit written permission to test.

---

## Quick Start

### Requirements

* Python 3.8+
* `pip` packages:

```
flask requests reportlab beautifulsoup4
```

Create `requirements.txt`:

```
flask
requests
reportlab
beautifulsoup4
```

### Install & Run

```bash
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
.venv\Scripts\activate          # Windows

pip install -r requirements.txt
python app.py
# Open http://127.0.0.1:5000/
```

---

## Repo layout

```
.
├─ app.py                 # Flask app + routes (scan/report/proxies)
├─ scanner_logic.py       # scan modules, threadpool, PDF report generation, webhook sender
├─ templates/index.html   # frontend (theme preserved)
├─ static/
│  ├─ images/spider.ico
│  └─ reports/            # saved PDF reports
├─ proxies.json           # proxy store (JSON)
└─ requirements.txt
```

---

## How to use (UI)

1. Open web UI.
2. Enter **Target Domain**.
3. Optionally enter **Proxy** and/or **Discord Webhook URL**.
4. Select modules and click **RUN SCAN**.
5. View live console; when finished, **Download Report** (PDF recommended). If webhook provided, backend will send an embed with a report download link.

---

## API (examples)

### `/api/scan` — POST

Start scan (returns aggregated logs).

```json
POST /api/scan
{
  "domain": "example.com",
  "modules": ["basic","whois","subdomain"],
  "proxy": "http://127.0.0.1:8080",   // optional
  "save_proxy": false,                // optional
  "webhook": "https://discord.com/api/webhooks/..." // optional
}
```

Response:

```json
{ "output": "newline separated log text..." }
```

### `/api/report` — POST

Generate and return report (PDF/TXT/MD/JSON/HTML). Saves PDF to `static/reports/` and returns it as download.

```json
POST /api/report
{
  "domain":"example.com",
  "full_log_output": ["..."],
  "findings": {"critical":0,"medium":1},
  "format":"pdf",
  "webhook":"https://discord.com/api/webhooks/..."   // optional
}
```

### `/api/proxies` — GET/POST/DELETE

Manage `proxies.json` (list/add/remove proxies).

---

## Important notes & security

* **Do not** run active exploitation against targets without explicit written permission.
* Passive tests (headers, WHOIS, DNS) are included. Active exploit automation (e.g., SQLMap, live XSS exploitation) must be deployed only into controlled environments and with firm authorization and audit controls.
* Protect `proxies.json` and generated reports — they may contain sensitive information.

---

## Customization & Extensibility

* ThreadPool for parallel modules is implemented in `scanner_logic.py`.
* PDF generation uses ReportLab (clean executive summary + raw logs appendix).
* Discord webhook embed contains a Download PDF Report link (publicly reachable path required).
* Proxy string passed per-scan; `save_proxy: true` persists to `proxies.json`.

---

## Troubleshooting

* Blank UI / no response → ensure `app.py` is running.
* Report generation failure → ensure `static/reports/` exists and is writable.
* Discord webhook not delivered → verify webhook URL and outbound access to `discord.com`.

---

## License

MIT — use responsibly.

