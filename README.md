# 🕷️ ABSpider — Vulnerability Scanner (v1.0)

![Python Version](https://img.shields.io/badge/Python-3.x-blue)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)
![Issues](https://img.shields.io/github/issues/zanesense/ABSpider)
![Stars](https://img.shields.io/github/stars/zanesense/ABSpider)
![Forks](https://img.shields.io/github/forks/zanesense/ABSpider)


ABSpider is a lightweight web reconnaissance and reporting dashboard built with **Flask + Tailwind**.  
It performs passive recon, header checks, WHOIS lookups, subdomain scans, and more — then generates **beautiful PDF reports**.  
Includes proxy rotation, Discord webhook integration, and threaded scanning for speed.

> ⚠️ Use only on systems you own or have written authorization to test.

---

## 🚀 Quick Start

### 🧰 Automatic Setup (Recommended)
Just clone and run:
```bash
git clone https://github.com/zanesense/ABSpider.git
cd ABSpider
chmod +x setup.sh
./setup.sh
```
The script will:
- Create a virtual environment  
- Install dependencies  
- Set up folders (`static/reports`, `static/images`)  
- Start the Flask app on [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

### 🧩 Manual Setup (if needed)
```bash
python3 -m venv .venv
source .venv/bin/activate      # (Linux/Mac)
.venv\Scripts\activate       # (Windows)

pip install -r requirements.txt
python app.py
```

---

## 🗂️ Project Structure
```
ABSpider/
├─ app.py                 # Flask backend + routes
├─ scanner_logic.py       # Scan logic, threading, PDF & webhook
├─ templates
│  ├─ index.html         
│  ├─ styles.css          
│  └─ app.js
├─ static/
│  ├─ images/spider.ico
│  └─ reports/
├─ proxies.json           # Stores saved proxies
├─ requirements.txt
└─ setup.sh               # One-click setup & launcher
```

---

## 💻 Usage
1. Open the web UI at `http://127.0.0.1:5000`
2. Enter **Target Domain**
3. Optionally add a **Proxy** or **Discord Webhook URL**
4. Select modules → click **RUN SCAN**
5. When complete, click **Download PDF Report**

If a webhook is set, the tool automatically sends a **Discord embed summary** (with a download link).

---

## 🌐 API Overview
**POST `/api/scan`**
```json
{
  "domain": "example.com",
  "modules": ["basic", "whois", "subdomain"],
  "proxy": "http://127.0.0.1:8080",
  "webhook": "https://discord.com/api/webhooks/..."
}
```

**POST `/api/report`**
```json
{
  "domain": "example.com",
  "full_log_output": ["..."],
  "format": "pdf"
}
```

---

## ⚙️ Features
- Threaded scanning (via `ThreadPoolExecutor`)
- Proxy management via `proxies.json`
- PDF reporting with `reportlab`
- Discord webhook embed integration
- Clean Tailwind dashboard UI (theme preserved)
- Optional favicon/logo (`/static/images/spider.ico`, `/static/images/spider_logo.png`)

---

## 🔐 Security Notes
- ABSpider is for **ethical testing and research only**.
- Never use against external targets without written consent.
- Store reports and proxy configs securely — they may contain sensitive data.

---

## 🧩 License
**MIT License** — free to use, modify, and share with attribution.

---

### 🧠 Credits
Developed with ❤️ by **Saim Ali** and contributors.  
🕷️ © zanesense.
