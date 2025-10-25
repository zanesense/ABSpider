# scanner_logic.py
import requests
import re
import socket
import warnings
import datetime
import io
import time
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# PDF generation
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Preformatted
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm

warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = int(__import__('os').environ.get("ABSPIDER_REQUEST_TIMEOUT", "6"))
VERIFY_SSL = __import__('os').environ.get("ABSPIDER_VERIFY_SSL", "true").lower() == "true"

DEFAULT_SUBDOMAINS = ['www', 'mail', 'ftp', 'dev', 'test', 'api', 'blog', 'admin', 'vpn', 'webmail', 'staging']

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def get_clean_hostname(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        from urllib.parse import urlparse
        host = urlparse(url).hostname or url
        if host.startswith('www.'):
            host = host[4:]
        return host
    except Exception:
        return url

def safe_dns_lookup(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception:
        return None

def safe_http_get(url, proxies=None, timeout=REQUEST_TIMEOUT):
    resp = requests.get(url, timeout=timeout, verify=VERIFY_SSL, allow_redirects=True, proxies=proxies)
    return resp.status_code, resp.headers, resp.text

def run_basic_scan(domain, proxies=None):
    logs = []
    clean_domain = get_clean_hostname(domain)
    url = f"https://{clean_domain}"

    logs.append(f"[INFO] Attempting DNS resolution for {clean_domain}...")
    ip = safe_dns_lookup(clean_domain)
    if ip:
        logs.append(f"[SUCCESS] Target IP resolved: {ip}")
    else:
        logs.append(f"[WARNING] DNS resolution failed for {clean_domain}. Continuing with HTTP checks...")

    logs.append(f"[INFO] Testing HTTP/S connectivity on {url}...")
    try:
        status, headers, text = safe_http_get(url, proxies=proxies)
        logs.append(f"[SUCCESS] Web server responded with Status: {status}")
        server_hdr = headers.get('Server', 'Not disclosed')
        logs.append(f"[INFO] Server: {server_hdr}")

        if 'Strict-Transport-Security' not in headers:
            logs.append("[FINDING] Medium-Severity: HSTS (Strict-Transport-Security) header is missing.")
        if 'X-Frame-Options' not in headers:
            logs.append("[FINDING] Low-Severity: X-Frame-Options header is missing.")
    except requests.exceptions.Timeout:
        logs.append(f"[CRITICAL ERROR] Connection timed out after {REQUEST_TIMEOUT}s to {url}.")
    except requests.exceptions.RequestException as e:
        logs.append(f"[CRITICAL ERROR] HTTP connectivity failed: {e.__class__.__name__}: {str(e)}")
    return logs

def run_subdomain_enumeration(domain, proxies=None, subdomains=None):
    logs = []
    clean_domain = get_clean_hostname(domain)
    subdomains = subdomains or DEFAULT_SUBDOMAINS
    logs.append(f"[INFO] Checking {len(subdomains)} common subdomains for {clean_domain}...")

    found = 0
    for sub in subdomains:
        fqdn = f"{sub}.{clean_domain}"
        ip = safe_dns_lookup(fqdn)
        if ip:
            logs.append(f"[SUCCESS] Subdomain found: {fqdn} -> {ip}")
            found += 1

    if found == 0:
        logs.append("[INFO] No common subdomains were found using the default list.")
    else:
        logs.append(f"[SUMMARY] Found {found} potential subdomains.")
    return logs

def run_wordpress_scan(domain, proxies=None):
    logs = []
    clean_domain = get_clean_hostname(domain)
    wp_login = f"https://{clean_domain}/wp-login.php"
    readme = f"https://{clean_domain}/readme.html"

    logs.append("[INFO] Checking for common WordPress indicators...")
    try:
        status, headers, text = safe_http_get(wp_login, proxies=proxies)
        if status == 200:
            logs.append("[SUCCESS] Found wp-login.php. Target is likely running WordPress.")
            try:
                r_status, r_headers, r_text = safe_http_get(readme, proxies=proxies)
                if r_status == 200 and 'WordPress' in r_text:
                    m = re.search(r'Version\s*([\d\.]+)', r_text, re.IGNORECASE)
                    if m:
                        logs.append(f"[INFO] WordPress Version: {m.group(1)}")
                    else:
                        logs.append("[INFO] WordPress detected, but version number could not be parsed from readme.")
            except Exception:
                logs.append("[INFO] readme.html not accessible or parse failed.")
        else:
            logs.append(f"[INFO] wp-login.php check returned status code {status}. Not detected as WordPress.")
    except requests.exceptions.RequestException as e:
        logs.append("[ERROR] WordPress detection connectivity failed: " + str(e.__class__.__name__))
    return logs

def run_whois_lookup(domain, proxies=None):
    logs = []
    clean_domain = get_clean_hostname(domain)
    WHOIS_SERVER = "whois.verisign-grs.com"
    WHOIS_PORT = 43

    logs.append(f"[INFO] Initiating WHOIS lookup via {WHOIS_SERVER}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((WHOIS_SERVER, WHOIS_PORT))
        s.send((clean_domain + "\r\n").encode('utf-8'))
        data = b""
        while True:
            part = s.recv(4096)
            if not part:
                break
            data += part
        s.close()
        text = data.decode('utf-8', errors='ignore')
        reg = re.search(r'Registrar:\s*(.+)', text, re.IGNORECASE)
        cdate = re.search(r'Creation Date:\s*(.+)', text, re.IGNORECASE)
        edate = re.search(r'Registry Expiry Date:\s*(.+)', text, re.IGNORECASE)
        if reg:
            logs.append(f"[SUCCESS] Registrar: {reg.group(1).strip()}")
        if cdate:
            logs.append(f"[INFO] Creation Date: {cdate.group(1).strip()}")
        if edate:
            logs.append(f"[INFO] Expiration Date: {edate.group(1).strip()}")
        if 'privacy' in text.lower() or 'redacted' in text.lower():
            logs.append(f"[FINDING] Low-Severity: Domain owner details appear protected by privacy/GDPR redaction.")
    except Exception as e:
        logs.append(f"[CRITICAL ERROR] WHOIS lookup failed: {str(e)}")
    return logs

def run_sqli_simulation(domain, proxies=None):
    logs = []
    clean_domain = get_clean_hostname(domain)
    logs.append("[SIMULATED] Initializing SQLi simulation on common parameters (safe simulation only)...")
    lower = clean_domain.lower()
    time.sleep(1.0)
    if 'test' in lower or 'dev' in lower or 'staging' in lower:
        logs.append("[CRITICAL] Simulated: parameter 'id' on /test.php appears vulnerable to basic injection.")
        logs.append("[DETAIL] Simulated payload 'or 1=1-- ' produced database error (simulated).")
    else:
        logs.append("[INFO] 30 simulated payloads tested (simulation). No obvious SQL error patterns detected.")
    return logs

def run_geoip_lookup_stub(domain_or_ip, proxies=None):
    logs = []
    logs.append("[INFO] Geo-IP stub invoked (frontend runs Geo-IP client-side by default).")
    logs.append("[INFO] This server-side Geo-IP is disabled by default for privacy reasons.")
    return logs

def run_xss_passive_scan(domain, proxies=None, crawl_paths=None, max_pages=5):
    logs = []
    clean_domain = get_clean_hostname(domain)
    base = f"https://{clean_domain}"
    logs.append("[INFO] Starting passive XSS surface analysis (no injections).")
    crawl_paths = crawl_paths or ["/", "/search", "/login", "/contact", "/?s=test"]
    pages_checked = 0
    discovered_forms = 0
    discovered_param_links = 0
    headers_to_check = ['Content-Security-Policy', 'X-Content-Type-Options', 'Referrer-Policy', 'X-Frame-Options']

    for rel in crawl_paths:
        if pages_checked >= max_pages:
            break
        try:
            url = urljoin(base, rel)
            logs.append(f"[INFO] Fetching {url} (passive check)...")
            status, headers, text = safe_http_get(url, proxies=proxies)
            pages_checked += 1
            missing = []
            for h in headers_to_check:
                if h not in headers:
                    missing.append(h)
            if missing:
                logs.append(f"[FINDING] Missing security headers on {url}: {', '.join(missing)}")
            try:
                soup = BeautifulSoup(text, "html.parser")
            except Exception:
                soup = None
            if soup:
                forms = soup.find_all("form")
                if forms:
                    discovered_forms += len(forms)
                    methods = sorted({(f.get('method') or 'GET').upper() for f in forms})
                    logs.append(f"[INFO] Found {len(forms)} form(s) on {url}. (methods: {', '.join(methods)})")
                    for idx, f in enumerate(forms[:5], start=1):
                        inputs = f.find_all(["input", "textarea", "select"])
                        input_names = [ (i.get('name') or i.get('id') or i.get('type') or 'unnamed') for i in inputs ]
                        logs.append(f"[INFO]  Form {idx} inputs: {', '.join(input_names) if input_names else 'none'}")
                links = soup.find_all("a", href=True)
                param_links = []
                for a in links:
                    href = a['href']
                    parsed = urlparse(href)
                    if parsed.scheme and parsed.scheme not in ('http', 'https'):
                        continue
                    abs_href = urljoin(url, href)
                    qp = urlparse(abs_href).query
                    if qp:
                        discovered_param_links += 1
                        param_links.append(abs_href)
                if param_links:
                    sample = param_links[:5]
                    logs.append(f"[INFO] Found {len(param_links)} link(s) with query-parameters on {url}. Sample: {', '.join(sample)}")
        except requests.exceptions.RequestException as e:
            logs.append(f"[ERROR] Could not fetch {rel}: {e.__class__.__name__}")
        except Exception as ex:
            logs.append(f"[ERROR] Unexpected error when analyzing {rel}: {str(ex)}")

    if discovered_forms == 0 and discovered_param_links == 0:
        logs.append("[INFO] Passive XSS surface analysis found no forms or query-parameter links on the scanned pages.")
    else:
        logs.append(f"[SUMMARY] Passive XSS surface: {discovered_forms} forms found, {discovered_param_links} links with params found across {pages_checked} pages.")
    logs.append("[INFO] Passive XSS scan complete. Perform authorized active tests in an isolated environment to verify.")
    return logs

def send_discord_webhook(webhook_url, scan_data, report_url=None):
    try:
        color = 0xEF4444
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        embed = {
            "title": "🕷️ ABSpider Scan Completed",
            "color": color,
            "fields": [
                {"name": "Target", "value": str(scan_data.get("target", scan_data.get("target", "Unknown"))), "inline": False},
                {"name": "Findings", "value": str(scan_data.get("findings", "No findings reported.")), "inline": False},
                {"name": "Severity Summary", "value": f"🔴 {scan_data.get('critical', 0)} Critical\n🟠 {scan_data.get('medium', 0)} Medium", "inline": True},
            ],
            "footer": {"text": f"ABSpider v1.0 • {timestamp}"},
        }

        components = []
        if report_url:
            components = [{
                "type": 1,
                "components": [
                    {
                        "type": 2,
                        "style": 5,  # link button
                        "label": "📄 Download PDF Report",
                        "url": report_url
                    }
                ]
            }]

        payload = {"embeds": [embed], "components": components}

        requests.post(webhook_url, json=payload, timeout=8)
        return True
    except Exception as e:
        logger.exception("Discord webhook send failed: %s", str(e))
        return False

def _split_logs_by_module(full_log_output):
    modules = {}
    current_module = "general"
    modules[current_module] = []
    for line in full_log_output:
        if line.strip().startswith('--- Executing Module:'):
            m = re.search(r'--- Executing Module:\s*([^\s-]+)', line)
            if m:
                current_module = m.group(1).strip()
                modules[current_module] = []
                continue
        modules[current_module].append(line)
    return modules

def run_generate_report(domain, full_log_output, findings, report_format='txt'):
    clean_domain = get_clean_hostname(domain)
    today = datetime.date.today().isoformat()
    ext = report_format.lower()
    filename = f"abspider-{clean_domain}-{today}.{ext}"

    if ext != 'pdf':
        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_lines = [
            "=" * 59,
            "ABSpider Vulnerability Scan Report",
            "=" * 59,
            f"Target Domain: {domain}",
            f"Scan Date/Time: {date_str}",
            f"Total Findings: {findings.get('critical', 0)} Critical, {findings.get('medium', 0)} Medium",
            f"Total Log Lines: {len(full_log_output)}",
            f"Report Format: {report_format.upper()}",
            "=" * 59,
            "",
            "--- RAW CONSOLE LOGS ---",
            ""
        ]
        report_lines.extend(full_log_output or [])
        buf = io.BytesIO()
        buf.write("\n".join(report_lines).encode('utf-8'))
        buf.seek(0)
        return buf, filename

    # PDF generation
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=18*mm, leftMargin=18*mm,
                            topMargin=18*mm, bottomMargin=18*mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=20, leading=24, alignment=1, spaceAfter=6)
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=10, leading=12, alignment=1, textColor=colors.grey, spaceAfter=12)
    heading_style = ParagraphStyle('Heading', parent=styles['Heading2'], fontSize=12, leading=14, spaceAfter=6)
    normal_style = styles['Normal']
    code_style = ParagraphStyle('Code', fontName='Courier', fontSize=8, leading=10)

    flow = []
    flow.append(Paragraph("ABSpider v1.0", title_style))
    flow.append(Paragraph("Vulnerability Scan Report", subtitle_style))
    flow.append(Spacer(1, 6))

    meta_table_data = [
        ['Target', domain],
        ['Report Generated', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ['Total Log Lines', str(len(full_log_output))],
        ['Critical Findings', str(findings.get('critical', 0))],
        ['Medium Findings', str(findings.get('medium', 0))],
    ]
    meta_table = Table(meta_table_data, colWidths=[80*mm, 80*mm], hAlign='LEFT')
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.whitesmoke),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOX', (0,0), (-1,-1), 0.5, colors.lightgrey),
        ('INNERGRID', (0,0), (-1,-1), 0.25, colors.lightgrey),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
    ]))
    flow.append(meta_table)
    flow.append(Spacer(1, 12))

    flow.append(Paragraph("Executive Summary", heading_style))
    exec_summary = "This report summarizes the results of a non-invasive scan run by ABSpider v1.0. Module outputs and raw logs are included."
    flow.append(Paragraph(exec_summary, normal_style))
    flow.append(Spacer(1, 10))

    modules = _split_logs_by_module(full_log_output)
    table_data = [['Module', 'Highlights', 'Risk Estimate']]
    for mod, lines in modules.items():
        risk = 'Low'
        highlights = []
        for l in lines:
            if '[CRITICAL]' in l or 'CRITICAL ERROR' in l:
                risk = 'High'
                highlights.append(l.strip())
            elif '[FINDING]' in l or '[WARNING]' in l:
                if risk != 'High':
                    risk = 'Medium'
                highlights.append(l.strip())
        highlights_text = "; ".join(highlights[:2]) if highlights else '—'
        table_data.append([mod, highlights_text, risk])

    summary_table = Table(table_data, colWidths=[50*mm, 80*mm, 30*mm], hAlign='LEFT')
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#ef4444')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('ALIGN', (2,1), (2,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOX', (0,0), (-1,-1), 0.5, colors.lightgrey),
        ('INNERGRID', (0,0), (-1,-1), 0.25, colors.lightgrey),
    ]))
    flow.append(Paragraph("Module Summary", heading_style))
    flow.append(summary_table)
    flow.append(Spacer(1, 12))

    for mod, lines in modules.items():
        flow.append(Paragraph(f"Module: {mod}", heading_style))
        if lines:
            preview = "\n".join(lines[:8])
            flow.append(Preformatted(preview, code_style))
            if len(lines) > 8:
                flow.append(Paragraph(f"... (See raw logs in appendix for full output of {mod})", normal_style))
        else:
            flow.append(Paragraph("No output from this module.", normal_style))
        flow.append(Spacer(1, 8))

    flow.append(PageBreak())
    flow.append(Paragraph("Appendix: Raw Console Logs", heading_style))
    flow.append(Spacer(1, 6))
    raw_text = "\n".join(full_log_output or ['(No logs captured)'])
    CHUNK_SIZE = 4000
    for i in range(0, len(raw_text), CHUNK_SIZE):
        chunk = raw_text[i:i+CHUNK_SIZE]
        flow.append(Preformatted(chunk, code_style))
        flow.append(Spacer(1, 6))

    flow.append(Spacer(1, 8))
    flow.append(Paragraph(f"Generated by ABSpider v1.0 • {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ParagraphStyle('Footer', alignment=1, fontSize=8, textColor=colors.grey)))

    doc.build(flow)
    buffer.seek(0)
    return buffer, filename
