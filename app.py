# app.py
import os
import io
import time
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
import werkzeug

import scanner_logic

# --- Configuration ---
MAX_WORKERS = int(os.environ.get("ABSPIDER_MAX_WORKERS", "6"))
MODULE_TIMEOUT = int(os.environ.get("ABSPIDER_MODULE_TIMEOUT", "30"))
PROXIES_STORE = os.environ.get("ABSPIDER_PROXIES_FILE", "proxies.json")
REPORTS_DIR = os.path.join('static', 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

# --- Flask init ---
app = Flask(__name__, static_folder='static', template_folder='templates')
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

MODULE_FUNCTION_MAP = {
    'basic': scanner_logic.run_basic_scan,
    'subdomain': scanner_logic.run_subdomain_enumeration,
    'wordpress': scanner_logic.run_wordpress_scan,
    'whois': scanner_logic.run_whois_lookup,
    'sqli': scanner_logic.run_sqli_simulation,
    'geoip': scanner_logic.run_geoip_lookup_stub,
    'xss': scanner_logic.run_xss_passive_scan
}

def _ensure_proxies_file():
    if not os.path.exists(PROXIES_STORE):
        with open(PROXIES_STORE, 'w', encoding='utf-8') as f:
            json.dump({"proxies": []}, f, indent=2)

def load_proxies():
    _ensure_proxies_file()
    with open(PROXIES_STORE, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
            return data.get("proxies", [])
        except Exception:
            return []

def save_proxies(proxies_list):
    with open(PROXIES_STORE, 'w', encoding='utf-8') as f:
        json.dump({"proxies": proxies_list}, f, indent=2)

def validate_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    d = domain.strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0]
    import re
    pattern = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})+$')
    return bool(pattern.match(d))

def wrap_module_call(module_key, func, domain, proxies=None):
    header = f"--- Executing Module: {module_key} ---"
    start_ts = time.time()
    logs = [f"[INFO] Module {module_key} started at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(start_ts))}"]
    try:
        module_result = func(domain, proxies=proxies)
        if isinstance(module_result, str):
            module_result_lines = module_result.splitlines()
        else:
            module_result_lines = list(module_result or [])
        logs.extend(module_result_lines)
    except Exception as e:
        logs.append(f"[CRITICAL ERROR] Exception while running module {module_key}: {str(e)}")
    end_ts = time.time()
    elapsed = round(end_ts - start_ts, 2)
    logs.append(f"[INFO] Module {module_key} finished in {elapsed}s")
    return header, logs

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def run_scan_api():
    data = request.get_json(force=True, silent=True) or {}
    domain = data.get('domain', '').strip()
    modules = data.get('modules', [])
    proxy = data.get('proxy')
    save_proxy_flag = bool(data.get('save_proxy', False))
    webhook_url = data.get('webhook')

    if not domain:
        return jsonify({"error": "No target domain provided."}), 400
    if not validate_domain(domain):
        return jsonify({"error": f"Invalid domain format: {domain}"}), 400
    if not modules:
        modules = ['basic']

    selected = [m for m in modules if m in MODULE_FUNCTION_MAP]
    if not selected:
        return jsonify({"error": "No valid modules selected."}), 400

    proxies = {"http": proxy, "https": proxy} if proxy else None

    if save_proxy_flag and proxy:
        current = load_proxies()
        if proxy not in current:
            current.append(proxy)
            save_proxies(current)
            logging.info("Saved new proxy to store: %s", proxy)

    logging.info("Scan requested for %s with modules: %s (proxy=%s)", domain, selected, proxy or "none")

    aggregated_lines = []
    structured = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_module = {}
        for module_key in selected:
            func = MODULE_FUNCTION_MAP[module_key]
            future = executor.submit(wrap_module_call, module_key, func, domain, proxies)
            future_to_module[future] = module_key

        for future in as_completed(future_to_module, timeout=MODULE_TIMEOUT * len(future_to_module)):
            module_key = future_to_module[future]
            try:
                header, logs = future.result(timeout=MODULE_TIMEOUT)
                structured.append({"module": module_key, "header": header, "logs": logs})
                aggregated_lines.append(header)
                aggregated_lines.extend(logs)
            except TimeoutError:
                msg = f"[CRITICAL ERROR] Module {module_key} timed out after {MODULE_TIMEOUT}s."
                logging.error(msg)
                structured.append({"module": module_key, "header": f"--- Executing Module: {module_key} ---", "logs": [msg]})
                aggregated_lines.append(f"--- Executing Module: {module_key} ---")
                aggregated_lines.append(msg)
            except Exception as e:
                msg = f"[CRITICAL ERROR] Module {module_key} failed with exception: {str(e)}"
                logging.exception(msg)
                structured.append({"module": module_key, "header": f"--- Executing Module: {module_key} ---", "logs": [msg]})
                aggregated_lines.append(f"--- Executing Module: {module_key} ---")
                aggregated_lines.append(msg)

    aggregated_lines.append("----------------------------------------------------")
    aggregated_lines.append(f"[COMPLETED] Scan finished for {domain} at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}")

    final_output = "\n".join(aggregated_lines)

    # send webhook summary asynchronously (best-effort)
    if webhook_url:
        try:
            findings_count = sum(1 for ln in aggregated_lines if any(tag in ln.upper() for tag in ('CRITICAL', 'FINDING', 'WARNING')))
            summary = {
                "target": domain,
                "status": "Completed",
                "findings": f"{findings_count} potential findings",
                "lines": len(aggregated_lines),
                "critical": sum(1 for ln in aggregated_lines if 'CRITICAL' in ln.upper()),
                "medium": sum(1 for ln in aggregated_lines if 'FINDING' in ln.upper() or 'WARNING' in ln.upper())
            }
            import threading
            threading.Thread(target=scanner_logic.send_discord_webhook, args=(webhook_url, summary, None), daemon=True).start()
        except Exception as e:
            logging.exception("Failed to start webhook sender thread: %s", str(e))

    return jsonify({"output": final_output})

@app.route('/api/report', methods=['POST'])
def generate_report_api():
    data = request.get_json(force=True, silent=True) or {}
    domain = data.get('domain')
    full_log_output = data.get('full_log_output', [])
    findings = data.get('findings', {})
    report_format = data.get('format', 'pdf').lower()
    webhook_url = data.get('webhook')

    if not domain or not full_log_output:
        return jsonify({"error": "Missing domain or log data for report generation."}), 400

    try:
        file_buffer, filename = scanner_logic.run_generate_report(domain, full_log_output, findings, report_format)

        # Save to static/reports for linkable URL if PDF
        save_path = os.path.join(REPORTS_DIR, filename)
        with open(save_path, 'wb') as f:
            f.write(file_buffer.read())
        file_buffer.seek(0)

        # Build public report URL
        report_url = f"{request.host_url}static/reports/{filename}"

        # Send webhook with report link async (best-effort)
        if webhook_url:
            try:
                summary = {
                    "target": domain,
                    "findings": f"{findings.get('critical',0)} critical, {findings.get('medium',0)} medium",
                    "critical": findings.get('critical', 0),
                    "medium": findings.get('medium', 0),
                    "lines": len(full_log_output)
                }
                import threading
                threading.Thread(target=scanner_logic.send_discord_webhook, args=(webhook_url, summary, report_url), daemon=True).start()
            except Exception:
                logging.exception("Failed to start webhook/report sender thread")

        # Return file for download
        # set mimetype
        mimetype = 'application/pdf' if report_format == 'pdf' else 'application/octet-stream'
        return send_file(
            io.BytesIO(open(save_path, 'rb').read()),
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logging.exception("Report generation failed: %s", str(e))
        return jsonify({"error": f"Report generation failed on the backend: {str(e)}"}), 500

@app.route('/api/upload-scan-results', methods=['POST'])
def upload_scan_results():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    f = request.files['file']
    domain = request.form.get('domain', '').strip()
    filename = werkzeug.utils.secure_filename(f.filename or 'upload.txt')
    raw = f.read()
    parsed_lines = []
    summary = {"lines": 0, "findings": 0}
    try:
        decoded = raw.decode('utf-8', errors='ignore').strip()
        if decoded.startswith('{') or decoded.startswith('['):
            try:
                data = json.loads(decoded)
                def extract_from_json(obj):
                    lines = []
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if isinstance(v, (list, dict)):
                                lines.extend(extract_from_json(v))
                            else:
                                lines.append(f"{k}: {v}")
                    elif isinstance(obj, list):
                        for item in obj:
                            lines.extend(extract_from_json(item))
                    else:
                        lines.append(str(obj))
                    return lines
                parsed = extract_from_json(data)
                parsed_lines = parsed
            except Exception:
                parsed_lines = decoded.splitlines()
        else:
            parsed_lines = decoded.splitlines()
    except Exception:
        parsed_lines = []
    parsed_lines = [ln.strip() for ln in parsed_lines if ln and ln.strip()]
    summary["lines"] = len(parsed_lines)
    summary["findings"] = sum(1 for ln in parsed_lines if any(tag in ln.upper() for tag in ('XSS','CRITICAL','VULN','INJECTION','SQLI','CROSS-SITE')))
    return jsonify({"parsed_lines": parsed_lines, "summary": summary, "filename": filename, "domain": domain}), 200

@app.route('/api/proxies', methods=['GET'])
def list_proxies():
    proxies = load_proxies()
    return jsonify({"proxies": proxies})

@app.route('/api/proxies', methods=['POST'])
def add_proxy():
    data = request.get_json(force=True, silent=True) or {}
    proxy = data.get('proxy', '').strip()
    if not proxy:
        return jsonify({"error": "No proxy provided"}), 400
    proxies = load_proxies()
    if proxy in proxies:
        return jsonify({"message": "Already present", "proxies": proxies}), 200
    proxies.append(proxy)
    save_proxies(proxies)
    return jsonify({"message": "Added", "proxies": proxies}), 201

@app.route('/api/proxies', methods=['DELETE'])
def delete_proxy():
    data = request.get_json(force=True, silent=True) or {}
    proxy = data.get('proxy', '').strip()
    if not proxy:
        return jsonify({"error": "No proxy provided"}), 400
    proxies = load_proxies()
    if proxy not in proxies:
        return jsonify({"error": "Proxy not found", "proxies": proxies}), 404
    proxies.remove(proxy)
    save_proxies(proxies)
    return jsonify({"message": "Deleted", "proxies": proxies}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=True)
