import requests 
import re 
import socket 
from urllib.parse import urlparse
import warnings
import datetime # NEW: for report date
import io       # NEW: for file streaming

# Suppress warnings for insecure request (because verify=False is used for SSL testing)
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# --- Utility Function ---
def get_clean_hostname(url):
    """Extracts a clean hostname (domain.tld) regardless of scheme or www."""
    try:
        # Prepend https if no scheme is present
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Extract the network location (hostname)
        host = urlparse(url).netloc
        
        # Remove 'www.' if present
        if host.startswith('www.'):
            host = host[4:]
            
        return host
    except Exception:
        # Return the original input if parsing fails (fallback)
        return url

# ----------------------------------------------------
# Core Scan Logic Functions (All now prioritize HTTPS)
# ----------------------------------------------------

def run_basic_scan(domain):
    results = []
    # Ensure domain is clean for both HTTP request and DNS lookup
    clean_domain = get_clean_hostname(domain)
    url = f"https://{clean_domain}" 
    
    # 1. Dynamic IP Resolution (Critical for Live Metrics)
    target_ip = "Unknown"
    dns_success = False
    results.append(f"[INFO] Attempting DNS resolution for {clean_domain}...")
    
    try:
        # Use socket to perform a basic DNS lookup
        target_ip = socket.gethostbyname(clean_domain)
        results.append(f"[SUCCESS] Target IP resolved: {target_ip}")
        dns_success = True
    except socket.gaierror:
        results.append(f"[CRITICAL ERROR] DNS resolution failed for {clean_domain}. Domain may not exist or is unreachable.")
    except Exception as e:
        results.append(f"[CRITICAL ERROR] Unexpected DNS error: {str(e)}")
        
    # 2. HTTP/S Connectivity Check
    results.append(f"[INFO] Testing HTTP/S connectivity on {url}...")
    
    try:
        # Use a short timeout and allow redirects
        response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        
        # Check for status codes
        if 200 <= response.status_code < 400:
            results.append(f"[SUCCESS] Web server responded with Status: {response.status_code}")
            
            # Look for Server header
            server_header = response.headers.get('Server', 'Not disclosed')
            results.append(f"[INFO] Server: {server_header}")
            
            # Check for missing security headers (Example: HSTS)
            if 'Strict-Transport-Security' not in response.headers:
                results.append("[FINDING] Medium-Severity: HSTS (Strict-Transport-Security) header is missing.")
            
        else:
            results.append(f"[WARNING] Server returned Status: {response.status_code}. Access denied or client error.")
            
    except requests.exceptions.Timeout:
        results.append(f"[CRITICAL ERROR] Connection timed out after 5 seconds to {url}.")
    except requests.exceptions.RequestException as e:
        results.append(f"[CRITICAL ERROR] Connection failed. Check if port 443 is open/reachable. Error: {e.__class__.__name__}")
        
    return results

def run_subdomain_enumeration(domain, subdomain_list):
    results = []
    clean_domain = get_clean_hostname(domain)
    
    results.append(f"[INFO] Checking {len(subdomain_list)} common subdomains for {clean_domain}...")

    found_count = 0
    for sub in subdomain_list:
        sub_domain = f"{sub}.{clean_domain}"
        try:
            # Perform DNS lookup to check for existence
            target_ip = socket.gethostbyname(sub_domain)
            results.append(f"[SUCCESS] Subdomain found: {sub_domain} -> {target_ip}")
            found_count += 1
            
        except socket.gaierror:
            # Domain not found, which is expected for most checks
            pass 
        except Exception as e:
            results.append(f"[ERROR] Subdomain check error for {sub_domain}: {str(e)}")
            
    if found_count == 0:
        results.append("[INFO] No common subdomains were found using the default list.")
    else:
        results.append(f"[SUMMARY] Found {found_count} potential subdomains.")
        
    return results

def run_wordpress_scan(domain):
    results = []
    clean_domain = get_clean_hostname(domain)
    
    # Check for common WordPress files/headers
    wp_login_url = f"https://{clean_domain}/wp-login.php"
    readme_url = f"https://{clean_domain}/readme.html"
    
    results.append(f"[INFO] Checking for common WordPress indicators...")
    is_wordpress = False

    try:
        # Check wp-login.php
        response = requests.get(wp_login_url, timeout=3, verify=False)
        if response.status_code == 200:
            is_wordpress = True
            results.append("[SUCCESS] Found wp-login.php. Target is likely running WordPress.")

            # Look for version information in readme.html (if accessible)
            readme_response = requests.get(readme_url, timeout=3, verify=False)
            if readme_response.status_code == 200 and 'WordPress' in readme_response.text:
                version_match = re.search(r'Version\s*(\d+\.\d+\.\d+)', readme_response.text)
                if version_match:
                    version = version_match.group(1)
                    results.append(f"[INFO] WordPress Version: {version}")
                else:
                    results.append("[INFO] WordPress detected, but version number is not easily parsable.")

            # Look for common directory listing issues (simulated for simplicity)
            if 'index of /wp-content' in response.text.lower():
                results.append("[CRITICAL] Directory listing enabled for /wp-content, exposing themes and plugins.")
        else:
            results.append(f"[INFO] wp-login.php check returned status code {response.status_code}. Not detected as WordPress.")

    except requests.exceptions.RequestException as e:
        results.append(f"[ERROR] WordPress detection connectivity failed: {e.__class__.__name__}")
        
    return results

def run_whois_lookup(domain):
    results = []
    clean_domain = get_clean_hostname(domain)
    
    # Simple, direct WHOIS lookup (requires whois library for complex domains, but this is a socket-based simulation)
    # Using a public WHOIS server for .com/.net
    WHOIS_SERVER = "whois.verisign-grs.com"
    WHOIS_PORT = 43
    
    results.append(f"[INFO] Initiating WHOIS lookup via {WHOIS_SERVER}...")

    try:
        # 1. Connect to WHOIS server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((WHOIS_SERVER, WHOIS_PORT))
        
        # 2. Send query
        s.send(f"{clean_domain}\r\n".encode('utf-8'))
        
        # 3. Receive response
        response_text = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response_text += data
        s.close()
        
        response_text = response_text.decode('utf-8', errors='ignore')
        
        # 4. Parse key fields (using regex to make it robust against raw WHOIS data)
        registrar_match = re.search(r'Registrar:\s*([^ \n\r]+)', response_text, re.IGNORECASE)
        creation_match = re.search(r'Creation Date:\s*([^ \n\r]+)', response_text, re.IGNORECASE)
        expiry_match = re.search(r'Registry Expiry Date:\s*([^ \n\r]+)', response_text, re.IGNORECASE)
        
        if registrar_match:
            results.append(f"[SUCCESS] Registrar: {registrar_match.group(1).strip()}")
        if creation_match:
            results.append(f"[INFO] Creation Date: {creation_match.group(1).strip()}")
        if expiry_match:
            results.append(f"[INFO] Expiration Date: {expiry_match.group(1).strip()}")
        
        # Check for privacy guard
        if 'privacy' in response_text.lower() or 'redacted' in response_text.lower():
             results.append(f"[FINDING] Low-Severity: Domain owner details are protected by privacy guard or GDPR redaction.")
        
        if not (registrar_match or creation_match):
             results.append(f"[INFO] Raw WHOIS data received, but common fields could not be parsed.")
             
    except socket.error as e:
        results.append(f"[CRITICAL ERROR] WHOIS lookup failed: Could not connect to {WHOIS_SERVER} on port {WHOIS_PORT}. (Socket Error: {e}). Check firewall/outbound access.")
    except Exception as e:
        results.append(f"[CRITICAL ERROR] WHOIS lookup failed: Unexpected error. {str(e)}")
        
    return results


# ----------------------------------------------------
# Report Generation (NEW FUNCTION)
# ----------------------------------------------------

def run_generate_report(domain, full_log_output, findings, report_format='txt'):
    """
    Generates a scan report in a specified format (currently only TXT)
    and returns a file buffer and filename for streaming.
    """
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_domain = get_clean_hostname(domain)
    filename = f"abspider-{clean_domain}-{datetime.date.today().isoformat()}.{report_format}"
    
    # --- Report Content Formatting (TXT) ---
    
    report_lines = [
        f"===========================================================",
        f"ABSpider Vulnerability Scan Report",
        f"===========================================================",
        f"Target Domain: {domain}",
        f"Scan Date/Time: {date_str}",
        f"Total Findings: {findings.get('critical', 0)} Critical, {findings.get('medium', 0)} Medium",
        f"Total Log Lines: {len(full_log_output)}",
        f"Report Format: {report_format.upper()}",
        f"===========================================================\n",
        f"--- RAW CONSOLE LOGS ---\n"
    ]
    
    # Add the raw logs directly
    report_lines.extend(full_log_output)
    report_content = "\n".join(report_lines)
    
    # --- File Generation ---
    
    # Create an in-memory file to hold the report content
    file_buffer = io.BytesIO()
    # Write the report content as bytes
    file_buffer.write(report_content.encode('utf-8'))
    # Reset the buffer's position to the start for reading/streaming via Flask
    file_buffer.seek(0)
    
    return file_buffer, filename
