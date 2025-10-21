from flask import Flask, render_template, request, jsonify, send_file
import scanner_logic
import time
import os
import io # New import for file streaming

# --- Flask Initialization ---
# Flask automatically looks for HTML files in a folder named 'templates'
app = Flask(__name__)

# Dummy subdomain list for the Subdomain Enumeration module
SUBDOMAINS = ['www', 'mail', 'ftp', 'dev', 'test', 'api', 'blog', 'admin', 'vpn', 'webmail', 'staging']

# --- Routes ---

@app.route('/')
def index():
    """Serves the main HTML interface."""
    # Ensure index.html is located in a 'templates' folder
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def run_scan_api():
    """API endpoint to receive scan requests from the frontend."""
        
    # Check if the required logic file is accessible
    if not os.path.exists('scanner_logic.py'):
        return jsonify({"error": "Backend logic file 'scanner_logic.py' not found."}), 500
        
    data = request.get_json()
    domain = data.get('domain')
    modules = data.get('modules', [])

    if not domain:
        return jsonify({"error": "No target domain was provided in the request."}), 400

    # List to collect all output lines from all modules
    full_output = []

    # Process each selected module sequentially
    for module in modules:
        module_output = []
        
        try:
            if module == 'basic':
                full_output.append("--- Executing Module: Basic Reconnaissance (Live Check)")
                # Call the real Python scanning logic
                module_output = scanner_logic.run_basic_scan(domain)
            
            elif module == 'subdomain':
                full_output.append("--- Executing Module: Subdomain Enumeration")
                module_output = scanner_logic.run_subdomain_enumeration(domain, SUBDOMAINS)
                
            elif module == 'wordpress':
                full_output.append("--- Executing Module: WordPress Detection & Vulnerability Check")
                module_output = scanner_logic.run_wordpress_scan(domain)

            elif module == 'whois':
                full_output.append("--- Executing Module: WHOIS Lookup")
                module_output = scanner_logic.run_whois_lookup(domain)
                
        except Exception as e:
            # Catch errors in the Python scanning logic
            module_output.append(f"[CRITICAL ERROR] Failed to run {module} scan: {str(e)}")
            
        full_output.extend(module_output)
    
    # Return the aggregated output as a single string, joined by newlines, for the frontend to parse
    return jsonify({"output": "\n".join(full_output)})

@app.route('/api/report', methods=['POST'])
def generate_report_api():
    """NEW API endpoint to generate and serve the scan report."""
    data = request.get_json()
    domain = data.get('domain')
    full_log_output = data.get('full_log_output', [])
    findings = data.get('findings', {})
    report_format = data.get('format', 'txt') # Report format requested by client

    if not domain or not full_log_output:
        return jsonify({"error": "Missing domain or log data for report generation."}), 400
    
    try:
        # Pass the data to the new report generation function in scanner_logic.py
        file_buffer, filename = scanner_logic.run_generate_report(domain, full_log_output, findings, report_format)
        
        # Stream the generated file (in-memory buffer) back to the client
        return send_file(
            file_buffer,
            mimetype=f'text/{report_format}', # Use correct MIME type for TXT
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({"error": f"Report generation failed on the backend: {str(e)}"}), 500

# --- Server Startup ---

if __name__ == '__main__':
    # debug=True allows for auto-reloading during development
    # Ensure you run this from the ABSpider-Scanner directory
    app.run(debug=True)
