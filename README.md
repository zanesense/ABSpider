# ABSpider Web Vulnerability Scanner

ABSpider is a simple, modular, web-based vulnerability and reconnaissance scanner built using **Python** and the **Flask** framework. It allows users to input a target domain and run various scanning modules through a web interface, aggregating the results and providing an option to download a comprehensive report.

---

## 🚀 Features

* **Modular Scanning:** Separate logic for different reconnaissance tasks.
* **Basic Recon:** HTTP/S connectivity check, DNS resolution, IP address retrieval, and basic security header analysis (e.g., HSTS).
* **Subdomain Enumeration:** Checks a predefined list of common subdomains via DNS lookup.
* **WordPress Check:** Detects the presence of WordPress via common file paths (`wp-login.php`, `readme.html`) and attempts to extract the version.
* **WHOIS Lookup:** Retrieves domain registration information (Registrar, Creation/Expiry Date) by connecting to a WHOIS server.
* **Web Interface:** Serves a main HTML interface for interacting with the scanner.
* **Report Generation:** Downloads a `.txt` report containing the full scan log and findings, utilizing an in-memory buffer for streaming.

---

## 🛠️ Prerequisites

Before running the application, ensure you have **Python 3.x** installed on your system.

---

## 📦 Installation and Setup

Follow these steps to get ABSpider running locally.

### 1. Ensure Files are Present

Make sure you have all the necessary project files in a single directory:
* `app.py`
* `scanner_logic.py`
* `requirements.txt`
* A `templates` folder containing your `index.html` (the web interface).

### 2. Install Dependencies

ABSpider relies on a few external Python libraries. Use `pip` to install them based on the `requirements.txt` file:

```bash
pip install -r requirements.txt
````

### 3\. Run the Application

Start the Flask server from your terminal:

```bash
python app.py
```

The server will typically start on `http://127.0.0.1:5000/`.

-----

## 🌐 Usage

1.  **Open the Browser:** Navigate to the address displayed in your terminal (default: `http://127.0.0.1:5000/`).
2.  **Enter a Domain:** Type the target domain (e.g., `example.com`) into the input field. The scanner will automatically clean the hostname regardless of scheme or `www.`.
3.  **Select Modules:** Check the boxes for the scanning modules you wish to execute.
4.  **Run Scan:** Click the **"Start Scan"** button. The aggregated output from all selected modules will appear in the log area.
5.  **Generate Report:** After a scan is complete, click the **"Generate Report"** button to download a detailed `.txt` log file.

-----

## 📂 Project Structure

| File/Folder | Description |
| :--- | :--- |
| `app.py` | The main Flask application file. Defines API routes (`/api/scan`, `/api/report`) and server setup. |
| `scanner_logic.py` | Contains all core scanning functions, including DNS lookups, HTTP requests, WHOIS logic, and the report generation function. |
| `requirements.txt` | Lists all necessary Python dependencies (`requests`, `flask`, `flask-cors`). |
| `templates/` | **(Required)** Folder where your main HTML file (`index.html`) must be located for Flask to find it. |

-----

## ⚙️ Customization

### Modifying the Subdomain List

The list of common subdomains checked during enumeration is hardcoded in `app.py`:

```python
SUBDOMAINS = ['www', 'mail', 'ftp', 'dev', 'test', 'api', 'blog', 'admin', 'vpn', 'webmail', 'staging']
```

You can edit this list directly in `app.py` to include more or fewer subdomains for the `subdomain` module.

### Adding or Modifying Scan Modules

New scan modules require changes in both files:

1.  **`scanner_logic.py`**: Define a new scanning function (e.g., `run_new_module(domain)`).
2.  **`app.py`**: Add a new `elif` block in the `/api/scan` route to call the new function.

-----

## ⚠️ Disclaimer

This tool is designed for educational purposes and ethical penetration testing ONLY. **DO NOT** use this application to scan targets without explicit, prior written permission from the target domain's owner. Misuse of this tool can lead to severe legal consequences.
