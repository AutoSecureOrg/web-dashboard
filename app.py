import threading
import time
from flask import Flask, json, render_template, request, jsonify, send_file, Response, stream_with_context, redirect, url_for, session
import os, subprocess
from fpdf import FPDF
import socket
import json
import re
from datetime import datetime
from dotenv import load_dotenv
from scripts.portExploit import nmap_scan, connect_to_metasploit, search_and_run_exploit, get_local_ip, port_exploit_report, query_nvd_api, clean_version_info, format_description
from scripts.web_scanner import login_sql_injection, xss_only, command_only, html_only, complete_scan, sql_only
from scripts.web_report import web_vuln_report
from scripts.wifi_tool import *
from werkzeug.utils import secure_filename
import uuid

AI_HOST = '127.0.0.1'
AI_PORT = 5005
# Load environment variables from .env file
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

app = Flask(__name__)

# --- Configuration for file uploads and session ---
# It's crucial to set a proper secret key for sessions
# Use a strong, random key in a real application, possibly from env vars
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))
UPLOAD_FOLDER = '/home/autosecure/FYP/exploits/uploaded'
ALLOWED_EXTENSIONS = {'py'} # Only allow Python scripts for now
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Ensure upload folder exists
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# --- End Configuration ---

# Ensure the reports directory exists
REPORTS_DIR = "/home/autosecure/FYP/reports/"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Global variables to hold scan and test results
services_found = {}
targets = []
nmap_results = {}
exploitation_results = {}
test_status = {"complete": False}
custom_exploit_results = {} # New global for custom results

# Helper function for allowed file extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/network-scanner', methods=['GET', 'POST'])
def network_scanner():
    global services_found, targets, nmap_results, exploitation_results
    # Reset globals and session data relevant to a new scan
    targets = []
    services_found = {}
    nmap_results = {}
    exploitation_results = {}
    session.pop('custom_exploit_path', None)
    # Also clear results from previous runs stored in globals
    global custom_exploit_results
    custom_exploit_results = {}

    if request.method == 'POST':
        start_ip = request.form.get('start_ip')
        end_ip = request.form.get('end_ip')
        target_ip = request.form.get('target_ip')
        start_port = request.form.get('start_port', type=int)
        end_port = request.form.get('end_port', type=int)

        # --- Handle Custom Exploit Upload ---
        custom_exploit_path = None
        if 'custom_exploit' in request.files:
            file = request.files['custom_exploit']
            if file and file.filename != '' and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4().hex}_{filename}"
                    saved_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    file.save(saved_path)
                    custom_exploit_path = saved_path
                    print(f"INFO: Custom exploit saved to: {custom_exploit_path}")
                    session['custom_exploit_path'] = custom_exploit_path # Store path in session
                except Exception as e:
                    print(f"ERROR: Failed to save uploaded exploit: {e}")
                    # Consider returning an error message to the user
                    # return jsonify({"error": f"Failed to save exploit: {e}"}), 500
            elif file and file.filename != '':
                 print(f"WARN: Custom exploit file type not allowed: {file.filename}")
                 # Consider returning an error message
                 # return jsonify({"error": "Invalid file type for custom exploit. Only .py allowed."}), 400

        # --- Target IP Processing --- (No changes needed here)
        # ...
        if start_ip and end_ip and not target_ip:
            # ... range logic ...
            end_num = end_ip.split(".")[-1]
            start_num = start_ip.split(".")[-1]
            prefix = start_ip.rsplit('.', 1)[0] + '.'
            for i in range(int(start_num), int(end_num) +1):
                targets.append(prefix + str(i))
        elif target_ip:
            targets.append(target_ip)

        if not targets:
            return jsonify({"error": "Target IP is required"}), 400

        # --- Nmap Scan --- (No changes needed here)
        try:
            for target_ip_scan in targets: # Use a different variable name to avoid clash
                open_ports = nmap_scan(target_ip_scan, start_port=start_port, end_port=end_port)
                services_found[target_ip_scan] = [
                    {"service": p["service"], "port": p["port"], "version": p.get("version", "Unknown")}
                    for p in open_ports
                ]
            # Pass necessary info (just services) to service selection
            return render_template('service_selection.html', services=services_found)
        except Exception as e:
            print(f"ERROR during Nmap scan: {e}")
            return jsonify({"error": f"Nmap scan failed: {e}"}), 500

    return render_template('network_scanner.html')


@app.route('/run-tests', methods=['POST'])
def run_tests():
    global test_status, nmap_results, exploitation_results, custom_exploit_results
    test_status["complete"] = False
    test_status.pop("error", None)
    test_status.pop("custom_error", None)
    nmap_results = {}
    exploitation_results = {}
    custom_exploit_results = {}

    selected_services = json.loads(request.form.get('services', '[]'))
    testing_mode = request.form.get('testing_mode', 'Lite')
    custom_exploit_path = session.get('custom_exploit_path', None)

    if not selected_services and not custom_exploit_path:
        return jsonify({"error": "No services selected or custom exploit provided"}), 400

    def perform_tests(mode, uploaded_exploit):
        global custom_exploit_results
        print(f"INFO: Starting test thread (Mode: {mode}, Custom Exploit: {uploaded_exploit})")
        local_ip = get_local_ip()
        if not local_ip:
             print("ERROR: Could not determine local IP address. Cannot proceed.")
             test_status["error"] = "Could not determine local IP"
             test_status["complete"] = True
             return

        # --- Run Metasploit tests if services were selected ---
        if selected_services:
            print("INFO: Proceeding with selected Metasploit tests...")
            try:
                client = connect_to_metasploit()
                if not client:
                    print("ERROR: Failed to connect to Metasploit. Aborting Metasploit tests.")
                    raise Exception("Failed to connect to Metasploit.")
                print("INFO: Connected to Metasploit.")

                for target_ip in targets:
                    print(f"INFO: Processing target IP for Metasploit: {target_ip}")
                    if target_ip not in exploitation_results:
                        exploitation_results[target_ip] = []
                    if target_ip not in nmap_results: # Check if Nmap results already exist for this IP
                        print(f"WARN: Nmap results missing for {target_ip} in run-tests. Populating now.")
                        # This suggests Nmap results might not be consistently stored or retrieved.
                        # For simplicity, we re-populate here if missing, but review data flow.
                        nmap_results[target_ip] = []
                        for service in services_found.get(target_ip, []):
                            # ... (Nmap result population logic as before) ...
                            service_name = service["service"]
                            version = service.get("version", "Unknown")
                            port = service["port"]
                            if version == "-" or version.lower() == "unknown":
                                description = "No version data provided."
                            else:
                                keyword = clean_version_info(service_name, version)
                                keyword = keyword if service_name.lower() == "ftp" else f"{service_name} {keyword}"
                                nvd_data = query_nvd_api(keyword, api_key=NVD_API_KEY)
                                description = format_description(nvd_data) if nvd_data else "No CVEs found."
                            nmap_results[target_ip].append({
                                "port": port, "service": service_name, "version": version, "vuln": description
                            })

                    print(f"INFO: Starting Metasploit exploit runs for {target_ip} (Mode: {mode})...")
                    for service_info in services_found.get(target_ip, []):
                        is_selected = any(
                            entry['ip'] == target_ip and service_info['service'].lower() == entry['service'].lower()
                            for entry in selected_services
                        )
                        if is_selected:
                            print(f"INFO: Running Metasploit exploits for {service_info['service']}@{target_ip}:{service_info['port']}...")
                            exploit_run_results = search_and_run_exploit(
                                client, service_info['service'], target_ip, service_info['port'], local_ip, mode
                            )
                            if not isinstance(exploit_run_results, list): exploit_run_results = [exploit_run_results]
                            for module_name, success in exploit_run_results:
                                exploitation_results[target_ip].append({
                                    "service": service_info['service'], "port": service_info['port'],
                                    "exploit": module_name if module_name else "No exploit found/run",
                                    "status": "Succeeded" if success else "Failed/Not Run"
                                })

                    if exploitation_results.get(target_ip):
                        print(f"INFO: Generating report for Metasploit results on {target_ip}...")
                        api_key_for_report = os.getenv("NVD_API_KEY")
                        # Pass only current IP's results to report function
                        port_exploit_report(REPORTS_DIR, [target_ip], {target_ip: nmap_results.get(target_ip, [])}, {target_ip: exploitation_results[target_ip]}, api_key=api_key_for_report)
            except Exception as e:
                print(f"ERROR: Exception during Metasploit tests: {e}")
                test_status["error"] = f"Metasploit Error: {e}"
        else:
            print("INFO: No services selected for Metasploit testing.")

        # --- Run Custom Exploit Script if provided --- (Logic remains largely the same)
        if uploaded_exploit and os.path.exists(uploaded_exploit):
            print(f"INFO: Attempting to run custom exploit script: {uploaded_exploit}")
            custom_exploit_results['script_path'] = uploaded_exploit
            custom_exploit_results['targets'] = {}
            for target_ip in targets:
                print(f"INFO: Running custom exploit against target: {target_ip}")
                try:
                    cmd = ["python3", uploaded_exploit, target_ip]
                    print(f"Executing: {' '.join(cmd)}")
                    timeout_seconds = 180
                    process = subprocess.run(
                        cmd, capture_output=True, text=True,
                        check=False, timeout=timeout_seconds
                    )
                    status = "Completed" if process.returncode == 0 else f"Exited with code {process.returncode}"
                    if process.returncode != 0:
                        print(f"WARN: Custom exploit script exited with code {process.returncode} for {target_ip}")
                    custom_exploit_results['targets'][target_ip] = {
                        "status": status,
                        "stdout": process.stdout.strip(),
                        "stderr": process.stderr.strip()
                    }
                    print(f"INFO: Custom exploit finished for {target_ip}. Status: {status}")
                except FileNotFoundError:
                    error_msg = "ERROR: 'python3' command not found or script invalid."
                    print(error_msg)
                    custom_exploit_results['targets'][target_ip] = {"status": "Execution Failed", "stderr": error_msg}
                    test_status["custom_error"] = error_msg # Store error globally
                except subprocess.TimeoutExpired:
                    error_msg = f"ERROR: Custom exploit timed out ({timeout_seconds}s) for {target_ip}."
                    print(error_msg)
                    custom_exploit_results['targets'][target_ip] = {"status": "Timeout", "stderr": error_msg}
                    test_status["custom_error"] = error_msg # Store error globally
                except Exception as e:
                    error_msg = f"ERROR: Exception running custom exploit for {target_ip}: {e}"
                    print(error_msg)
                    custom_exploit_results['targets'][target_ip] = {"status": "Exception", "stderr": error_msg}
                    test_status["custom_error"] = error_msg # Store error globally
        elif uploaded_exploit:
            print(f"WARN: Custom exploit file path found in session but file does not exist: {uploaded_exploit}")
            custom_exploit_results['error'] = "Uploaded exploit file not found on server."
            test_status["custom_error"] = "Uploaded exploit file not found"
        else:
             print("INFO: No custom exploit script provided.")

        # --- Finalization ---
        print("INFO: Test thread finished. Setting test_status['complete'] = True")
        test_status["complete"] = True

    # Start the thread
    print(f"INFO: Creating test thread (Mode: {testing_mode}, Custom: {custom_exploit_path})")
    thread = threading.Thread(target=perform_tests, args=(testing_mode, custom_exploit_path))
    thread.daemon = True
    thread.start()
    return jsonify({"status": "Tests started"}), 200


@app.route('/check-status', methods=['GET'])
def check_status():
    # Return the current status, potentially including custom results summary if needed
    status_data = test_status.copy()
    # if custom_exploit_results: status_data['custom_running'] = True # Example
    return jsonify(status_data)


@app.route('/results')
def results():
    """ Displays results stored in global variables. """
    metasploit_error = test_status.get("error")
    custom_error = test_status.get("custom_error")

    # Combine errors for display if needed
    overall_error = metasploit_error or custom_error

    return render_template(
        'results.html',
        nmap_results=nmap_results,
        exploitation_results=exploitation_results,
        custom_exploit_results=custom_exploit_results,
        metasploit_error=metasploit_error,
        custom_exploit_error=custom_error
    )


def call_ai_stream(prompt: str):
    """
    Generator: yields raw text chunks from the socket AI server.
    """
    payload = json.dumps({"prompt": prompt}).encode('utf-8')
    try:
        with socket.socket() as sock:
            sock.settimeout(5)  # Set a timeout for connection
            sock.connect((AI_HOST, AI_PORT))
            sock.sendall(payload)
            sock.settimeout(None)  # Reset timeout for receiving
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                yield chunk
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"AI server connection error: {str(e)}")
        yield f"Error connecting to AI server: {str(e)}".encode('utf-8')


@app.route('/get-system-ai-insight', methods=['POST'])
def get_system_ai_insight():
    data    = request.get_json(force=True)
    service = data.get('service','')
    version = data.get('version','')
    #vuln    = data.get('vuln','')
    vuln = re.search(r'CVE-\d{4}-\d{4,7}', data.get('vuln', '')).group(0) if re.search(r'CVE-\d{4}-\d{4,7}', data.get('vuln', '')) else 'UNKNOWN-CVE'

    prompt = (
        f"Compact short technical security recommendations for {service} {version}. {vuln}\n\n"
        "1. Mitigation steps\n"
        "2. Patch availability (& commits)\n"
        "3. Detection methods (& CLI commands)\n\n"
    )

    def generate():
        for chunk in call_ai_stream(prompt):
            yield chunk  # forces flush to client

    return Response(stream_with_context(generate()), content_type='text/plain')


@app.route('/get-web-ai-insight', methods=['POST'])
def get_web_ai_insight():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"No data provided"}), 400

        payload = data.get('payload', '').strip()
        if not payload:
            return jsonify({"No vulnerability payload provided"}), 400

        print(f"Web AI insight request received with payload: {payload[:100]}...")  # Log first 100 chars

        prompt = (
            "Give compact technical buletted remediation steps for these web vulnerabilities:\n"
            f"{payload}\n\n"
        )

        def generate():
            for chunk in call_ai_stream(prompt):
                yield chunk

        return Response(stream_with_context(generate()), content_type='text/plain')
    except Exception as e:
        print(f"Error in get-web-ai-insight: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/download-report/<report_type>')
def download_report(report_type):
    try:
        latest_file = sorted(
            [os.path.join(REPORTS_DIR, f)
             for f in os.listdir(REPORTS_DIR) if f.endswith('.txt')],
            key=os.path.getmtime,
            reverse=True
        )[0]

        if report_type == "text":
            return send_file(latest_file, as_attachment=True)

        elif report_type == "pdf":
            pdf_path = os.path.splitext(latest_file)[0] + ".pdf"
            convert_text_to_pdf(latest_file, pdf_path)
            return send_file(pdf_path, as_attachment=True)

        else:
            return jsonify({"error": "Invalid report type. Use 'text' or 'pdf'."}), 400

    except IndexError:
        return jsonify({"error": "No reports found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


class PDF(FPDF):
    def header(self):
        """Create a header with a title and timestamp."""
        self.set_fill_color(50, 50, 50)  # Dark gray
        self.set_text_color(255, 255, 255)  # White text
        self.set_font("Courier", "B", 11)
        self.cell(0, 8, "TESTING REPORT", ln=True, align="C", fill=True)

        # Timestamp
        self.set_text_color(0, 0, 0)  # Reset text to black
        self.set_font("Courier", "B", 8)
        self.cell(0, 5, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        self.ln(3)  # Small spacing

    def footer(self):
        """Create a footer with page number."""
        self.set_y(-12)
        self.set_font("Courier", size=7)
        self.cell(0, 8, f"Page {self.page_no()}", align="C")

    def add_table_row(self, col1, col2, col3, col_widths, row_fill):
        """Helper function to format table rows with alternating colors and black text."""
        self.set_fill_color(230, 230, 230) if row_fill else self.set_fill_color(255, 255, 255)
        self.set_text_color(0, 0, 0)  # Ensure text remains black
        self.cell(col_widths[0], 6, col1, border=1, fill=True)
        self.cell(col_widths[1], 6, col2, border=1, fill=True)
        self.multi_cell(col_widths[2], 6, col3, border=1, fill=True)


def convert_text_to_pdf(text_file, pdf_file):
    """Convert structured ASCII vulnerability scan report into a well-formatted PDF."""
    try:
        pdf = PDF()
        pdf.set_auto_page_break(auto=True, margin=12)
        pdf.set_margins(10, 10, 10)
        pdf.add_page()
        pdf.set_font("Courier", size=7)

        page_width = pdf.w - 2 * pdf.l_margin
        col_widths = [page_width * 0.2, page_width * 0.15, page_width * 0.65]  # Adjusted widths

        row_fill = False  # Alternating row color flag

        with open(text_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.rstrip()

                # Handle ASCII table lines
                if line.startswith("+"):
                    if pdf.get_y() + 4.5 > pdf.h - 12:
                        pdf.add_page()
                    pdf.set_font("Courier", "B", 7)
                    pdf.set_text_color(0, 0, 0)  # Ensure table separators remain black
                    pdf.cell(0, 4.5, line, ln=True)
                elif line.startswith("|"):
                    parts = line.strip("|").split("|")
                    parts = [p.strip() for p in parts]

                    if len(parts) == 3:
                        if pdf.get_y() + 6 > pdf.h - 12:
                            pdf.add_page()
                        pdf.add_table_row(parts[0], parts[1], parts[2], col_widths, row_fill)
                        row_fill = not row_fill  # Toggle row color
                    else:
                        if pdf.get_y() + 6 > pdf.h - 12:
                            pdf.add_page()
                        pdf.set_text_color(0, 0, 0)  # Keep text black
                        pdf.multi_cell(0, 6, line, border=1)

                else:
                    # Regular text outside of table
                    if pdf.get_y() + 6 > pdf.h - 12:
                        pdf.add_page()
                    pdf.set_text_color(0, 0, 0)  # Keep text black
                    pdf.multi_cell(0, 6, line)

        pdf.output(pdf_file)
        print(f"✅ PDF successfully created: {pdf_file}")

    except Exception as e:
        print(f"❌ Error: {e}")


@app.route('/download-web-report/<report_type>')
def download_web_report(report_type):
    try:
        # Get the latest web vulnerability scan report
        latest_file = sorted(
            [os.path.join(REPORTS_DIR, f)
             for f in os.listdir(REPORTS_DIR) if f.startswith("web_scan") and f.endswith('.txt')],
            key=os.path.getmtime,
            reverse=True
        )[0]

        if report_type == "text":
            return send_file(latest_file, as_attachment=True)

        elif report_type == "pdf":
            pdf_path = os.path.splitext(latest_file)[0] + ".pdf"
            convert_text_to_pdf(latest_file, pdf_path)
            return send_file(pdf_path, as_attachment=True)

        else:
            return jsonify({"error": "Invalid report type. Use 'text' or 'pdf'."}), 400

    except IndexError:
        return jsonify({"error": "No web vulnerability reports found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/website_scanner', methods=['GET', 'POST'])
def website_scanner():
    if request.method == 'POST':
        target_url = request.form['target_url']
        scan_type = request.form['scan_type']

        results = ""

        try:
            if scan_type == "all":
                results = complete_scan(target_url)
            elif scan_type == "sql_login":
                results = login_sql_injection(target_url, None)
            elif scan_type == "sql_injection":
                results = sql_only(target_url)
            elif scan_type == "xss":
                results = xss_only(target_url)
            elif scan_type == "html_injection":
                results = html_only(target_url)
            elif scan_type == "command_injection":
                results = command_only(target_url)
            else:
                results = "Invalid scan type selected."

        except Exception as e:
            results = f"An error occurred: {str(e)}"

        # Format results into a list of dictionaries
        results_list = []
        if isinstance(results, str):  # Convert strings to list of dictionaries
            for line in results.split("\n"):
                if line.strip():
                    results_list.append({"type": "General", "status": "Info", "payload": line})
        elif isinstance(results, list):  # Use provided list format
            for res in results:
                if isinstance(res, dict):
                    results_list.append({
                        "type": res.get("type", "Unknown"),
                        "status": res.get("status", "Unknown"),
                        "payload": res.get("payload", "N/A")
                    })
                else:
                    results_list.append({"type": "General", "status": "Info", "payload": str(res)})

        # Display all results (including General) in the dashboard
        display_results = results_list if results_list else [{"type": "No vulnerabilities found", "status": "Safe", "payload": "N/A"}]

        # Generate a report
        report_path = web_vuln_report(REPORTS_DIR, target_url, results_list)

        return render_template(
            'report.html',
            output=display_results,
            target_url=target_url,
            report_path=report_path
        )

    return render_template('website_scanner.html')


#------------------------------------------------------------------------------wifi---------------------------------
@app.route("/check-upnp")
def check_upnp_route():
    result = check_upnp_enabled_on_router()
    return jsonify({"result": result})


@app.route("/check-router-admin")
def check_router_admin():
    result = check_router_admin_interface()
    return jsonify({"result": result})


@app.route('/wifi')
def wifi_page():
    return render_template('wifi_page.html')


@app.route('/wifi-analyze-page')
def wifi_analyze_page():
    return render_template('wifi_analyze.html')


@app.route('/wifi-results', methods=['POST'])
def wifi_results_page():
    networks, rogue_data = scan_and_analyze()
    return render_template(
        'wifi_results.html',
        networks=networks.to_dict(orient='records'),
        rogue=rogue_data.to_dict(orient='records')
    )


@app.route('/wifi_results.html')
def wifi_result():
    return render_template('wifi_results.html')


@app.route('/wifi-scan', methods=['POST'])
def wifi_scan():
    networks_df, rogue_df = scan_and_analyze()
    return jsonify({
        "networks": networks_df.to_dict(orient="records"),
        "rogue": rogue_df.to_dict(orient="records")
    })


@app.route('/wifi-analyze', methods=['POST'])
def wifi_analyze():
    ssid = request.json.get("ssid")
    bssid = request.json.get("bssid")

    # Step 1: Scan subnet and devices
    subnet = detect_subnet_from_gateway()
    devices_df = scan_connected_devices(subnet)
    fp_df = fingerprint_devices(devices_df)

    # Step 2: Create a DataFrame from the selected target
    selected_network = {
        "SSID": ssid,
        "BSSID": bssid,
        "Signal Strength": "Unknown",
        "Encryption Type": "Unknown"
    }

    # If possible, re-scan Wi-Fi networks to get encryption and signal info
    scanned_df = scan_wifi_networks_nmcli()
    if scanned_df is not None:
        match = scanned_df[
            (scanned_df["SSID"] == ssid) & (scanned_df["BSSID"] == bssid)
        ]
        if not match.empty:
            selected_network["Signal Strength"] = match.iloc[0]["Signal Strength"]
            selected_network["Encryption Type"] = match.iloc[0]["Encryption Type"]

    # Step 3: Analyze vulnerabilities
    vuln_df = analyze_network_vulnerabilities(pd.DataFrame([selected_network]))
    vuln_row = vuln_df.iloc[0]

    vulnerability_info = {
        "ssid": vuln_row["SSID"],
        "bssid": vuln_row["BSSID"],
        "encryption": vuln_row["Encryption Type"],
        "signal": vuln_row["Signal Strength"],
        "risk": vuln_row["Risk Analysis"]
    }

    # ✅ Step 4: Construct Target Identification Info
    try:
        signal_val = int(selected_network["Signal Strength"].replace(" dBm", ""))
    except:
        signal_val = 0

    target_info = {
        "SSID": selected_network["SSID"],
        "BSSID": selected_network["BSSID"],
        "Encryption Type": selected_network["Encryption Type"] + " (Mixed Mode)" if "WPA1" in selected_network["Encryption Type"] else selected_network["Encryption Type"],
        "Signal Strength": selected_network["Signal Strength"] + " (Very Strong)" if signal_val >= 75 else selected_network["Signal Strength"],

        "Channel": get_channel_for_network(selected_network["SSID"], selected_network["BSSID"]),

        "Subnet": subnet,
        "Gateway MAC": get_gateway_mac() or "Unknown"
    }

    # ✅ Final result
    return jsonify({
        "ssid": ssid,
        "bssid": bssid,
        "subnet": subnet,
        "devices": fp_df.to_dict(orient="records"),
        "vulnerability": vulnerability_info,
        "target_info": target_info  # ✅ properly added here
    })


@app.route('/attack', methods=['POST'])
def launch_attack():
    data = request.json
    attack_type = data.get("type")
    target = data.get("target")  # Can be BSSID (for deauth) or None

    INTERFACE = "wlan0"  # Change to wlan1 if your DHCP/monitoring runs on that

    try:
        if attack_type == "deauth":
            if target:
                deauth_flood(target, interface=INTERFACE)
            else:
                return jsonify({"status": "error", "message": "Target BSSID required for deauth."}), 400

        elif attack_type == "beacon":
            beacon_flood(interface=INTERFACE)

        elif attack_type == "dhcp":
            dhcp_starvation(interface=INTERFACE, count=50)

        elif attack_type == "mitm":
            mitm_sniffing_http_credentials()  # Already uses interface internally
        elif attack_type == "arp-flood":
            output = auto_arp_replay_flood(interface="wlan0", spoof_replies=True, randomize_mac=True)
            return jsonify({"status": "success", "output": output})


        else:
            return jsonify({"status": "error", "message": f"Unknown attack type: {attack_type}"}), 400

        return jsonify({"status": "launched", "attack": attack_type})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/arp-flood', methods=['POST'])
def trigger_arp_flood():
    try:
        result = auto_arp_replay_flood(interface="wlan0")
        return jsonify({"status": "success", "output": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


def program_exists(program):
    """Check if a program exists in the system path"""
    try:
        subprocess.run(['which', program], capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


if __name__ == '__main__':
    if not app.secret_key or app.secret_key == 'temporary_secret_key_for_testing':
        print("Warning: Using default/temporary FLASK_SECRET_KEY. Set a strong secret key in your environment.")
        app.secret_key = os.urandom(24) # Ensure a key is set for session
    app.run(host='0.0.0.0', port=5556, debug=True)
