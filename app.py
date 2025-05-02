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
import zipfile
import tempfile
import shutil

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
ALLOWED_EXTENSIONS = {'py', 'zip'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Ensure upload folder exists
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# --- End Configuration ---

# --- Added Configuration for Mobile Scan ---
MOBSFSCAN_OUTPUT_DIR = "/home/autosecure/FYP/mobtest_results" # Directory to store mobsfscan JSON results
MOBTEST_DIR = "/home/autosecure/FYP/mobtest" # Fixed directory for extracting/scanning
os.makedirs(MOBSFSCAN_OUTPUT_DIR, exist_ok=True)
os.makedirs(MOBTEST_DIR, exist_ok=True) # Ensure the mobtest directory exists
# --- End Mobile Scan Config ---

# --- Added Configuration for Quark Scan ---
QUARK_OUTPUT_DIR = "/home/autosecure/FYP/quark_results"
os.makedirs(QUARK_OUTPUT_DIR, exist_ok=True)
# --- End Quark Scan Config ---

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
mobile_scan_results = {} # Global for mobile scan results

# Helper function for allowed file extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/network-scanner', methods=['GET', 'POST'])
def network_scanner():
    global services_found, targets, nmap_results, exploitation_results, test_status, custom_exploit_results
    if request.method == 'POST':
        # Clear all global variables at the start of a new scan
        services_found = {}
        targets = []
        nmap_results = {}
        exploitation_results = {}
        custom_exploit_results = {}
        test_status = {"complete": False}
        session.pop('custom_exploit_path', None)

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

        # --- Target IP Processing ---
        if start_ip and end_ip and not target_ip:
            end_num = end_ip.split(".")[-1]
            start_num = start_ip.split(".")[-1]
            prefix = start_ip.rsplit('.', 1)[0] + '.'
            for i in range(int(start_num), int(end_num) +1):
                targets.append(prefix + str(i))
        elif target_ip:
            targets.append(target_ip)

        if not targets:
            return jsonify({"error": "Target IP is required"}), 400

        # --- Nmap Scan ---
        try:
            for target_ip_scan in targets:
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
    # Reset all test-related globals at the start of new tests
    test_status = {"complete": False}
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

    def add_quark_table_row(self, cols, col_widths, row_fill):
        """Helper function to format quark table rows."""
        self.set_fill_color(230, 230, 230) if row_fill else self.set_fill_color(255, 255, 255)
        self.set_text_color(0, 0, 0) # Ensure text remains black
        # Use multi_cell for potentially long crime descriptions
        current_y = self.get_y()
        current_x = self.get_x()

        # Calculate height needed for each cell without drawing yet (fpdf doesn't have dry_run)
        # Instead, draw and calculate height, then reposition for next cell

        self.multi_cell(col_widths[0], 5, cols[0], border=1, fill=True) # Rule ID
        col1_height = self.get_y() - current_y
        self.set_xy(current_x + col_widths[0], current_y) # Reset position for next cell

        self.multi_cell(col_widths[1], 5, cols[1], border=1, fill=True) # Crime
        col2_height = self.get_y() - current_y
        self.set_xy(current_x + col_widths[0] + col_widths[1], current_y)

        self.multi_cell(col_widths[2], 5, cols[2], border=1, fill=True) # Confidence
        col3_height = self.get_y() - current_y
        self.set_xy(current_x + col_widths[0] + col_widths[1] + col_widths[2], current_y)

        self.multi_cell(col_widths[3], 5, cols[3], border=1, fill=True) # Score
        col4_height = self.get_y() - current_y
        self.set_xy(current_x + col_widths[0] + col_widths[1] + col_widths[2] + col_widths[3], current_y)

        self.multi_cell(col_widths[4], 5, cols[4], border=1, fill=True) # Labels
        col5_height = self.get_y() - current_y

        # Move down by the maximum height used by any cell in this row
        max_height = max(col1_height, col2_height, col3_height, col4_height, col5_height)
        self.set_xy(current_x, current_y + max_height) # Set position for the start of the next row


def format_quark_report_text(quark_data):
    """Formats parsed Quark JSON data into a structured text report."""
    lines = []
    lines.append("=======================================")
    lines.append("      Quark Engine Scan Report         ")
    lines.append("=======================================")
    lines.append(f"APK Filename: {quark_data.get('apk_filename', 'N/A')}")
    lines.append(f"MD5 Hash:     {quark_data.get('md5', 'N/A')}")
    lines.append(f"Size (Bytes): {quark_data.get('size_bytes', 'N/A')}")
    lines.append(f"Threat Level: {quark_data.get('threat_level', 'N/A')}")
    lines.append(f"Total Score:  {quark_data.get('total_score', 'N/A')}")
    lines.append("\n")
    lines.append("Detected Findings (Crimes):")
    lines.append("---------------------------")

    if not quark_data.get('crimes'):
        lines.append("No specific findings reported.")
        return "\n".join(lines)

    # Basic text table formatting
    lines.append("{:<12} {:<12} {:<8} {:<60} {:<30}".format(
        "Rule ID", "Confidence", "Score", "Crime Description", "Labels"
    ))
    lines.append("{:<12} {:<12} {:<8} {:<60} {:<30}".format(
        "---------", "----------", "-----", "-----------------", "------"
    ))

    for crime in quark_data.get('crimes', []):
        rule_id = crime.get('rule', 'N/A').replace('.json', '')
        confidence = crime.get('confidence', 'N/A')
        score = str(crime.get('score', 'N/A'))
        description = crime.get('crime', 'N/A')
        labels = ", ".join(crime.get('label', []))
        lines.append("{:<12} {:<12} {:<8} {:<60} {:<30}".format(
            rule_id, confidence, score, description[:58] + (".." if len(description) > 58 else ""), labels[:28] + (".." if len(labels) > 28 else "")
        ))

    return "\n".join(lines)


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
        raise # Re-raise exception


def convert_quark_report_to_pdf(json_file, pdf_file):
    """Converts a Quark Engine JSON report into a formatted PDF with tables."""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            quark_data = json.load(f)

        pdf = PDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_margins(10, 10, 10)
        pdf.add_page()

        # Title and General Info
        pdf.set_font("Courier", "B", 12)
        pdf.cell(0, 10, "Quark Engine Scan Report", ln=True, align="C")
        pdf.set_font("Courier", size=8)
        pdf.cell(0, 5, f"APK Filename: {quark_data.get('apk_filename', 'N/A')}", ln=True)
        pdf.cell(0, 5, f"MD5 Hash:     {quark_data.get('md5', 'N/A')}", ln=True)
        pdf.cell(0, 5, f"Size (Bytes): {quark_data.get('size_bytes', 'N/A')}", ln=True)
        pdf.cell(0, 5, f"Threat Level: {quark_data.get('threat_level', 'N/A')}", ln=True)
        pdf.cell(0, 5, f"Total Score:  {quark_data.get('total_score', 'N/A')}", ln=True)
        pdf.ln(8)

        # Findings Table
        pdf.set_font("Courier", "B", 9)
        pdf.cell(0, 6, "Detected Findings (Crimes):", ln=True)
        pdf.set_font("Courier", size=7)

        if not quark_data.get('crimes'):
            pdf.cell(0, 5, "No specific findings reported.", ln=True)
            pdf.output(pdf_file)
            print(f"✅ Quark PDF report created (no findings): {pdf_file}")
            return

        page_width = pdf.w - 2 * pdf.l_margin
        # Rule ID, Crime Description, Confidence, Score, Labels
        col_widths = [page_width * 0.10, page_width * 0.45, page_width * 0.12, page_width * 0.08, page_width * 0.25]

        # Table Header
        pdf.set_font("Courier", "B", 7)
        pdf.set_fill_color(200, 200, 200)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(col_widths[0], 6, "Rule ID", border=1, fill=True)
        pdf.cell(col_widths[1], 6, "Crime Description", border=1, fill=True)
        pdf.cell(col_widths[2], 6, "Confidence", border=1, fill=True)
        pdf.cell(col_widths[3], 6, "Score", border=1, fill=True)
        pdf.cell(col_widths[4], 6, "Labels", border=1, fill=True, ln=True)

        # Table Rows
        pdf.set_font("Courier", size=6) # Smaller font for rows
        row_fill = False
        for crime in quark_data.get('crimes', []):
            if pdf.get_y() + 10 > pdf.h - pdf.b_margin: # Estimate space needed, add page if low
                pdf.add_page()
                # Re-add header on new page
                pdf.set_font("Courier", "B", 7)
                pdf.set_fill_color(200, 200, 200)
                pdf.cell(col_widths[0], 6, "Rule ID", border=1, fill=True)
                pdf.cell(col_widths[1], 6, "Crime Description", border=1, fill=True)
                pdf.cell(col_widths[2], 6, "Confidence", border=1, fill=True)
                pdf.cell(col_widths[3], 6, "Score", border=1, fill=True)
                pdf.cell(col_widths[4], 6, "Labels", border=1, fill=True, ln=True)
                pdf.set_font("Courier", size=6)
                row_fill = False # Reset row fill on new page if needed

            rule_id = crime.get('rule', 'N/A').replace('.json', '')
            description = crime.get('crime', 'N/A')
            confidence = crime.get('confidence', 'N/A')
            score = str(crime.get('score', 'N/A'))
            labels = ", ".join(crime.get('label', []))

            cols_data = [rule_id, description, confidence, score, labels]
            pdf.add_quark_table_row(cols_data, col_widths, row_fill)
            row_fill = not row_fill

        pdf.output(pdf_file)
        print(f"✅ Quark PDF report successfully created: {pdf_file}")

    except json.JSONDecodeError as e:
        print(f"❌ Error decoding Quark JSON file {json_file}: {e}")
        raise # Re-raise exception
    except Exception as e:
        print(f"❌ Error creating Quark PDF report: {e}")
        raise # Re-raise exception


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


@app.route('/mobile_scan', methods=['GET', 'POST'])
def mobile_scan():
    global mobile_scan_results
    if request.method == 'POST':
        scan_type = request.form.get('scan_type', 'zip') # Default to zip if not provided
        if 'app_file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        file = request.files['app_file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        # --- File Type Validation based on scan_type ---
        allowed_extensions_for_type = {'zip'} if scan_type == 'zip' else {'apk'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if not file_ext in allowed_extensions_for_type:
            return jsonify({"error": f"Invalid file type for {scan_type.upper()} scan. Expected .{list(allowed_extensions_for_type)[0]}"}), 400
        # --------------------------------------------

        scan_results = {'scan_type': scan_type} # Store scan type in results
        error_message = None
        output_data = ""
        report_filename = None

        try:
            # --- Clear the MOBTEST_DIR before placing new file --- (Common for both scans)
            print(f"INFO: Clearing contents of {MOBTEST_DIR}...")
            for item in os.listdir(MOBTEST_DIR):
                item_path = os.path.join(MOBTEST_DIR, item)
                try:
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    else:
                        os.remove(item_path)
                except Exception as e:
                    print(f"WARN: Failed to remove item {item_path}: {e}")
            print(f"INFO: Finished clearing {MOBTEST_DIR}.")
            # ---------------------------------------------

            if scan_type == 'zip':
                # --- Handle ZIP upload for mobsfscan --- (Existing Logic slightly adapted)
                print("INFO: Handling ZIP file for mobsfscan")
                temp_zip_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f"{uuid.uuid4().hex}_{file.filename}"))
                file.save(temp_zip_path)
                print(f"INFO: Saved uploaded zip temporarily to: {temp_zip_path}")

                extract_path = MOBTEST_DIR
                with zipfile.ZipFile(temp_zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
                print(f"INFO: Extracted zip to: {extract_path}")

                try:
                    os.remove(temp_zip_path)
                    print(f"INFO: Removed temporary zip file: {temp_zip_path}")
                except Exception as e:
                    print(f"WARN: Failed to remove temporary zip file {temp_zip_path}: {e}")

                cmd = ["mobsfscan", MOBTEST_DIR]
                print(f"INFO: Running mobsfscan command: {' '.join(cmd)}")
                timeout_seconds = 300
                process = None
                try:
                    process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout_seconds)
                    print(f"INFO: mobsfscan completed with return code: {process.returncode}")
                    #print(f"INFO: mobsfscan stdout:\n{process.stdout}")
                    #print(f"INFO: mobsfscan stderr:\n{process.stderr}")

                    # Process mobsfscan results (stderr preferred)
                    combined_output = process.stderr if process.stderr else process.stdout
                    combined_output = combined_output.strip()

                    filtered_lines = []
                    lines = combined_output.splitlines()
                    results_started = False
                    for line in lines:
                        if line.strip().startswith(("╒", "|", "├──", "└──", "+-")):
                            results_started = True
                        if results_started:
                            filtered_lines.append(line)

                    if not filtered_lines and combined_output:
                        print("WARN: mobsfscan output filtering removed all lines or start pattern not found. Using raw output.")
                        output_data = combined_output
                    else:
                        output_data = "\n".join(filtered_lines)

                except FileNotFoundError:
                    error_message = "ERROR: 'mobsfscan' command not found. Is it installed and in PATH?"
                    print(error_message)
                except subprocess.TimeoutExpired:
                    error_message = f"mobsfscan timed out after {timeout_seconds} seconds."
                    print(f"ERROR: {error_message}")
                except Exception as e:
                    error_message = f"ERROR: Exception during mobsfscan execution: {e}"
                    print(error_message)

                # --- Save mobsfscan Report --- (If output exists)
                if output_data and not error_message:
                    try:
                        timestamp = datetime.now().strftime("%d_%m_%y-%H_%M")
                        report_filename = f"mobile_scan_{timestamp}.txt"
                        report_filepath = os.path.join(REPORTS_DIR, report_filename)
                        with open(report_filepath, "w", encoding="utf-8") as f:
                            f.write(output_data)
                        print(f"INFO: Mobile scan (mobsfscan) report saved to {report_filepath}")
                    except Exception as e:
                        print(f"ERROR: Failed to save mobsfscan report: {e}")
                        error_message = error_message or "Failed to save report file."

            elif scan_type == 'apk':
                # --- Handle APK upload for quark-engine ---
                print("INFO: Handling APK file for quark-engine")
                apk_filename = secure_filename(file.filename)
                apk_path = os.path.join(MOBTEST_DIR, apk_filename)
                file.save(apk_path)
                print(f"INFO: Saved uploaded APK to: {apk_path}")

                # --- Check and Setup Quark Rules ---
                quark_rules_path = os.path.expanduser("~/.quark-engine/quark-rules/rules")
                if not os.path.exists(quark_rules_path):
                    print(f"INFO: Quark rules not found at {quark_rules_path}. Attempting to set up.")
                    try:
                        subprocess.run(["git", "clone", "https://github.com/quark-engine/quark-rules.git", quark_rules_path], check=True)
                        print("INFO: Quark rules successfully cloned.")
                    except subprocess.CalledProcessError as e:
                        error_message = "Failed to set up Quark rules automatically. Please ensure git is installed and rules can be cloned."
                        print(f"ERROR: {error_message} {e}")
                        # Return error immediately if rules setup fails
                        scan_results['error'] = error_message
                        mobile_scan_results = scan_results
                        return render_template('mobile_scan.html', results=scan_results, error=error_message)
                    except FileNotFoundError:
                        error_message = "Failed to set up Quark rules: 'git' command not found. Please install git."
                        print(f"ERROR: {error_message}")
                        scan_results['error'] = error_message
                        mobile_scan_results = scan_results
                        return render_template('mobile_scan.html', results=scan_results, error=error_message)
                else:
                    print("INFO: Quark rules found.")

                # --- Define Quark JSON output path ---
                quark_report_basename = f"quark_report_{os.path.splitext(apk_filename)[0]}.json"
                quark_json_output_path = os.path.join(QUARK_OUTPUT_DIR, quark_report_basename)
                print(f"INFO: Quark JSON report target path: {quark_json_output_path}")

                # Ensure QUARK_OUTPUT_DIR exists
                os.makedirs(QUARK_OUTPUT_DIR, exist_ok=True)

                # --- Run Quark command (output to JSON) ---
                cmd = ["quark", "-a", apk_path, "-o", quark_json_output_path]
                print(f"INFO: Running APK analysis command: {' '.join(cmd)}")
                timeout_seconds = 300
                process = None
                try:
                    process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout_seconds)
                    print(f"INFO: APK analysis completed with return code: {process.returncode}")
                    # print(f"DEBUG: quark stdout:\n{process.stdout}")
                    # print(f"DEBUG: quark stderr:\n{process.stderr}")

                    # --- Process Quark Results ---
                    if os.path.exists(quark_json_output_path):
                        print(f"INFO: Quark JSON report found at {quark_json_output_path}")
                        raw_json_data = ""
                        parsed_quark_data = None
                        try:
                            # Read JSON content for parsing and display in HTML
                            with open(quark_json_output_path, 'r', encoding='utf-8') as f_json:
                               raw_json_data = f_json.read()
                               # Rewind or reopen not strictly necessary if only reading once
                               # but good practice if file might be used again
                               f_json.seek(0)
                               parsed_quark_data = json.load(f_json)
                            output_data = raw_json_data # Display raw JSON in HTML <pre> tag
                        except json.JSONDecodeError as e:
                            error_message = f"Error parsing generated Quark report: {e}"
                            print(f"ERROR: {error_message}")
                            output_data = raw_json_data # Show raw data even if parsing failed
                            parsed_quark_data = None # Ensure it's None
                        except Exception as e:
                             error_message = f"Error reading Quark report file: {e}"
                             print(f"ERROR: {error_message}")
                             output_data = f"Error reading report: {e}"
                             parsed_quark_data = None

                        # If JSON parsing was successful, format and save text/PDF reports
                        if parsed_quark_data:
                            try:
                                timestamp = datetime.now().strftime("%d_%m_%y-%H_%M")
                                report_filename_base = f"apk_scan_{timestamp}"
                                text_report_filename = f"{report_filename_base}.txt"
                                json_report_filename_for_download = f"{report_filename_base}.json"

                                text_report_path = os.path.join(REPORTS_DIR, text_report_filename)
                                json_download_path = os.path.join(REPORTS_DIR, json_report_filename_for_download)

                                # Format the text report using the helper function
                                formatted_text_report = format_quark_report_text(parsed_quark_data)

                                # Write the FORMATTED text report
                                with open(text_report_path, "w", encoding="utf-8") as f_txt:
                                    f_txt.write(formatted_text_report)
                                print(f"INFO: APK scan formatted text report saved to {text_report_path}")

                                # Copy the original JSON to the reports dir for direct download
                                shutil.copy2(quark_json_output_path, json_download_path)
                                print(f"INFO: Copied Quark JSON report to {json_download_path} for download.")

                                # Store the base name for download links
                                scan_results['report_filename_base'] = report_filename_base

                            except Exception as e:
                                print(f"ERROR: Failed to save formatted text report or copy JSON: {e}")
                                error_message = error_message or "Failed to save report files."
                                scan_results.pop('report_filename_base', None)

                    else:
                        # JSON file was NOT created
                        error_message = "APK analysis ran but did not produce the expected report file."
                        print(f"ERROR: {error_message} Expected at: {quark_json_output_path}")
                        # Include command output in error message if helpful
                        if process.stderr:
                            error_message += f"\nDetails: {process.stderr.strip()}"
                        elif process.stdout:
                             error_message += f"\nDetails: {process.stdout.strip()}"
                        output_data = process.stdout + "\n" + process.stderr # Show command output as fallback in HTML

                    # Handle non-zero exit codes if the report wasn't generated
                    if process.returncode != 0 and not os.path.exists(quark_json_output_path):
                         error_message = error_message or f"APK analysis failed with exit code {process.returncode}."
                         output_data = output_data or process.stdout + "\n" + process.stderr # Show command output

                except FileNotFoundError:
                    error_message = "ERROR: Analysis command ('quark') not found. Is the tool installed and in PATH?"
                    print(error_message)
                    output_data = error_message
                except subprocess.TimeoutExpired:
                    error_message = f"APK analysis timed out after {timeout_seconds} seconds."
                    print(f"ERROR: {error_message}")
                    output_data = error_message
                except Exception as e:
                    error_message = f"ERROR: Exception during APK analysis execution: {e}"
                    print(error_message)
                    output_data = error_message

            else: # Handle zip scan type (mobsfscan)
                # --- Handle ZIP upload for mobsfscan --- (Existing Logic adapted)
                print("INFO: Handling ZIP file for mobsfscan")
                # ... (rest of mobsfscan logic remains the same)
                # ... ensure it sets scan_results['report_filename_base'] too
                # --- Save mobsfscan Report --- (If output exists)
                if output_data and not error_message:
                    try:
                        timestamp = datetime.now().strftime("%d_%m_%y-%H_%M")
                        report_filename_base = f"mobile_scan_{timestamp}" # Base name for mobsfscan
                        text_report_filename = f"{report_filename_base}.txt"
                        report_filepath = os.path.join(REPORTS_DIR, text_report_filename)
                        with open(report_filepath, "w", encoding="utf-8") as f:
                            f.write(output_data)
                        print(f"INFO: Mobile scan (mobsfscan) report saved to {report_filepath}")
                        scan_results['report_filename_base'] = report_filename_base # Store base name
                    except Exception as e:
                        print(f"ERROR: Failed to save mobsfscan report: {e}")
                        error_message = error_message or "Failed to save report file."
                        scan_results.pop('report_filename_base', None)

        except zipfile.BadZipFile: # Keep this for the zip path
            print("ERROR: Uploaded file is not a valid zip file.")
            error_message = "Invalid zip file uploaded."
            output_data = ""
        except Exception as e:
             error_message = f"An unexpected error occurred during mobile scan setup: {e}"
             print(f"ERROR: {error_message}")
             output_data = ""

        scan_results['output_data'] = output_data
        # No longer using report_filename directly, using report_filename_base
        # scan_results['report_filename'] = report_filename
        if error_message:
            scan_results['error'] = error_message # Store specific error

        mobile_scan_results = scan_results # Store results globally (consider session)

        # Render the template with results and potential error
        return render_template('mobile_scan.html', results=scan_results, error=scan_results.get('error'))

    # GET request: just show the upload page
    mobile_scan_results = {} # Clear results on GET
    return render_template('mobile_scan.html', results=None, error=None)


@app.route('/download_mobile_report/<report_type>')
def download_mobile_report(report_type):
    scan_type = request.args.get('scan_type', None) # Get scan type from query param
    base_filename = request.args.get('base_filename', None) # Get base filename if provided

    print(f"INFO: Download request for type '{report_type}', scan_type='{scan_type}', base_filename='{base_filename}'")

    if not base_filename:
        # Fallback: Try to find the latest based on prefix if base_filename isn't provided
        # (This might happen if user navigates directly or session is lost)
        print("WARN: Base filename not provided in download request. Attempting to find latest.")
        if not scan_type:
            return jsonify({"error": "Scan type is required to find the latest report without a base filename."}), 400
        try:
            prefix = 'mobile_scan_' if scan_type == 'zip' else 'apk_scan_' # Match base name structure
            report_files_base = sorted(
                [f.replace('.txt','').replace('.json','') # Get base name
                 for f in os.listdir(REPORTS_DIR) if f.startswith(prefix) and (f.endswith('.txt') or f.endswith('.json'))],
                key=lambda f: os.path.getmtime(os.path.join(REPORTS_DIR, f + ('.txt' if os.path.exists(os.path.join(REPORTS_DIR, f + '.txt')) else '.json'))),
                reverse=True
            )
            if not report_files_base:
                raise IndexError(f"No reports found with prefix '{prefix}'.")
            base_filename = report_files_base[0]
            print(f"INFO: Found latest report base filename: {base_filename}")
        except IndexError as e:
            type_name = "Source Code (ZIP)" if scan_type == 'zip' else "APK"
            print(f"ERROR: No reports found for scan type '{scan_type}' prefix '{prefix}'. {e}")
            return jsonify({"error": f"No {type_name} scan reports found."}), 404
        except Exception as e:
             print(f"ERROR finding latest report: {e}")
             return jsonify({"error": f"Failed to find latest report: {e}"}), 500

    # Construct file paths based on the base filename
    text_report_path = os.path.join(REPORTS_DIR, f"{base_filename}.txt")
    json_report_path = os.path.join(REPORTS_DIR, f"{base_filename}.json")
    pdf_report_path = os.path.join(REPORTS_DIR, f"{base_filename}.pdf")

    try:
        if report_type == "text":
            if os.path.exists(text_report_path):
                return send_file(text_report_path, as_attachment=True)
            else:
                 raise FileNotFoundError(f"Text report not found: {text_report_path}")

        elif report_type == "json":
            # Only applicable for APK scans that generated a JSON
            if os.path.exists(json_report_path):
                return send_file(json_report_path, as_attachment=True, mimetype='application/json')
            else:
                # Provide a more specific error if JSON is requested but doesn't exist
                # (e.g., for mobsfscan or if quark failed to save JSON)
                return jsonify({"error": "JSON report format not available for this scan or it failed to generate."}), 404

        elif report_type == "pdf":
            # Decide which converter to use based on scan_type implied by base_filename prefix
            if base_filename.startswith('apk_scan_'):
                # Need the JSON file path for the dedicated Quark PDF converter
                if os.path.exists(json_report_path):
                    convert_quark_report_to_pdf(json_report_path, pdf_report_path)
                    print(f"INFO: Converted Quark JSON {json_report_path} to PDF at {pdf_report_path}")
                    return send_file(pdf_report_path, as_attachment=True)
                else:
                    # Fallback or error if JSON is missing but PDF was requested
                    print(f"ERROR: Cannot generate Quark PDF, source JSON missing: {json_report_path}")
                    return jsonify({"error": f"Cannot generate PDF: Source JSON report file not found for {base_filename}."}), 404
            elif base_filename.startswith('mobile_scan_'):
                # Use the standard text-to-PDF converter for mobsfscan
                if os.path.exists(text_report_path):
                    convert_mobile_scan_to_pdf(text_report_path, pdf_report_path)
                    print(f"INFO: Converted mobsfscan text {text_report_path} to PDF at {pdf_report_path}")
                    return send_file(pdf_report_path, as_attachment=True)
                else:
                    raise FileNotFoundError(f"Cannot generate PDF: Source text report not found: {text_report_path}")
            else:
                # Handle unknown base filename prefix
                print(f"ERROR: Unknown report prefix in base_filename: {base_filename}")
                return jsonify({"error": "Cannot determine report type from filename to generate PDF."}), 400

        else:
            return jsonify({"error": "Invalid report type requested. Use 'text', 'json', or 'pdf'."}), 400

    except FileNotFoundError as e:
        print(f"ERROR: Report file not found. {e}")
        return jsonify({"error": f"Requested report file not found."}), 404
    except Exception as e:
        print(f"ERROR in download_mobile_report: {e}")
        return jsonify({"error": f"Failed to generate or send report: {e}"}), 500


def convert_mobile_scan_to_pdf(text_file, pdf_file):
    """Convert mobile scan report to PDF as plain text."""
    try:
        pdf = PDF() # Use the base FPDF class setup in the main file
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_margins(15, 15, 15)
        pdf.add_page()
        pdf.set_font('Courier', '', 8) # Monospaced font, reasonable size

        # Replacements for special chars and color codes
        replacements = {
            '[0m': '', '[31m': '', '[33m': '', '[36m': '', # Color codes
            '├': '+', '─': '-', '┤': '+', '┌': '+', '┐': '+', '└': '+', '┘': '+', '│': '|',
            '┬': '+', '┴': '+', '┼': '+',
            '╒': '+', '╕': '+', '╘': '+', '╛': '+', '╔': '+', '╗': '+', '╚': '+', '╝': '+',
            '═': '=', '║': '|', '╠': '+', '╣': '+', '╦': '+', '╩': '+', '╬': '+',
            '╤': '+', '╧': '+', '╪': '+', '╫': '+',
        }

        # Calculate usable page width
        page_width = pdf.w - 2 * pdf.l_margin
        line_height = 4 # Adjust line height for readability

        with open(text_file, "r", encoding="utf-8") as file:
            lines = file.readlines()

        # Process lines: replace chars
        processed_lines = []
        for line in lines:
            original_line = line.rstrip() # Keep trailing spaces if any? No, rstrip is fine.
            processed_line = original_line
            for old, new in replacements.items():
                processed_line = processed_line.replace(old, new)
            # Keep all lines, including potentially empty ones from original formatting
            processed_lines.append(processed_line)

        # --- Simple Rendering Logic ---
        for line in processed_lines:
            # Check for page break before rendering line
            # Estimate height simply based on line count (multi_cell handles wrapping)
            if pdf.get_y() + line_height > pdf.h - pdf.b_margin:
                pdf.add_page()
                pdf.set_font('Courier', '', 8) # Reset font on new page

            # Render the entire processed line using multi_cell
            pdf.multi_cell(page_width, line_height, line)
            # multi_cell automatically adds a line break

        pdf.output(pdf_file)
        print(f"✅ Mobile scan PDF (plain text) successfully created: {pdf_file}")
    except Exception as e:
        print(f"❌ Error creating mobile scan PDF (plain text): {e}")
        raise


if __name__ == '__main__':
    if not app.secret_key or app.secret_key == 'temporary_secret_key_for_testing':
        app.secret_key = os.urandom(24) # Ensure a key is set for session
    app.run(host='0.0.0.0', port=5556, debug=True)
