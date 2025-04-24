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
from scripts.wifi_tool import auto_arp_replay_flood,scan_and_analyze 
from scripts.wifi_tool import *
from scripts.mobsf_handler import upload_apk_to_mobsf, get_static_analysis_url

AI_HOST = '127.0.0.1'
AI_PORT = 5005
# Load environment variables from .env file
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

app = Flask(__name__)

# Ensure the reports directory exists
REPORTS_DIR = "/home/autosecure/FYP/reports/"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Global variables to hold scan and test results
services_found = {}
targets = []
nmap_results = []
exploitation_results = []
test_status = {"complete": False}


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/network-scanner', methods=['GET', 'POST'])
def network_scanner():
    global services_found
    global targets
    # init variables to avoid overlap with previous test runs
    targets = []
    nmap_results = {}
    exploitation_results = {}
    if request.method == 'POST':
        start_ip = request.form.get('start_ip')
        end_ip = request.form.get('end_ip')
        target_ip = request.form.get('target_ip')
        start_port = request.form.get('start_port', type=int)
        end_port = request.form.get('end_port', type=int)

        if start_ip and end_ip and not target_ip:
            end_num = end_ip.split(".")[-1]
            start_num = start_ip.split(".")[-1]
            prefix = start_ip.split(".", 3)
            prefix = prefix[0] + '.' + prefix[1] + '.' + prefix[2] + '.'

            for i in range(int(start_num), int(end_num) +1):
                targets.append(prefix + str(i))
        elif target_ip:
            targets.append(target_ip)

        if (len(targets) < 1):
            return jsonify({"error": "Target IP is required"}), 400

        try:
            for target_ip in targets:
                # Pass start_port and end_port to the nmap_scan function
                open_ports = nmap_scan(target_ip, start_port=start_port, end_port=end_port)
                services_found[target_ip] = [
                    {"service": port_info["service"],
                     "port": port_info["port"],
                     "version": port_info.get("version", "Unknown")
                    }
                    for port_info in open_ports
                ]

            return render_template('service_selection.html', services=services_found)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return render_template('network_scanner.html')


@app.route('/run-tests', methods=['POST'])
def run_tests():
    global test_status, nmap_results, exploitation_results
    test_status["complete"] = False
    nmap_results = {}
    exploitation_results = {}

    selected_services = json.loads(request.form.get('services'))  # Convert JSON string to list of objects

    if not selected_services:
        return jsonify({"error": "No services selected"}), 400

    # Run tests in a background thread
    def perform_tests():
        #global test_status, nmap_results, exploitation_results
        try:
            client = connect_to_metasploit()
            if not client:
                raise Exception("Failed to connect to Metasploit.")

            local_ip = get_local_ip()

            # Iterate over each IP and perform tests
            for target_ip in targets:
                results = []

                if target_ip not in services_found:
                    continue  # Skip if no services were found for this IP

                # Populate Nmap results for each IP
                nmap_results[target_ip] = []
                for service in services_found[target_ip]:
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
                        "port": port,
                        "service": service_name,
                        "version": version,
                        "vuln": description
                    })

                # Run exploits for each service
                for service_info in services_found[target_ip]:
                    if any(service_info['service'].lower() == entry['service'].lower() for entry in selected_services):
                        module_name, success = search_and_run_exploit(
                            client, service_info['service'], target_ip, service_info['port'], local_ip
                        )
                        results.append({
                            "service": service_info['service'],
                            "port": service_info['port'],
                            "exploit": module_name if module_name else "No exploit found",
                            "status": "Succeeded" if success else "Failed"
                        })

                # Store results per IP
                exploitation_results[target_ip] = results

                # Generate a report for each IP
                port_exploit_report(REPORTS_DIR, targets, nmap_results, exploitation_results, api_key=NVD_API_KEY)

        except Exception as e:
            print(f"Error during tests: {e}")
        finally:
            test_status["complete"] = True

    threading.Thread(target=perform_tests).start()
    return jsonify({"status": "Tests started"}), 200


@app.route('/check-status', methods=['GET'])
def check_status():
    return jsonify(test_status)


@app.route('/results')
def results():
    """
    Displays results stored in global variables.
    """
    return render_template(
        'results.html',
        nmap_results=nmap_results,
        exploitation_results=exploitation_results
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
    

@app.route('/mobile', methods=['GET'])
def mobile_landing():
    """
    Legacy mobile pentest route - redirects to new landing page
    """
    return render_template("mobile_landing.html")


@app.route('/mobile/apk-scan', methods=['POST'])
def scan_apk_and_redirect():
    apk_file = request.files.get("apk_file")

    if not apk_file:
        return "No file uploaded", 400

    # Force save to disk with correct extension
    filename = apk_file.filename
    if not filename.endswith(".apk"):
        return "Only .apk files are supported", 400

    upload_dir = "./uploads"
    os.makedirs(upload_dir, exist_ok=True)
    apk_path = os.path.join(upload_dir, filename)

    apk_file.save(apk_path)

    # Extra: confirm file was saved and not 0 bytes
    if not os.path.isfile(apk_path) or os.path.getsize(apk_path) < 10000:
        return "Uploaded file is too small or corrupt", 400

    try:
        print(f"[+] Uploading: {apk_path} ({os.path.getsize(apk_path)} bytes)")
        result = upload_apk_to_mobsf(apk_path)
        md5_hash = result.get("hash")
        redirect_url = get_static_analysis_url(md5_hash)
        return redirect(redirect_url)

    except Exception as e:
        return f"Upload failed: {str(e)}", 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5556, debug=True)