import threading
import time
from flask import Flask, json, render_template, request, jsonify, send_file
import os, subprocess
from fpdf import FPDF
from scripts.portExploit import nmap_scan, connect_to_metasploit, search_and_run_exploit, get_local_ip, port_exploit_report
from scripts.web_scanner import test_sql_injection, xss_only, command_only, html_only, complete_scan

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
                nmap_results[target_ip] = [{
                    "port": service["port"],
                    "service": service["service"],
                    "version": service.get("version", "Unknown")
                } for service in services_found[target_ip]]

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
                port_exploit_report(REPORTS_DIR, targets, nmap_results, exploitation_results)

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


def convert_text_to_pdf(text_file, pdf_file):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    with open(text_file, "r") as file:
        for line in file:
            pdf.cell(200, 10, txt=line.strip(), ln=True)

    pdf.output(pdf_file)


@app.route('/website_scanner', methods=['GET', 'POST'])
def website_scanner():
    if request.method == 'POST':
        target_url = request.form['target_url']
        scan_type = request.form['scan_type']

        # Initialize results variable to store scan output
        results = ""

        try:
            if scan_type == "all":
                # Run the entire script for all scans
                results = complete_scan(target_url)
                '''subprocess.run(
                    ['python', 'scripts/web_scanner.py', target_url],
                    capture_output=True,
                    text=True,
                    check=True
                ).stdout'''
            elif scan_type == "sql_injection":
                # Run the SQL Injection test only
                results = test_sql_injection(target_url,None)
            elif scan_type == "xss":
                # Run SQL Injection first to log in, then XSS
                results = xss_only(target_url)
            elif scan_type == "html_injection":
                # Add open ports handling here if implemented in your script
                results = html_only(target_url)
            elif scan_type == "command_injection":
                # Run SQL Injection first to log in, then Command Injection
                results = command_only(target_url)
            else:
                results = "Invalid scan type selected."

        except Exception as e:
            results = f"An error occurred: {str(e)}"

        # Render the results in the report.html template
        return render_template('report.html', output=results, tool='Website Scanner')

    return render_template('website_scanner.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
