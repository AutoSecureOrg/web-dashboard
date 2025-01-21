import threading
import time
from flask import Flask, render_template, request, jsonify, send_file
import os
from fpdf import FPDF
from scripts.portExploit import nmap_scan, connect_to_metasploit, search_and_run_exploit, get_local_ip, port_exploit_report

app = Flask(__name__)

# Ensure the reports directory exists
REPORTS_DIR = "/home/autosecure/FYP/reports/"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Global variables to hold scan and test results
services_found = []
nmap_results = []
exploitation_results = []
test_status = {"complete": False}


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/network-scanner', methods=['GET', 'POST'])
def network_scanner():
    global services_found
    if request.method == 'POST':
        target_ip = request.form.get('target_ip')
        start_port = request.form.get('start_port', type=int)
        end_port = request.form.get('end_port', type=int)

        if not target_ip:
            return jsonify({"error": "Target IP is required"}), 400

        if start_port is None or end_port is None:
            return jsonify({"error": "Start Port and End Port are required"}), 400

        try:
            # Pass start_port and end_port to the nmap_scan function
            open_ports = nmap_scan(target_ip, start_port=start_port, end_port=end_port)
            services_found = [
                {"service": port_info["service"], "port": port_info["port"], "version": port_info.get("version", "Unknown")}
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
    nmap_results = []
    exploitation_results = []

    selected_services = request.form.get('services').split(',')
    target_ip = request.form.get('target_ip')

    if not selected_services:
        return jsonify({"error": "No services selected"}), 400

    # Run tests in a background thread
    def perform_tests():
        global test_status, nmap_results, exploitation_results
        try:
            client = connect_to_metasploit()
            if not client:
                raise Exception("Failed to connect to Metasploit.")

            local_ip = get_local_ip()
            results = []

            # Populate Nmap results
            nmap_results = [{
                "port": service["port"],
                "service": service["service"],
                "version": service.get("version", "Unknown")
            } for service in services_found]

            # Run exploits
            for service_info in services_found:
                if 'All' in selected_services or service_info['service'] in selected_services:
                    module_name, success = search_and_run_exploit(
                        client, service_info['service'], target_ip, service_info['port'], local_ip
                    )
                    results.append({
                        "service": service_info['service'],
                        "port": service_info['port'],
                        "exploit": module_name if module_name else "No exploit found",
                        "status": "Succeeded" if success else "Failed"
                    })

            # Update global results
            exploitation_results = results

            # Generate a report
            port_exploit_report(REPORTS_DIR, target_ip, nmap_results, exploitation_results)

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

        # Run the web_scanner.py script with the provided target URL
        try:
            results = subprocess.run(
                ['python', 'scripts/web_scanner.py', target_url],
                capture_output=True,
                text=True,
                check=True
            )
            output = results.stdout
        except subprocess.CalledProcessError as e:
            output = f"Error occurred during scanning: {e.stderr}"

        return render_template('report.html', output=output, tool='Website Scanner')

    return render_template('website_scanner.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
