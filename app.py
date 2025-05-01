import threading
import time
from flask import Flask, json, render_template, request, jsonify, send_file
import os, subprocess
from fpdf import FPDF
from scripts.portExploit import nmap_scan, connect_to_metasploit, search_and_run_exploit, get_local_ip, port_exploit_report
from scripts.web_scanner import login_sql_injection, xss_only, command_only, html_only, complete_scan, sql_only
from scripts.web_report import web_vuln_report
from datetime import datetime

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
        urls = request.form.getlist('urls')  # <-- Get all URLs
        scan_type = request.form['scan_type']
        all_results = []
        combined_results = ""

        for target_url in urls:
            if not target_url.strip():
                continue

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
                    results = ["[-] Invalid scan type selected."]
            except Exception as e:
                results = [f"[-] Error while scanning {target_url}: {str(e)}"]

            # Add this header only to text report
            combined_results += f"\n=== Results for {target_url} ===\n" + "\n".join(results) + "\n"

            # Add header separately in output list (for UI), then all result lines
            all_results.append({
                "type": "Header",
                "status": "Target URL",
                "payload": f"=== Results for {target_url} ==="
            })

            for line in results:
                if line.strip():
                    all_results.append({
                        "type": "General",
                        "status": "Info",
                        "payload": line
                    })

        # If no results were added, show default message
        if not all_results:
            all_results = [{"type": "No vulnerabilities found", "status": "Safe", "payload": "N/A"}]

        # Generate one report file combining all URLs
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(REPORTS_DIR, f"web_scan_{timestamp}.txt")
        with open(report_path, 'w') as f:
            f.write(combined_results)

        return render_template(
            'report.html',
            output=all_results,
            target_url="Multiple Targets",
            report_path=report_path
        )

    return render_template('website_scanner.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
