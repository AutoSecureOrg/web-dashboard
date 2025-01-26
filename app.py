from flask import Flask, render_template, request, jsonify, send_file
import os, subprocess
from fpdf import FPDF
from scripts.portExploit import nmap_scan, connect_to_metasploit, search_and_run_exploit, get_local_ip, port_exploit_report
from scripts.web_scanner import test_sql_injection, test_xss, test_command_injection, xss_only, command_only

app = Flask(__name__)

# Ensure the reports directory exists
REPORTS_DIR = "/home/autosecure/FYP/reports/"
os.makedirs(REPORTS_DIR, exist_ok=True)


# Route for Home Page
@app.route('/')
def home():
    return render_template('home.html')


# Route for Network Scanner Page
@app.route('/network-scanner', methods=['GET', 'POST'])
def network_scanner():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        start_port = request.form.get('start_port', 1, type=int)
        end_port = request.form.get('end_port', 65535, type=int)
        results = []

        if scan_type == 'single':
            target_ip = request.form.get('target_ip')
            if not target_ip:
                return jsonify({"error": "Target IP is required"}), 400

            results = perform_scan(target_ip, start_port, end_port)

        elif scan_type == 'range':
            start_ip = request.form.get('start_ip')
            end_ip = request.form.get('end_ip')
            if not start_ip or not end_ip:
                return jsonify({"error": "Start IP and End IP are required"}), 400

            ip_range = generate_ip_range(start_ip, end_ip)
            for ip in ip_range:
                results += perform_scan(ip, start_port, end_port)

        else:
            return jsonify({"error": "Invalid scan type"}), 400

        return jsonify({"results": results})
    return render_template('network_scanner.html')


# Route to Download Report
@app.route('/download-report/<report_type>')
def download_report(report_type):
    try:
        # Find the latest report file
        latest_file = sorted(
            [os.path.join(REPORTS_DIR, f) for f in os.listdir(REPORTS_DIR) if f.endswith('.txt')],
            key=os.path.getmtime,
            reverse=True
        )[0]

        if report_type == "text":
            # Download as text file
            return send_file(latest_file, as_attachment=True)

        elif report_type == "pdf":
            # Convert to PDF
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
    """
    Converts a text file to a PDF.
    """
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    with open(text_file, "r") as file:
        for line in file:
            pdf.cell(200, 10, txt=line.strip(), ln=True)

    pdf.output(pdf_file)


def perform_scan(target_ip, start_port, end_port):
    try:
        open_ports = nmap_scan(target_ip)
        nmap_table = [{"port": port_info["port"], "service": port_info["service"]} for port_info in open_ports]

        client = connect_to_metasploit()
        if not client:
            return [{"error": "Failed to connect to Metasploit"}]

        local_ip = get_local_ip()
        results = []
        for port_info in open_ports:
            service = port_info["service"]
            port = port_info["port"]
            success = search_and_run_exploit(client, service, target_ip, port, local_ip)
            results.append({
                "service": service,
                "port": port,
                "exploit": f"{service} exploit",
                "status": "Succeeded" if success else "Failed"
            })

        port_exploit_report(REPORTS_DIR, target_ip, nmap_table, results)

        return results
    except Exception as e:
        return [{"error": str(e)}]


def generate_ip_range(start_ip, end_ip):
    import ipaddress
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    return [str(ip) for ip in range(int(start), int(end) + 1)]


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
                results = subprocess.run(
                    ['python', 'scripts/web_scanner.py', target_url],
                    capture_output=True,
                    text=True,
                    check=True
                ).stdout
            elif scan_type == "sql_injection":
                # Run the SQL Injection test only
                results = test_sql_injection(target_url,None)
            elif scan_type == "xss":
                # Run SQL Injection first to log in, then XSS
                results = xss_only(target_url)
            elif scan_type == "csrf":
                # Add CSRF handling here if implemented in your script
                results = "CSRF testing not yet implemented."
            elif scan_type == "open_ports":
                # Add open ports handling here if implemented in your script
                results = "Open Ports scanning not yet implemented."
            elif scan_type == "security_headers":
                # Add security headers handling here if implemented in your script
                results = "Security Headers scanning not yet implemented."
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
