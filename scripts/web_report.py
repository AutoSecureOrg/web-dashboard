import os
import datetime
from prettytable import PrettyTable

def web_vuln_report(directory, target_url, vulnerabilities):
    """
    Generates a report for web vulnerability scanning results.

    Args:
        directory (str): Path to the directory where the report will be stored.
        target_url (str): The target URL that was scanned.
        vulnerabilities (list): A list of vulnerability results.

    Returns:
        str: The path to the generated report file.
    """
    os.makedirs(directory, exist_ok=True)

    # Generate a sanitized timestamp for the filename
    raw_timestamp = datetime.datetime.now().strftime("%d/%m/%y-%H:%M")
    sanitized_timestamp = raw_timestamp.replace("/", "_").replace(":", "-")
    file_name = os.path.join(directory, f"web_scan_{sanitized_timestamp}.txt")

    try:
        with open(file_name, "w") as report_file:
            report_file.write(f"Target URL: {target_url}\n")
            report_file.write(f"Scan Time: {datetime.datetime.now().strftime('%d/%m/%y %H:%M:%S')}\n")
            report_file.write("=" * 50 + "\n")

            if vulnerabilities:
                report_file.write("Detected Vulnerabilities:\n")
                vuln_table = PrettyTable(["Vulnerability Type", "Status", "Payload"])
                
                for vuln in vulnerabilities:
                    vuln_table.add_row([
                        vuln.get("type", "Unknown"),
                        vuln.get("status", "Unknown"),
                        vuln.get("payload", "N/A")
                    ])

                report_file.write(f"{vuln_table}\n")
            else:
                report_file.write("No vulnerabilities detected.\n")

            report_file.write("=" * 50 + "\n")

        print(f"[+] Web report generated successfully: {file_name}")  # Debug message
        return file_name  # Return report path

    except Exception as e:
        print(f"[-] Failed to write web vulnerability report: {e}")
        return None
