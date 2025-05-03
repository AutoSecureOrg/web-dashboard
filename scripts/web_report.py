import os
import datetime
from prettytable import PrettyTable

def web_vuln_report(directory, target_urls, all_results):
    """
    Generates a report for web vulnerability scanning results from multiple URLs.

    Args:
        directory (str): Path to the directory where the report will be stored.
        target_urls (list): A list of target URLs that were scanned.
        all_results (dict): A dictionary where keys are URLs and values are
                            lists of vulnerability result dictionaries.

    Returns:
        str: The path to the generated report file, or None if failed.
    """
    os.makedirs(directory, exist_ok=True)

    # Generate a sanitized timestamp for the filename
    raw_timestamp = datetime.datetime.now().strftime("%d/%m/%y-%H:%M")
    sanitized_timestamp = raw_timestamp.replace("/", "_").replace(":", "-")
    # Create a more generic filename for multi-url reports
    file_name = os.path.join(directory, f"web_scan_report_{sanitized_timestamp}.txt")

    try:
        with open(file_name, "w", encoding="utf-8") as report_file:
            report_file.write("Web Vulnerability Scan Report\n")
            report_file.write(f"Scan Time: {datetime.datetime.now().strftime('%d/%m/%y %H:%M:%S')}\n")
            report_file.write(f"Targets Scanned: {len(target_urls)}\n")
            report_file.write("\n" + "=" * 60 + "\n\n")

            if all_results:
                # Loop through each URL and its results
                for url, vulnerabilities in all_results.items():
                    report_file.write(f"--- Results for: {url} ---\n")

                    if vulnerabilities:
                        # Create a table for this URL's vulnerabilities
                        vuln_table = PrettyTable(["Vulnerability Type", "Status", "Payload/Details"])
                        vuln_table.align = "l" # Left align
                        vuln_table.max_width["Payload/Details"] = 60 # Limit payload width

                        for vuln in vulnerabilities:
                            payload = str(vuln.get("payload", "N/A"))
                            # Basic newline handling for prettytable
                            payload_formatted = payload.replace('\n', '\n ') # Add space for better wrap

                            vuln_table.add_row([
                                vuln.get("type", "Unknown"),
                                vuln.get("status", "Unknown"),
                                payload_formatted
                            ])

                        report_file.write(f"{vuln_table}\n\n")
                    else:
                        # Should not happen if app.py logic is correct, but handle defensively
                        report_file.write("No specific vulnerability data found for this URL.\n\n")

            else:
                report_file.write("No scan results were generated for any URL.\n")

            report_file.write("End of Report\n")
            report_file.write("=" * 60 + "\n")

        print(f"[+] Web report generated successfully: {file_name}")
        return file_name

    except Exception as e:
        print(f"[-] Failed to write web vulnerability report: {e}")
        import traceback
        traceback.print_exc() # Print full traceback for debugging
        return None # Return None on failure