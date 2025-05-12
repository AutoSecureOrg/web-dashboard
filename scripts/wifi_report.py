import os
import datetime
from tabulate import tabulate
import re

def remove_emojis(text):
    # Removes emojis and non-latin characters for PDF compatibility
    return re.sub(r'[^\x00-\x7F]+', '', text)

def wifi_vuln_report(report_dir, ssid, bssid, target_info, vuln_info, rogue_info, crack_result=None, all_networks_df=None):
    os.makedirs(report_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%d%m%y_%H%M%S")
    safe_bssid = bssid.replace(':', '-').replace(' ', '_')
    filename = os.path.join(report_dir, f"wifi_full_{safe_bssid}_{timestamp}.txt")

    with open(filename, "w", encoding="utf-8") as f:
        # === HEADER ===
        f.write("Wi-Fi Security Scan Report\n")
        f.write("=" * 80 + "\n\n")

        # === All Detected Networks ===
        f.write("All Detected Wi-Fi Networks\n")
        f.write("-" * 80 + "\n")
        if all_networks_df is not None and not all_networks_df.empty:
            f.write(tabulate(all_networks_df, headers="keys", tablefmt="grid", stralign="left"))
        else:
            f.write("No Wi-Fi networks were found during scanning.\n")
        f.write("\n\n")

        # === Rogue Summary ===
        f.write("Rogue Access Point Summary\n")
        f.write("-" * 80 + "\n")
        rogue_summary = rogue_info.get("summary", [])
        if rogue_summary:
            for entry in rogue_summary:
                f.write(f"SSID       : {entry['SSID']}\n")
                f.write(f"Status     : {entry['Status']}\n")
                f.write(f"Severity   : {entry['Severity']}\n")
                f.write(f"Indicators : {entry['Rogue Indicators']}\n")
                f.write("-" * 40 + "\n")
        else:
            f.write("No rogue APs detected based on current indicators.\n")
        f.write("\n\n")

        # === Rogue Detailed Log ===
        f.write("Rogue Detailed Log\n")
        f.write("-" * 80 + "\n")
        f.write(remove_emojis(rogue_info.get("detailed_log", "No detailed rogue log available.")))
        f.write("\n\n")

        # === Target Info ===
        f.write("Selected Target Network Info\n")
        f.write("-" * 80 + "\n")
        if isinstance(target_info, dict):
            for key, val in target_info.items():
                f.write(f"{key:<20}: {val}\n")
        else:
            f.write("No target info available.\n")
        f.write("\n\n")

        # === Vulnerability Info ===
        f.write("Vulnerability Analysis\n")
        f.write("-" * 80 + "\n")
        risk_lines = vuln_info.get("risk", "")
        if risk_lines:
            for line in risk_lines.splitlines():
                f.write(f" - {remove_emojis(line)}\n")
        else:
            f.write(" - No vulnerability data available.\n")
        f.write("\n\n")

        # === Cracked Password ===
        f.write("Password Cracking Result\n")
        f.write("-" * 80 + "\n")
        if crack_result and isinstance(crack_result, dict):
            f.write(f"Cracked Password   : {crack_result.get('password', 'N/A')}\n")
            analysis = crack_result.get("analysis", {})

            if analysis.get("strength_issues"):
                f.write("Strength Issues    : " + ", ".join(analysis["strength_issues"]) + "\n")
            else:
                f.write("Password Strength  : Good\n")

            if analysis.get("pwned_count"):
                f.write(f"Leaked in Breaches : {analysis['pwned_count']} times\n")
            elif analysis.get("pwned_error"):
                f.write(f"Pwned Check Error  : {analysis['pwned_error']}\n")
            else:
                f.write("No Known Breaches\n")

            if analysis.get("suggestion"):
                f.write(f"Suggested Password : {analysis['suggestion']}\n")
        else:
            f.write("Password cracking not attempted or failed.\n")

        # === Footer ===
        f.write("\n" + "=" * 80 + "\n")
        f.write("End of Wi-Fi Report\n")

    return filename
