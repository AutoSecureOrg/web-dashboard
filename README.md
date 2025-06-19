<div align="center">
    <img src="static/images/logo.png" alt="AutoSecure Logo" height="200" width="auto">
    </br></br>

# AutoSecure

Preview Landing Page: <a href="https://autosecureorg.github.io">AutoSecure</a>
</div>

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Project Setup](#project-setup)
  - [Dashboard Prerequisite Setup](#dashboard-prerequisite-setup)
  - [Automation Setup](#automation-setup)
  - [AI Server Setup](#ai-server-setup)
- [Disclaimer](#disclaimer)
- [Authors](#authors)

## Introduction

AutoSecure is a dashboard designed to automate tedious penetration testing tasks, providing cybersecurity professionals with a quick and comprehensive solution for assessing security vulnerabilities.

## Features

* **System Testing:** Comprehensive testing for system-level vulnerabilities:
  * Checks for open ports and identifies running services
  * Leverages the Metasploit Framework for automated exploitation
  * Offers Lite Testing for quick scans and Deep Testing for thorough analysis
  * Allows users to upload and integrate their own custom exploits
  * Supports testing on a single host or a range of IP addresses

* **Web Application Testing:** Comprehensive web application security testing with automated vulnerability detection:
  * Login Detection & Authentication Bypass:
    * Automatic login page detection
    * SQL Injection attempts
    * Brute-force attacks using local wordlists
  * Form & Input Field Parsing:
    * Extracts all forms and input fields using BeautifulSoup
    * Analyzes action URLs, input names/types, and methods (GET/POST)
  * Vulnerability Detection Modules:
    * SQL Injection: Payloads, error-based detection, response diffing
    * XSS: Reflective input tests using JavaScript payloads
    * Command Injection: OS-specific command testing
    * HTML Injection: Unfiltered tag testing
  * API Endpoint Detection:
    * Scans JavaScript files for fetch() and AJAX calls
    * Tests discovered endpoints with known input keys
  * Standalone Testing Modes:
    * Individual module execution (xss_only, sql_only)
    * Customizable payload management

* **WiFi Network Testing:** Advanced wireless network security assessment and analysis:
  * Wi-Fi Scanning:
    * Comprehensive network discovery
    * Signal strength analysis
    * BSSID and encryption details
  * Rogue AP Detection:
    * SSID spoofing identification
    * Signal anomaly detection
    * MAC prefix reuse analysis
    * Vendor mismatch verification
  * Encryption Risk Analysis:
    * Weak protocol detection (WEP, WPA1)
    * Open network identification
    * Default SSID flagging
    * Signal strength vulnerability assessment
  * Password Security:
    * Brute-force attempts using wordlists
    * Connection verification via nmcli
    * Password leak checking via HaveIBeenPwned API
    * Strength analysis and improvement suggestions

* **Mobile Application Testing:** Static and dynamic analysis for Mobile App Code & Android applications (APKs):
  * Analyzes uploaded Mobile App Code and APK files for known vulnerabilities, insecure configurations, and malicious code patterns
  * Detects hardcoded secrets and sensitive information leakage
  * Identifies excessive application permissions
  * Checks for insecure network communication practices
  * Scans for known malware signatures and potentially harmful code
  * Analyzes APK files for requested permissions and maps them to potential privacy risks
  * Detects insecure data storage practices (e.g., world-readable/writable files)
  * Identifies weak cryptographic implementations
  * Checks for potential intent vulnerabilities (e.g., broadcast theft, intent spoofing)
  * Flags potentially malicious behaviors like dynamic code loading or SMS manipulation

* **AI-Powered Analysis:** Advanced threat detection and analysis powered by locally-hosted LLaMA 3 AI model with real-time NVD integration:
  * Real-Time Threat Intelligence: Direct integration with the National Vulnerability Database (NVD) for live vulnerability data, including CVE details, severity indicators, and risk scores
  * Comprehensive Vulnerability Profiling: Detailed analysis including severity ratings with visual indicators, CWE classifications, and full vulnerability descriptions with reference links
  * Offline-Capable AI Analysis: Locally hosted LLaMA 3 model ensures secure, private, and instantaneous vulnerability assessment without external dependencies
  * Automated Remediation Guidance: AI-generated expert remediation steps including:
    * Specific patch recommendations
    * Detection and verification commands
    * Strategic mitigation approaches
  * Real-Time Processing: Instant analysis and response generation, enabling immediate security decision-making and rapid vulnerability management

* **Report Generation:** Creates detailed PDF reports summarizing the findings from network, web, wifi and mobile scans.

## Project Setup

### Dashboard Prerequisite Setup

* Create user 'autosecure' in kali.
* Create directory `/home/FYP` and place/clone web-dashboard repository here.
* Create and install python virtual environment and install necessary packages:
  * `python3 -m venv venv`
  * `source venv/bin/activate`
  * `pip install -r requirements.txt`

### Automation Setup

* Create a bash file 'startup_script.sh' in `/home/autosecure/` directory:
  * `sudo nano startup_script.sh`
* Place the following code:

    ```bash
    #!/bin/bash
    # Wait for Wi-Fi to connect
    while ! ping -c 1 -W 1 google.com > /dev/null 2>&1; do
    echo "Waiting for Wi-Fi connection..."
    sleep 5
    done
    echo "Wi-Fi connected."
    # Start the Flask backend in the same terminal
    x-terminal-emulator -e "bash -c 'cd FYP/web-dashboard && source venv/bin/activate && python3 app.py; exec bash'" &
    # Launch Metasploit in another terminal and keep it running
    x-terminal-emulator -e "bash -c 'msfconsole -q -x \"load msgrpc ServerHost=127.0.0.1 ServerPort=55552 Pass=your_password\"; exec bash'" &
    ```

* `chmod +x /home/autosecure/startup_script.sh`
* For automating Metasploit database startup and Flask application startup; set up an autostart script using Linux desktop scripts:
  * `mkdir -p ~/.config/autostart`
  * `nano ~/.config/autostart/startup_script.desktop`
  * Paste the following code in file:

    ```ini
    [Desktop Entry]
    Type=Application
    Exec=/bin/bash /home/autosecure/startup_script.sh
    Hidden=false
    NoDisplay=false
    X-GNOME-Autostart-enabled=true
    Name=Startup Script
    Comment=Run custom startup script
    ```

### AI Server Setup

* Add the following code to `startup_script.sh` in `/home/` directory (Note: The user previously specified `/home/autosecure/` for this script. Assuming `/home/autosecure/startup_script.sh` based on prior context):

    ```bash
    # Run AI Server
    # Ensure VENV_PATH is defined, e.g., VENV_PATH=/home/autosecure/FYP/web-dashboard/venv
    x-terminal-emulator -e "bash -c 'source $VENV_PATH/bin/activate && python3 /home/autosecure/FYP/web-dashboard/ai_server.py; exec bash'" &
    ```

* Clone `llama.cpp` repository and build it:

    ```bash
    git clone https://github.com/ggerganov/llama.cpp.git
    cd llama.cpp
    #Install libcurl support:
    sudo apt install libcurl4-openssl-dev
    cmake -B build
    cmake --build build --config Release
    ```

* Download the Llama-3 WhiteRabbitNeo GGUF model:

    ```bash
    sudo apt install aria2
    # Assuming you are in the llama.cpp directory
    cd models
    aria2c -x 16 -s 16 "https://huggingface.co/mradermacher/Llama-3-WhiteRabbitNeo-8B-v2.0-GGUF/resolve/main/Llama-3-WhiteRabbitNeo-8B-v2.0.Q4_K_M.gguf"
    ```

    *Ensure the `MODEL_PATH` in `ai_server.py` points to the correct location of this downloaded model file (e.g., `/home/autosecure/llama.cpp/models/Llama-3-WhiteRabbitNeo-8B-v2.0.Q4_K_M.gguf`).*

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Unauthorized scanning or attacking of networks or systems is illegal and unethical. Use responsibly and ensure you have explicit permission before testing any target. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## Authors

* [Daim Bin Khalid](https://github.com/daimbk)
* [Hafsah Shahbaz](https://github.com/Emeika)
* [Syeda Manal Ammad](https://github.com/manalammad)
* [Kiran Qaiser](https://github.com/kiranQaiser)
