<div align="center">
    <img src="static/images/logo.png" alt="AutoSecure Logo" height="200" width="auto">
    </br></br>

# AutoSecure    
Preview Landing Page: <a href="autosecureorg.github.io">AutoSecure</a>
</div>

## Introduction

AutoSecure is a dashboard designed to automate tedious penetration testing tasks, providing cybersecurity professionals with a quick and comprehensive solution for assessing security vulnerabilities.

## Features

*   **System Testing:** Comprehensive testing for system-level vulnerabilities:
    * Checks for open ports and identifies running services
    * Leverages the Metasploit Framework for automated exploitation
    * Offers Lite Testing for quick scans and Deep Testing for thorough analysis
    * Allows users to upload and integrate their own custom exploits
    * Supports testing on a single host or a range of IP addresses

*   **Web Application Testing:** Comprehensive web application security testing with automated vulnerability detection:
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

*   **WiFi Network Testing:** Advanced wireless network security assessment and analysis:
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

*   **Mobile Application Testing:** Static and dynamic analysis for Mobile App Code & Android applications (APKs):
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

*   **AI-Powered Analysis:** Advanced threat detection and analysis powered by locally-hosted LLaMA 3 AI model with real-time NVD integration:
    * Real-Time Threat Intelligence: Direct integration with the National Vulnerability Database (NVD) for live vulnerability data, including CVE details, severity indicators, and risk scores
    * Comprehensive Vulnerability Profiling: Detailed analysis including severity ratings with visual indicators, CWE classifications, and full vulnerability descriptions with reference links
    * Offline-Capable AI Analysis: Locally hosted LLaMA 3 model ensures secure, private, and instantaneous vulnerability assessment without external dependencies
    * Automated Remediation Guidance: AI-generated expert remediation steps including:
        * Specific patch recommendations
        * Detection and verification commands
        * Strategic mitigation approaches
    * Real-Time Processing: Instant analysis and response generation, enabling immediate security decision-making and rapid vulnerability management

*   **Report Generation:** Creates detailed PDF reports summarizing the findings from network, web, wifi and mobile scans.


## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Unauthorized scanning or attacking of networks or systems is illegal and unethical. Use responsibly and ensure you have explicit permission before testing any target. The developers assume no liability and are not responsible for any misuse or damage caused by this program.


## Authors

<div>
    <a href="https://github.com/daimbk">Daim Bin Khalid</a>
    </br>
    <a href="https://github.com/Emeika">Hafsah Shahbaz</a>
    </br>
    <a href="https://github.com/manalammad">Syeda Manal Ammad</a>
    </br>
    <a href="https://github.com/kiranQaiser">Kiran Qaiser</a>
</div>