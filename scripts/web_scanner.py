import sys

if len(sys.argv) != 2:
    print("Usage: python web_scanner.py <target_url>")
    sys.exit(1)

target_url = sys.argv[1]
print(f"Scanning {target_url}...")
print("No vulnerabilities found. This is a dummy scanner output.")
