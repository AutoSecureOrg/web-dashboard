import os
import requests
from dotenv import load_dotenv

load_dotenv()

MOBSF_API_KEY = os.getenv("MOBSF_API_KEY")
MOBSF_API_URL = os.getenv("MOBSF_API_URL").rstrip('/') + "/"

def upload_apk_to_mobsf(apk_path):
    headers = {
        "Authorization": MOBSF_API_KEY
    }

    filename = os.path.basename(apk_path)
    mime_type = "application/vnd.android.package-archive"

    with open(apk_path, "rb") as f:
        files = {
            "file": (filename, f, mime_type)
        }

        # Step 1: Upload APK
        upload_response = requests.post(
            MOBSF_API_URL + "upload",
            files=files,
            headers=headers
        )
        upload_response.raise_for_status()
        upload_data = upload_response.json()
        scan_hash = upload_data.get("hash")

        print(f"[+] Upload success. Hash: {scan_hash}")

        # Step 2: Trigger scan on uploaded hash
        scan_data = {
            "hash": scan_hash,
            "scan_type": "apk",
            "re_scan": "false"
        }

        scan_response = requests.post(
            MOBSF_API_URL + "scan",
            data=scan_data,
            headers=headers
        )
        scan_response.raise_for_status()
        print("[+] Scan triggered successfully")

        return upload_data  # same format: includes hash, etc.


def get_static_analysis_url(scan_hash):
    base_url = os.getenv("MOBSF_API_URL").replace("/api/v1/", "").rstrip('/')
    return f"{base_url}/staticAnalyzer/?md5={scan_hash}"