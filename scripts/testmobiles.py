import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from startup.mobsf_api import upload_apk_to_mobsf, scan_apk, get_report_pdf, get_report_json, extract_apk_icon, delete_scan, list_scans

def get_previous_scans():
    try:
        return list_scans()
    except Exception as e:
        print(f"Error getting previous scans: {e}")
        return []

def handle_apk_upload(apk_file):
    findings, report_path, app_info, error_msg = [], None, None, None

    if apk_file.filename.endswith('.apk'):
        os.makedirs("uploads", exist_ok=True)
        filepath = os.path.join("uploads", apk_file.filename)
        apk_file.save(filepath)

        apk_hash = upload_apk_to_mobsf(filepath)
        if apk_hash:
            scan_results = scan_apk(apk_hash)
            app_info = extract_app_info(scan_results, apk_hash)
            findings = extract_findings(scan_results)

            report_path = f"reports/{apk_hash}.pdf"
            os.makedirs("reports", exist_ok=True)
            get_report_pdf(apk_hash, report_path)
        else:
            error_msg = "Failed to upload APK to MobSF"
    else:
        error_msg = "Not an APK file"

    return findings, report_path, app_info, error_msg

def view_scan(hash_to_view):
    findings, report_path, app_info, error_msg = [], None, None, None
    scan_results = get_report_json(hash_to_view)

    if scan_results:
        app_info = extract_app_info(scan_results, hash_to_view)
        findings = extract_findings(scan_results)

        report_path = f"reports/{hash_to_view}.pdf"
        if not os.path.exists(report_path):
            os.makedirs("reports", exist_ok=True)
            get_report_pdf(hash_to_view, report_path)
    else:
        error_msg = "Failed to fetch scan results"

    return findings, report_path, app_info, error_msg

def delete_scan_files(hash_to_delete):
    error_msg = None
    result = delete_scan(hash_to_delete)

    if result and result.get('deleted') == hash_to_delete:
        try:
            icon_path = f"static/icons/{hash_to_delete}.png"
            report_path = f"reports/{hash_to_delete}.pdf"
            if os.path.exists(icon_path):
                os.remove(icon_path)
            if os.path.exists(report_path):
                os.remove(report_path)
        except:
            pass
        return True, None
    else:
        error_msg = "Failed to delete scan"
        return False, error_msg

def extract_app_info(scan_results, apk_hash):
    return {
        'name': scan_results.get('app_name', 'Unknown'),
        'package': scan_results.get('package_name', 'Unknown'),
        'version': scan_results.get('version_name', 'Unknown'),
        'sdk': scan_results.get('target_sdk', 'Unknown'),
        'hash': apk_hash,
        'icon': save_app_icon(apk_hash)
    }

def extract_findings(scan_results):
    findings = []
    if 'findings' in scan_results:
        findings = scan_results['findings']
    else:
        for section in ['permissions', 'code_analysis', 'network_security', 'binary_analysis']:
            if section in scan_results:
                for key, item in scan_results[section].items():
                    if isinstance(item, dict) and 'status' in item and item['status'] == 'failed':
                        findings.append({
                            'category': section.replace('_', ' ').title(),
                            'severity': item.get('severity', 'info').lower(),
                            'description': item.get('description', key)
                        })
    return findings

def save_app_icon(apk_hash):
    try:
        icon_path = f"static/icons/{apk_hash}.png"
        os.makedirs("static/icons", exist_ok=True)
        extract_apk_icon(apk_hash, icon_path)
        return f"/static/icons/{apk_hash}.png"
    except:
        return None
