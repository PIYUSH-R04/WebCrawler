import requests
from ..scan_manager import scan_manager

from urllib.parse import urlparse

VENDOR_PRODUCT_MAP = {
    "nginx": ("nginx", "nginx"),
    "php": ("php", "php"),
    "apache": ("apache", "http_server"),
    "asp": ("microsoft", "asp.net"),
    "asp.net": ("microsoft", "asp.net")
}

API_BASE = "https://cve.circl.lu/api/vulnerability/search"

def deep_search(obj, keyword):
    if isinstance(obj, dict):
        return any(deep_search(v, keyword) for v in obj.values())
    elif isinstance(obj, list):
        return any(deep_search(i, keyword) for i in obj)
    elif isinstance(obj, str):
        return keyword.lower() in obj.lower()
    return False

def check(url, log):
    result = {}

    try:
        scan_id = next((k for k, v in scan_manager.scans.items() if v["config"]["url"] == url), None)
        if not scan_id:
            log("[x] CVE: No matching scan found.")
            return {}

        scan = scan_manager.get_scan(scan_id)
        outdated = scan.get("results", {}).get("outdated", {}).get("outdated", {})

        if not outdated:
            log("[i] No outdated tech found to perform CVE lookup.")
            return {}

        for tech, info in outdated.items():
            vendor, product = VENDOR_PRODUCT_MAP.get(tech, (tech, tech))
            ver = info.get("version")
            log(f"[*] Querying CVEs for {vendor}/{product} @ {ver}")

            try:
                res = requests.get(f"{API_BASE}/{vendor}/{product}", timeout=20)
                if res.status_code != 200:
                    log(f"[x] CIRCL API failed for {tech} ({res.status_code})")
                    continue

                all_cves = res.json()
                relevant = []

                for cve in all_cves:
                    if deep_search(cve, ver):
                        relevant.append({
                            "id": cve.get("id"),
                            "summary": cve.get("summary", "")[:200],
                            "cvss": cve.get("cvss", "N/A"),
                            "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.get('id')}"
                        })
                    if len(relevant) >= 10:
                        break

                if relevant:
                    result[tech] = relevant
                    log(f"[✓] Found {len(relevant)} CVEs for {tech} {ver}")
                else:
                    log(f"[i] No CVEs match version {ver} for {tech}")

            except requests.exceptions.RequestException as e:
                log(f"[x] CVE API request failed for {tech}: {e}")

    except Exception as outer:
        log(f"[x] CVE scanner fatal error: {outer}")

    return result
