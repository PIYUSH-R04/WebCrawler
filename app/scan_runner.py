import threading
import time
import os
from .scan_manager import scan_manager
from .scanner import headers, outdated, forms, cve
from .report_generator import generate_formatted_report, build_report

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

def run_scan(scan_id):
    scan = scan_manager.get_scan(scan_id)
    if not scan:
        return

    config = scan["config"]
    modules = config["modules"]
    url = config["url"]
    max_pages = config["max_pages"]
    timeout = config["timeout"]
    respect_robots = config["respect_robots"]

    start_time = time.time()

    def log(msg):
        scan_manager.append_log(scan_id, msg)

    def check_abort():
        return scan_manager.get_scan(scan_id).get("aborted", False)

    scan["results"] = {}

    for module in modules:
        if check_abort():
            log(f"[!] Scan aborted before module '{module}'")
            scan_manager.update_status(scan_id, module, "aborted")
            break

        log(f"[*] Running module: {module}")
        scan_manager.update_status(scan_id, module, "running")

        try:
            if module == "headers":
                scan["results"]["headers"] = headers.check(url, log)
            elif module == "outdated":
                version_file = config.get("version_file")
                scan["results"]["outdated"] = outdated.check(url, log, version_file)
            elif module == "forms":
                scan["results"]["forms"] = forms.check(url, log, respect_robots, max_pages)
            elif module == "cve":
                scan["results"]["cve"] = cve.check(url, log)

            scan_manager.update_status(scan_id, module, "done")
        except Exception as e:
            log(f"[x] Error in module '{module}': {e}")
            scan_manager.update_status(scan_id, module, "failed")

        if time.time() - start_time > timeout:
            log("[!] Scan timed out.")
            break

    log("[✓] Scan completed.")

    report_data = {
        "target": url,
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "max_pages": max_pages,
        "timeout": timeout,
        "respect_robots": respect_robots,
        "modules": modules,
        "pages": [],
        "subdomains": set(),
        "crawled_urls": scan["results"].get("forms", {}).get("crawled_urls", [])
    }

    page_results = {}

    if "headers" in scan["results"]:
        page_results["headers"] = scan["results"]["headers"]
    if "outdated" in scan["results"]:
        page_results["outdated"] = scan["results"]["outdated"]
    if "forms" in scan["results"]:
        page_results["forms"] = scan["results"]["forms"]
    if "cve" in scan["results"]:
        page_results["cve"] = scan["results"]["cve"]

    report_data["pages"].append({
        "url": url,
        "results": page_results
    })

    report_lines = generate_formatted_report(report_data)
    scan["log"].extend(report_lines)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    report_path = os.path.join(REPORTS_DIR, f"{scan_id}.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    build_report(scan_id, scan)
