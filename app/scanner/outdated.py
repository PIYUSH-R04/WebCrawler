import os
import requests
import re
from packaging import version

STATIC_LATEST = {
    "nginx": "1.25.3",
    "php": "8.3.9",
    "apache": "2.4.59"
}

PATTERNS = {
    "nginx": r"nginx/([\d\.]+)",
    "php": r"php/([\d\.]+)",
    "apache": r"apache/([\d\.]+)",
    "asp": r"asp\.net",
    "wordpress": r"wordpress",
    "joomla": r"joomla"
}

def parse_uploaded_versions(file_path, log):
    found = {}
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if ":" not in line:
                continue
            name, versions = line.strip().split(":", 1)
            name = name.lower()
            if name not in STATIC_LATEST:
                continue
            latest = STATIC_LATEST[name]
            for v in versions.split(","):
                v = v.strip()
                if not v:
                    continue
                if version.parse(v) < version.parse(latest):
                    found[name] = {
                        "version": v,
                        "latest": latest,
                        "status": "outdated",
                        "note": f"{name.capitalize()} {v} is older than {latest}"
                    }
                    log(f"[!] {name.capitalize()} {v} from uploaded file is outdated (latest: {latest})")
                else:
                    log(f"[+] {name.capitalize()} {v} from uploaded file is up to date.")
    return found

def check(url, log, file_path=None):
    result = {
        "detected": {},
        "outdated": {}
    }

    try:
        res = requests.get(url, timeout=10)
        combined = (res.headers.get("Server", "") + " " +
                    res.headers.get("X-Powered-By", "")).lower()

        for name, regex in PATTERNS.items():
            match = re.search(regex, combined)
            if match:
                current_ver = match.group(1)
                latest_ver = STATIC_LATEST[name]
                result["detected"][name] = current_ver
                if version.parse(current_ver) < version.parse(latest_ver):
                    result["outdated"][name] = {
                        "version": current_ver,
                        "latest": latest_ver,
                        "status": "outdated",
                        "note": f"{name.capitalize()} {current_ver} is older than latest {latest_ver}"
                    }
                    log(f"[!] {name.capitalize()} {current_ver} is outdated (latest: {latest_ver})")
                else:
                    log(f"[+] {name.capitalize()} {current_ver} is up to date.")
    except Exception as e:
        log(f"[x] Outdated scan error: {e}")

    if file_path and os.path.exists(file_path):
        file_outdated = parse_uploaded_versions(file_path, log)
        result["outdated"].update(file_outdated)

    return result
