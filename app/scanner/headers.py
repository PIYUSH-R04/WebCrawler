import requests
from urllib.parse import urlparse

REQUIRED_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
    "Pragma"
]

EXPLOITABLE_HEADERS = {
    "X-Frame-Options": {
        "type": "Clickjacking",
        "description": "Can be embedded via iframe (Clickjacking).",
        "poc": "<iframe src='{url}' width='600' height='400'></iframe>"
    },
    "Content-Security-Policy": {
        "type": "XSS/Script Injection",
        "description": "Lack of CSP allows arbitrary script execution.",
        "poc": "<script>alert('XSS')</script>"
    },
    "Strict-Transport-Security": {
        "type": "Downgrade Attack",
        "description": "HSTS missing; SSLStrip attacks possible.",
        "poc": "Force downgrade via MITM with SSLStrip"
    }
}

def check(url, log):
    result = {
        "missing": [],
        "present": [],
        "exploitable": [],
        "exploits": [],
        "details": {}
    }

    try:
        res = requests.get(url, timeout=15, allow_redirects=True)
        headers = res.headers
        parsed_url = urlparse(url)

        for h in REQUIRED_HEADERS:
            val = headers.get(h)
            if val:
                result["present"].append(h)
                result["details"][h] = val
            else:
                result["missing"].append(h)
                log(f"[-] Missing Header: {h}")
                if h in EXPLOITABLE_HEADERS:
                    exploit_info = EXPLOITABLE_HEADERS[h]
                    result["exploitable"].append(h)
                    result["exploits"].append({
                        "type": exploit_info["type"],
                        "description": exploit_info["description"],
                        "poc_html": exploit_info["poc"].format(url=url)
                    })

        if "Server" in headers:
            server_info = headers["Server"]
            if any(x in server_info.lower() for x in ["apache", "nginx", "iis"]):
                log(f"[!] Server header leaks technology: {server_info}")
                result["details"]["Server"] = server_info

        if result["missing"]:
            log(f"[!] Headers missing: {', '.join(result['missing'])}")
        else:
            log("[+] All important headers are present.")

    except requests.exceptions.Timeout:
        log("[x] Header check timed out.")
    except requests.exceptions.RequestException as e:
        log(f"[x] Header scan error: {e}")

    return result
