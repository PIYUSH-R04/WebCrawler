import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def check(url, log, respect_robots, max_pages):
    result = {
        "scanned_pages": 0,
        "issues": [],
        "crawled_urls": []
    }

    visited = set()
    to_visit = [url]
    base_domain = urlparse(url).netloc

    while to_visit and len(visited) < max_pages:
        current = to_visit.pop(0)
        if current in visited or urlparse(current).netloc != base_domain:
            continue

        try:
            res = requests.get(current, timeout=10)
            visited.add(current)
            result["scanned_pages"] += 1
            result["crawled_urls"].append(current)
            log(f"[+] Visited: {current}")

            soup = BeautifulSoup(res.text, "html.parser")

            forms = soup.find_all("form")
            for form in forms:
                method = form.get("method", "").upper()
                action = form.get("action", "").strip()
                auto_submit = "onsubmit" in str(form).lower()

                issue = {
                    "url": current,
                    "missing_action": not action,
                    "uses_get": method == "GET",
                    "auto_submit": auto_submit
                }

                if issue["missing_action"] or issue["uses_get"] or issue["auto_submit"]:
                    result["issues"].append(issue)
                    log(f"[!] Form issue at {current} — "
                        f"{'missing action' if issue['missing_action'] else ''} "
                        f"{'uses GET' if issue['uses_get'] else ''} "
                        f"{'auto-submit' if issue['auto_submit'] else ''}")

            links = [urljoin(current, a.get("href")) for a in soup.find_all("a", href=True)]
            for link in links:
                if urlparse(link).netloc == base_domain and link not in visited:
                    to_visit.append(link)

        except Exception as e:
            log(f"[x] Error scanning {current}: {e}")

    log(f"[i] Scanned {result['scanned_pages']} pages.")
    log(f"[i] Detected {len(result['issues'])} vulnerable forms.")
    return result
