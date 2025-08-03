import os
import markdown2
from datetime import datetime
from jinja2 import Template

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(REPORT_DIR, exist_ok=True)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Vulnerability Report</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f8f9fa; padding: 30px; color: #1e1e1e; }
    h1, h2, h3 { color: #0f172a; }
    code, pre { background-color: #e2e8f0; padding: 5px 10px; border-radius: 4px; }
    .section { margin-bottom: 40px; }
    .tag { font-weight: bold; color: #b91c1c; }
    .success { color: #15803d; }
    .warning { color: #ca8a04; }
    .info { color: #0e7490; }
  </style>
</head>
<body>
{{ body }}
</body>
</html>
"""

def md_escape(s):
    return s.replace("_", "\\_").replace("*", "\\*")

def generate_markdown(scan_id, scan):
    url = scan["config"]["url"]
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    modules = scan["config"]["modules"]
    results = scan.get("results", {})

    md = f"# Vulnerability Scan Report\n\n"
    md += f"**Target:** {url}\n\n"
    md += f"**Scan ID:** `{scan_id}`  \n"
    md += f"**Timestamp:** {timestamp}  \n"
    md += f"**Modules:** {', '.join(modules)}\n\n"
    md += "---\n"

    crawled = scan.get("results", {}).get("forms", {}).get("crawled_urls", [])
    if crawled:
        md += "## 🌐 Crawled URLs\n"
        for u in crawled:
            md += f"- {u}\n"
        md += "\n---\n"

    if "headers" in results:
        h = results["headers"]
        md += "## 🔒 HTTP Security Headers\n"
        if h["missing"]:
            md += f"**❌ Missing Headers:** {', '.join(h['missing'])}\n\n"
        else:
            md += "**✅ All important headers are present.**\n\n"
        if h["exploitable"]:
            md += f"**💥 Exploitable Headers:** {', '.join(h['exploitable'])}\n\n"
            for exp in h["exploits"]:
                md += f"- **{exp['type']}**: {exp['description']}\n"
                md += f"  - PoC: `{exp['poc_html']}`\n"
        md += "\n---\n"

    if "outdated" in results and results["outdated"].get("outdated"):
        md += "## 🧱 Outdated Software\n"

        for name, info in results["outdated"]["outdated"].items():
            current_ver = info["version"]
            latest_ver = info["latest"]
            note = info["note"]
            md += f"- **{name.capitalize()}**: ❌ `{current_ver}` (Latest: `{latest_ver}`)  \n"
            md += f"  - {note}\n"

        detected = results["outdated"].get("detected", {})
        for name, current_ver in detected.items():
            if name not in results["outdated"]["outdated"]:
                md += f"- **{name.capitalize()}**: ✅ `{current_ver}` (Up to date)\n"
        
        md += "\n---\n"

    if "forms" in results:
        md += "## 📋 Form Vulnerabilities\n"
        md += f"- Pages Scanned: {results['forms']['scanned_pages']}\n"
        if not results["forms"]["issues"]:
            md += "- ✅ No insecure forms detected.\n"
        else:
            for i, form in enumerate(results["forms"]["issues"], 1):
                md += f"**Form #{i}** — `{form['url']}`\n"
                if form["missing_action"]: md += "- ❌ Missing `action`\n"
                if form["uses_get"]: md += "- ❌ Uses `GET` method\n"
                if form["auto_submit"]: md += "- ❌ Contains JavaScript auto-submit\n"
                md += "\n"
        md += "\n---\n"

    if "cve" in results:
        md += "## 📚 CVE Lookup\n"
        for tech, cves in results["cve"].items():
            md += f"### {tech.capitalize()}\n"
            for cve in cves:
                md += f"- **{cve['id']}** ({cve['cvss']})\n"
                md += f"  - {md_escape(cve['summary'])}\n"
                md += f"  - [View on MITRE]({cve['url']})\n"
            md += "\n"
        md += "\n---\n"

    md += "*Built by Piyush R.*\n"
    return md

def build_report(scan_id, scan):
    md_path = os.path.join(REPORT_DIR, f"{scan_id}.md")
    html_path = os.path.join(REPORT_DIR, f"{scan_id}.html")
    pdf_path = os.path.join(REPORT_DIR, f"{scan_id}.pdf")

    md_content = generate_markdown(scan_id, scan)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    html_body = markdown2.markdown(md_content)
    html_full = Template(HTML_TEMPLATE).render(body=html_body)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_full)

def generate_formatted_report(scan_data):
    lines = []
    lines.append(f"📄 Target: {scan_data['target']}")
    lines.append(f"🕒 Date: {scan_data['date']}")
    lines.append(f"🔧 Modules: {', '.join(scan_data['modules'])}")
    lines.append(f"🔁 Max Pages: {scan_data['max_pages']}")
    lines.append(f"⏱ Timeout: {scan_data['timeout']}s")
    lines.append(f"🤖 Respect robots.txt: {'Yes' if scan_data['respect_robots'] else 'No'}")
    lines.append("============================================")

    for page in scan_data["pages"]:
        lines.append(f"\n🌐 Page: {page['url']}")
        results = page.get("results", {})

        if "headers" in results:
            headers = results["headers"]
            lines.append("🔒 HTTP Security Headers:")
            if headers["missing"]:
                for h in headers["missing"]:
                    lines.append(f"  ❌ Missing: {h}")
            else:
                lines.append("  ✅ All important headers present.")
            if headers["exploitable"]:
                lines.append("  💥 Exploitable headers:")
                for x in headers["exploits"]:
                    lines.append(f"    - {x['type']}: {x['description']}")
                    lines.append(f"      PoC: {x['poc_html']}")

        if "outdated" in results:
            outdated = results["outdated"]
            lines.append("🧱 Outdated Software:")
            for tech, version in outdated.get("detected", {}).items():
                if tech in outdated.get("outdated", {}):
                    info = outdated["outdated"][tech]
                    lines.append(f"  ❌ {tech}: {version} (Latest: {info['latest']}) — {info['note']}")
                else:
                    lines.append(f"  ✅ {tech}: {version} (Up-to-date)")

        if "forms" in results:
            forms = results["forms"]
            lines.append(f"📋 Form Scan: {forms['scanned_pages']} pages")
            if not forms["issues"]:
                lines.append("  ✅ No form issues detected.")
            else:
                for i, issue in enumerate(forms["issues"], 1):
                    lines.append(f"  ❌ Form #{i} on {issue['url']}")
                    if issue["missing_action"]: lines.append("    - Missing action attribute")
                    if issue["uses_get"]: lines.append("    - Uses GET method")
                    if issue["auto_submit"]: lines.append("    - JavaScript auto-submit found")

        if "cve" in results:
            lines.append("📚 CVE Lookup:")
            for tech, cves in results["cve"].items():
                lines.append(f"  🔧 {tech}:")
                for cve in cves:
                    lines.append(f"    - {cve['id']} (CVSS: {cve['cvss']})")
                    lines.append(f"      {cve['summary']}")
                    lines.append(f"      URL: {cve['url']}")

    lines.append("\n✅ Scan complete.")
    return lines

