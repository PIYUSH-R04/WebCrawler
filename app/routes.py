import os
import threading
from flask import Blueprint, current_app, render_template, request, redirect, send_file, url_for, jsonify

from .scan_manager import scan_manager
from app.scan_runner import run_scan

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/scan')
def scan():
    return render_template('scan.html')

@main.route('/scan/start', methods=['POST'])
def start_scan():
    url = request.form.get("url")
    max_pages = int(request.form.get("max_pages", 15))
    timeout = int(request.form.get("timeout", 60))
    respect_robots = "respect_robots" in request.form
    modules = request.form.getlist("modules")

    uploaded_file = request.files.get("version_file")
    version_file_path = None
    if uploaded_file and uploaded_file.filename.endswith(".txt"):
        version_file_path = os.path.join("temp", uploaded_file.filename)
        os.makedirs("temp", exist_ok=True)
        uploaded_file.save(version_file_path)

    config = {
        "url": url,
        "max_pages": max_pages,
        "timeout": timeout,
        "respect_robots": respect_robots,
        "modules": modules,
        "version_file": version_file_path
    }

    scan_id = scan_manager.create_scan(config)
    threading.Thread(target=run_scan, args=(scan_id,), daemon=True).start()
    return redirect(url_for('main.scan') + f"?scan_id={scan_id}")


@main.route('/scan/status/<scan_id>')
def scan_status(scan_id):
    scan = scan_manager.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Invalid scan ID"}), 404

    return jsonify({
        "status": scan["status"],
        "log": scan["log"],
        "aborted": scan["aborted"]
    })

@main.route('/scan/abort/<scan_id>', methods=['POST'])
def scan_abort(scan_id):
    scan_manager.abort(scan_id)
    return jsonify({"status": "aborted"})

@main.route("/report/<scan_id>")
def download_report(scan_id):
    fmt = request.args.get("format", "md")
    ext = fmt if fmt in ["md", "html"] else "md"

    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")
    report_path = os.path.join(REPORTS_DIR, f"{scan_id}.{ext}")

    if os.path.exists(report_path):
        mime_map = {
            "md": "text/markdown",
            "html": "text/html",
        }
        return send_file(report_path, mimetype=mime_map.get(ext), as_attachment=True)
    return "Report not found", 404
