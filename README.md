# 🕷️ WebCrawler - Web Vulnerability Scanner

WebCrawler is a web vulnerability scanner designed for security assessments. It performs deep, multi-layered scans including HTTP header checks, outdated software detection, insecure form analysis, and CVE lookups.

---

# 🌐 Live Deployment

The application is deployed via Render and accessible through:

🔗 URL: https://webcrawler-9k2d.onrender.com/

---

## 🔧 Features

* 🌐 URL crawler with configurable page limits
* 🔒 Detection of missing/exploitable HTTP security headers
* 🧱 Outdated software version checker (via static + optional custom version file)
* 📋 Insecure form analyzer (missing `action`, `GET`, auto-submit)
* 📚 CVE lookup via CIRCL API (only if outdated software found)
* 📝 Downloadable scan reports in Markdown and HTML

---

## 🖥️ Tech Stack

* **Backend:** Python (Flask)
* **Frontend:** HTML/CSS + vanilla JS
* **Reporting:** Markdown2, Jinja2,
* **CVE API:** [https://cve.circl.lu](https://cve.circl.lu)
* **Data Storage:** Local filesystem

---

## 🚀 Getting Started

### 1. Clone the Repo

```bash
git clone https://github.com/PIYUSH-R04/WebCrawler.git
cd webcrawler
```

### 2. Setup Python Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Run Locally

```bash
python run.py
```

Open `http://localhost:5000` in your browser.

---


## 📜 Module Details

### 🔒 Headers Module

* Checks for:

  * Strict-Transport-Security
  * X-Content-Type-Options
  * X-Frame-Options
  * Content-Security-Policy
  * Referrer-Policy
* Flags clickjacking and other exploits

### 🧱 Outdated Software

* Checks:

  * Apache, Nginx, PHP, ASP.NET, WordPress, Joomla
* Supports:

  * Static latest versions
  * Optional `uploaded_versions.txt` with formats like `php:1.1.1,1.1.2`

### 📋 Form Scanner

* Detects:

  * Missing action attribute
  * GET method usage
  * JavaScript auto-submit

### 📚 CVE Lookup

* If outdated version is detected, fetches top 5 relevant CVEs using CIRCL API

---

## 📅 Report Formats

* Markdown (`.md`)
* HTML (`.html`)

Each report includes:

* Config metadata
* Crawled URLs
* Per-page findings (headers, forms, outdated, CVEs)
* Notes and live logs

---

## 📄 License

MIT License. See `LICENSE` for more info.
