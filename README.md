# 🛡️ Web Vulnerability Scanner

A Python-based web vulnerability scanner built for educational purposes and CTF practice.

## Features
- 🕷️ **Web Crawler** — auto-discovers pages and forms
- 💉 **SQL Injection** — error-based and blind detection
- ⚡ **XSS Scanner** — reflected XSS in forms and URL params
- 🔒 **Security Headers** — checks for 7 missing headers
- ↗️ **Open Redirect** — tests redirect parameters

## Installation
```bash
git clone https://github.com/YOUR_USERNAME/web-vuln-scanner
cd web-vuln-scanner
pip install -r requirements.txt
```

## Usage
```bash
# Full scan with HTML report
python scanner.py http://target.com --report

# Specific modules only
python scanner.py http://target.com -m xss headers

# Crawl more pages
python scanner.py http://target.com -p 50 --report
```

## ⚠️ Disclaimer
This tool is for **educational purposes only**.
Only test on targets you have **explicit permission** to scan.
Legal targets: testasp.vulnweb.com, testphp.vulnweb.com, DVWA (local)

## Results Example
| Module | Issues Found |
|--------|-------------|
| SQL Injection | 3 |
| XSS | 13 |
| Missing Headers | 7 |
| Open Redirects | 0 |
