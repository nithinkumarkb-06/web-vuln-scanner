# 🛡️ WebVulnScanner

<div align="center">

```
██╗    ██╗███████╗██████╗     ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
██║    ██║██╔════╝██╔══██╗    ██║   ██║██║   ██║██║     ████╗  ██║
██║ █╗ ██║█████╗  ██████╔╝    ██║   ██║██║   ██║██║     ██╔██╗ ██║
██║███╗██║██╔══╝  ██╔══██╗    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
╚███╔███╔╝███████╗██████╔╝     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
 ╚══╝╚══╝ ╚══════╝╚═════╝       ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝
```

**A modular Python web vulnerability scanner built for education, CTFs & bug bounty hunting.**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Modules](https://img.shields.io/badge/Modules-5-blue?style=for-the-badge)

</div>

---

## 📸 Demo

```
[*] Starting crawler on http://target.com

[CRAWLING] http://target.com
[CRAWLING] http://target.com/Login.asp
[CRAWLING] http://target.com/Register.asp
...

[+] Pages visited : 20
[+] Forms found   : 13
[+] Links found   : 44

[VULNERABLE] Blind SQLi detected!
  → URL   : http://target.com/Login.asp
  → Diff  : true=5081B | false=3162B

[HIGH] Missing CSRF Token
  → URL      : http://target.com/Login.asp
  → Evidence : POST form has no CSRF token field

=======================================================
  SCAN COMPLETE — 34 issue(s) found
=======================================================
  SQLi vulnerabilities  : 6
  XSS  vulnerabilities  : 9
  Missing headers       : 7
  Open redirects        : 0
  CSRF vulnerabilities  : 12
=======================================================


```

---

## ⚡ Features

| Module | Description | Detects |
|--------|-------------|---------|
| 🕷️ **Crawler** | Auto-discovers pages, forms & links | Up to N pages deep |
| 💉 **SQLi Scanner** | Error-based + Boolean blind injection | MySQL, MSSQL, Oracle, MS Access |
| ⚡ **XSS Scanner** | Reflected XSS in forms & URL params | 15+ payloads + filter bypass variants |
| 🔒 **Headers Checker** | Audits HTTP security response headers | 7 critical headers |
| ↗️ **Open Redirect** | Tests redirect parameters for hijacking | 5 bypass payloads |
| 🔄 **CSRF Scanner** | Detects missing/weak CSRF tokens | HIGH & MEDIUM severity |

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/nithinkumarkb-06/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
```

### Basic Usage

```bash
# Full scan with HTML report
python scanner.py http://target.com --report

# Scan specific modules only
python scanner.py http://target.com -m xss csrf --report

# Crawl more pages (default: 20)
python scanner.py http://target.com -p 50 --report
```

### Module Selection

```bash
# Available modules: sqli | xss | headers | redirect | csrf

# SQLi + XSS only
python scanner.py http://target.com -m sqli xss

# Headers audit only (fast)
python scanner.py http://target.com -m headers

# Everything
python scanner.py http://target.com -m sqli xss headers redirect csrf --report
```


---

## 📊 HTML Report

The `--report` flag generates a **dark-themed HTML report** including:

- 📈 Summary dashboard with vulnerability counts
- 💉 SQL Injection findings with payloads & evidence
- ⚡ XSS findings with working payloads
- 🔒 Missing security headers with risk descriptions
- 🔄 CSRF findings with severity ratings and remediation steps
- ↗️ Open redirect findings

---

## 🧪 Legal Test Targets

**Only scan targets you have explicit permission to test.**

Safe practice targets for testing this tool:

| Target | Type | URL |
|--------|------|-----|
| Acunetix ASP Demo | Live intentionally vulnerable | `http://testasp.vulnweb.com` |
| Acunetix PHP Demo | Live intentionally vulnerable | `http://testphp.vulnweb.com` |
| DVWA | Local (install via XAMPP) | `http://localhost/dvwa` |
| HackTheBox | Lab machines | `https://hackthebox.com` |
| TryHackMe | Guided labs | `https://tryhackme.com` |

---

## 🔬 Real Results

Tested on `testasp.vulnweb.com` (legal Acunetix demo target):

```
SQLi vulnerabilities  : 6   🔴 Critical
XSS  vulnerabilities  : 9   🔴 Critical  
Missing headers       : 7   🟡 Medium
Open redirects        : 0   ✅ Clean
CSRF vulnerabilities  : 12  🔴 HIGH
──────────────────────────────
Total issues found    : 34
```

---

## 🛠️ Requirements

```
requests
beautifulsoup4
colorama
```

```bash
pip install -r requirements.txt
```

Python 3.8+ required.

---


## ⚠️ Disclaimer

This tool is for **educational purposes and authorized security testing only.**

- ✅ Use on targets you **own** or have **written permission** to test
- ✅ Use on intentionally vulnerable apps (DVWA, VulnHub, HackTheBox)
- ❌ Never use on live production sites without authorization
- ❌ Unauthorized scanning is illegal in most jurisdictions

The author is not responsible for any misuse of this tool.

---


<div align="center">

**⭐ Star this repo if it helped you learn!**

</div>
