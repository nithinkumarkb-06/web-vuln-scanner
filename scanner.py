import argparse
import os
from datetime import datetime
from colorama import Fore, Style, init

from modules.crawler import Crawler
from modules.sqli import SQLiScanner
from modules.xss import XSSScanner
from modules.headers import HeadersScanner
from modules.open_redirect import OpenRedirectScanner
from modules.csrf import CSRFScanner

init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN}
██╗    ██╗███████╗██████╗     ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
██║    ██║██╔════╝██╔══██╗    ██║   ██║██║   ██║██║     ████╗  ██║
██║ █╗ ██║█████╗  ██████╔╝    ██║   ██║██║   ██║██║     ██╔██╗ ██║
██║███╗██║██╔══╝  ██╔══██╗    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
╚███╔███╔╝███████╗██████╔╝     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
 ╚══╝╚══╝ ╚══════╝╚═════╝       ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.YELLOW}        Web Vulnerability Scanner — Built for Education & CTFs
        Use ONLY on targets you have permission to test!
{Style.RESET_ALL}
"""
    print(banner)


def run_scan(target, max_pages, modules):
    all_vulns = {
        "sqli"     : [],
        "xss"      : [],
        "headers"  : [],
        "redirect" : [],
        "csrf"     : [],
    }

    # Step 1 — Crawl
    print(f"{Fore.CYAN}[*] Starting crawler on {target}{Style.RESET_ALL}\n")
    crawler = Crawler(target, max_pages=max_pages)
    crawler.crawl()
    results = crawler.get_results()

    print(f"\n{Fore.GREEN}[+] Pages visited : {len(results['visited'])}")
    print(f"[+] Forms found   : {len(results['forms'])}")
    print(f"[+] Links found   : {len(results['links'])}{Style.RESET_ALL}\n")

    # Step 2 — Run selected modules
    if "sqli" in modules:
        all_vulns["sqli"] = SQLiScanner().scan(results["forms"])

    if "xss" in modules:
        all_vulns["xss"] = XSSScanner().scan(results["forms"], results["links"])

    if "headers" in modules:
        all_vulns["headers"] = HeadersScanner().scan(target)

    if "redirect" in modules:
        all_vulns["redirect"] = OpenRedirectScanner().scan(results["links"], target)

    if "csrf" in modules:
        all_vulns["csrf"] = CSRFScanner().scan(results["forms"])

    return all_vulns, results


def print_summary(all_vulns):
    total = sum(len(v) for v in all_vulns.values())
    print(f"\n{Fore.BLUE}{'='*55}")
    print(f"  SCAN COMPLETE — {total} issue(s) found")
    print(f"{'='*55}{Style.RESET_ALL}")
    print(f"  {Fore.RED}SQLi vulnerabilities  : {len(all_vulns['sqli'])}{Style.RESET_ALL}")
    print(f"  {Fore.RED}XSS  vulnerabilities  : {len(all_vulns['xss'])}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Missing headers       : {len(all_vulns['headers'])}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Open redirects        : {len(all_vulns['redirect'])}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}CSRF vulnerabilities  : {len(all_vulns['csrf'])}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}{'='*55}{Style.RESET_ALL}\n")


def generate_report(target, all_vulns, results):
    """Generate a clean HTML report in the reports/ folder."""
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"reports/report_{timestamp}.html"
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total     = sum(len(v) for v in all_vulns.values())

    def vuln_rows(vulns, keys):
        if not vulns:
            return "<tr><td colspan='10' style='text-align:center;color:#888'>None found</td></tr>"
        rows = ""
        for v in vulns:
            cells = "".join(f"<td>{v.get(k, '-')}</td>" for k in keys)
            rows += f"<tr>{cells}</tr>"
        return rows

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Scan Report — {target}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; padding: 30px; }}
    h1 {{ color: #00d4ff; font-size: 2em; margin-bottom: 5px; }}
    h2 {{ color: #00d4ff; margin: 30px 0 10px; font-size: 1.2em; border-left: 4px solid #00d4ff; padding-left: 10px; }}
    .meta {{ color: #888; margin-bottom: 30px; font-size: 0.9em; }}
    .summary {{ display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 30px; }}
    .card {{ background: #1a1d2e; border-radius: 10px; padding: 20px 30px; text-align: center; flex: 1; min-width: 140px; }}
    .card .num {{ font-size: 2.5em; font-weight: bold; }}
    .card .label {{ color: #888; font-size: 0.85em; margin-top: 5px; }}
    table {{ width: 100%; border-collapse: collapse; background: #1a1d2e; border-radius: 10px; overflow: hidden; margin-bottom: 20px; }}
    th {{ background: #00d4ff22; color: #00d4ff; padding: 12px 15px; text-align: left; font-size: 0.85em; text-transform: uppercase; }}
    td {{ padding: 10px 15px; border-top: 1px solid #2a2d3e; font-size: 0.88em; word-break: break-all; }}
    tr:hover {{ background: #2a2d3e; }}
    .footer {{ text-align: center; color: #555; margin-top: 40px; font-size: 0.8em; }}
    .disclaimer {{ background: #ff4d4d11; border: 1px solid #ff4d4d44; border-radius: 8px; padding: 12px 18px; margin-bottom: 25px; color: #ff8888; font-size: 0.85em; }}
  </style>
</head>
<body>
  <h1>🛡️ Web Vulnerability Scanner</h1>
  <div class="meta">
    Target: <strong>{target}</strong> &nbsp;|&nbsp;
    Scanned: {scan_time} &nbsp;|&nbsp;
    Pages: {len(results['visited'])} &nbsp;|&nbsp;
    Forms: {len(results['forms'])}
  </div>

  <div class="disclaimer">
    ⚠️ This report is for <strong>educational purposes only</strong>.
    Only test targets you have explicit permission to scan.
  </div>

  <div class="summary">
    <div class="card"><div class="num" style="color:#ff4d4d">{len(all_vulns['sqli'])}</div><div class="label">SQL Injection</div></div>
    <div class="card"><div class="num" style="color:#ff4d4d">{len(all_vulns['xss'])}</div><div class="label">XSS</div></div>
    <div class="card"><div class="num" style="color:#ffd700">{len(all_vulns['headers'])}</div><div class="label">Missing Headers</div></div>
    <div class="card"><div class="num" style="color:#ffd700">{len(all_vulns['redirect'])}</div><div class="label">Open Redirects</div></div>
    <div class="card"><div class="num" style="color:#ff9900">{len(all_vulns['csrf'])}</div><div class="label">CSRF</div></div>
    <div class="card"><div class="num" style="color:#00d4ff">{total}</div><div class="label">Total Issues</div></div>
  </div>

  <h2>💉 SQL Injection</h2>
  <table>
    <tr><th>Type</th><th>URL</th><th>Method</th><th>Payload / Info</th></tr>
    {vuln_rows(all_vulns['sqli'], ['type','url','method','matched_error'])}
  </table>

  <h2>⚡ Cross-Site Scripting (XSS)</h2>
  <table>
    <tr><th>Type</th><th>URL</th><th>Method</th><th>Payload</th></tr>
    {vuln_rows(all_vulns['xss'], ['type','url','method','payload'])}
  </table>

  <h2>🔒 Missing Security Headers</h2>
  <table>
    <tr><th>Header</th><th>Risk Description</th></tr>
    {vuln_rows(all_vulns['headers'], ['header','description'])}
  </table>

  <h2>↗️ Open Redirects</h2>
  <table>
    <tr><th>URL</th><th>Payload</th></tr>
    {vuln_rows(all_vulns['redirect'], ['url','payload'])}
  </table>

  <h2>🔄 CSRF Vulnerabilities</h2>
  <table>
    <tr><th>Type</th><th>Severity</th><th>URL</th><th>Evidence</th><th>Fix</th></tr>
    {vuln_rows(all_vulns['csrf'], ['type','severity','url','evidence','fix'])}
  </table>

  <div class="footer">Generated by WebVulnScanner &nbsp;|&nbsp; For educational use only</div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"{Fore.GREEN}[+] Report saved → {filename}{Style.RESET_ALL}")
    return filename


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("target",
                        help="Target URL (e.g. http://testasp.vulnweb.com)")
    parser.add_argument("-p", "--pages",
                        type=int, default=20,
                        help="Max pages to crawl (default: 20)")
    parser.add_argument("-m", "--modules",
                        nargs="+",
                        default=["sqli", "xss", "headers", "redirect", "csrf"],
                        choices=["sqli", "xss", "headers", "redirect", "csrf"],
                        help="Modules to run (default: all)")
    parser.add_argument("-r", "--report",
                        action="store_true",
                        help="Generate HTML report")
    args = parser.parse_args()

    all_vulns, results = run_scan(args.target, args.pages, args.modules)
    print_summary(all_vulns)

    if args.report:
        generate_report(args.target, all_vulns, results)


if __name__ == "__main__":
    main()