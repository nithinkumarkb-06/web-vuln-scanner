from modules.crawler import Crawler
from modules.sqli import SQLiScanner
from modules.xss import XSSScanner
from modules.headers import HeadersScanner
from modules.open_redirect import OpenRedirectScanner
from modules.csrf import CSRFScanner

TARGET = "http://testasp.vulnweb.com"

# Crawl
print("Starting crawler...\n")
crawler = Crawler(TARGET, max_pages=20)
crawler.crawl()
results = crawler.get_results()

print(f"\nPages visited : {len(results['visited'])}")
print(f"Forms found   : {len(results['forms'])}")
print(f"Links found   : {len(results['links'])}\n")

# All modules
sqli_vulns     = SQLiScanner().scan(results["forms"])
xss_vulns      = XSSScanner().scan(results["forms"], results["links"])
header_vulns   = HeadersScanner().scan(TARGET)
redirect_vulns = OpenRedirectScanner().scan(results["links"], TARGET)
csrf_vulns     = CSRFScanner().scan(results["forms"])   # ← must be BEFORE summary

# Summary
total = len(sqli_vulns)+len(xss_vulns)+len(header_vulns)+len(redirect_vulns)+len(csrf_vulns)
print(f"\n{'='*55}")
print(f"  FULL SCAN COMPLETE — {total} issue(s) found")
print(f"{'='*55}")
print(f"  SQLi            : {len(sqli_vulns)}")
print(f"  XSS             : {len(xss_vulns)}")
print(f"  Missing Headers : {len(header_vulns)}")
print(f"  Open Redirects  : {len(redirect_vulns)}")
print(f"  CSRF            : {len(csrf_vulns)}")
print(f"{'='*55}")