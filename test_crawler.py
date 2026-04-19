from modules.crawler import Crawler
from modules.sqli import SQLiScanner
from modules.xss import XSSScanner
from modules.headers import HeadersScanner
from modules.open_redirect import OpenRedirectScanner

TARGET = "http://testasp.vulnweb.com"

# Step 1 - Crawl
print("Starting crawler...\n")
crawler = Crawler(TARGET, max_pages=10)
crawler.crawl()
results = crawler.get_results()

print(f"\nPages visited : {len(results['visited'])}")
print(f"Forms found   : {len(results['forms'])}")
print(f"Links found   : {len(results['links'])}\n")

# Step 2 - SQLi
sqli_vulns = SQLiScanner().scan(results["forms"])

# Step 3 - XSS
xss_vulns = XSSScanner().scan(results["forms"], results["links"])

# Step 4 - Headers
header_vulns = HeadersScanner().scan(TARGET)

# Step 5 - Open Redirect
redirect_vulns = OpenRedirectScanner().scan(results["links"], TARGET)

# Final Summary
total = len(sqli_vulns) + len(xss_vulns) + len(header_vulns) + len(redirect_vulns)
print(f"\n{'='*50}")
print(f"  FULL SCAN COMPLETE")
print(f"  SQLi vulnerabilities    : {len(sqli_vulns)}")
print(f"  XSS  vulnerabilities    : {len(xss_vulns)}")
print(f"  Missing headers         : {len(header_vulns)}")
print(f"  Open redirects          : {len(redirect_vulns)}")
print(f"  Total issues found      : {total}")
print(f"{'='*50}")