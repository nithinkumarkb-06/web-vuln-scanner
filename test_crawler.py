from modules.crawler import Crawler
from modules.sqli import SQLiScanner

# Step 1 - Crawl
print("Starting crawler...\n")
crawler = Crawler("http://testasp.vulnweb.com", max_pages=10)
crawler.crawl()
results = crawler.get_results()

print(f"\nPages visited : {len(results['visited'])}")
print(f"Forms found   : {len(results['forms'])}")
print(f"Links found   : {len(results['links'])}\n")

# Step 2 - SQLi Scan
scanner = SQLiScanner()
vulns = scanner.scan(results["forms"])

# Summary
print(f"\n{'='*50}")
print(f"SCAN COMPLETE — {len(vulns)} SQLi vulnerability(ies) found")
print(f"{'='*50}")