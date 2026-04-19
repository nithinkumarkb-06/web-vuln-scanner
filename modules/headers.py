import requests
from colorama import Fore, Style

# Security headers and what they protect against
SECURITY_HEADERS = {
    "X-Frame-Options"           : "Protects against Clickjacking",
    "X-XSS-Protection"          : "Enables browser XSS filter",
    "X-Content-Type-Options"    : "Prevents MIME-type sniffing",
    "Content-Security-Policy"   : "Prevents XSS & data injection",
    "Strict-Transport-Security" : "Enforces HTTPS (HSTS)",
    "Referrer-Policy"           : "Controls referrer information",
    "Permissions-Policy"        : "Controls browser feature access",
}

class HeadersScanner:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = "WebVulnScanner/1.0"
        self.vulnerabilities = []

    def scan(self, url):
        print(f"\n{Fore.BLUE}{'='*50}")
        print(f"  SECURITY HEADERS SCAN")
        print(f"{'='*50}{Style.RESET_ALL}\n")

        try:
            response = self.session.get(url, timeout=5)
            headers  = response.headers

            for header, description in SECURITY_HEADERS.items():
                if header not in headers:
                    result = {
                        "type"        : "Missing Security Header",
                        "url"         : url,
                        "header"      : header,
                        "description" : description,
                    }
                    self.vulnerabilities.append(result)
                    print(f"{Fore.RED}[MISSING]{Style.RESET_ALL} {header}")
                    print(f"  → Risk : {description}\n")
                else:
                    print(f"{Fore.GREEN}[PRESENT]{Style.RESET_ALL} {header}: {headers[header]}")

        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {e}")

        return self.vulnerabilities