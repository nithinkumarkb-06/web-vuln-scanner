import requests
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

# Common redirect parameter names
REDIRECT_PARAMS = [
    "RetURL", "redirect", "redirect_url", "return",
    "returnUrl", "next", "url", "goto", "target",
    "redir", "destination", "continue", "ref"
]

# Payloads — external domains an attacker would redirect to
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/phish",
    "///evil.com",
    "/\\evil.com",
]

class OpenRedirectScanner:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = "WebVulnScanner/1.0"
        self.vulnerabilities = []

    def is_redirected_externally(self, response, original_host):
        """Check if the final URL after redirects is on a different domain."""
        final_url  = response.url
        final_host = urlparse(final_url).netloc
        return final_host and final_host != original_host

    def scan(self, links, base_url):
        print(f"\n{Fore.BLUE}{'='*50}")
        print(f"  OPEN REDIRECT SCAN")
        print(f"{'='*50}{Style.RESET_ALL}\n")

        original_host = urlparse(base_url).netloc

        for link in links:
            parsed = urlparse(link)
            if not parsed.query:
                continue

            # Check if any known redirect param is in the URL
            params = parsed.query.split("&")
            for param in params:
                key = param.split("=")[0]
                if key not in REDIRECT_PARAMS:
                    continue

                # Test each payload
                for payload in REDIRECT_PAYLOADS:
                    test_url = link.replace(f"{key}={param.split('=')[1]}", f"{key}={payload}")

                    try:
                        response = self.session.get(
                            test_url, timeout=5, allow_redirects=True
                        )
                        if self.is_redirected_externally(response, original_host):
                            result = {
                                "type"    : "Open Redirect",
                                "url"     : test_url,
                                "payload" : payload,
                            }
                            self.vulnerabilities.append(result)
                            print(f"{Fore.RED}[VULNERABLE]{Style.RESET_ALL} Open Redirect!")
                            print(f"  → URL     : {test_url}")
                            print(f"  → Payload : {payload}\n")
                            break
                        else:
                            print(f"{Fore.YELLOW}[TESTING]{Style.RESET_ALL} {key}={payload[:30]}")

                    except Exception as e:
                        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {e}")

        return self.vulnerabilities