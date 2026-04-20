import requests
from urllib.parse import urljoin
from colorama import Fore, Style

# Common CSRF token field names used by frameworks
CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "csrftoken", "_csrf", "_token",
    "token", "authenticity_token", "nonce", "request_token",
    "__requestverificationtoken",  # ASP.NET
    "csrfmiddlewaretoken",         # Django
    "_csrf_token",                 # Symfony
    "csrf-token", "x-csrf-token",  # Generic
    "anti-forgery-token",
]

# Sensitive action keywords — GET forms doing these are always vulnerable
SENSITIVE_ACTIONS = [
    "delete", "remove", "transfer", "payment", "pay",
    "update", "change", "modify", "edit", "password",
    "email", "logout", "purchase", "confirm", "approve",
]

# Severity levels
SEVERITY = {
    "missing_token_post"  : "HIGH",
    "missing_token_get"   : "MEDIUM",
    "sensitive_get_form"  : "HIGH",
    "weak_token"          : "MEDIUM",
}

class CSRFScanner:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = "WebVulnScanner/1.0"
        self.vulnerabilities = []

    def has_csrf_token(self, inputs):
        """Check if any input field looks like a CSRF token."""
        for input_field in inputs:
            name  = (input_field.get("name")  or "").lower()
            value = (input_field.get("value") or "").lower()

            # Check if name matches known token names
            for token_name in CSRF_TOKEN_NAMES:
                if token_name in name:
                    return True, input_field.get("name"), input_field.get("value")

        return False, None, None

    def is_weak_token(self, token_value):
        """
        Flag tokens that are too short, sequential, or look predictable.
        A good CSRF token should be 20+ random chars.
        """
        if not token_value:
            return True

        token_value = str(token_value)

        # Too short
        if len(token_value) < 16:
            return True

        # All same character
        if len(set(token_value)) < 4:
            return True

        # Purely numeric (predictable)
        if token_value.isdigit():
            return True

        return False

    def is_sensitive_form(self, action, inputs):
        """Check if the form performs a sensitive action."""
        action_lower = (action or "").lower()
        for keyword in SENSITIVE_ACTIONS:
            if keyword in action_lower:
                return True, keyword

        # Also check input names for sensitive keywords
        for input_field in inputs:
            name = (input_field.get("name") or "").lower()
            for keyword in SENSITIVE_ACTIONS:
                if keyword in name:
                    return True, keyword

        return False, None

    def scan_form(self, form, page_url):
        """Analyze a single form for CSRF vulnerabilities."""
        action  = form.get("action", "")
        method  = form.get("method", "get").lower()
        inputs  = form.get("inputs", [])
        target_url = urljoin(page_url, action) if action else page_url

        has_token, token_name, token_value = self.has_csrf_token(inputs)
        is_sensitive, sensitive_keyword    = self.is_sensitive_form(action, inputs)

        # --- Check 1: POST form with no CSRF token (most critical) ---
        if method == "post" and not has_token:
            result = {
                "type"       : "Missing CSRF Token",
                "severity"   : SEVERITY["missing_token_post"],
                "url"        : target_url,
                "method"     : method.upper(),
                "evidence"   : "POST form has no CSRF token field",
                "impact"     : "Attacker can forge state-changing requests on behalf of victim",
                "fix"        : "Add a cryptographically random CSRF token to all POST forms",
            }
            self.vulnerabilities.append(result)
            self._print_vuln(result)

        # --- Check 2: GET form performing sensitive action ---
        elif method == "get" and is_sensitive:
            result = {
                "type"       : "Sensitive Action via GET",
                "severity"   : SEVERITY["sensitive_get_form"],
                "url"        : target_url,
                "method"     : method.upper(),
                "evidence"   : f"GET form contains sensitive keyword: '{sensitive_keyword}'",
                "impact"     : "Sensitive actions over GET can be triggered via URL — easily exploitable",
                "fix"        : "Use POST for state-changing actions and add CSRF tokens",
            }
            self.vulnerabilities.append(result)
            self._print_vuln(result)

        # --- Check 3: Token exists but looks weak ---
        elif has_token and self.is_weak_token(token_value):
            result = {
                "type"       : "Weak CSRF Token",
                "severity"   : SEVERITY["weak_token"],
                "url"        : target_url,
                "method"     : method.upper(),
                "evidence"   : f"Token field '{token_name}' has weak value: '{token_value}'",
                "impact"     : "Predictable tokens can be guessed or brute-forced by attackers",
                "fix"        : "Use cryptographically secure random tokens (min 32 chars)",
            }
            self.vulnerabilities.append(result)
            self._print_vuln(result)

        # --- All good ---
        else:
            token_info = f"token='{token_name}'" if has_token else "no token (GET — acceptable)"
            print(f"{Fore.GREEN}[SAFE]{Style.RESET_ALL} {target_url} | {method.upper()} | {token_info}")

    def _print_vuln(self, result):
        """Pretty print a vulnerability finding."""
        severity_color = Fore.RED if result["severity"] == "HIGH" else Fore.YELLOW
        print(f"\n{severity_color}[{result['severity']}] {result['type']}{Style.RESET_ALL}")
        print(f"  → URL      : {result['url']}")
        print(f"  → Method   : {result['method']}")
        print(f"  → Evidence : {result['evidence']}")
        print(f"  → Impact   : {result['impact']}")
        print(f"  → Fix      : {result['fix']}\n")

    def scan(self, forms):
        """Scan all forms for CSRF vulnerabilities."""
        print(f"\n{Fore.BLUE}{'='*55}")
        print(f"  CSRF SCAN — {len(forms)} forms to analyze")
        print(f"{'='*55}{Style.RESET_ALL}\n")

        if not forms:
            print("No forms to scan.")
            return []

        for form in forms:
            page_url = form.get("page_url", "")
            print(f"{Fore.CYAN}[FORM]{Style.RESET_ALL} Analyzing: {page_url}")
            self.scan_form(form, page_url)

        # Summary
        high   = sum(1 for v in self.vulnerabilities if v["severity"] == "HIGH")
        medium = sum(1 for v in self.vulnerabilities if v["severity"] == "MEDIUM")

        print(f"\n{Fore.BLUE}--- CSRF Summary ---{Style.RESET_ALL}")
        print(f"  {Fore.RED}HIGH   : {high}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}MEDIUM : {medium}{Style.RESET_ALL}")

        return self.vulnerabilities