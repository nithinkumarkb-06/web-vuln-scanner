import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

class Crawler:
    def __init__(self, base_url, max_pages=20):
        self.base_url = base_url
        self.max_pages = max_pages
        self.visited = set()
        self.forms = []
        self.links = []
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "WebVulnScanner/1.0"

    def is_same_domain(self, url):
        """Make sure we only crawl the target domain."""
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def get_all_forms(self, url):
        """Extract all forms from a page."""
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except Exception:
            return []

    def get_form_details(self, form):
        """Extract details from a single form — action, method, inputs."""
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []

        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": input_value
            })

        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def crawl(self, url=None):
        """Recursively crawl the site up to max_pages."""
        if url is None:
            url = self.base_url

        if url in self.visited or len(self.visited) >= self.max_pages:
            return

        try:
            print(f"{Fore.CYAN}[CRAWLING]{Style.RESET_ALL} {url}")
            response = self.session.get(url, timeout=5)
            self.visited.add(url)

            soup = BeautifulSoup(response.content, "html.parser")

            # Collect forms on this page
            forms = self.get_all_forms(url)
            for form in forms:
                form_details = self.get_form_details(form)
                form_details["page_url"] = url
                self.forms.append(form_details)

            # Collect and follow links
            for tag in soup.find_all("a", href=True):
                full_url = urljoin(url, tag["href"])
                if self.is_same_domain(full_url) and full_url not in self.visited:
                    self.links.append(full_url)
                    self.crawl(full_url)

        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not crawl {url}: {e}")

    def get_results(self):
        return {
            "visited": list(self.visited),
            "forms": self.forms,
            "links": self.links
        }