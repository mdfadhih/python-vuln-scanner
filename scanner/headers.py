import requests
from colorama import Fore

class HeadersScanner:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.required_headers = {
            "X-Frame-Options": {
                "severity": "Medium",
                "description": "Missing X-Frame-Options header. Application may be vulnerable to clickjacking attacks where attackers embed the site in an iframe.",
                "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
                "owasp": "A05:2021 - Security Misconfiguration"
            },
            "X-Content-Type-Options": {
                "severity": "Low",
                "description": "Missing X-Content-Type-Options header. Browser may interpret files as different MIME types enabling MIME-sniffing attacks.",
                "remediation": "Add header: X-Content-Type-Options: nosniff",
                "owasp": "A05:2021 - Security Misconfiguration"
            },
            "Strict-Transport-Security": {
                "severity": "High",
                "description": "Missing Strict-Transport-Security (HSTS) header. Application does not enforce HTTPS connections, leaving users vulnerable to downgrade attacks.",
                "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                "owasp": "A05:2021 - Security Misconfiguration"
            },
            "Content-Security-Policy": {
                "severity": "Medium",
                "description": "Missing Content-Security-Policy header. No CSP means the browser will execute any scripts included in the page, enabling XSS attacks.",
                "remediation": "Add header: Content-Security-Policy: default-src 'self'",
                "owasp": "A05:2021 - Security Misconfiguration"
            },
            "X-XSS-Protection": {
                "severity": "Low",
                "description": "Missing X-XSS-Protection header. Older browsers may not block reflected XSS attacks.",
                "remediation": "Add header: X-XSS-Protection: 1; mode=block",
                "owasp": "A05:2021 - Security Misconfiguration"
            },
        }

    def scan(self):
        findings = []
        try:
            response = requests.get(
                self.target,
                timeout=5,
                verify=False,
                allow_redirects=True
            )
            response_headers = {k.lower(): v for k, v in response.headers.items()}

            for header, info in self.required_headers.items():
                if header.lower() not in response_headers:
                    finding = {
                        "check": f"Missing Security Header — {header}",
                        "severity": info["severity"],
                        "owasp": info["owasp"],
                        "url": self.target,
                        "payload": f"HTTP GET request — checking response headers",
                        "description": info["description"],
                        "remediation": info["remediation"],
                        "evidence": f"Header '{header}' not present in HTTP response"
                    }
                    findings.append(finding)
                    color = Fore.YELLOW if info["severity"] in ("High", "Critical") else Fore.CYAN
                    print(color + f"    [{info['severity'].upper()}] Missing header: {header}")
                else:
                    print(Fore.GREEN + f"    [PASS] Header present: {header}")

        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"    [ERROR] Could not connect to {self.target}: {e}")

        return findings