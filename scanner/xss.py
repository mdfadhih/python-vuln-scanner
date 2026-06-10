import requests
from colorama import Fore

class XSSScanner:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert(1)</script>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
        ]
        self.test_paths = [
            "/vulnerabilities/xss_r/?name=",
            "/?search=",
            "/index.php?name=",
            "/search?q=",
        ]

    def scan(self):
        findings = []
        for path in self.test_paths:
            url = self.target + path
            for payload in self.payloads:
                try:
                    test_url = url + payload
                    response = requests.get(
                        test_url,
                        timeout=5,
                        allow_redirects=True,
                        verify=False
                    )
                    if payload.lower() in response.text.lower():
                        finding = {
                            "check": "Cross-Site Scripting (XSS)",
                            "severity": "High",
                            "owasp": "A03:2021 - Injection",
                            "url": test_url,
                            "payload": payload,
                            "description": f"XSS payload reflected unescaped in response. Attackers could inject malicious scripts to steal session cookies or redirect users.",
                            "remediation": "Encode all user-supplied output using HTML entity encoding. Implement Content Security Policy (CSP) headers. Use a web application firewall.",
                            "evidence": response.text[:200]
                        }
                        findings.append(finding)
                        print(Fore.YELLOW + f"    [HIGH] XSS vulnerability found: {test_url}")
                        break
                except requests.exceptions.RequestException:
                    pass
        if not findings:
            print(Fore.GREEN + "    [PASS] No XSS vulnerabilities detected")
        return findings