import requests
from colorama import Fore

class SQLInjectionScanner:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "admin'--",
            "1' AND '1'='1",
        ]
        self.error_signatures = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "microsoft ole db provider for sql server",
            "odbc sql server driver",
            "syntax error",
            "mysql_fetch",
            "pg_query",
            "sqlite3",
        ]
        self.test_paths = [
            "/vulnerabilities/sqli/?id=",
            "/login.php?user=",
            "/?search=",
            "/index.php?id=",
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
                    for sig in self.error_signatures:
                        if sig in body:
                            finding = {
                                "check": "SQL Injection",
                                "severity": "Critical",
                                "owasp": "A03:2021 - Injection",
                                "url": test_url,
                                "payload": payload,
                                "description": f"SQL error signature '{sig}' detected in response. Application may be vulnerable to SQL injection.",
                                "remediation": "Use parameterised queries or prepared statements. Never concatenate user input into SQL queries. Implement input validation and sanitisation.",
                                "evidence": body[:200]
                            }
                            findings.append(finding)
                            print(Fore.RED + f"    [CRITICAL] SQL Injection found: {test_url}")
                            break
                except requests.exceptions.RequestException:
                    pass
        if not findings:
            print(Fore.GREEN + "    [PASS] No SQL injection vulnerabilities detected")
        return findings