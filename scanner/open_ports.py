import socket
from urllib.parse import urlparse
from colorama import Fore

class PortScanner:
    def __init__(self, target):
        self.target = target.rstrip('/')
        parsed = urlparse(target)
        self.host = parsed.hostname or "localhost"
        self.risky_ports = {
            21: ("FTP", "High", "FTP transmits data in plaintext including credentials"),
            22: ("SSH", "Medium", "SSH exposed — ensure key-based auth only, no root login"),
            23: ("Telnet", "Critical", "Telnet transmits all data including passwords in plaintext"),
            80: ("HTTP", "Low", "HTTP traffic is unencrypted — use HTTPS"),
            443: ("HTTPS", "Info", "HTTPS — standard secure web traffic"),
            445: ("SMB", "High", "SMB exposed — vulnerable to EternalBlue and ransomware attacks"),
            3306: ("MySQL", "Critical", "MySQL database port exposed externally"),
            3389: ("RDP", "High", "RDP exposed — vulnerable to brute force attacks"),
            8080: ("HTTP-Alt", "Medium", "Alternative HTTP port exposed"),
            8443: ("HTTPS-Alt", "Low", "Alternative HTTPS port"),
        }

    def check_port(self, port, timeout=2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan(self):
        findings = []
        for port, (service, severity, description) in self.risky_ports.items():
            if self.check_port(port):
                if severity in ("Critical", "High"):
                    color = Fore.RED if severity == "Critical" else Fore.YELLOW
                    print(color + f"    [{severity.upper()}] Port {port}/{service} is open")
                    finding = {
                        "check": f"Open Port — {service} ({port})",
                        "severity": severity,
                        "owasp": "A05:2021 - Security Misconfiguration",
                        "url": f"{self.host}:{port}",
                        "payload": f"TCP connect to port {port}",
                        "description": description,
                        "remediation": f"Close port {port} if not required. If required, restrict access to trusted IP ranges using firewall rules.",
                        "evidence": f"Port {port} ({service}) is open and accepting connections"
                    }
                    findings.append(finding)
        if not findings:
            print(Fore.GREEN + "    [PASS] No critical open ports detected")
        return findings