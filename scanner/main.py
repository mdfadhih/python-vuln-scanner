import argparse
import sys
from colorama import init, Fore, Style
from sql_injection import SQLInjectionScanner
from xss import XSSScanner
from open_ports import PortScanner
from headers import HeadersScanner
from directory import DirectoryScanner
from report import generate_report

init(autoreset=True)

BANNER = """
╔═══════════════════════════════════════════════╗
║         Python Vulnerability Scanner          ║
║         Author: Mohamed Fadhih                ║
║         OWASP Top 10 | v1.0                   ║
╚═══════════════════════════════════════════════╝
"""

def run_scanner(target, output):
    print(Fore.CYAN + BANNER)
    print(Fore.YELLOW + f"[*] Target: {target}")
    print(Fore.YELLOW + f"[*] Starting scan...\n")

    findings = []

    # Check 1 - SQL Injection
    print(Fore.CYAN + "[*] Check 1/5: SQL Injection (OWASP A03)...")
    sqli = SQLInjectionScanner(target)
    findings.extend(sqli.scan())

    # Check 2 - XSS
    print(Fore.CYAN + "[*] Check 2/5: Cross-Site Scripting (OWASP A03)...")
    xss = XSSScanner(target)
    findings.extend(xss.scan())

    # Check 3 - Open Ports
    print(Fore.CYAN + "[*] Check 3/5: Open Ports (OWASP A05)...")
    ports = PortScanner(target)
    findings.extend(ports.scan())

    # Check 4 - Security Headers
    print(Fore.CYAN + "[*] Check 4/5: Security Headers (OWASP A05)...")
    headers = HeadersScanner(target)
    findings.extend(headers.scan())

    # Check 5 - Directory Traversal
    print(Fore.CYAN + "[*] Check 5/5: Directory Traversal (OWASP A01)...")
    directory = DirectoryScanner(target)
    findings.extend(directory.scan())

    # Summary
    critical = len([f for f in findings if f['severity'] == 'Critical'])
    high = len([f for f in findings if f['severity'] == 'High'])
    medium = len([f for f in findings if f['severity'] == 'Medium'])
    low = len([f for f in findings if f['severity'] == 'Low'])

    print(Fore.GREEN + "\n[+] Scan Complete!")
    print(Fore.RED +    f"    Critical : {critical}")
    print(Fore.YELLOW + f"    High     : {high}")
    print(Fore.CYAN +   f"    Medium   : {medium}")
    print(Fore.WHITE +  f"    Low      : {low}")
    print(f"    Total    : {len(findings)}")

    # Generate report
    report_file = generate_report(target, findings, output)
    print(Fore.GREEN + f"\n[+] Report saved: {report_file}")
    return findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target URL e.g. http://localhost")
    parser.add_argument("--output", default="html", choices=["html", "json"], help="Report format")
    args = parser.parse_args()

    if not args.target.startswith("http"):
        print(Fore.RED + "[-] Target must start with http:// or https://")
        sys.exit(1)

    run_scanner(args.target, args.output)