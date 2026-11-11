# Python Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.11-blue)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20(5%20checks)-red)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED)
[![CI](https://github.com/mdfadhih/python-vuln-scanner/actions/workflows/scan.yml/badge.svg)](https://github.com/mdfadhih/python-vuln-scanner/actions/workflows/scan.yml)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Overview

A small Python web vulnerability scanner that implements five OWASP Top 10-related checks. It generates HTML reports with severity ratings, OWASP references, and remediation guidance. Tested against DVWA (Damn Vulnerable Web App).

Built to demonstrate application security skills relevant to the Australian cybersecurity market — combining development and security knowledge. This is an educational tool with basic checks, not a replacement for tools like OWASP ZAP or Burp Suite (see Limitations).

---

## Features

| Check                      | OWASP Category                       | Severity |
| -------------------------- | ------------------------------------ | -------- |
| SQL Injection              | A03:2021 — Injection                 | Critical |
| Cross-Site Scripting (XSS) | A03:2021 — Injection                 | High     |
| Open Port Detection        | A05:2021 — Security Misconfiguration | High     |
| Missing Security Headers   | A05:2021 — Security Misconfiguration | Medium   |
| Directory Traversal        | A01:2021 — Broken Access Control     | Critical |

---

## Quick Start

### Run with Python

```bash
git clone https://github.com/mdfadhih/python-vuln-scanner.git
cd python-vuln-scanner
pip install -r requirements.txt
python scanner/main.py --target http://localhost --output html
```

Note: the open-port check uses `python-nmap`, which requires the `nmap` program to be installed on your system.

### Run against DVWA (test target)

```bash
# Start DVWA
docker run -d -p 80:80 vulnerables/web-dvwa

# Run scanner
python scanner/main.py --target http://localhost --output html
```

DVWA setup: open `http://localhost/setup.php`, click "Create / Reset Database", log in (default `admin` / `password`), and set the DVWA security level to Low.

### Run with Docker

Inside a container, `localhost` refers to the container itself, so point the scanner at the host:

```bash
docker build -t vuln-scanner .

# Linux
docker run --rm --network host -v "$(pwd)/reports:/app/reports" vuln-scanner --target http://localhost --output html

# Windows / macOS (Docker Desktop)
docker run --rm -v "$(pwd)/reports:/app/reports" vuln-scanner --target http://host.docker.internal --output html
```

---

## Sample Output (abridged)

Findings and counts vary by target.

```
╔═══════════════════════════════════════════════╗
║         Python Vulnerability Scanner          ║
║         Author: Mohamed Fadhih                ║
║         OWASP Top 10 | v1.0                   ║
╚═══════════════════════════════════════════════╝

[*] Target: http://localhost
[*] Starting scan...

[*] Check 1/5: SQL Injection (OWASP A03)...
    [CRITICAL] SQL Injection found: http://localhost/vulnerabilities/sqli/?id='
[*] Check 2/5: Cross-Site Scripting (OWASP A03)...
    [HIGH] XSS vulnerability found: http://localhost/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>
[*] Check 3/5: Open Ports (OWASP A05)...
    [HIGH] Port 445/SMB is open
[*] Check 4/5: Security Headers (OWASP A05)...
    [HIGH] Missing header: Strict-Transport-Security
    [MEDIUM] Missing header: Content-Security-Policy
[*] Check 5/5: Directory Traversal (OWASP A01)...
    [CRITICAL] Directory traversal found: http://localhost/vulnerabilities/fi/?page=../../../etc/passwd

[+] Scan Complete!
    Critical : 2
    High     : 3
    Medium   : 2
    Low      : 1
    Total    : 8

[+] Report saved: reports/scan_report_20260610_120000.html
```

---

## HTML Report

The scanner generates an HTML report with:

- Severity-coloured findings (Critical/High/Medium/Low)
- OWASP Top 10 reference for each finding
- Full URL and payload used
- Remediation guidance for each vulnerability
- Summary metrics dashboard

See the `/reports` folder for sample scan output.

---

## Project Structure

```
python-vuln-scanner/
├── scanner/
│   ├── __init__.py
│   ├── main.py           ← entry point + CLI
│   ├── sql_injection.py  ← SQL injection checks
│   ├── xss.py            ← XSS checks
│   ├── open_ports.py     ← port scanning
│   ├── headers.py        ← security header checks
│   ├── directory.py      ← directory traversal checks
│   └── report.py         ← HTML report generator
├── reports/              ← scan output saved here
├── screenshots/          ← evidence screenshots
├── tests/
│   └── test_scanner.py   ← pytest unit tests
├── .github/
│   └── workflows/
│       └── scan.yml      ← GitHub Actions CI
├── Dockerfile
├── LICENSE
├── requirements.txt
└── README.md
```

---

## CI/CD Pipeline

GitHub Actions runs on every push:

1. Spins up DVWA as a service container
2. Runs pytest unit tests
3. Executes a scan against DVWA
4. Uploads the HTML report as an artifact

---

## Limitations

- Basic, payload-based checks only; it can produce false positives and false negatives.
- Tested only against DVWA, an intentionally vulnerable application.
- No crawling, authenticated scanning or rate limiting beyond what the code implements.
- Not a replacement for professional tools such as OWASP ZAP or Burp Suite.

---

## Ethical Use

This tool is for authorised security testing only. Only scan systems you own or have explicit written permission to test. The author accepts no liability for misuse.

---

## Dependencies

| Package        | Purpose                    |
| -------------- | -------------------------- |
| requests       | HTTP requests for scanning |
| beautifulsoup4 | HTML parsing               |
| python-nmap    | Port scanning              |
| jinja2         | HTML report templating     |
| colorama       | Terminal colours           |

---

## About

**Mohamed Fadhih** — Cybersecurity Analyst | Melbourne, Australia

- Master of Cybersecurity — Monash University
- AWS Certified Cloud Practitioner
- Google Cybersecurity Professional Certificate

[LinkedIn](https://www.linkedin.com/in/fadhih) | [Portfolio](https://cybersecurity-portfolio-drab.vercel.app/)
[![Project 1](https://img.shields.io/badge/Project_1-Azure_Sentinel-blue)](https://github.com/mdfadhih/soc-lab-threat-detection)
[![Project 2](https://img.shields.io/badge/Project_2-Home_SOC_Lab-orange)](https://github.com/mdfadhih/home-soc-lab)
