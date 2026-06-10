import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanner'))

from headers import HeadersScanner
from open_ports import PortScanner

def test_headers_scanner_init():
    scanner = HeadersScanner("http://localhost")
    assert scanner.target == "http://localhost"
    assert len(scanner.required_headers) == 5

def test_port_scanner_init():
    scanner = PortScanner("http://localhost")
    assert scanner.host == "localhost"
    assert 3389 in scanner.risky_ports
    assert 445 in scanner.risky_ports

def test_headers_required_list():
    scanner = HeadersScanner("http://localhost")
    assert "X-Frame-Options" in scanner.required_headers
    assert "Content-Security-Policy" in scanner.required_headers
    assert "Strict-Transport-Security" in scanner.required_headers

def test_port_severity_levels():
    scanner = PortScanner("http://localhost")
    assert scanner.risky_ports[23][1] == "Critical"
    assert scanner.risky_ports[3306][1] == "Critical"
    assert scanner.risky_ports[445][1] == "High"

def test_report_generation():
    from report import generate_report
    findings = [{
        "check": "Test Finding",
        "severity": "High",
        "owasp": "A03:2021",
        "url": "http://localhost/test",
        "payload": "test payload",
        "description": "Test description",
        "remediation": "Test remediation",
        "evidence": "test evidence"
    }]
    report_file = generate_report("http://localhost", findings, "html")
    assert os.path.exists(report_file)
    os.remove(report_file)