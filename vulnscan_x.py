#!/usr/bin/env python3
"""
VulnScan X - Automated Vulnerability Scanner
Author: Cyber Security Research
Version: 1.0
Description: Free vulnerability scanner without paid APIs
"""

import requests
import socket
import threading
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime

class VulnScanX:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) VulnScanX/1.0'
        })

        self.sql_injection_payloads = [
            "'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1"
        ]

        self.xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ]

        self.common_paths = [
            '/admin/', '/login/', '/wp-admin/', '/phpmyadmin/',
            '/.git/', '/.env', '/config.php', '/backup/',
            '/test/', '/dev/', '/api/', '/robots.txt'
        ]

        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443]

    def scan_website(self, url):
        results = {
            'target': url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': []
        }

        results['info'] = self.gather_info(url)
        results['vulnerabilities'] += self.test_sql_injection(url)
        results['vulnerabilities'] += self.test_xss(url)
        results['vulnerabilities'] += self.scan_directories(url)
        results['ports'] = self.scan_ports(url)
        results['vulnerabilities'] += self.check_security_headers(url)

        return results

    def gather_info(self, url):
        info = {}
        try:
            r = self.session.get(url, timeout=10)
            info['server'] = r.headers.get('Server', 'Unknown')
            info['status_code'] = r.status_code
            domain = urlparse(url).netloc
            info['ip_address'] = socket.gethostbyname(domain)
        except:
            pass
        return info

    def test_sql_injection(self, url):
        vulns = []
        try:
            r = self.session.get(url)
            soup = BeautifulSoup(r.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action', '')
                inputs = form.find_all('input')

                for payload in self.sql_injection_payloads:
                    data = {}
                    for i in inputs:
                        name = i.get('name')
                        if name:
                            data[name] = payload

                    test_url = urljoin(url, action)
                    res = self.session.post(test_url, data=data)

                    if "sql" in res.text.lower():
                        vulns.append({
                            'type': 'SQL Injection',
                            'severity': 'HIGH',
                            'url': test_url,
                            'payload': payload,
                            'description': 'Possible SQL Injection'
                        })
                        break
        except:
            pass
        return vulns

    def test_xss(self, url):
        vulns = []
        parsed = urlparse(url)

        if parsed.query:
            for payload in self.xss_payloads:
                test_url = f"{url}&xss={payload}"
                try:
                    r = self.session.get(test_url)
                    if payload in r.text:
                        vulns.append({
                            'type': 'XSS',
                            'severity': 'MEDIUM',
                            'url': test_url,
                            'payload': payload,
                            'description': 'Reflected XSS'
                        })
                        break
                except:
                    pass
        return vulns

    def scan_directories(self, url):
        vulnerabilities = []
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        for path in self.common_paths:
            test_url = urljoin(base_url, path)
            try:
                r = self.session.get(test_url, timeout=3)
                if r.status_code in [200, 403]:
                    vulnerabilities.append({
                        'type': 'Exposed Path',
                        'severity': 'LOW',
                        'url': test_url,
                        'status': r.status_code,
                        'description': 'Accessible or restricted path found'
                    })
            except:
                continue

        return vulnerabilities

    def scan_ports(self, url):
        results = {'open_ports': []}
        ip = socket.gethostbyname(urlparse(url).netloc)

        def scan(port):
            try:
                s = socket.socket()
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    results['open_ports'].append(port)
                s.close()
            except:
                pass

        threads = []
        for p in self.common_ports:
            t = threading.Thread(target=scan, args=(p,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        return results

    def check_security_headers(self, url):
        vulns = []
        try:
            r = self.session.get(url)
            headers = [
                'X-Frame-Options',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ]
            for h in headers:
                if h not in r.headers:
                    vulns.append({
                        'type': 'Missing Security Header',
                        'severity': 'LOW',
                        'header': h,
                        'description': 'Header not set'
                    })
        except:
            pass
        return vulns


def main():
    url = input("Enter target URL: ").strip()
    if not url.startswith("http"):
        url = "https://" + url

    scanner = VulnScanX()
    results = scanner.scan_website(url)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
