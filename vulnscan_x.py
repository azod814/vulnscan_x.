#!/usr/bin/env python3
"""
VulnScan X - Automated Vulnerability Scanner
Author: Cyber Security Research
Version: 1.0
Description: Free vulnerability scanner without paid APIs
"""

import requests
import re
import time
import sys
import socket
import threading
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import dns.resolver
import subprocess
import json
from datetime import datetime

class VulnScanX:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) VulnScanX/1.0'
        })
        
        # Common vulnerability patterns
        self.sql_injection_payloads = [
            "'", "''", "\"", "\"\"", "1' OR '1'='1", "1\" OR \"1\"=\"1",
            "'; DROP TABLE users; --", "' UNION SELECT * FROM users --"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>", "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>", "';alert('XSS');//"
        ]
        
        self.common_paths = [
            '/admin/', '/login/', '/wp-admin/', '/phpmyadmin/',
            '/.git/', '/.env', '/config.php', '/backup/',
            '/test/', '/dev/', '/api/', '/robots.txt'
        ]
        
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
    def scan_website(self, url):
        """Main scanning function"""
        print(f"🔍 Starting vulnerability scan for: {url}")
        print("=" * 60)
        
        results = {
            'target': url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': []
        }
        
        # 1. Basic Information Gathering
        print("📊 [1/6] Gathering basic information...")
        results['info'] = self.gather_info(url)
        
        # 2. SQL Injection Testing
        print("💉 [2/6] Testing for SQL Injection...")
        sql_vulns = self.test_sql_injection(url)
        if sql_vulns:
            results['vulnerabilities'].extend(sql_vulns)
        
        # 3. XSS Testing
        print("🎯 [3/6] Testing for XSS vulnerabilities...")
        xss_vulns = self.test_xss(url)
        if xss_vulns:
            results['vulnerabilities'].extend(xss_vulns)
        
        # 4. Directory/File Discovery
        print("📁 [4/6] Scanning for hidden directories...")
        dir_vulns = self.scan_directories(url)
        if dir_vulns:
            results['vulnerabilities'].extend(dir_vulns)
        
        # 5. Port Scanning
        print("🚪 [5/6] Scanning open ports...")
        port_results = self.scan_ports(url)
        results['ports'] = port_results
        
        # 6. Security Headers Check
        print("🔒 [6/6] Checking security headers...")
        header_vulns = self.check_security_headers(url)
        if header_vulns:
            results['vulnerabilities'].extend(header_vulns)
        
        return results
    
    def gather_info(self, url):
        """Gather basic information about the target"""
        info = {}
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Server information
            info['server'] = response.headers.get('Server', 'Unknown')
            info['status_code'] = response.status_code
            info['content_type'] = response.headers.get('Content-Type', 'Unknown')
            
            # Technology detection
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # CMS Detection
            if 'wp-content' in response.text:
                info['cms'] = 'WordPress'
            elif 'Joomla' in response.text:
                info['cms'] = 'Joomla'
            elif 'Drupal' in response.text:
                info['cms'] = 'Drupal'
            else:
                info['cms'] = 'Unknown'
            
            # Framework detection
            if 'bootstrap' in response.text.lower():
                info['framework'] = 'Bootstrap'
            elif 'react' in response.text.lower():
                info['framework'] = 'React'
            elif 'angular' in response.text.lower():
                info['framework'] = 'Angular'
            
            # Get IP address
            domain = urlparse(url).netloc
            try:
                info['ip_address'] = socket.gethostbyname(domain)
            except:
                info['ip_address'] = 'Unknown'
                
        except Exception as e:
            print(f"❌ Error gathering info: {e}")
        
        return info
    
    def test_sql_injection(self, url):
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Find all forms
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                
                for payload in self.sql_injection_payloads[:3]:  # Test first 3 payloads
                    data = {}
                    for input_tag in inputs:
                        input_name = input_tag.get('name', '')
                        if input_name:
                            data[input_name] = payload
                    
                    try:
                        if method == 'post':
                            test_url = urljoin(url, form_action)
                            response = self.session.post(test_url, data=data, timeout=5)
                        else:
                            test_url = urljoin(url, form_action) + '?' + '&'.join([f"{k}={v}" for k, v in data.items()])
                            response = self.session.get(test_url, timeout=5)
                        
                        # Check for SQL error messages
                        sql_errors = [
                            "mysql_fetch", "sql syntax", "ora-", "microsoft odbc",
                            "sqlite_", "sqlstate", "warning: mysql"
                        ]
                        
                        if any(error.lower() in response.text.lower() for error in sql_errors):
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'HIGH',
                                'url': test_url,
                                'payload': payload,
                                'description': 'Potential SQL injection vulnerability detected'
                            })
                            break
                            
                    except:
                        continue
                        
        except Exception as e:
            print(f"❌ SQL injection test error: {e}")
        
        return vulnerabilities
    
    def test_xss(self, url):
        """Test for XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test URL parameters
            parsed = urlparse(url)
            if parsed.query:
                for payload in self.xss_payloads[:2]:  # Test first 2 payloads
                    test_params = {}
                    for param in parsed.query.split('&'):
                        if '=' in param:
                            key = param.split('=')[0]
                            test_params[key] = payload
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    
                    try:
                        response = self.session.get(test_url, timeout=5)
                        
                        if payload in response.text:
                            vulnerabilities.append({
                                'type': 'XSS (Cross-Site Scripting)',
                                'severity': 'MEDIUM',
                                'url': test_url,
                                'payload': payload,
                                'description': 'Reflected XSS vulnerability detected'
                            })
                            break
                            
                    except:
                        continue
                        
        except Exception as e:
            print(f"❌ XSS test error: {e}")
        
        return vulnerabilities
    
    def scan_directories(self, url):
        """Scan for hidden directories and files"""
        vulnerabilities = []
        
        try: 
            base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for path in self.common_paths:
                test_url = urljoin(base_url, path)
                
                try:
                    response = self.session.get(test_url, timeout=3)
                    
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Exposed Directory/File',
                            'severity': 'MEDIUM',
                            'url': test_url,
                            'status_code': response.status_code,
                            'description': f'Exposed directory or file found: {path}'
                        })
                    elif response.status_code == 403:
                        vulnerabilities.append({
                            'type': 'Restricted Directory',
                            'severity': 'LOW',
                            'url': test_url,
                            'status_code': response.status_code,
                            'description': f'Restricted directory found: {path}'
                        })
                        
                except:
                    continue
                    
        except Exception as e:
            print(f"❌ Directory scan error: {e}")
        
        return vulnerabilities
    
    def scan_ports(self, url):
        """Scan for open ports on the target"""
        results = {'open_ports': [], 'closed_ports': []}
        
        try:
            domain = urlparse(url).netloc
            ip = socket.gethostbyname(domain)
            
            print(f"📍 Scanning ports for {ip}...")
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = 'Unknown'
                        
                        results['open_ports'].append({
                            'port': port,
                            'service': service,
                            'status': 'OPEN'
                        })
                        print(f"✅ Port {port} ({service}) - OPEN")
                    else:
                        results['closed_ports'].append(port)
                    
                    sock.close()
                    
                except:
                    pass
            
            # Multi-threaded port scanning
            threads = []
            for port in self.common_ports:
                thread = threading.Thread(target=scan_port, args=(port,))
                threads.append(thread)
                thread.start()
            
            for thread in threads:
                thread.join()
                
        except Exception as e:
            print(f"❌ Port scan error: {e}")
        
        return results
    
    def check_security_headers(self, url):
        """Check for missing security headers"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=5)
            
            # Important security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'CSP protection',
                'Referrer-Policy': 'Referrer policy'
            }
            
            for header, description in security_headers.items():
                if header not in response.headers:
                    vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'severity': 'LOW',
                        'header': header,
                        'description': f'Missing {header} - {description}'
                    })
                    
        except Exception as e:
            print(f"❌ Security headers check error: {e}")
        
        return vulnerabilities
    
    def generate_report(self, results):
        """Generate a detailed vulnerability report"""
        print("\n" + "=" * 60)
        print("🎯 VULNSCAN X - SECURITY REPORT")
        print("=" * 60)
        
        print(f"\n📊 Target: {results['target']}")
        print(f"⏰ Scan Date: {results['timestamp']}")
        
        # Basic Information
        print(f"\n📋 BASIC INFORMATION:")
        print("-" * 30)
        info = results.get('info', {})
        print(f"Server: {info.get('server', 'Unknown')}")
        print(f"IP Address: {info.get('ip_address', 'Unknown')}")
        print(f"Status Code: {info.get('status_code', 'Unknown')}")
        print(f"CMS: {info.get('cms', 'Unknown')}")
        print(f"Framework: {info.get('framework', 'Unknown')}")
        
        # Vulnerabilities Summary
        vulnerabilities = results.get('vulnerabilities', [])
        print(f"\n🚨 VULNERABILITIES FOUND: {len(vulnerabilities)}")
        print("-" * 30)
        
        if vulnerabilities:
            high_vulns = [v for v in vulnerabilities if v['severity'] == 'HIGH']
            medium_vulns = [v for v in vulnerabilities if v['severity'] == 'MEDIUM']
            low_vulns = [v for v in vulnerabilities if v['severity'] == 'LOW']
            
            print(f"🔴 HIGH: {len(high_vulns)}")
            print(f"🟡 MEDIUM: {len(medium_vulns)}")
            print(f"🟢 LOW: {len(low_vulns)}")
            
            # Detailed vulnerabilities
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n{i}. {vuln['type']} [{vuln['severity']}]")
                print(f"   Description: {vuln['description']}")
                if 'url' in vuln:
                    print(f"   URL: {vuln['url']}")
                if 'payload' in vuln:
                    print(f"   Payload: {vuln['payload']}")
        else:
            print("✅ No vulnerabilities found!")
        
        # Port Scan Results
        ports = results.get('ports', {})
        if ports:
            print(f"\n🚪 PORT SCAN RESULTS:")
            print("-" * 30)
            open_ports = ports.get('open_ports', [])
            print(f"Open Ports: {len(open_ports)}")
            
            for port_info in open_ports:
                print(f"  Port {port_info['port']} ({port_info['service']}) - {port_info['status']}")
        
        # Recommendations
        print(f"\n💡 SECURITY RECOMMENDATIONS:")
        print("-" * 30)
        
        if any(v['type'] == 'SQL Injection' for v in vulnerabilities):
            print("• Use parameterized queries to prevent SQL injection")
            print("• Implement input validation and sanitization")
        
        if any(v['type'] == 'XSS (Cross-Site Scripting)' for v in vulnerabilities):
            print("• Implement Content Security Policy (CSP)")
            print("• Sanitize user input and encode output")
        
        if any(v['type'] == 'Missing Security Header' for v in vulnerabilities):
            print("• Add missing security headers to server configuration")
            print("• Implement proper HTTP security headers")
        
        if any(v['type'] == 'Exposed Directory/File' for v in vulnerabilities):
            print("• Restrict access to sensitive directories")
            print("• Remove exposed configuration files")
        
        if len(ports.get('open_ports', [])) > 5:
            print("• Close unnecessary open ports")
            print("• Implement firewall rules")
        
        print("\n" + "=" * 60)
        print("📊 SCAN COMPLETE - STAY SECURE!")
        print("=" * 60)

def main():
    """Main function to run VulnScan X"""
    print("🛡️  VULNSCAN X - AUTOMATED VULNERABILITY SCANNER")
    print("=" * 60)
    print("🔍 Free vulnerability scanner for ethical hacking")
    print("⚠️  Use only on authorized targets!")
    print("=" * 60)
    
    target_url = input("\n🌐 Enter target URL (e.g., https://example.com): ").strip()
    
    if not target_url:
        print("❌ Please enter a valid URL!")
        return
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    scanner = VulnScanX()
    
    try:
        results = scanner.scan_website(target_url)
        scanner.generate_report(results)
        
        # Save results to file
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Report saved to: {filename}")
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Scan error: {e}")

if __name__ == "__main__":
    main()
