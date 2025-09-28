
#!/usr/bin/env python3
"""
BlackDeD Web Application Security Scanner Module
Web vulnerability scanning and testing tools
"""

import requests
import threading
import time
import urllib.parse
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor
import ssl
import socket

console = Console(style="on black")

class WebScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerabilities = []
        
    def directory_bruteforce(self):
        """Directory and file discovery"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}📁 Directory Bruteforce Scanner")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        target_url = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter target URL: ").strip()
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        # Common directories and files
        wordlist = [
            'admin', 'administrator', 'login', 'panel', 'dashboard', 'config',
            'backup', 'test', 'dev', 'staging', 'api', 'v1', 'v2', 'uploads',
            'files', 'images', 'css', 'js', 'includes', 'inc', 'lib', 'libs',
            'tmp', 'temp', 'cache', 'logs', 'log', 'database', 'db', 'sql',
            'phpmyadmin', 'mysql', 'wp-admin', 'wp-content', 'wp-includes',
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config', 'crossdomain.xml',
            'readme.txt', 'changelog.txt', 'install.php', 'setup.php', 'info.php'
        ]
        
        found_paths = []
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning directories...", total=len(wordlist))
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {}
                
                for path in wordlist:
                    test_url = f"{target_url.rstrip('/')}/{path}"
                    future = executor.submit(self.check_url, test_url)
                    futures[future] = (path, test_url)
                
                for future in futures:
                    path, test_url = futures[future]
                    status_code, response_length = future.result()
                    
                    if status_code in [200, 301, 302, 403]:
                        found_paths.append({
                            'path': path,
                            'url': test_url,
                            'status': status_code,
                            'length': response_length
                        })
                    
                    progress.advance(task)
        
        # Display results
        if found_paths:
            results_table = Table(show_header=True, header_style="bold green on black", style="on black")
            results_table.add_column("Path", style="green on black")
            results_table.add_column("Status", style="bright_green on black")
            results_table.add_column("Length", style="white on black")
            results_table.add_column("URL", style="cyan on black")
            
            for result in found_paths:
                status_color = "green" if result['status'] == 200 else "yellow"
                results_table.add_row(
                    result['path'],
                    f"[{status_color}]{result['status']}[/{status_color}]",
                    str(result['length']),
                    result['url']
                )
            
            panel = Panel(results_table, title=f"[green on black]Directory Scan Results ({len(found_paths)} found)[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
        else:
            console.print(f"{Back.BLACK}{Fore.YELLOW}[!] No accessible directories found")
    
    def check_url(self, url):
        """Check if URL is accessible"""
        try:
            response = self.session.get(url, timeout=5, allow_redirects=False)
            return response.status_code, len(response.content)
        except:
            return 0, 0
    
    def sql_injection_test(self):
        """Basic SQL injection testing"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}💉 SQL Injection Tester")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        target_url = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter target URL with parameter: ").strip()
        
        # SQL injection payloads
        payloads = [
            "'", "''", "\"", "\"\"", "/", "//", "\\", "\\\\",
            "1'", "1\"", "1/", "1\\", "1')", "1\")", "1/)", "1\\)",
            "1' OR '1'='1", "1\" OR \"1\"=\"1", "1' OR '1'='1' --",
            "1\" OR \"1\"=\"1\" --", "1' OR '1'='1' /*", "1\" OR \"1\"=\"1\" /*",
            "admin'--", "admin\"--", "admin'/*", "admin\"/*",
            "' UNION SELECT NULL--", "\" UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--", "\" UNION SELECT 1,2,3--"
        ]
        
        vulnerable = False
        
        try:
            # Get normal response first
            normal_response = self.session.get(target_url, timeout=10)
            normal_length = len(normal_response.content)
            
            console.print(f"{Back.BLACK}{Fore.GREEN}[+] Testing {len(payloads)} SQL injection payloads...")
            
            vulnerabilities = []
            
            for payload in payloads:
                # Test GET parameter injection
                if '?' in target_url:
                    test_url = target_url + urllib.parse.quote(payload)
                else:
                    test_url = target_url + '?id=' + urllib.parse.quote(payload)
                
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for SQL error messages
                    error_signatures = [
                        'mysql_fetch', 'ORA-', 'Microsoft OLE DB', 'ODBC SQL',
                        'PostgreSQL', 'SQLite', 'mysql_num_rows', 'mysql_query',
                        'Warning: mysql', 'Error: mysql', 'SQL syntax error',
                        'syntax error at or near', 'mysql_result', 'ora-00942'
                    ]
                    
                    response_text = response.text.lower()
                    for signature in error_signatures:
                        if signature.lower() in response_text:
                            vulnerabilities.append({
                                'payload': payload,
                                'url': test_url,
                                'error': signature,
                                'method': 'GET'
                            })
                            vulnerable = True
                            break
                    
                    # Check for response length differences
                    if abs(len(response.content) - normal_length) > 100:
                        vulnerabilities.append({
                            'payload': payload,
                            'url': test_url,
                            'error': 'Response length difference detected',
                            'method': 'GET'
                        })
                        vulnerable = True
                
                except:
                    continue
            
            # Display results
            if vulnerabilities:
                vuln_table = Table(show_header=True, header_style="bold red on black", style="on black")
                vuln_table.add_column("Payload", style="red on black")
                vuln_table.add_column("Method", style="green on black")
                vuln_table.add_column("Evidence", style="yellow on black")
                
                for vuln in vulnerabilities[:10]:  # Show first 10 results
                    vuln_table.add_row(
                        vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload'],
                        vuln['method'],
                        vuln['error'][:40] + "..." if len(vuln['error']) > 40 else vuln['error']
                    )
                
                panel = Panel(vuln_table, title="[red on black]⚠️ SQL Injection Vulnerabilities Detected ⚠️[/red on black]", border_style="red on black", style="on black")
                console.print(panel)
                
                console.print(f"\n{Back.BLACK}{Fore.RED}[!] CRITICAL: SQL injection vulnerability detected!")
                console.print(f"{Back.BLACK}{Fore.RED}[!] This application is vulnerable to SQL injection attacks!")
            else:
                console.print(f"{Back.BLACK}{Fore.GREEN}[+] No obvious SQL injection vulnerabilities detected")
                
        except Exception as e:
            console.print(f"{Back.BLACK}{Fore.RED}[-] Error during SQL injection test: {e}")
    
    def xss_scanner(self):
        """Cross-Site Scripting (XSS) scanner"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🔗 XSS Vulnerability Scanner")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        target_url = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter target URL: ").strip()
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "\"><img src=x onerror=alert('XSS')>"
        ]
        
        vulnerabilities = []
        
        for payload in xss_payloads:
            # Test GET parameter
            if '?' in target_url:
                test_url = target_url + '&xss=' + urllib.parse.quote(payload)
            else:
                test_url = target_url + '?xss=' + urllib.parse.quote(payload)
            
            try:
                response = self.session.get(test_url, timeout=5)
                
                # Check if payload is reflected in response
                if payload in response.text or urllib.parse.quote(payload) in response.text:
                    vulnerabilities.append({
                        'payload': payload,
                        'url': test_url,
                        'type': 'Reflected XSS',
                        'method': 'GET'
                    })
            except:
                continue
        
        # Display results
        if vulnerabilities:
            xss_table = Table(show_header=True, header_style="bold red on black", style="on black")
            xss_table.add_column("Type", style="red on black")
            xss_table.add_column("Method", style="green on black")
            xss_table.add_column("Payload", style="yellow on black")
            
            for vuln in vulnerabilities:
                xss_table.add_row(
                    vuln['type'],
                    vuln['method'],
                    vuln['payload'][:50] + "..." if len(vuln['payload']) > 50 else vuln['payload']
                )
            
            panel = Panel(xss_table, title="[red on black]⚠️ XSS Vulnerabilities Detected ⚠️[/red on black]", border_style="red on black", style="on black")
            console.print(panel)
            
            console.print(f"\n{Back.BLACK}{Fore.RED}[!] CRITICAL: XSS vulnerability detected!")
        else:
            console.print(f"{Back.BLACK}{Fore.GREEN}[+] No XSS vulnerabilities detected")
    
    def ssl_certificate_check(self):
        """SSL/TLS certificate analysis"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🔒 SSL/TLS Certificate Analysis")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        hostname = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter hostname: ").strip()
        port = 443
        
        try:
            # Get SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            
            # Analyze certificate
            cert_table = Table(show_header=False, border_style="green on black", style="on black")
            cert_table.add_column("Property", style="green on black", justify="right")
            cert_table.add_column("Value", style="bright_green on black")
            
            cert_table.add_row("Subject", str(dict(x[0] for x in cert['subject'])))
            cert_table.add_row("Issuer", str(dict(x[0] for x in cert['issuer'])))
            cert_table.add_row("Version", str(cert['version']))
            cert_table.add_row("Serial Number", str(cert['serialNumber']))
            cert_table.add_row("Not Before", cert['notBefore'])
            cert_table.add_row("Not After", cert['notAfter'])
            
            if 'subjectAltName' in cert:
                alt_names = ', '.join([name[1] for name in cert['subjectAltName']])
                cert_table.add_row("Alt Names", alt_names)
            
            panel = Panel(cert_table, title=f"[green on black]SSL Certificate for {hostname}[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
            
            # Check for vulnerabilities
            issues = []
            
            # Check expiry
            from datetime import datetime
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.now()).days
            
            if days_until_expiry < 30:
                issues.append(f"Certificate expires in {days_until_expiry} days")
            
            if issues:
                console.print(f"\n{Back.BLACK}{Fore.YELLOW}[!] SSL Issues found:")
                for issue in issues:
                    console.print(f"{Back.BLACK}{Fore.YELLOW}  - {issue}")
            else:
                console.print(f"\n{Back.BLACK}{Fore.GREEN}[+] SSL certificate appears to be valid")
                
        except Exception as e:
            console.print(f"{Back.BLACK}{Fore.RED}[-] SSL analysis failed: {e}")
    
    def show_menu(self):
        """Display web scanner menu"""
        while True:
            console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🕸️ WEB APPLICATION SECURITY MODULE")
            console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 50)
            
            options = [
                ("1", "📁 Directory Bruteforce", "Discover hidden directories and files"),
                ("2", "💉 SQL Injection Scanner", "Test for SQL injection vulnerabilities"),
                ("3", "🔗 XSS Scanner", "Test for Cross-Site Scripting vulnerabilities"),
                ("4", "🔒 SSL Certificate Analysis", "Analyze SSL/TLS certificates"),
                ("5", "🌐 HTTP Header Analysis", "Analyze security headers"),
                ("0", "🔙 Back to Main Menu", "Return to BlackDeD main menu")
            ]
            
            menu_table = Table(show_header=True, header_style="bold green on black", style="on black")
            menu_table.add_column("Option", style="green on black", justify="center", width=8)
            menu_table.add_column("Tool", style="bright_green on black", width=30)
            menu_table.add_column("Description", style="white on black", width=40)
            
            for option, tool, description in options:
                menu_table.add_row(option, tool, description)
            
            panel = Panel(menu_table, title="[green on black]Web Security Tools[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
            
            try:
                choice = input(f"\n{Back.BLACK}{Fore.GREEN}root@blackded:~# Select option: ").strip()
                
                if choice == "1":
                    self.directory_bruteforce()
                elif choice == "2":
                    self.sql_injection_test()
                elif choice == "3":
                    self.xss_scanner()
                elif choice == "4":
                    self.ssl_certificate_check()
                elif choice == "5":
                    self.http_header_analysis()
                elif choice == "0":
                    break
                else:
                    console.print(f"{Back.BLACK}{Fore.RED}[-] Invalid option!")
                
                if choice != "0":
                    input(f"\n{Back.BLACK}{Fore.GREEN}[*] Press Enter to continue...")
                    
            except KeyboardInterrupt:
                console.print(f"\n{Back.BLACK}{Fore.YELLOW}[!] Returning to main menu...")
                break
    
    def http_header_analysis(self):
        """Analyze HTTP security headers"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🌐 HTTP Header Security Analysis")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        target_url = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter target URL: ").strip()
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        try:
            response = self.session.get(target_url, timeout=10)
            headers = response.headers
            
            # Security headers to check
            security_headers = {
                'Strict-Transport-Security': 'HSTS - Enforces HTTPS connections',
                'Content-Security-Policy': 'CSP - Prevents XSS attacks',
                'X-Frame-Options': 'Prevents clickjacking attacks',
                'X-Content-Type-Options': 'Prevents MIME sniffing',
                'X-XSS-Protection': 'Built-in XSS protection',
                'Referrer-Policy': 'Controls referrer information',
                'Permissions-Policy': 'Controls browser feature permissions'
            }
            
            header_table = Table(show_header=True, header_style="bold green on black", style="on black")
            header_table.add_column("Header", style="green on black")
            header_table.add_column("Status", style="bright_green on black")
            header_table.add_column("Value", style="white on black")
            header_table.add_column("Description", style="cyan on black")
            
            missing_headers = []
            
            for header, description in security_headers.items():
                if header in headers:
                    status = "✅ Present"
                    value = headers[header][:50] + "..." if len(headers[header]) > 50 else headers[header]
                else:
                    status = "❌ Missing"
                    value = "Not set"
                    missing_headers.append(header)
                
                header_table.add_row(header, status, value, description)
            
            panel = Panel(header_table, title=f"[green on black]Security Headers Analysis[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
            
            if missing_headers:
                console.print(f"\n{Back.BLACK}{Fore.YELLOW}[!] Missing security headers:")
                for header in missing_headers:
                    console.print(f"{Back.BLACK}{Fore.YELLOW}  - {header}")
            else:
                console.print(f"\n{Back.BLACK}{Fore.GREEN}[+] All recommended security headers are present")
                
        except Exception as e:
            console.print(f"{Back.BLACK}{Fore.RED}[-] Header analysis failed: {e}")

def main():
    scanner = WebScanner()
    scanner.show_menu()

if __name__ == "__main__":
    main()
