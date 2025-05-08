import requests
import argparse
import re
import sqlite3
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import json
import time
from colorama import Fore, init, Style

init(autoreset=True)

class WebVulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.init_db()
        self.vulnerabilities = []
        self.scanned_urls = set()
        
    def init_db(self):
        """تهيئة قاعدة البيانات لتخزين النتائج"""
        self.conn = sqlite3.connect('vulnerabilities.db')
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                vulnerability_type TEXT,
                severity TEXT,
                description TEXT,
                payload TEXT,
                language TEXT,
                discovered_at TIMESTAMP
            )
        ''')
        self.conn.commit()
    
    def save_vulnerability(self, url, vuln_type, severity, description, payload, language):
        """حفظ الثغرة المكتشفة في قاعدة البيانات"""
        self.cursor.execute('''
            INSERT INTO vulnerabilities 
            (url, vulnerability_type, severity, description, payload, language, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (url, vuln_type, severity, description, payload, language, time.strftime('%Y-%m-%d %H:%M:%S')))
        self.conn.commit()
        self.vulnerabilities.append({
            'url': url,
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'payload': payload,
            'language': language
        })
    
    def scan_sql_injection(self, url, language):
        """فحص ثغرات SQL Injection"""
        payloads = {
            'php': ["'", "' OR '1'='1", "' OR 1=1 --", "' OR 1=1 #"],
            'asp': ["'", "' OR '1'='1", "' OR 1=1 --"],
            'java': ["'", "' OR '1'='1", "' OR 1=1 --"],
            'python': ["'", "' OR '1'='1", "' OR 1=1 --"]
        }
        
        for payload in payloads.get(language, payloads['php']):
            try:
                test_url = f"{url}?id={payload}"
                response = self.session.get(test_url, timeout=10)
                
                error_patterns = {
                    'php': ["SQL syntax", "MySQL server", "syntax error"],
                    'asp': ["Microsoft OLE DB Provider", "SQL Server", "syntax error"],
                    'java': ["java.sql.SQLException", "JDBC Driver", "SQL error"],
                    'python': ["sqlite3.Error", "psycopg2.Error", "MySQLdb.Error"]
                }
                
                for pattern in error_patterns.get(language, error_patterns['php']):
                    if pattern.lower() in response.text.lower():
                        self.save_vulnerability(
                            url, 'SQL Injection', 'High',
                            f"Possible SQL injection vulnerability detected using payload: {payload}",
                            payload, language
                        )
                        print(f"{Fore.RED}[!] SQL Injection vulnerability found at {url}")
                        return True
            except Exception as e:
                print(f"{Fore.YELLOW}[~] Error testing SQLi on {url}: {e}")
        return False
    
    def scan_xss(self, url, language):
        """فحص ثغرات Cross-Site Scripting (XSS)"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}?q={payload}"
                response = self.session.get(test_url, timeout=10)
                
                if payload in response.text:
                    self.save_vulnerability(
                        url, 'XSS', 'Medium',
                        f"Possible XSS vulnerability detected using payload: {payload}",
                        payload, language
                    )
                    print(f"{Fore.RED}[!] XSS vulnerability found at {url}")
                    return True
            except Exception as e:
                print(f"{Fore.YELLOW}[~] Error testing XSS on {url}: {e}")
        return False
    
    def scan_directory_traversal(self, url, language):
        """فحص ثغرات Directory Traversal"""
        payloads = {
            'php': ["../../../../etc/passwd", "../index.php"],
            'asp': ["..\\..\\..\\windows\\win.ini"],
            'java': ["../../WEB-INF/web.xml"],
            'python': ["../../../../etc/passwd"]
        }
        
        for payload in payloads.get(language, payloads['php']):
            try:
                test_url = f"{url}?file={payload}"
                response = self.session.get(test_url, timeout=10)
                
                sensitive_patterns = {
                    'php': ["root:x:", "<?php"],
                    'asp': ["[extensions]", "[fonts]"],
                    'java': ["<web-app>", "<servlet>"],
                    'python': ["root:x:", "import django"]
                }
                
                for pattern in sensitive_patterns.get(language, sensitive_patterns['php']):
                    if pattern.lower() in response.text.lower():
                        self.save_vulnerability(
                            url, 'Directory Traversal', 'High',
                            f"Possible directory traversal vulnerability detected using payload: {payload}",
                            payload, language
                        )
                        print(f"{Fore.RED}[!] Directory Traversal vulnerability found at {url}")
                        return True
            except Exception as e:
                print(f"{Fore.YELLOW}[~] Error testing Directory Traversal on {url}: {e}")
        return False
    
    def scan_rce(self, url, language):
        """فحص ثغرات Remote Code Execution"""
        payloads = {
            'php': [";id", "|id", "`id`", "$(id)"],
            'asp': ["|dir", "&dir"],
            'java': [";ls", "|ls"],
            'python': [";ls", "|ls"]
        }
        
        for payload in payloads.get(language, payloads['php']):
            try:
                test_url = f"{url}?cmd={payload}"
                response = self.session.get(test_url, timeout=10)
                
                rce_patterns = ["uid=", "gid=", "index.php", "Directory of"]
                
                for pattern in rce_patterns:
                    if pattern.lower() in response.text.lower():
                        self.save_vulnerability(
                            url, 'RCE', 'Critical',
                            f"Possible RCE vulnerability detected using payload: {payload}",
                            payload, language
                        )
                        print(f"{Fore.RED}[!] RCE vulnerability found at {url}")
                        return True
            except Exception as e:
                print(f"{Fore.YELLOW}[~] Error testing RCE on {url}: {e}")
        return False
    
    def detect_technology(self, url):
        """كشف التقنيات المستخدمة في الموقع"""
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            cookies = response.cookies
            content = response.text
            
            tech = {
                'language': 'unknown',
                'server': headers.get('Server', 'unknown'),
                'framework': 'unknown'
            }
            
            # الكشف عن لغة البرمجة
            if 'X-Powered-By' in headers:
                if 'PHP' in headers['X-Powered-By']:
                    tech['language'] = 'php'
                elif 'ASP.NET' in headers['X-Powered-By']:
                    tech['language'] = 'asp'
                elif 'JSP' in headers['X-Powered-By']:
                    tech['language'] = 'java'
            
            # إذا لم يتم الكشف من الهيدر، نبحث في المحتوى
            if tech['language'] == 'unknown':
                if '<?php' in content:
                    tech['language'] = 'php'
                elif '<%@ Page' in content:
                    tech['language'] = 'asp'
                elif 'jsp' in content.lower():
                    tech['language'] = 'java'
                elif 'django' in content.lower() or 'flask' in content.lower():
                    tech['language'] = 'python'
            
            # الكشف عن الإطارات
            if 'wordpress' in content.lower():
                tech['framework'] = 'WordPress'
            elif 'django' in content.lower():
                tech['framework'] = 'Django'
            elif 'laravel' in content.lower():
                tech['framework'] = 'Laravel'
            elif 'spring' in content.lower():
                tech['framework'] = 'Spring'
            
            return tech
            
        except Exception as e:
            print(f"{Fore.YELLOW}[~] Error detecting technology: {e}")
            return {'language': 'unknown', 'server': 'unknown', 'framework': 'unknown'}
    
    def crawl_website(self, base_url, max_pages=10):
        """زحف الموقع لاكتشاف الصفحات"""
        try:
            queue = [base_url]
            discovered = set()
            
            while queue and len(discovered) < max_pages:
                url = queue.pop(0)
                
                if url in self.scanned_urls:
                    continue
                    
                self.scanned_urls.add(url)
                
                try:
                    response = self.session.get(url, timeout=10)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        absolute_url = urljoin(url, href)
                        
                        if absolute_url.startswith(base_url) and absolute_url not in discovered:
                            discovered.add(absolute_url)
                            queue.append(absolute_url)
                            
                except Exception as e:
                    print(f"{Fore.YELLOW}[~] Error crawling {url}: {e}")
            
            return discovered
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error during crawling: {e}")
            return set()
    
    def scan_url(self, url, language='auto'):
        """فحص عنوان URL لاكتشاف الثغرات"""
        if language == 'auto':
            tech = self.detect_technology(url)
            language = tech['language']
            print(f"{Fore.CYAN}[*] Detected technology: {tech}")
        
        print(f"{Fore.BLUE}[*] Scanning {url} for vulnerabilities...")
        
        # إجراء الفحوصات
        self.scan_sql_injection(url, language)
        self.scan_xss(url, language)
        self.scan_directory_traversal(url, language)
        self.scan_rce(url, language)
    
    def generate_report(self, format='console'):
        """إنشاء تقرير بالثغرات المكتشفة"""
        if format == 'console':
            print(f"\n{Fore.GREEN}{Style.BRIGHT}=== Vulnerability Scan Report ===")
            print(f"{Fore.CYAN}Total vulnerabilities found: {len(self.vulnerabilities)}\n")
            
            for vuln in self.vulnerabilities:
                print(f"{Fore.RED}[!] {vuln['type']} ({vuln['severity']}) at {vuln['url']}")
                print(f"{Fore.YELLOW}Description: {vuln['description']}")
                print(f"{Fore.MAGENTA}Payload: {vuln['payload']}")
                print(f"{Fore.BLUE}Language: {vuln['language']}\n")
                
        elif format == 'json':
            report = {
                'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities
            }
            with open('vulnerability_report.json', 'w') as f:
                json.dump(report, f, indent=4)
            print(f"{Fore.GREEN}[*] Report saved to vulnerability_report.json")
    
    def close(self):
        """إغلاق اتصال قاعدة البيانات"""
        self.conn.close()

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-f', '--file', help='File containing list of URLs to scan')
    parser.add_argument('-l', '--language', help='Programming language (php, asp, java, python)', default='auto')
    parser.add_argument('-c', '--crawl', help='Crawl website to discover pages', action='store_true')
    parser.add_argument('-o', '--output', help='Output format (console, json)', default='console')
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.print_help()
        return
    
    scanner = WebVulnerabilityScanner()
    
    try:
        if args.url:
            if args.crawl:
                print(f"{Fore.CYAN}[*] Crawling {args.url} to discover pages...")
                urls = scanner.crawl_website(args.url)
                print(f"{Fore.GREEN}[*] Found {len(urls)} pages to scan")
                
                for url in urls:
                    scanner.scan_url(url, args.language)
            else:
                scanner.scan_url(args.url, args.language)
                
        elif args.file:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
                
            for url in urls:
                scanner.scan_url(url, args.language)
        
        scanner.generate_report(args.output)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user")
    except Exception as e:
        print(f"{Fore.RED}[!] Error during scanning: {e}")
    finally:
        scanner.close()

if __name__ == "__main__":
    main()
