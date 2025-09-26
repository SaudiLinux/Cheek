#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cheek - أداة فحص أمني شاملة
Cheek - Comprehensive Security Scanning Tool

المبرمج: SayerLinux
الإيميل: SaudiSayer@gmail.com
"""

import argparse
import socket
import requests
import json
import time
import threading
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import ssl
import smtplib
import imaplib
import poplib
import subprocess
import sys
from datetime import datetime

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

class CheekScanner:
    def __init__(self, target, threads=10, timeout=5):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'web_servers': [],
            'email_servers': [],
            'databases': [],
            'frameworks': [],
            'cms': [],
            'cicd': [],
            'containers': [],
            'vulnerabilities': [],
            'ports': []
        }
        
    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
 ██████╗██╗  ██╗███████╗███████╗███████╗
██╔════╝██║  ██║██╔════╝██╔════╝██╔════╝
██║     ███████║█████╗  █████╗  █████╗  
██║     ██╔══██║██╔══╝  ██╔══╝  ██╔══╝  
╚██████╗██║  ██║███████╗███████╗███████╗
 ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
{Colors.PURPLE}
    أداة فحص أمني شاملة
    Comprehensive Security Scanner
    
{Colors.YELLOW}المبرمج: {Colors.GREEN}SayerLinux
{Colors.YELLOW}الإيميل: {Colors.GREEN}SaudiSayer@gmail.com
{Colors.RESET}
"""
        print(banner)
        
    def is_port_open(self, port):
        """فحص ما إذا كان المنفذ مفتوحاً"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_ports(self, ports):
        """مسح المنافذ"""
        print(f"{Colors.YELLOW}[*] بدء مسح المنافذ...{Colors.RESET}")
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.is_port_open, port): port for port in ports}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                if future.result():
                    open_ports.append(port)
                    print(f"{Colors.GREEN}[+] المنفذ {port} مفتوح{Colors.RESET}")
        
        self.results['ports'] = open_ports
        return open_ports
    
    def detect_web_server(self):
        """الكشف عن خادم الويب"""
        print(f"{Colors.YELLOW}[*] الكشف عن خوادم الويب...{Colors.RESET}")
        
        try:
            # اختبار HTTP
            url = f"http://{self.target}"
            response = requests.get(url, timeout=self.timeout, headers={'User-Agent': 'CheekScanner/1.0'})
            
            server_info = {
                'type': 'Unknown',
                'version': 'Unknown',
                'method': 'HTTP Headers',
                'port': 80
            }
            
            # تحليل الرؤوس
            if 'Server' in response.headers:
                server_header = response.headers['Server']
                
                if 'Apache' in server_header:
                    server_info['type'] = 'Apache HTTP Server'
                    version_match = re.search(r'Apache/([\d.]+)', server_header)
                    if version_match:
                        server_info['version'] = version_match.group(1)
                
                elif 'nginx' in server_header.lower():
                    server_info['type'] = 'Nginx'
                    version_match = re.search(r'nginx/([\d.]+)', server_header)
                    if version_match:
                        server_info['version'] = version_match.group(1)
                
                elif 'Microsoft-IIS' in server_header:
                    server_info['type'] = 'Microsoft IIS'
                    version_match = re.search(r'Microsoft-IIS/([\d.]+)', server_header)
                    if version_match:
                        server_info['version'] = version_match.group(1)
                
                elif 'lighttpd' in server_header.lower():
                    server_info['type'] = 'Lighttpd'
                    version_match = re.search(r'lighttpd/([\d.]+)', server_header)
                    if version_match:
                        server_info['version'] = version_match.group(1)
                
                else:
                    server_info['type'] = server_header
            
            # اختبار HTTPS
            try:
                https_url = f"https://{self.target}"
                https_response = requests.get(https_url, timeout=self.timeout, verify=False)
                
                if 'Server' in https_response.headers:
                    https_server = {
                        'type': 'Unknown',
                        'version': 'Unknown',
                        'method': 'HTTPS Headers',
                        'port': 443
                    }
                    
                    server_header = https_response.headers['Server']
                    if 'Apache' in server_header:
                        https_server['type'] = 'Apache HTTP Server'
                    elif 'nginx' in server_header.lower():
                        https_server['type'] = 'Nginx'
                    elif 'Microsoft-IIS' in server_header:
                        https_server['type'] = 'Microsoft IIS'
                    
                    self.results['web_servers'].append(https_server)
                    print(f"{Colors.GREEN}[+] خادم ويب (HTTPS): {https_server['type']} على المنفذ 443{Colors.RESET}")
            except:
                pass
            
            self.results['web_servers'].append(server_info)
            print(f"{Colors.GREEN}[+] خادم ويب (HTTP): {server_info['type']} {server_info['version']} على المنفذ 80{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[-] فشل الكشف عن خادم الويب: {e}{Colors.RESET}")
    
    def detect_email_servers(self):
        """الكشف عن خوادم البريد الإلكتروني"""
        print(f"{Colors.YELLOW}[*] الكشف عن خوادم البريد الإلكتروني...{Colors.RESET}")
        
        email_ports = {
            25: ('SMTP', self.test_smtp),
            587: ('SMTP Submission', self.test_smtp),
            465: ('SMTPS', self.test_smtps),
            143: ('IMAP', self.test_imap),
            993: ('IMAPS', self.test_imaps),
            110: ('POP3', self.test_pop3),
            995: ('POP3S', self.test_pop3s)
        }
        
        for port, (service, test_func) in email_ports.items():
            if self.is_port_open(port):
                try:
                    result = test_func(port)
                    if result:
                        self.results['email_servers'].append(result)
                        print(f"{Colors.GREEN}[+] خادم بريد: {result['type']} على المنفذ {port}{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.RED}[-] فشل اختبار {service} على المنفذ {port}: {e}{Colors.RESET}")
    
    def test_smtp(self, port):
        """اختبار SMTP"""
        try:
            server = smtplib.SMTP(self.target, port, timeout=self.timeout)
            banner = server.ehlo()
            server.quit()
            
            return {
                'type': 'SMTP Server',
                'port': port,
                'banner': str(banner) if banner else 'Unknown'
            }
        except:
            return None
    
    def test_smtps(self, port):
        """اختبار SMTPS"""
        try:
            server = smtplib.SMTP_SSL(self.target, port, timeout=self.timeout)
            banner = server.ehlo()
            server.quit()
            
            return {
                'type': 'SMTPS Server',
                'port': port,
                'banner': str(banner) if banner else 'Unknown'
            }
        except:
            return None
    
    def test_imap(self, port):
        """اختبار IMAP"""
        try:
            server = imaplib.IMAP4(self.target, port)
            banner = server.welcome
            server.logout()
            
            return {
                'type': 'IMAP Server',
                'port': port,
                'banner': str(banner) if banner else 'Unknown'
            }
        except:
            return None
    
    def test_imaps(self, port):
        """اختبار IMAPS"""
        try:
            server = imaplib.IMAP4_SSL(self.target, port)
            banner = server.welcome
            server.logout()
            
            return {
                'type': 'IMAPS Server',
                'port': port,
                'banner': str(banner) if banner else 'Unknown'
            }
        except:
            return None
    
    def test_pop3(self, port):
        """اختبار POP3"""
        try:
            server = poplib.POP3(self.target, port, timeout=self.timeout)
            banner = server.getwelcome()
            server.quit()
            
            return {
                'type': 'POP3 Server',
                'port': port,
                'banner': str(banner) if banner else 'Unknown'
            }
        except:
            return None
    
    def test_pop3s(self, port):
        """اختبار POP3S"""
        try:
            server = poplib.POP3_SSL(self.target, port, timeout=self.timeout)
            banner = server.getwelcome()
            server.quit()
            
            return {
                'type': 'POP3S Server',
                'port': port,
                'banner': str(banner) if banner else 'Unknown'
            }
        except:
            return None
    
    def detect_databases(self):
        """الكشف عن قواعد البيانات"""
        print(f"{Colors.YELLOW}[*] الكشف عن قواعد البيانات...{Colors.RESET}")
        
        db_ports = {
            3306: ('MySQL', 'MySQL Database'),
            5432: ('PostgreSQL', 'PostgreSQL Database'),
            6379: ('Redis', 'Redis Database'),
            27017: ('MongoDB', 'MongoDB Database'),
            11211: ('Memcached', 'Memcached'),
            5984: ('CouchDB', 'CouchDB Database'),
            9200: ('Elasticsearch', 'Elasticsearch')
        }
        
        for port, (service, full_name) in db_ports.items():
            if self.is_port_open(port):
                self.results['databases'].append({
                    'type': full_name,
                    'port': port,
                    'service': service
                })
                print(f"{Colors.GREEN}[+] قاعدة بيانات: {full_name} على المنفذ {port}{Colors.RESET}")
    
    def detect_frameworks(self):
        """الكشف عن الأطر والتقنيات"""
        print(f"{Colors.YELLOW}[*] الكشف عن الأطر وتقنيات الويب...{Colors.RESET}")
        
        try:
            url = f"http://{self.target}"
            response = requests.get(url, timeout=self.timeout)
            
            # تحليل الرؤوس للكشف عن الأطر
            headers = response.headers
            content = response.text
            
            frameworks = []
            
            # Django
            if 'csrftoken' in response.cookies or 'WSGIServer' in content:
                frameworks.append({'type': 'Django', 'method': 'Cookies/Content'})
            
            # Flask
            if 'Werkzeug' in content or 'flask' in content.lower():
                frameworks.append({'type': 'Flask', 'method': 'Content Analysis'})
            
            # Ruby on Rails
            if 'csrf-token' in content or 'rails' in content.lower():
                frameworks.append({'type': 'Ruby on Rails', 'method': 'Content Analysis'})
            
            # Laravel
            if 'laravel' in content.lower() or 'csrf-token' in content:
                frameworks.append({'type': 'Laravel', 'method': 'Content Analysis'})
            
            # Express.js
            if 'express' in content.lower() or 'X-Powered-By' in headers and 'Express' in headers['X-Powered-By']:
                frameworks.append({'type': 'Express.js', 'method': 'Headers/Content'})
            
            # ASP.NET
            if 'X-Powered-By' in headers and 'ASP.NET' in headers['X-Powered-By']:
                frameworks.append({'type': 'ASP.NET', 'method': 'Headers'})
            
            # Spring
            if 'X-Application-Context' in headers or 'spring' in content.lower():
                frameworks.append({'type': 'Spring Framework', 'method': 'Headers/Content'})
            
            # PHP
            if 'X-Powered-By' in headers and 'PHP' in headers['X-Powered-By']:
                version_match = re.search(r'PHP/([\d.]+)', headers['X-Powered-By'])
                version = version_match.group(1) if version_match else 'Unknown'
                frameworks.append({'type': 'PHP', 'version': version, 'method': 'Headers'})
            
            self.results['frameworks'] = frameworks
            
            for framework in frameworks:
                version_info = f" {framework.get('version', '')}" if framework.get('version') else ''
                print(f"{Colors.GREEN}[+] إطار عمل: {framework['type']}{version_info}{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.RED}[-] فشل الكشف عن الأطر: {e}{Colors.RESET}")
    
    def detect_cms(self):
        """الكشف عن أنظمة إدارة المحتوى"""
        print(f"{Colors.YELLOW}[*] الكشف عن أنظمة إدارة المحتوى...{Colors.RESET}")
        
        try:
            # مسارات CMS المشهورة
            cms_paths = {
                'WordPress': ['/wp-content/', '/wp-includes/', '/wp-admin/', '/xmlrpc.php'],
                'Joomla': ['/administrator/', '/components/', '/modules/', '/plugins/'],
                'Drupal': ['/sites/', '/modules/', '/themes/', '/core/'],
                'Magento': ['/admin/', '/catalog/', '/customer/', '/checkout/'],
                'OpenCart': ['/admin/', '/catalog/', '/system/', '/image/'],
                'PrestaShop': ['/admin/', '/modules/', '/themes/', '/img/']
            }
            
            detected_cms = []
            
            for cms_name, paths in cms_paths.items():
                for path in paths:
                    try:
                        url = f"http://{self.target}{path}"
                        response = requests.head(url, timeout=self.timeout, allow_redirects=True)
                        
                        if response.status_code == 200:
                            detected_cms.append({
                                'type': cms_name,
                                'path': path,
                                'method': 'Path Detection'
                            })
                            print(f"{Colors.GREEN}[+] CMS: {cms_name} (العثور على: {path}){Colors.RESET}")
                            break
                    except:
                        continue
            
            self.results['cms'] = detected_cms
            
        except Exception as e:
            print(f"{Colors.RED}[-] فشل الكشف عن CMS: {e}{Colors.RESET}")
    
    def detect_cicd(self):
        """الكشف عن منصات CI/CD"""
        print(f"{Colors.YELLOW}[*] الكشف عن منصات CI/CD...{Colors.RESET}")
        
        cicd_indicators = {
            'Jenkins': ['/jenkins/', '/job/', '/build/', 'X-Jenkins'],
            'GitLab': ['/gitlab/', '/api/v4/', '/-/metrics'],
            'Travis CI': ['travis-ci', '.travis.yml'],
            'Drone CI': ['/drone/', '.drone.yml'],
            'GoCD': ['/go/', 'CruiseControl'],
            'GitHub Actions': ['.github/workflows/', 'github-actions']
        }
        
        try:
            url = f"http://{self.target}"
            response = requests.get(url, timeout=self.timeout)
            
            detected_cicd = []
            
            for cicd_name, indicators in cicd_indicators.items():
                for indicator in indicators:
                    # فحص الرؤوس
                    if indicator in response.headers:
                        detected_cicd.append({
                            'type': cicd_name,
                            'method': 'Headers',
                            'indicator': indicator
                        })
                        print(f"{Colors.GREEN}[+] CI/CD: {cicd_name} (عبر الرؤوس){Colors.RESET}")
                        break
                    
                    # فحص المحتوى
                    if indicator in response.text:
                        detected_cicd.append({
                            'type': cicd_name,
                            'method': 'Content',
                            'indicator': indicator
                        })
                        print(f"{Colors.GREEN}[+] CI/CD: {cicd_name} (عبر المحتوى){Colors.RESET}")
                        break
                    
                    # فحص المسارات
                    try:
                        test_url = f"http://{self.target}{indicator}"
                        test_response = requests.head(test_url, timeout=self.timeout)
                        if test_response.status_code == 200:
                            detected_cicd.append({
                                'type': cicd_name,
                                'method': 'Path Detection',
                                'indicator': indicator
                            })
                            print(f"{Colors.GREEN}[+] CI/CD: {cicd_name} (العثور على: {indicator}){Colors.RESET}")
                            break
                    except:
                        continue
            
            self.results['cicd'] = detected_cicd
            
        except Exception as e:
            print(f"{Colors.RED}[-] فشل الكشف عن CI/CD: {e}{Colors.RESET}")
    
    def detect_containers(self):
        """الكشف عن الحاويات والتنسيق"""
        print(f"{Colors.YELLOW}[*] الكشف عن الحاويات والتنسيق...{Colors.RESET}")
        
        container_ports = {
            6443: ('Kubernetes API', 'Kubernetes'),
            2375: ('Docker API', 'Docker'),
            2376: ('Docker API (TLS)', 'Docker'),
            8080: ('Kubernetes Dashboard', 'Kubernetes'),
            8500: ('Consul', 'HashiCorp Consul'),
            4646: ('Nomad', 'HashiCorp Nomad'),
            8088: ('YARN ResourceManager', 'Hadoop YARN'),
            50070: ('Hadoop NameNode', 'Hadoop HDFS')
        }
        
        detected_containers = []
        
        for port, (service, platform) in container_ports.items():
            if self.is_port_open(port):
                detected_containers.append({
                    'type': platform,
                    'service': service,
                    'port': port
                })
                print(f"{Colors.GREEN}[+] منصة حاويات: {platform} ({service}) على المنفذ {port}{Colors.RESET}")
        
        self.results['containers'] = detected_containers
    
    def detect_vulnerabilities(self):
        """الكشف عن الثغرات الأمنية"""
        print(f"{Colors.YELLOW}[*] الكشف عن الثغرات الأمنية...{Colors.RESET}")
        
        vulnerabilities = []
        
        try:
            url = f"http://{self.target}"
            response = requests.get(url, timeout=self.timeout)
            headers = response.headers
            
            # فحص تصفح الدليل
            if response.status_code == 403 and 'Index of /' in response.text:
                vulnerabilities.append({
                    'type': 'Directory Listing Enabled',
                    'severity': 'Medium',
                    'description': 'تمكين تصفح الدليل قد يكشف عن ملفات حساسة'
                })
                print(f"{Colors.RED}[!] ثغرة: تمكين تصفح الدليل{Colors.RESET}")
            
            # فحص رؤوس الأمان
            security_headers = {
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'X-XSS-Protection': 'XSS Protection',
                'Strict-Transport-Security': 'HTTPS Enforcement',
                'Content-Security-Policy': 'Content Security Policy'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': f'Missing {header}',
                        'severity': 'Low',
                        'description': f'رأس الأمان {header} مفقود: {description}'
                    })
                    print(f"{Colors.YELLOW}[!] تحذير: رأس الأمان {header} مفقود{Colors.RESET}")
            
            # فحص ملفات تعريف الارتباط
            for cookie in response.cookies:
                if not cookie.secure:
                    vulnerabilities.append({
                        'type': 'Insecure Cookie Configuration',
                        'severity': 'Low',
                        'description': f'ملف تعريف الارتباط {cookie.name} لا يستخدم علامة Secure'
                    })
                    print(f"{Colors.YELLOW}[!] تحذير: ملف تعريف الارتباط {cookie.name} غير آمن{Colors.RESET}")
                
                if not hasattr(cookie, 'httponly') or not cookie.httponly:
                    vulnerabilities.append({
                        'type': 'Cookie Missing HttpOnly Flag',
                        'severity': 'Low',
                        'description': f'ملف تعريف الارتباط {cookie.name} لا يحتوي على علامة HttpOnly'
                    })
            
            # فحص معلومات الخادم
            if 'Server' in headers:
                server_info = headers['Server']
                if '/' in server_info:
                    vulnerabilities.append({
                        'type': 'Server Version Disclosure',
                        'severity': 'Low',
                        'description': f'تم الكشف عن إصدار الخادم: {server_info}'
                    })
                    print(f"{Colors.YELLOW}[!] تحذير: الكشف عن إصدار الخادم{Colors.RESET}")
            
            # فحص الروابط المخفية
            hidden_links = re.findall(r'<a[^>]*href=["\']?([^"\'>]+)', response.text, re.IGNORECASE)
            interesting_paths = ['/admin', '/config', '/backup', '/test', '/dev', '/debug']
            
            for link in hidden_links:
                for path in interesting_paths:
                    if path in link.lower():
                        vulnerabilities.append({
                            'type': 'Potentially Sensitive Path',
                            'severity': 'Info',
                            'description': f'تم العثور على مسار حساس محتمل: {link}'
                        })
                        print(f"{Colors.CYAN}[i] معلومات: مسار حساس محتمل: {link}{Colors.RESET}")
            
            self.results['vulnerabilities'] = vulnerabilities
            
        except Exception as e:
            print(f"{Colors.RED}[-] فشل الكشف عن الثغرات: {e}{Colors.RESET}")
    
    def generate_report(self):
        """إنشاء تقرير مفصل"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== تقرير الفحص الأمني ==={Colors.RESET}")
        print(f"{Colors.YELLOW}الهدف: {Colors.GREEN}{self.target}{Colors.RESET}")
        print(f"{Colors.YELLOW}وقت الفحص: {Colors.GREEN}{self.results['scan_time']}{Colors.RESET}")
        
        print(f"\n{Colors.BLUE}[+] المنافذ المفتوحة:{Colors.RESET}")
        for port in self.results['ports']:
            print(f"  - المنفذ {port}")
        
        print(f"\n{Colors.BLUE}[+] خوادم الويب:{Colors.RESET}")
        for server in self.results['web_servers']:
            print(f"  - {server['type']} {server.get('version', '')} (المنفذ {server['port']})")
        
        print(f"\n{Colors.BLUE}[+] خوادم البريد الإلكتروني:{Colors.RESET}")
        for server in self.results['email_servers']:
            print(f"  - {server['type']} (المنفذ {server['port']})")
        
        print(f"\n{Colors.BLUE}[+] قواعد البيانات:{Colors.RESET}")
        for db in self.results['databases']:
            print(f"  - {db['type']} (المنفذ {db['port']})")
        
        print(f"\n{Colors.BLUE}[+] الأطر وتقنيات الويب:{Colors.RESET}")
        for framework in self.results['frameworks']:
            version_info = f" {framework.get('version', '')}" if framework.get('version') else ''
            print(f"  - {framework['type']}{version_info}")
        
        print(f"\n{Colors.BLUE}[+] أنظمة إدارة المحتوى:{Colors.RESET}")
        for cms in self.results['cms']:
            print(f"  - {cms['type']} (تم الكشف عبر: {cms['path']})")
        
        print(f"\n{Colors.BLUE}[+] منصات CI/CD:{Colors.RESET}")
        for cicd in self.results['cicd']:
            print(f"  - {cicd['type']} (الطريقة: {cicd['method']})")
        
        print(f"\n{Colors.BLUE}[+] منصات الحاويات:{Colors.RESET}")
        for container in self.results['containers']:
            print(f"  - {container['type']} ({container['service']}) على المنفذ {container['port']}")
        
        if self.results['vulnerabilities']:
            print(f"\n{Colors.RED}[!] الثغرات الأمنية المكتشفة:{Colors.RESET}")
            for vuln in self.results['vulnerabilities']:
                severity_color = Colors.RED if vuln['severity'] == 'High' else Colors.YELLOW
                print(f"{severity_color}  - {vuln['type']} (الخطورة: {vuln['severity']}){Colors.RESET}")
                print(f"    الوصف: {vuln['description']}")
        else:
            print(f"\n{Colors.GREEN}[+] لم يتم العثور على ثغرات أمنية واضحة{Colors.RESET}")
        
        # حفظ التقرير كملف JSON
        report_filename = f"cheek_report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(report_filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, ensure_ascii=False, indent=2)
            print(f"\n{Colors.GREEN}[+] تم حفظ التقرير الكامل في: {report_filename}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] فشل حفظ التقرير: {e}{Colors.RESET}")
    
    def run_full_scan(self):
        """تشغيل فحص شامل"""
        self.print_banner()
        
        # مسح المنافذ الشائعة
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
        self.scan_ports(common_ports)
        
        # تشغيل جميع وحدات الكشف
        self.detect_web_server()
        self.detect_email_servers()
        self.detect_databases()
        self.detect_frameworks()
        self.detect_cms()
        self.detect_cicd()
        self.detect_containers()
        self.detect_vulnerabilities()
        
        # إنشاء التقرير
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(
        description='Cheek - أداة فحص أمني شاملة | Comprehensive Security Scanner',
        epilog='المبرمج: SayerLinux | الإيميل: SaudiSayer@gmail.com',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('target', help='الهدف (IP أو نطاق)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='عدد مؤشرات الترابط (افتراضي: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='مهلة الاتصال بالثواني (افتراضي: 5)')
    parser.add_argument('--ports', nargs='+', type=int, help='المنافذ المحددة للفحص')
    parser.add_argument('--output', help='ملف الإخراج للتقرير')
    
    args = parser.parse_args()
    
    scanner = CheekScanner(args.target, args.threads, args.timeout)
    
    try:
        scanner.run_full_scan()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] تم إيقاف الفحص بواسطة المستخدم{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] خطأ غير متوقع: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == '__main__':
    main()