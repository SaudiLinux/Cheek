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
import platform
import warnings
from colorama import init, Fore, Back, Style
import dns.resolver
import nmap
from exploits.web_exploits import WebExploits
from exploits.advanced_exploits import AdvancedExploits
from exploits.modern_vulnerabilities import ModernVulnerabilities

# Initialize colorama for Windows compatibility
init(autoreset=True)

class Colors:
    # Use colorama colors for better cross-platform support
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    PURPLE = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    BOLD = Style.BRIGHT
    UNDERLINE = '\033[4m'
    RESET = Style.RESET_ALL

class CheekScanner:
    def __init__(self, target, threads=10, timeout=5):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        # Initialize colorama for Windows compatibility
        init(autoreset=True)
        # Initialize warnings filter
        warnings.filterwarnings('ignore', message='Unverified HTTPS request')
        # Setup requests session with better settings
        self.session = requests.Session()
        self.session.verify = False
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=threads,
            pool_maxsize=threads * 2,
            max_retries=requests.adapters.Retry(
                total=2,
                backoff_factor=0.3,
                status_forcelist=[500, 502, 503, 504]
            )
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
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
            'ports': [],
            'dns_info': [],
            'subdomains': [],
            'apis': [],
            'cloud_services': []
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
            response = self.session.get(url, timeout=self.timeout, headers={'User-Agent': 'CheekScanner/1.0'})
            
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
                https_response = self.session.get(https_url, timeout=self.timeout, verify=False)
                
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
            
        except requests.exceptions.Timeout:
            print(f"{Colors.YELLOW}[!] مهلة الاتصال لخادم الويب{Colors.RESET}")
        except requests.exceptions.ConnectionError:
            print(f"{Colors.YELLOW}[!] خطأ في الاتصال بخادم الويب{Colors.RESET}")
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
    
    def gather_dns_info(self):
        """جمع معلومات DNS"""
        print(f"{Colors.YELLOW}[*] جمع معلومات DNS...{Colors.RESET}")
        
        try:
            # DNS A record
            answers = dns.resolver.resolve(self.target, 'A')
            for rdata in answers:
                dns_info = {
                    'type': 'A Record',
                    'value': str(rdata),
                    'description': 'IPv4 Address'
                }
                self.results['dns_info'].append(dns_info)
                print(f"{Colors.GREEN}[+] DNS A Record: {rdata}{Colors.RESET}")
            
            # DNS MX record
            try:
                mx_answers = dns.resolver.resolve(self.target, 'MX')
                for rdata in mx_answers:
                    dns_info = {
                        'type': 'MX Record',
                        'value': str(rdata.exchange),
                        'priority': rdata.preference,
                        'description': 'Mail Exchange'
                    }
                    self.results['dns_info'].append(dns_info)
                    print(f"{Colors.GREEN}[+] DNS MX Record: {rdata.exchange} (Priority: {rdata.preference}){Colors.RESET}")
            except:
                pass
            
            # DNS TXT record
            try:
                txt_answers = dns.resolver.resolve(self.target, 'TXT')
                for rdata in txt_answers:
                    txt_value = str(rdata).strip('"')
                    dns_info = {
                        'type': 'TXT Record',
                        'value': txt_value,
                        'description': 'Text Record'
                    }
                    self.results['dns_info'].append(dns_info)
                    print(f"{Colors.GREEN}[+] DNS TXT Record: {txt_value[:50]}...{Colors.RESET}")
            except:
                pass
            
            # DNS NS record
            try:
                ns_answers = dns.resolver.resolve(self.target, 'NS')
                for rdata in ns_answers:
                    dns_info = {
                        'type': 'NS Record',
                        'value': str(rdata),
                        'description': 'Name Server'
                    }
                    self.results['dns_info'].append(dns_info)
                    print(f"{Colors.GREEN}[+] DNS NS Record: {rdata}{Colors.RESET}")
            except:
                pass
                
        except Exception as e:
            print(f"{Colors.RED}[-] فشل جمع معلومات DNS: {e}{Colors.RESET}")
    
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

    def detect_modern_apis(self):
        """الكشف عن واجهات برمجة التطبيقات الحديثة"""
        try:
            print(f"{Colors.YELLOW}[*] جاري فحص واجهات برمجة التطبيقات الحديثة...{Colors.RESET}")
            
            # قائمة بمسارات API الشائعة
            api_endpoints = [
                '/api/v1', '/api/v2', '/api/v3',
                '/rest/api', '/graphql', '/swagger-ui.html',
                '/api-docs', '/v1/api-docs', '/openapi.json',
                '/swagger.json', '/api/swagger.json',
                '/api/health', '/api/status', '/api/info',
                '/api/users', '/api/auth', '/api/login',
                '/api/register', '/api/profile', '/api/settings'
            ]
            
            # قائمة برؤوس API الشائعة
            api_headers = [
                'X-API-Key', 'X-API-Version', 'X-RateLimit-Limit',
                'X-RateLimit-Remaining', 'X-RateLimit-Reset',
                'X-Request-ID', 'X-Correlation-ID', 'X-Forwarded-For'
            ]
            
            for endpoint in api_endpoints:
                try:
                    url = f"http://{self.target}{endpoint}"
                    response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                    
                    if response.status_code == 200:
                        self.results['apis'].append({
                            'endpoint': endpoint,
                            'status': response.status_code,
                            'content_type': response.headers.get('Content-Type', 'Unknown')
                        })
                        
                        # التحقق من نوع API
                        if 'application/json' in response.headers.get('Content-Type', ''):
                            try:
                                json_data = response.json()
                                if isinstance(json_data, dict):
                                    # التحقق من وجود مفاتيح API شائعة
                                    api_keys = ['version', 'endpoints', 'swagger', 'openapi']
                                    if any(key in str(json_data).lower() for key in api_keys):
                                        self.results['apis'].append({
                                            'endpoint': endpoint,
                                            'type': 'REST API Documentation',
                                            'detected_keys': list(json_data.keys())[:5]  # أول 5 مفاتيح فقط
                                        })
                            except:
                                pass
                        
                        elif 'text/html' in response.headers.get('Content-Type', ''):
                            if 'swagger' in response.text.lower() or 'openapi' in response.text.lower():
                                self.results['apis'].append({
                                    'endpoint': endpoint,
                                    'type': 'API Documentation (Swagger/OpenAPI)',
                                    'status': response.status_code
                                })
                    
                    elif response.status_code == 401:
                        self.results['apis'].append({
                            'endpoint': endpoint,
                            'status': response.status_code,
                            'note': 'API requires authentication'
                        })
                    
                    elif response.status_code == 403:
                        self.results['apis'].append({
                            'endpoint': endpoint,
                            'status': response.status_code,
                            'note': 'API access forbidden'
                        })
                    
                except requests.exceptions.RequestException:
                    continue
            
            # فحص رؤوس API في الاستجابة الأساسية
            try:
                response = requests.get(f"http://{self.target}", timeout=self.timeout, verify=False)
                detected_headers = []
                for header in api_headers:
                    if header in response.headers:
                        detected_headers.append(header)
                
                if detected_headers:
                    self.results['apis'].append({
                        'type': 'API Headers Detected',
                        'headers': detected_headers
                    })
                    
            except:
                pass
                
        except Exception as e:
            self.results['apis'].append(f"خطأ في فحص واجهات API: {str(e)}")
    
    def detect_cloud_services(self):
        """الكشف عن خدمات الحوسبة السحابية"""
        try:
            print(f"{Colors.YELLOW}[*] جاري فحص خدمات الحوسبة السحابية...{Colors.RESET}")
            
            # قائمة بخدمات AWS الشائعة
            aws_services = [
                's3.amazonaws.com', 'ec2.amazonaws.com', 'rds.amazonaws.com',
                'elasticbeanstalk.com', 'cloudfront.net', 'elastic.co',
                'amazonaws.com', 'awsstatic.com'
            ]
            
            # قائمة بخدمات Azure
            azure_services = [
                'azurewebsites.net', 'cloudapp.azure.com', 'blob.core.windows.net',
                'database.windows.net', 'azure-api.net', 'azureedge.net'
            ]
            
            # قائمة بخدمات Google Cloud
            gcp_services = [
                'appspot.com', 'googleapis.com', 'cloudfunctions.net',
                'run.app', 'firebaseapp.com', 'cloud.google.com'
            ]
            
            # التحقق من DNS والاستجابات
            try:
                # فحص DNS للهدف
                dns_records = dns.resolver.resolve(self.target.replace('http://', '').replace('https://', ''), 'A')
                for record in dns_records:
                    ip = str(record)
                    # التحقق من نطاقات AWS
                    if any(aws in self.target for aws in aws_services):
                        self.results['cloud_services'].append({
                            'type': 'AWS Service',
                            'service': 'Amazon Web Services',
                            'detected_by': 'domain_pattern'
                        })
                    
                    # التحقق من نطاقات Azure
                    elif any(azure in self.target for azure in azure_services):
                        self.results['cloud_services'].append({
                            'type': 'Azure Service',
                            'service': 'Microsoft Azure',
                            'detected_by': 'domain_pattern'
                        })
                    
                    # التحقق من نطاقات GCP
                    elif any(gcp in self.target for gcp in gcp_services):
                        self.results['cloud_services'].append({
                            'type': 'GCP Service',
                            'service': 'Google Cloud Platform',
                            'detected_by': 'domain_pattern'
                        })
            
            except:
                pass
            
            # فحص رؤوس الاستجابة للكشف عن الخدمات السحابية
            try:
                if not self.target.startswith(('http://', 'https://')):
                    url = f"http://{self.target}"
                else:
                    url = self.target
                
                response = requests.get(url, timeout=self.timeout, verify=False)
                
                # رؤوس AWS
                aws_headers = [
                    'x-amz-request-id', 'x-amz-id-2', 'x-amz-cf-id',
                    'x-amz-server-side-encryption', 'x-amz-version-id'
                ]
                
                # رؤوس Azure
                azure_headers = [
                    'x-ms-request-id', 'x-ms-version', 'x-ms-lease-status',
                    'x-ms-blob-type', 'x-ms-ratelimit-remaining'
                ]
                
                # رؤوس GCP
                gcp_headers = [
                    'x-goog-generation', 'x-goog-metageneration', 'x-goog-hash',
                    'x-goog-storage-class', 'x-cloud-trace-context'
                ]
                
                # التحقق من الرؤوس
                for header in aws_headers:
                    if header in response.headers:
                        self.results['cloud_services'].append({
                            'type': 'AWS Header',
                            'header': header,
                            'value': response.headers[header][:50] + '...' if len(response.headers[header]) > 50 else response.headers[header]
                        })
                
                for header in azure_headers:
                    if header in response.headers:
                        self.results['cloud_services'].append({
                            'type': 'Azure Header',
                            'header': header,
                            'value': response.headers[header][:50] + '...' if len(response.headers[header]) > 50 else response.headers[header]
                        })
                
                for header in gcp_headers:
                    if header in response.headers:
                        self.results['cloud_services'].append({
                            'type': 'GCP Header',
                            'header': header,
                            'value': response.headers[header][:50] + '...' if len(response.headers[header]) > 50 else response.headers[header]
                        })
                        
            except:
                pass
                
        except Exception as e:
            self.results['cloud_services'].append(f"خطأ في فحص الخدمات السحابية: {str(e)}")

    def generate_report(self):
        """إنشاء تقرير مفصل"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== تقرير الفحص الأمني ==={Colors.RESET}")
        print(f"{Colors.YELLOW}الهدف: {Colors.GREEN}{self.target}{Colors.RESET}")
        print(f"{Colors.YELLOW}وقت الفحص: {Colors.GREEN}{self.results['scan_time']}{Colors.RESET}")
        
        if self.results['dns_info']:
            print(f"\n{Colors.BLUE}[+] معلومات DNS:{Colors.RESET}")
            for dns in self.results['dns_info']:
                print(f"  - {dns['type']}: {dns['value']}")
        
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
        
        # عرض الثغرات الحديثة
        if self.results.get('modern_vulnerabilities'):
            print(f"\n{Colors.RED}[!] الثغرات الحديثة المكتشفة:{Colors.RESET}")
            for vuln in self.results['modern_vulnerabilities']:
                severity = vuln.get('severity', 'Unknown')
                severity_symbol = {
                    'Critical': '🔴',
                    'High': '🟠',
                    'Medium': '🟡',
                    'Low': '🟢',
                    'Info': '🔵'
                }.get(severity, '⚪')
                
                print(f"  {Colors.RED}{severity_symbol} {vuln['type']} ({severity}){Colors.RESET}")
                print(f"    {Colors.YELLOW}الوصف: {vuln['description']}{Colors.RESET}")
                if 'endpoint' in vuln:
                    print(f"    {Colors.CYAN}نقطة النهاية: {vuln['endpoint']}{Colors.RESET}")
                if 'exploit' in vuln:
                    print(f"    {Colors.MAGENTA}الاستغلال: {vuln['exploit']}{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}[+] لم يتم العثور على ثغرات حديثة{Colors.RESET}")
        
        # عرض معلومات API
        if self.results.get('apis'):
            print(f"\n{Colors.CYAN}[+] واجهات برمجة التطبيقات الحديثة:{Colors.RESET}")
            for api_info in self.results['apis']:
                if isinstance(api_info, dict):
                    if 'endpoint' in api_info:
                        print(f"  - نقطة نهاية API: {api_info['endpoint']} (الحالة: {api_info.get('status', 'غير معروف')})")
                        if 'type' in api_info:
                            print(f"    النوع: {api_info['type']}")
                        if 'note' in api_info:
                            print(f"    ملاحظة: {api_info['note']}")
                        if 'content_type' in api_info:
                            print(f"    نوع المحتوى: {api_info['content_type']}")
                    elif 'type' in api_info and api_info['type'] == 'API Headers Detected':
                        print(f"  - رؤوس API: {', '.join(api_info['headers'])}")
                else:
                    print(f"  - {api_info}")
        
        # عرض معلومات الخدمات السحابية
        if self.results.get('cloud_services'):
            print(f"\n{Colors.CYAN}[+] الخدمات السحابية المكتشفة:{Colors.RESET}")
            for cloud_info in self.results['cloud_services']:
                if isinstance(cloud_info, dict):
                    if 'type' in cloud_info and 'service' in cloud_info:
                        print(f"  - {cloud_info['service']} ({cloud_info['type']})")
                        if 'detected_by' in cloud_info:
                            print(f"    طريقة الكشف: {cloud_info['detected_by']}")
                    elif 'type' in cloud_info and 'header' in cloud_info:
                        print(f"  - رأس سحابي: {cloud_info['header']}")
                        if 'value' in cloud_info:
                            print(f"    القيمة: {cloud_info['value']}")
                else:
                    print(f"  - {cloud_info}")
        
        # حفظ التقرير كملف JSON مع تنسيق محسن
        report_filename = f"cheek_report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            # إنشاء هيكل JSON محسن
            enhanced_results = {
                'scan_metadata': {
                    'target': self.results.get('target', self.target),
                    'scan_time': self.results.get('scan_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    'scanner_version': '2.0',
                    'total_scan_duration': getattr(self, 'scan_duration', 'Unknown')
                },
                'scan_summary': {
                    'total_services_detected': len(self.results.get('services', [])),
                    'total_vulnerabilities': len(self.results.get('vulnerabilities', [])) + len(self.results.get('modern_vulnerabilities', [])),
                    'total_applications': len(self.results.get('applications', [])) + len(self.results.get('cms', [])),
                    'total_frameworks': len(self.results.get('frameworks', [])),
                    'total_apis': len(self.results.get('apis', [])),
                    'cloud_services_detected': len(self.results.get('cloud_services', [])),
                    'dns_records_found': len(self.results.get('dns_info', [])),
                    'total_open_ports': len(self.results.get('ports', []))
                },
                'dns_information': self.results.get('dns_info', []),
                'network_services': {
                    'open_ports': self.results.get('ports', []),
                    'web_servers': self.results.get('web_servers', []),
                    'email_servers': self.results.get('email_servers', []),
                    'databases': self.results.get('databases', [])
                },
                'applications_and_technologies': {
                    'applications': self.results.get('applications', []),
                    'content_management_systems': self.results.get('cms', []),
                    'frameworks': self.results.get('frameworks', []),
                    'cicd_platforms': self.results.get('cicd', []),
                    'containerization_technologies': self.results.get('containers', [])
                },
                'api_detection': {
                    'detected_apis': self.results.get('apis', []),
                    'total_endpoints_tested': len(self.results.get('apis', []))
                },
                'cloud_services': self.results.get('cloud_services', []),
                'security_assessment': {
                    'common_vulnerabilities': self.results.get('vulnerabilities', []),
                    'modern_vulnerabilities': self.results.get('modern_vulnerabilities', []),
                    'security_headers': self.results.get('security_headers', {}),
                    'exploit_results': {
                        'web_exploits': self.results.get('web_exploits', []),
                        'advanced_exploits': self.results.get('advanced_exploits', [])
                    }
                },
                'risk_assessment': {
                    'critical_vulnerabilities': len([v for v in self.results.get('vulnerabilities', []) + self.results.get('modern_vulnerabilities', []) if v.get('severity') == 'Critical']),
                    'high_vulnerabilities': len([v for v in self.results.get('vulnerabilities', []) + self.results.get('modern_vulnerabilities', []) if v.get('severity') == 'High']),
                    'medium_vulnerabilities': len([v for v in self.results.get('vulnerabilities', []) + self.results.get('modern_vulnerabilities', []) if v.get('severity') == 'Medium']),
                    'low_vulnerabilities': len([v for v in self.results.get('vulnerabilities', []) + self.results.get('modern_vulnerabilities', []) if v.get('severity') == 'Low']),
                    'overall_risk_level': self.calculate_risk_level()
                },
                'raw_scan_data': self.results  # Include original results for reference
            }
            
            with open(report_filename, 'w', encoding='utf-8') as f:
                json.dump(enhanced_results, f, ensure_ascii=False, indent=2, sort_keys=False)
            print(f"\n{Colors.GREEN}[+] تم حفظ التقرير الكامل في: {report_filename}{Colors.RESET}")
            
            # Create a summary report
            summary_filename = report_filename.replace('.json', '_summary.json')
            summary_data = {
                'scan_metadata': enhanced_results['scan_metadata'],
                'scan_summary': enhanced_results['scan_summary'],
                'risk_assessment': enhanced_results['risk_assessment'],
                'critical_findings': [
                    vuln for vuln in 
                    enhanced_results['security_assessment']['common_vulnerabilities'] + 
                    enhanced_results['security_assessment']['modern_vulnerabilities']
                    if vuln.get('severity') in ['Critical', 'High']
                ]
            }
            
            with open(summary_filename, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, ensure_ascii=False, indent=2)
            print(f"{Colors.GREEN}[+] تم حفظ تقرير الملخص في: {summary_filename}{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[-] فشل حفظ التقرير: {e}{Colors.RESET}")
    
    def calculate_risk_level(self):
        """Calculate overall risk level based on vulnerabilities found"""
        critical_count = len([v for v in self.results.get('vulnerabilities', []) + self.results.get('modern_vulnerabilities', []) if v.get('severity') == 'Critical'])
        high_count = len([v for v in self.results.get('vulnerabilities', []) + self.results.get('modern_vulnerabilities', []) if v.get('severity') == 'High'])
        medium_count = len([v for v in self.results.get('vulnerabilities', []) + self.results.get('modern_vulnerabilities', []) if v.get('severity') == 'Medium'])
        
        if critical_count > 0:
            return 'CRITICAL'
        elif high_count >= 3:
            return 'HIGH'
        elif high_count > 0 or medium_count >= 5:
            return 'MEDIUM'
        elif medium_count > 0:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def run_modern_vulnerabilities_scan(self):
        """Run modern vulnerability scans"""
        print(f"{Colors.YELLOW}[*] Starting modern vulnerabilities scan{Colors.RESET}")
        
        try:
            modern_scanner = ModernVulnerabilities(self.results['target'])
            modern_results = modern_scanner.run_modern_scan()
            
            # Store results in main results
            if 'modern_vulnerabilities' not in self.results:
                self.results['modern_vulnerabilities'] = []
            
            self.results['modern_vulnerabilities'].extend(modern_results['vulnerabilities'])
            
            print(f"{Colors.GREEN}[+] Modern vulnerabilities scan completed{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[-] Error in modern vulnerabilities scan: {e}{Colors.RESET}")
    
    def run_full_scan(self):
        """تشغيل فحص شامل"""
        self.print_banner()
        
        # جمع معلومات DNS
        self.gather_dns_info()
        
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
        self.detect_modern_apis()
        self.detect_cloud_services()
        
        # تشغيل فحص الثغرات الحديثة
        self.run_modern_vulnerabilities_scan()
        
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