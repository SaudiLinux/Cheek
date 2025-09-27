#!/usr/bin/env python3
"""
Advanced Security Tests for Cheek Scanner
اختبارات أمان متقدمة لأداة Cheek
"""

import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class AdvancedSecurityTester:
    """فئة للاختبارات الأمنية المتقدمة"""
    
    def __init__(self, target, timeout=5):
        self.target = target
        self.timeout = timeout
        
        # ألوان للطباعة
        self.RED = '\033[91m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.BLUE = '\033[94m'
        self.CYAN = '\033[96m'
        self.RESET = '\033[0m'
    
    def test_cors_vulnerabilities(self):
        """اختبار ثغرات CORS المتقدم"""
        print(f"\n{self.YELLOW}[*] بدء اختبار CORS المتقدم...{self.RESET}")
        
        results = {
            'vulnerable_endpoints': [],
            'exploitation_details': []
        }
        
        # اختبار النقاط الطرفية الشائعة
        test_endpoints = ['/', '/api', '/login', '/admin']
        
        for endpoint in test_endpoints:
            url = f"https://{self.target}{endpoint}"
            
            try:
                # اختبار 1: CORS مع أصل أي
                headers = {
                    'Origin': 'https://evil.com',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
                
                cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                creds_header = response.headers.get('Access-Control-Allow-Credentials', '').lower()
                
                if cors_header == '*' or cors_header == 'https://evil.com':
                    severity = 'عالية' if creds_header == 'true' else 'متوسطة'
                    exploitable = 'قابلة للاستغلال' if creds_header == 'true' else 'محتملة'
                    
                    results['vulnerable_endpoints'].append({
                        'url': url,
                        'severity': severity,
                        'exploitable': exploitable,
                        'issue': f'CORS يسمح بالأصل الخبيث: {cors_header}',
                        'credentials': creds_header == 'true'
                    })
                    
                    if creds_header == 'true':
                        results['exploitation_details'].append(f"يمكن سرقة بيانات الاعتماد من {url}")
                
            except Exception:
                pass
        
        # طباعة النتائج
        self.print_cors_results(results)
        return results
    
    def test_http_methods(self):
        """اختبار طرق HTTP المتقدم"""
        print(f"\n{self.YELLOW}[*] بدء اختبار طرق HTTP المتقدم...{self.RESET}")
        
        results = {
            'dangerous_methods': [],
            'method_override_vulnerabilities': [],
            'exploitation_details': []
        }
        
        test_endpoints = ['/', '/api', '/users']
        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
        
        for endpoint in test_endpoints:
            url = f"https://{self.target}{endpoint}"
            
            for method in dangerous_methods:
                try:
                    if method == 'PUT':
                        response = requests.put(url, data='test=data', timeout=self.timeout, verify=False)
                    elif method == 'DELETE':
                        response = requests.delete(url, timeout=self.timeout, verify=False)
                    elif method == 'PATCH':
                        response = requests.patch(url, json={'test': 'data'}, timeout=self.timeout, verify=False)
                    else:
                        response = requests.request(method, url, timeout=self.timeout, verify=False)
                    
                    if response.status_code < 400:
                        severity = 'عالية' if method in ['PUT', 'DELETE'] else 'متوسطة'
                        
                        results['dangerous_methods'].append({
                            'url': url,
                            'method': method,
                            'status_code': response.status_code,
                            'severity': severity,
                            'exploitable': 'قابلة للاستغلال'
                        })
                        
                        if method in ['PUT', 'DELETE']:
                            results['exploitation_details'].append(f"يمكن استخدام {method} على {url}")
                
                except Exception:
                    pass
        
        # اختبار تجاوز الطرق
        override_headers = ['X-HTTP-Method-Override', 'X-Method-Override']
        
        for endpoint in test_endpoints:
            url = f"https://{self.target}{endpoint}"
            
            for header in override_headers:
                try:
                    headers = {header: 'DELETE'}
                    response = requests.post(url, headers=headers, timeout=self.timeout, verify=False)
                    
                    if response.status_code < 400:
                        results['method_override_vulnerabilities'].append({
                            'url': url,
                            'method': 'DELETE',
                            'header': header,
                            'status_code': response.status_code,
                            'severity': 'عالية'
                        })
                        
                        results['exploitation_details'].append(f"يمكن تجاوز الطرق باستخدام {header}")
                
                except Exception:
                    pass
        
        self.print_http_methods_results(results)
        return results
    
    def test_security_headers(self):
        """اختبار رؤوس الأمان المتقدم"""
        print(f"\n{self.YELLOW}[*] بدء اختبار رؤوس الأمان المتقدم...{self.RESET}")
        
        results = {
            'missing_headers': [],
            'misconfigured_headers': [],
            'exploitation_details': []
        }
        
        security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        
        test_endpoints = ['/', '/login', '/admin']
        
        for endpoint in test_endpoints:
            url = f"https://{self.target}{endpoint}"
            
            try:
                response = requests.get(url, timeout=self.timeout, verify=False)
                headers = response.headers
                
                missing_headers = []
                for header in security_headers:
                    if header not in headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    results['missing_headers'].append({
                        'url': url,
                        'missing': missing_headers,
                        'severity': 'عالية' if len(missing_headers) > 2 else 'متوسطة'
                    })
                
                # التحقق من التهيئة الخاطئة
                if 'X-Frame-Options' in headers:
                    xfo_value = headers['X-Frame-Options'].lower()
                    if xfo_value not in ['deny', 'sameorigin']:
                        results['misconfigured_headers'].append({
                            'url': url,
                            'header': 'X-Frame-Options',
                            'value': xfo_value,
                            'issue': 'قيمة غير آمنة'
                        })
                
                if 'Strict-Transport-Security' in headers:
                    hsts_value = headers['Strict-Transport-Security']
                    if 'max-age=0' in hsts_value:
                        results['misconfigured_headers'].append({
                            'url': url,
                            'header': 'Strict-Transport-Security',
                            'value': hsts_value,
                            'issue': 'max-age=0 يعطل HSTS'
                        })
                
            except Exception:
                pass
        
        # إضافة تفاصيل الاستغلال
        if results['missing_headers']:
            for endpoint in results['missing_headers']:
                if 'X-Frame-Options' in endpoint['missing']:
                    results['exploitation_details'].append(f"يمكن تضمين {endpoint['url']} في iframe")
                if 'X-XSS-Protection' in endpoint['missing']:
                    results['exploitation_details'].append(f"لا يوجد حماية XSS في {endpoint['url']}")
        
        self.print_security_headers_results(results)
        return results
    
    def print_cors_results(self, cors_results):
        """طباعة نتائج CORS"""
        print(f"\n{self.YELLOW}[*] نتائج اختبار CORS المتقدم:{self.RESET}")
        
        if cors_results['vulnerable_endpoints']:
            print(f"{self.RED}[!] تم العثور على {len(cors_results['vulnerable_endpoints'])} نقاط ضعف CORS:{self.RESET}")
            for endpoint in cors_results['vulnerable_endpoints']:
                print(f"{self.RED}    • {endpoint['url']} - خطورة: {endpoint['severity']} - الاستغلال: {endpoint['exploitable']}{self.RESET}")
        else:
            print(f"{self.GREEN}[+] لا توجد ثغرات CORS حرجة{self.RESET}")
        
        if cors_results['exploitation_details']:
            print(f"{self.YELLOW}[*] تفاصيل الاستغلال:{self.RESET}")
            for detail in cors_results['exploitation_details']:
                print(f"{self.CYAN}    - {detail}{self.RESET}")
    
    def print_http_methods_results(self, http_results):
        """طباعة نتائج طرق HTTP"""
        print(f"\n{self.YELLOW}[*] نتائج اختبار طرق HTTP المتقدم:{self.RESET}")
        
        if http_results['dangerous_methods']:
            print(f"{self.RED}[!] تم العثور على {len(http_results['dangerous_methods'])} طريقة خطرة:{self.RESET}")
            for method in http_results['dangerous_methods']:
                print(f"{self.RED}    • {method['method']} - {method['url']} - خطورة: {method['severity']}{self.RESET}")
        
        if http_results['method_override_vulnerabilities']:
            print(f"{self.RED}[!] تم العثور على {len(http_results['method_override_vulnerabilities'])} ثغرة تجاوز الطرق:{self.RESET}")
            for vuln in http_results['method_override_vulnerabilities']:
                print(f"{self.RED}    • {vuln['method']} عبر {vuln['header']} - {vuln['url']}{self.RESET}")
        
        if http_results['exploitation_details']:
            print(f"{self.YELLOW}[*] تفاصيل الاستغلال:{self.RESET}")
            for detail in http_results['exploitation_details']:
                print(f"{self.CYAN}    - {detail}{self.RESET}")
    
    def print_security_headers_results(self, headers_results):
        """طباعة نتائج رؤوس الأمان"""
        print(f"\n{self.YELLOW}[*] نتائج اختبار رؤوس الأمان المتقدم:{self.RESET}")
        
        if headers_results['missing_headers']:
            print(f"{self.RED}[!] رؤوس الأمان المفقودة:{self.RESET}")
            for endpoint in headers_results['missing_headers']:
                print(f"{self.RED}    • {endpoint['url']}:{self.RESET}")
                for header in endpoint['missing']:
                    print(f"{self.RED}      - {header}{self.RESET}")
        
        if headers_results['misconfigured_headers']:
            print(f"{self.YELLOW}[!] رؤوس الأمان غير المهيأة بشكل صحيح:{self.RESET}")
            for header in headers_results['misconfigured_headers']:
                print(f"{self.YELLOW}    • {header['header']} في {header['url']} - مشكلة: {header['issue']}{self.RESET}")
        
        if headers_results['exploitation_details']:
            print(f"{self.YELLOW}[*] تفاصيل الاستغلال:{self.RESET}")
            for detail in headers_results['exploitation_details']:
                print(f"{self.CYAN}    - {detail}{self.RESET}")


# دالة مساعدة لتشغيل الاختبارات
def run_advanced_tests(target, test_type='cors'):
    """تشغيل اختبار متقدم محدد"""
    tester = AdvancedSecurityTester(target)
    
    if test_type == 'cors':
        return tester.test_cors_vulnerabilities()
    elif test_type == 'http':
        return tester.test_http_methods()
    elif test_type == 'headers':
        return tester.test_security_headers()
    else:
        print(f"نوع الاختبار غير معروف: {test_type}")
        return None


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("الاستخدام: python advanced_tests.py <target> <test_type>")
        print("أنواع الاختبارات: cors, http, headers")
        sys.exit(1)
    
    target = sys.argv[1]
    test_type = sys.argv[2]
    
    run_advanced_tests(target, test_type)