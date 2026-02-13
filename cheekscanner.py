#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CheekScanner - فئة الفحص الشامل المتقدمة
المبرمج: SayerLinux
الإيميل: SaudiSayer@gmail.com
"""

import json
import time
from datetime import datetime
from collections import defaultdict

class CheekScanner:
    """فئة متقدمة للفحص الأمني الشامل"""
    
    def __init__(self):
        """تهيئة كاشف الفحص الشامل"""
        self.scan_results = {
            'target': '',
            'scan_start': '',
            'scan_end': '',
            'duration': 0,
            'vulnerabilities': [],
            'security_issues': [],
            'recommendations': [],
            'risk_assessment': {},
            'ml_detections': [],
            'advanced_analytics': {}
        }
        self.ml_detector = None
        self.advanced_reporter = None
        self.setup_ml_components()
    
    def setup_ml_components(self):
        """إعداد مكونات التعلم الآلي"""
        try:
            from ml_threat_detection import MLThreatDetector
            from advanced_reporting import AdvancedReporter
            self.ml_detector = MLThreatDetector()
            print("[+] ML components initialized successfully")
        except ImportError as e:
            print(f"[!] ML components not available: {e}")
    
    def run_full_scan(self, target, options=None):
        """تشغيل الفحص الأمني الشامل"""
        print(f"\n{'='*60}")
        print(f"CheekScanner - Full Security Assessment")
        print(f"Target: {target}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        
        self.scan_results['target'] = target
        self.scan_results['scan_start'] = datetime.now().isoformat()
        start_time = time.time()
        
        # تشغيل مراحل الفحص المختلفة
        self.run_reconnaissance(target)
        self.run_vulnerability_scanning(target)
        self.run_ml_threat_detection(target)
        self.run_advanced_tests(target)
        self.generate_advanced_analytics()
        
        # حساب المدة
        end_time = time.time()
        self.scan_results['duration'] = round(end_time - start_time, 2)
        self.scan_results['scan_end'] = datetime.now().isoformat()
        
        # توليد التقرير النهائي
        self.generate_comprehensive_report()
        
        return self.scan_results
    
    def run_reconnaissance(self, target):
        """تشغيل مرحلة الاستطلاع"""
        print(f"\n{Colors.CYAN}[*] Phase 1: Reconnaissance{Colors.RESET}")
        
        # جمع المعلومات الأساسية
        recon_data = {
            'target_info': self.gather_target_info(target),
            'subdomains': self.enumerate_subdomains(target),
            'technologies': self.detect_technologies(target),
            'attack_surface': self.map_attack_surface(target)
        }
        
        self.scan_results['reconnaissance'] = recon_data
        print(f"[+] Reconnaissance completed")
    
    def run_vulnerability_scanning(self, target):
        """تشغيل فحص الثغرات"""
        print(f"\n{Colors.CYAN}[*] Phase 2: Vulnerability Scanning{Colors.RESET}")
        
        vulns_found = []
        
        # فحص الثغرات الشائعة
        common_vulns = self.scan_common_vulnerabilities(target)
        vulns_found.extend(common_vulns)
        
        # فحص الثغرات الحديثة
        modern_vulns = self.scan_modern_vulnerabilities(target)
        vulns_found.extend(modern_vulns)
        
        # فحص الثغرات السحابية
        cloud_vulns = self.scan_cloud_vulnerabilities(target)
        vulns_found.extend(cloud_vulns)
        
        self.scan_results['vulnerabilities'] = vulns_found
        print(f"[+] Found {len(vulns_found)} vulnerabilities")
    
    def run_ml_threat_detection(self, target):
        """تشغيل الكشف بالتعلم الآلي"""
        print(f"\n{Colors.CYAN}[*] Phase 3: ML Threat Detection{Colors.RESET}")
        
        if not self.ml_detector:
            print("[!] ML detector not available, skipping...")
            return
        
        ml_results = []
        
        # تحليل الطلبات المشبوهة
        suspicious_requests = self.generate_test_requests(target)
        
        for request in suspicious_requests:
            try:
                result = self.ml_detector.analyze_request(request)
                if result['risk_level'] != 'LOW' or result['anomaly_score'] > 0.3:
                    ml_results.append({
                        'request': request,
                        'detection': result,
                        'timestamp': datetime.now().isoformat()
                    })
            except Exception as e:
                print(f"[!] ML analysis error: {e}")
        
        self.scan_results['ml_detections'] = ml_results
        print(f"[+] ML threat detection completed: {len(ml_results)} suspicious patterns found")
    
    def run_advanced_tests(self, target):
        """تشغيل الاختبارات المتقدمة"""
        print(f"\n{Colors.CYAN}[*] Phase 4: Advanced Security Tests{Colors.RESET}")
        
        advanced_issues = []
        
        # اختبار CORS
        cors_issues = self.test_cors_security(target)
        advanced_issues.extend(cors_issues)
        
        # اختبار رؤوس الأمان
        header_issues = self.test_security_headers(target)
        advanced_issues.extend(header_issues)
        
        # اختبار طرق HTTP
        method_issues = self.test_http_methods(target)
        advanced_issues.extend(method_issues)
        
        # اختبار السحابة
        cloud_issues = self.test_cloud_security(target)
        advanced_issues.extend(cloud_issues)
        
        self.scan_results['security_issues'] = advanced_issues
        print(f"[+] Advanced tests completed: {len(advanced_issues)} issues found")
    
    def generate_advanced_analytics(self):
        """توليل التحليلات المتقدمة"""
        print(f"\n{Colors.CYAN}[*] Phase 5: Advanced Analytics{Colors.RESET}")
        
        if self.advanced_reporter:
            analytics = self.advanced_reporter.generate_comprehensive_analytics()
            self.scan_results['advanced_analytics'] = analytics
        else:
            # تحليلات أساسية
            self.scan_results['advanced_analytics'] = self.basic_analytics()
        
        print("[+] Advanced analytics generated")
    
    def generate_comprehensive_report(self):
        """توليد التقرير الشامل"""
        print(f"\n{Colors.CYAN}[*] Generating Comprehensive Report{Colors.RESET}")
        
        # توليد التوصيات
        self.generate_recommendations()
        
        # تقييم المخاطر
        self.assess_overall_risk()
        
        # حفظ التقرير
        report_filename = f"cheekscanner_report_{self.scan_results['target']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(report_filename, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, ensure_ascii=False, indent=2)
            
            print(f"\n{Colors.GREEN}[+] Comprehensive report saved: {report_filename}{Colors.RESET}")
            self.display_summary()
            
        except Exception as e:
            print(f"{Colors.RED}[-] Error saving report: {e}{Colors.RESET}")
    
    def display_summary(self):
        """عرض ملخص النتائج"""
        print(f"\n{Colors.YELLOW}{'='*60}")
        print(f"SCAN SUMMARY")
        print(f"{'='*60}{Colors.RESET}")
        
        vuln_count = len(self.scan_results['vulnerabilities'])
        issue_count = len(self.scan_results['security_issues'])
        ml_count = len(self.scan_results['ml_detections'])
        duration = self.scan_results['duration']
        
        print(f"Target: {self.scan_results['target']}")
        print(f"Duration: {duration} seconds")
        print(f"Vulnerabilities Found: {vuln_count}")
        print(f"Security Issues: {issue_count}")
        print(f"ML Detections: {ml_count}")
        
        if self.scan_results['vulnerabilities']:
            severity_counts = defaultdict(int)
            for vuln in self.scan_results['vulnerabilities']:
                severity = vuln.get('severity', 'UNKNOWN')
                severity_counts[severity] += 1
            
            print(f"\nSeverity Distribution:")
            for severity, count in severity_counts.items():
                color = Colors.RED if severity == 'CRITICAL' else Colors.YELLOW if severity == 'HIGH' else Colors.CYAN
                print(f"  {color}{severity}: {count}{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}[+] Scan completed successfully!{Colors.RESET}")
    
    # Methods stubs for implementation
    def gather_target_info(self, target):
        return {'target': target, 'scan_time': datetime.now().isoformat()}
    
    def enumerate_subdomains(self, target):
        return []
    
    def detect_technologies(self, target):
        return {}
    
    def map_attack_surface(self, target):
        return {}
    
    def scan_common_vulnerabilities(self, target):
        return []
    
    def scan_modern_vulnerabilities(self, target):
        return []
    
    def scan_cloud_vulnerabilities(self, target):
        return []
    
    def generate_test_requests(self, target):
        return [
            {'url': f'http://{target}/admin', 'method': 'GET', 'params': {}, 'headers': {}},
            {'url': f'http://{target}/login', 'method': 'POST', 'params': {'user': 'admin\'--'}, 'headers': {}},
            {'url': f'http://{target}/search', 'method': 'GET', 'params': {'q': '<script>alert(1)</script>'}, 'headers': {}}
        ]
    
    def test_cors_security(self, target):
        return []
    
    def test_security_headers(self, target):
        return []
    
    def test_http_methods(self, target):
        return []
    
    def test_cloud_security(self, target):
        return []
    
    def basic_analytics(self):
        return {'basic_stats': 'analytics_placeholder'}
    
    def generate_recommendations(self):
        self.scan_results['recommendations'] = [
            "Review and patch identified vulnerabilities",
            "Implement security headers",
            "Regular security assessments recommended"
        ]
    
    def assess_overall_risk(self):
        vuln_count = len(self.scan_results['vulnerabilities'])
        if vuln_count > 10:
            risk_level = 'CRITICAL'
        elif vuln_count > 5:
            risk_level = 'HIGH'
        elif vuln_count > 2:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        self.scan_results['risk_assessment'] = {
            'overall_risk': risk_level,
            'vulnerability_count': vuln_count,
            'recommendation': f'Risk level: {risk_level}'
        }

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'

# دالة مساعدة للاستخدام السريع
def run_cheek_scanner(target, **options):
    """تشغيل فحص شامل باستخدام CheekScanner"""
    scanner = CheekScanner()
    return scanner.run_full_scan(target, options)

if __name__ == "__main__":
    # مثال على الاستخدام
    target = "testphp.vulnweb.com"
    print("[*] Starting CheekScanner demonstration...")
    
    results = run_cheek_scanner(target)
    print(f"\n[+] Scan completed for {target}")
    print(f"[+] Results: {len(results['vulnerabilities'])} vulnerabilities found")