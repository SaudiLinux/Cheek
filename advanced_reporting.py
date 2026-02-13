#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced Reporting and Analytics Module for Cheek
وحدة التقارير والتحليلات المتقدمة
المبرمج: SayerLinux
الإيميل: SaudiSayer@gmail.com
"""

import json
import csv
from datetime import datetime
from collections import Counter, defaultdict

class AdvancedReporter:
    """فئة متقدمة لإنشاء تقارير تحليلية شاملة"""
    
    def __init__(self, scan_results, target):
        self.scan_results = scan_results
        self.target = target
        self.report_timestamp = datetime.now()
        self.analytics = {}
    
    def generate_comprehensive_analytics(self):
        """توليد تحليلات شاملة للنتائج"""
        print("[*] Generating comprehensive analytics...")
        
        # تحليل التوزيع الجغرافي للمخاطر
        self.analyze_risk_distribution()
        
        # تحليل الأنماط والاتجاهات
        self.analyze_vulnerability_patterns()
        
        # تحليل تأثير الثغرات
        self.analyze_impact_assessment()
        
        # تحليل تهديدات التعلم الآلي
        self.analyze_ml_threats()
        
        return self.analytics
    
    def analyze_risk_distribution(self):
        """تحليل توزيع المخاطر"""
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        
        # توزيع الخطورة
        severity_counts = Counter()
        category_counts = defaultdict(int)
        endpoint_risks = defaultdict(list)
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            vuln_type = vuln.get('type', 'Unknown')
            endpoint = vuln.get('endpoint', 'Unknown')
            
            severity_counts[severity] += 1
            category_counts[vuln_type] += 1
            endpoint_risks[endpoint].append(severity)
        
        # حساب نسب المخاطر
        total_vulns = len(vulnerabilities)
        risk_ratios = {
            severity: (count / total_vulns * 100) if total_vulns > 0 else 0
            for severity, count in severity_counts.items()
        }
        
        # تحديد نقاط الضعف الحرجة
        critical_endpoints = [
            endpoint for endpoint, severities in endpoint_risks.items()
            if 'CRITICAL' in severities or severities.count('HIGH') >= 2
        ]
        
        self.analytics['risk_distribution'] = {
            'severity_counts': dict(severity_counts),
            'category_counts': dict(category_counts),
            'risk_ratios': risk_ratios,
            'critical_endpoints': critical_endpoints,
            'total_vulnerabilities': total_vulns
        }
    
    def analyze_vulnerability_patterns(self):
        """تحليل أنماط الثغرات"""
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        
        # تحليل التكرارات
        vuln_patterns = defaultdict(list)
        attack_vectors = defaultdict(int)
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            endpoint = vuln.get('endpoint', 'Unknown')
            exploit = vuln.get('exploit', '')
            
            # نمط الثغرة
            pattern_key = f"{vuln_type}_{endpoint}"
            vuln_patterns[pattern_key].append(vuln)
            
            # تحليل ناقل الهجوم
            if 'SSRF' in vuln_type:
                attack_vectors['ssrf'] += 1
            elif 'Injection' in vuln_type:
                attack_vectors['injection'] += 1
            elif 'Authentication' in vuln_type:
                attack_vectors['auth'] += 1
            elif 'CORS' in vuln_type or 'CSRF' in vuln_type:
                attack_vectors['client_side'] += 1
        
        # تحديد الأنماط المتكررة
        recurring_patterns = {
            pattern: vulns for pattern, vulns in vuln_patterns.items()
            if len(vulns) > 1
        }
        
        self.analytics['vulnerability_patterns'] = {
            'recurring_patterns': recurring_patterns,
            'attack_vectors': dict(attack_vectors),
            'pattern_frequency': {pattern: len(vulns) for pattern, vulns in vuln_patterns.items()}
        }
    
    def analyze_impact_assessment(self):
        """تحليل تأثير الثغرات"""
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        
        # تصنيف التأثير
        impact_scores = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 1
        }
        
        total_impact_score = 0
        confidentiality_impact = 0
        integrity_impact = 0
        availability_impact = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            vuln_type = vuln.get('type', '')
            
            score = impact_scores.get(severity, 0)
            total_impact_score += score
            
            # تحليل تأثير CIA الثلاثي
            if any(word in vuln_type for word in ['Data', 'Information', 'Credentials']):
                confidentiality_impact += score
            if any(word in vuln_type for word in ['Injection', 'Tampering', 'Modification']):
                integrity_impact += score
            if any(word in vuln_type for word in ['DoS', 'Resource', 'Performance']):
                availability_impact += score
        
        # حساب متوسط التأثير
        avg_impact = total_impact_score / len(vulnerabilities) if vulnerabilities else 0
        
        # تصنيف المخاطر العام
        if total_impact_score >= 50:
            overall_risk = 'CRITICAL'
        elif total_impact_score >= 30:
            overall_risk = 'HIGH'
        elif total_impact_score >= 15:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'
        
        self.analytics['impact_assessment'] = {
            'total_impact_score': total_impact_score,
            'average_impact_score': avg_impact,
            'overall_risk_level': overall_risk,
            'cia_impacts': {
                'confidentiality': confidentiality_impact,
                'integrity': integrity_impact,
                'availability': availability_impact
            }
        }
    
    def generate_html_report(self):
        """توليد تقرير HTML متقدم"""
        print("[*] Generating HTML report...")
        
        # إنشاء HTML باستخدام استبدال النصوص البسيط
        html_content = f'''
        <!DOCTYPE html>
        <html lang="ar" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Analysis Report - {self.target}</title>
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 20px;
                    background-color: #f5f5f5;
                }}
                .container {{ 
                    max-width: 1200px; 
                    margin: 0 auto; 
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                .header {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                    text-align: center;
                }}
                .risk-critical {{ background-color: #dc3545; color: white; padding: 5px 10px; border-radius: 5px; }}
                .risk-high {{ background-color: #fd7e14; color: white; padding: 5px 10px; border-radius: 5px; }}
                .risk-medium {{ background-color: #ffc107; color: black; padding: 5px 10px; border-radius: 5px; }}
                .risk-low {{ background-color: #28a745; color: white; padding: 5px 10px; border-radius: 5px; }}
                .metric-card {{ 
                    background: white;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 10px;
                    text-align: center;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    transition: transform 0.2s;
                }}
                .metric-card:hover {{ transform: translateY(-5px); }}
                .vulnerability-item {{ 
                    border-left: 4px solid #007bff;
                    background: #f8f9fa;
                    margin: 10px 0;
                    padding: 15px;
                    border-radius: 5px;
                }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f8f9fa; font-weight: bold; }}
                .recommendations {{ background: #e8f5e8; padding: 20px; border-radius: 8px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <!-- Header -->
                <div class="header">
                    <h1><i>🛡️</i> Security Analysis Report</h1>
                    <p><strong>Target:</strong> {self.target} | <strong>Date:</strong> {self.report_timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <!-- Executive Summary -->
                <div class="stats-grid">
                    <div class="metric-card">
                        <h3>Total Vulnerabilities</h3>
                        <h2 style="color: #dc3545;">{self.analytics['risk_distribution']['total_vulnerabilities']}</h2>
                    </div>
                    <div class="metric-card">
                        <h3>Risk Level</h3>
                        <h2 class="risk-{self.analytics['impact_assessment']['overall_risk_level'].lower()}">
                            {self.analytics['impact_assessment']['overall_risk_level']}
                        </h2>
                    </div>
                    <div class="metric-card">
                        <h3>Impact Score</h3>
                        <h2 style="color: #fd7e14;">{self.analytics['impact_assessment']['total_impact_score']:.1f}</h2>
                    </div>
                    <div class="metric-card">
                        <h3>Critical Endpoints</h3>
                        <h2 style="color: #6f42c1;">{len(self.analytics['risk_distribution']['critical_endpoints'])}</h2>
                    </div>
                </div>
                
                <!-- Risk Distribution -->
                <h2><i>📊</i> Risk Distribution</h2>
                <div class="stats-grid">
        '''
        
        # إضافة توزيع المخاطر
        for severity, count in self.analytics['risk_distribution']['severity_counts'].items():
            percentage = self.analytics['risk_distribution']['risk_ratios'][severity]
            html_content += f'''
                    <div class="metric-card">
                        <h4>{severity} Vulnerabilities</h4>
                        <h2 class="risk-{severity.lower()}">{count}</h2>
                        <p>{percentage:.1f}%</p>
                    </div>
            '''
        
        html_content += '''
                </div>
                
                <!-- CIA Impact Analysis -->
                <h2><i>🎯</i> CIA Impact Analysis</h2>
                <div class="stats-grid">
                    <div class="metric-card">
                        <h4>Confidentiality Impact</h4>
                        <h2 style="color: #17a2b8;">{self.analytics['impact_assessment']['cia_impacts']['confidentiality']}</h2>
                    </div>
                    <div class="metric-card">
                        <h4>Integrity Impact</h4>
                        <h2 style="color: #ffc107;">{self.analytics['impact_assessment']['cia_impacts']['integrity']}</h2>
                    </div>
                    <div class="metric-card">
                        <h4>Availability Impact</h4>
                        <h2 style="color: #dc3545;">{self.analytics['impact_assessment']['cia_impacts']['availability']}</h2>
                    </div>
                </div>
                
                <!-- Vulnerability Details -->
                <h2><i>🔍</i> Vulnerability Details</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Endpoint</th>
                            <th>Description</th>
                            <th>Exploit</th>
                        </tr>
                    </thead>
                    <tbody>
        '''
        
        # إضافة تفاصيل الثغرات
        for vuln in self.scan_results.get('vulnerabilities', []):
            html_content += f'''
                        <tr>
                            <td><strong>{vuln.get('type', 'Unknown')}</strong></td>
                            <td><span class="risk-{vuln.get('severity', 'low').lower()}">{vuln.get('severity', 'Unknown')}</span></td>
                            <td><code>{vuln.get('endpoint', 'N/A')}</code></td>
                            <td>{vuln.get('description', '')}</td>
                            <td><small>{vuln.get('exploit', 'N/A')}</small></td>
                        </tr>
            '''
        
        html_content += '''
                    </tbody>
                </table>
                
                <!-- Critical Endpoints -->
        '''
        
        if self.analytics['risk_distribution']['critical_endpoints']:
            html_content += '''
                <h2><i>⚠️</i> Critical Endpoints</h2>
                <div class="vulnerability-item">
                    <ul>
            '''
            for endpoint in self.analytics['risk_distribution']['critical_endpoints']:
                html_content += f'''
                        <li><strong>{endpoint}</strong> - Requires immediate attention</li>
                '''
            html_content += '''
                    </ul>
                </div>
            '''
        
        html_content += '''
                
                <!-- Recommendations -->
                <div class="recommendations">
                    <h2><i>💡</i> Recommendations</h2>
                    <div class="stats-grid">
                        <div>
                            <h4>Immediate Actions</h4>
                            <ul>
                                <li>Patch all CRITICAL vulnerabilities immediately</li>
                                <li>Secure exposed API endpoints</li>
                                <li>Review authentication mechanisms</li>
                            </ul>
                        </div>
                        <div>
                            <h4>Long-term Improvements</h4>
                            <ul>
                                <li>Implement security testing in CI/CD</li>
                                <li>Regular security assessments</li>
                                <li>Security awareness training</li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <!-- Footer -->
                <div style="text-align: center; margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 8px;">
                    <p><strong>Generated by Cheek Security Scanner</strong></p>
                    <p>Advanced Analytics Module | {self.report_timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><em>Target: {self.target}</em></p>
                </div>
            </div>
        </body>
        </html>
        '''
        
        # حفظ ملف HTML
        html_report_path = f'advanced_report_{self.target}_{self.report_timestamp.strftime("%Y%m%d_%H%M%S")}.html'
        with open(html_report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] Advanced HTML report generated: {html_report_path}")
        return html_report_path
    
    def generate_csv_export(self):
        """توليد ملف CSV للبيانات"""
        print("[*] Generating CSV export...")
        
        csv_file = f'vulnerability_data_{self.target}_{self.report_timestamp.strftime("%Y%m%d_%H%M%S")}.csv'
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['timestamp', 'target', 'vulnerability_type', 'severity', 'endpoint', 
                         'description', 'exploit', 'cvss_score', 'risk_level']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for vuln in self.scan_results.get('vulnerabilities', []):
                writer.writerow({
                    'timestamp': self.report_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'target': self.target,
                    'vulnerability_type': vuln.get('type', 'Unknown'),
                    'severity': vuln.get('severity', 'Unknown'),
                    'endpoint': vuln.get('endpoint', 'N/A'),
                    'description': vuln.get('description', ''),
                    'exploit': vuln.get('exploit', ''),
                    'cvss_score': self.estimate_cvss_score(vuln),
                    'risk_level': self.calculate_risk_level(vuln)
                })
        
        print(f"[+] CSV data export generated: {csv_file}")
        return csv_file
    
    def estimate_cvss_score(self, vulnerability):
        """تقدير درجة CVSS للثغرة"""
        severity = vulnerability.get('severity', 'LOW')
        vuln_type = vulnerability.get('type', '')
        
        # نموذج تقديري مبسط
        base_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5
        }
        
        base_score = base_scores.get(severity, 0)
        
        # تعديل حسب نوع الثغرة
        if 'Injection' in vuln_type:
            base_score += 1.0
        elif 'SSRF' in vuln_type:
            base_score += 0.5
        elif 'Authentication' in vuln_type:
            base_score += 0.8
        
        return min(base_score, 10.0)
    
    def calculate_risk_level(self, vulnerability):
        """حساب مستوى المخاطر"""
        severity = vulnerability.get('severity', 'LOW')
        endpoint = vulnerability.get('endpoint', '')
        
        # تصنيف المخاطر بناءً على الخطورة والنقطة الطرفية
        if severity == 'CRITICAL':
            return 'IMMEDIATE'
        elif severity == 'HIGH' and any(keyword in endpoint for keyword in ['/admin', '/api', '/login']):
            return 'HIGH_PRIORITY'
        elif severity == 'HIGH':
            return 'HIGH'
        elif severity == 'MEDIUM':
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_executive_summary(self):
        """توليد ملخص تنفيذي"""
        print("[*] Generating executive summary...")
        
        summary = f"""EXECUTIVE SUMMARY - SECURITY ASSESSMENT REPORT
Target: {self.target}
Assessment Date: {self.report_timestamp.strftime('%Y-%m-%d %H:%M:%S')}

OVERALL SECURITY POSTURE: {self.analytics.get('impact_assessment', {}).get('overall_risk_level', 'UNKNOWN')}

KEY FINDINGS:
- Total Vulnerabilities Identified: {self.analytics.get('risk_distribution', {}).get('total_vulnerabilities', 0)}
- Critical Vulnerabilities: {self.analytics.get('risk_distribution', {}).get('severity_counts', {}).get('CRITICAL', 0)}
- High Risk Vulnerabilities: {self.analytics.get('risk_distribution', {}).get('severity_counts', {}).get('HIGH', 0)}

RISK ASSESSMENT:
- Total Impact Score: {self.analytics.get('impact_assessment', {}).get('total_impact_score', 0)}
- Average Impact Score: {self.analytics.get('impact_assessment', {}).get('average_impact_score', 0):.1f}

IMMEDIATE ACTIONS REQUIRED:
1. Address all CRITICAL vulnerabilities immediately
2. Review and secure high-risk endpoints
3. Implement additional security controls

ESTIMATED REMEDIATION EFFORT: {'HIGH' if self.analytics.get('impact_assessment', {}).get('total_impact_score', 0) > 30 else 'MEDIUM' if self.analytics.get('impact_assessment', {}).get('total_impact_score', 0) > 15 else 'LOW'}

COMPLIANCE IMPLICATIONS: Based on identified vulnerabilities, immediate attention is required to maintain security standards and regulatory compliance.
"""
        
        summary_file = f'executive_summary_{self.target}_{self.report_timestamp.strftime("%Y%m%d_%H%M%S")}.txt'
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(summary)
        
        print(f"[+] Executive summary generated: {summary_file}")
        return summary_file
    
    def generate_all_reports(self):
        """توليد جميع أنواع التقارير"""
        print("[*] Starting comprehensive report generation...")
        
        # توليد التحليلات
        self.generate_comprehensive_analytics()
        
        # توليد جميع التقارير
        reports = {}
        
        reports['html_report'] = self.generate_html_report()
        reports['csv_export'] = self.generate_csv_export()
        reports['executive_summary'] = self.generate_executive_summary()
        
        # حفظ التحليلات في ملف JSON
        analytics_file = f'advanced_analytics_{self.target}_{self.report_timestamp.strftime("%Y%m%d_%H%M%S")}.json'
        with open(analytics_file, 'w', encoding='utf-8') as f:
            json.dump({
                'target': self.target,
                'timestamp': self.report_timestamp.isoformat(),
                'analytics': self.analytics,
                'reports': reports
            }, f, ensure_ascii=False, indent=2)
        
        reports['analytics_json'] = analytics_file
        
        print("\n[+] Comprehensive reporting completed!")
        print("[+] Generated reports:")
        for report_type, file_path in reports.items():
            print(f"    - {report_type}: {file_path}")
        
        return reports
    
    def analyze_ml_threats(self):
        """تحليل تهديدات التعلم الآلي"""
        print("[*] Analyzing ML threat detection results...")
        
        # استخراج نتائج التعلم الآلي من البيانات
        ml_results = []
        
        # البحث عن نتائج ML في البيانات الخام
        if 'raw_scan_data' in self.scan_results:
            raw_data = self.scan_results['raw_scan_data']
            # البحث عن نتائج الكشف بالتعلم الآلي
            for key, value in raw_data.items():
                if 'ml' in key.lower() and isinstance(value, list):
                    ml_results.extend(value)
        
        # تحليل التهديدات المكتشفة
        threat_categories = {}
        confidence_scores = []
        anomaly_scores = []
        
        for result in ml_results:
            if isinstance(result, dict):
                predictions = result.get('predictions', {})
                anomaly_score = result.get('anomaly_score', 0)
                confidence = result.get('confidence', 0)
                
                # تصنيف التهديدات
                for threat_type, threat_confidence in predictions.items():
                    if threat_type not in threat_categories:
                        threat_categories[threat_type] = []
                    threat_categories[threat_type].append(threat_confidence)
                
                # جمع درجات الثقة والشذوذ
                confidence_scores.append(confidence)
                anomaly_scores.append(anomaly_score)
        
        # حساب الإحصائيات
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        avg_anomaly = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0
        
        # تحديد أعلى التهديدات ثقة
        top_threats = []
        for threat_type, confidences in threat_categories.items():
            max_confidence = max(confidences) if confidences else 0
            top_threats.append((threat_type, max_confidence))
        
        top_threats.sort(key=lambda x: x[1], reverse=True)
        
        # تحليل المخاطر
        risk_level = 'LOW'
        if avg_confidence > 0.8 or avg_anomaly > 0.8:
            risk_level = 'CRITICAL'
        elif avg_confidence > 0.6 or avg_anomaly > 0.6:
            risk_level = 'HIGH'
        elif avg_confidence > 0.4 or avg_anomaly > 0.4:
            risk_level = 'MEDIUM'
        
        self.analytics['ml_threat_analysis'] = {
            'total_ml_detections': len(ml_results),
            'threat_categories': {k: len(v) for k, v in threat_categories.items()},
            'top_threats': top_threats[:5],
            'average_confidence': avg_confidence,
            'average_anomaly_score': avg_anomaly,
            'risk_level': risk_level,
            'ml_detection_summary': {
                'critical_threats': len([t for t in top_threats if t[1] > 0.8]),
                'high_threats': len([t for t in top_threats if 0.6 < t[1] <= 0.8]),
                'medium_threats': len([t for t in top_threats if 0.4 < t[1] <= 0.6]),
                'low_threats': len([t for t in top_threats if t[1] <= 0.4])
            }
        }
        
        print(f"[+] ML threat analysis completed: {len(ml_results)} detections, Risk level: {risk_level}")

# دالة مساعدة للاستخدام السريع
def generate_advanced_reports(scan_results, target):
    """دالة سريعة لتوليد التقارير المتقدمة"""
    reporter = AdvancedReporter(scan_results, target)
    return reporter.generate_all_reports()

if __name__ == '__main__':
    # مثال على الاستخدام
    sample_results = {
        'vulnerabilities': [
            {
                'type': 'SQL Injection',
                'severity': 'HIGH',
                'endpoint': '/api/users',
                'description': 'SQL injection vulnerability in user parameter',
                'exploit': 'Can extract database information'
            },
            {
                'type': 'XSS',
                'severity': 'MEDIUM',
                'endpoint': '/search',
                'description': 'Cross-site scripting vulnerability',
                'exploit': 'Can execute JavaScript in user browser'
            }
        ]
    }
    
    reports = generate_advanced_reports(sample_results, 'example.com')
    print("\n[+] Sample reports generated successfully!")