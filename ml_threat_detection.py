#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Machine Learning-based Threat Detection Module for Cheek
وحدة الكشف عن التهديدات باستخدام التعلم الآلي
المبرمج: SayerLinux
الإيميل: SaudiSayer@gmail.com
"""

import numpy as np
import json
import pickle
import hashlib
import re
import os
from datetime import datetime
from collections import defaultdict, Counter
from urllib.parse import urlparse, parse_qs
import math

class MLThreatDetector:
    """فئة الكشف عن التهديدات باستخدام التعلم الآلي"""
    
    def __init__(self):
        self.models = {}
        self.feature_extractors = {}
        self.threat_patterns = {}
        self.baseline_profiles = {}
        self.training_data = {}  # إضافة تهيئة بيانات التدريب
        # مسارات حفظ النماذج
        self.model_paths = {
            'anomaly_detection': 'models/anomaly_model.pkl',
            'behavior_analysis': 'models/behavior_model.pkl',
            'threat_classification': 'models/classification_model.pkl',
            'predictive_analytics': 'models/predictive_model.pkl',
            'advanced_heuristics': 'models/heuristics_model.pkl'
        }
        self.initialize_models()
    
    def initialize_models(self):
        """تهيئة النماذج والمستخرجات"""
        print("[*] Initializing ML threat detection models...")
        
        # نماذج الكشف عن الأنماط الخبيثة
        self.models = {
            'anomaly_detection': AnomalyDetector(),
            'behavior_analysis': BehaviorAnalyzer(),
            'threat_classification': ThreatClassifier(),
            'predictive_analytics': PredictiveAnalytics(),
            'advanced_heuristics': AdvancedHeuristics()
        }
        
        # مستخرجات الميزات
        self.feature_extractors = {
            'url_features': URLFeatureExtractor(),
            'payload_features': PayloadFeatureExtractor(),
            'behavior_features': BehaviorFeatureExtractor(),
            'temporal_features': TemporalFeatureExtractor(),
            'network_features': NetworkFeatureExtractor()
        }
        
        # الأنماط المعروفة
        self.threat_patterns = self.load_threat_patterns()
        self.baseline_profiles = self.load_baseline_profiles()
    
    def load_threat_patterns(self):
        """تحميل أنماط التهديدات المعروفة"""
        return {
            'sql_injection_patterns': [
                r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b|\binsert\b.*\binto\b|\bdelete\b.*\bfrom\b)",
                r"(\bOR\b.*=.*OR\b|\b1\s*=\s*1\b|\b'\s*OR\s*'\s*=\s*'\b)",
                r"(\bWAITFOR\b.*\bDELAY\b|\bSLEEP\b\(\d+\)|\bBENCHMARK\b\(\d+\s*,\s*\w+\))"
            ],
            'xss_patterns': [
                r"(<script.*?>.*?</script>|javascript:|onerror=|onload=|onclick=)",
                r"(&lt;script.*?&gt;.*?&lt;/script&gt;|&#60;script.*?&#62;.*?&#60;/script&#62;)",
                r"(alert\(|confirm\(|prompt\(|document\.cookie|window\.location)"
            ],
            'ssrf_patterns': [
                r"(http://169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1|0\.0\.0\.0)",
                r"(file://|dict://|gopher://|ftp://|ssh://|telnet://)",
                r"(aws\.amazon\.com|ec2\.amazonaws\.com|s3\.amazonaws\.com)"
            ],
            'lfi_patterns': [
                r"(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f)",
                r"(/etc/passwd|/etc/shadow|C:\\windows\\system32|win\.ini)",
                r"(php://filter|php://input|data://text|expect://)"
            ],
            'command_injection_patterns': [
                r"(\b&&\b|\b\|\|\b|\b;\b|`.*?`|\$\(.*\)|\${.*?})",
                r"(\bnc\b.*\b-e\b|\bwget\b.*\b-O\b|\bcurl\b.*\b-o\b|\bpython\b.*\b-c\b)",
                r"(/bin/bash|/bin/sh|cmd\.exe|powershell\.exe)"
            ],
            'advanced_persistence_patterns': [
                r"(webshell|backdoor|reverse.*shell|bind.*shell)",
                r"(eval\(|assert\(|system\(|exec\(|shell_exec\(|passthru\()",
                r"(base64_decode|str_rot13|gzinflate|strrev|hex2bin)"
            ]
        }
    
    def load_baseline_profiles(self):
        """تحميل الملفات الأساسية للمقارنة"""
        return {
            'normal_request_patterns': {
                'avg_param_length': 15,
                'max_params': 10,
                'common_headers': ['User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding'],
                'normal_response_time': 0.5,
                'common_methods': ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
            },
            'normal_response_patterns': {
                'status_codes': [200, 301, 302, 400, 401, 403, 404, 500],
                'content_types': ['text/html', 'application/json', 'text/plain', 'application/xml'],
                'avg_response_size': 1024
            }
        }
    
    def analyze_request(self, request_data):
        """تحليل الطلب باستخدام الذكاء الاصطناعي"""
        results = {
            'anomaly_score': 0,
            'threat_indicators': [],
            'risk_level': 'LOW',
            'predictions': {},
            'confidence': 0.0
        }
        
        try:
            # استخراج الميزات
            features = self.extract_features(request_data)
            
            # الكشف عن الشذوذ
            anomaly_results = self.models['anomaly_detection'].detect_anomalies(features)
            results['anomaly_score'] = anomaly_results['score']
            results['threat_indicators'].extend(anomaly_results['indicators'])
            
            # تحليل السلوك
            behavior_results = self.models['behavior_analysis'].analyze_behavior(features)
            results['threat_indicators'].extend(behavior_results['indicators'])
            
            # تصنيف التهديد
            classification_results = self.models['threat_classification'].classify_threat(features)
            results['predictions'] = classification_results['predictions']
            results['confidence'] = classification_results['confidence']
            
            # التحليل التنبؤي
            predictive_results = self.models['predictive_analytics'].predict_risk(features)
            results['risk_level'] = predictive_results['risk_level']
            results['threat_indicators'].extend(predictive_results['indicators'])
            
            # الاستدلال المتقدم
            heuristic_results = self.models['advanced_heuristics'].analyze_heuristics(features)
            results['threat_indicators'].extend(heuristic_results['indicators'])
            
            # تحديد مستوى الخطورة النهائي
            results['risk_level'] = self.calculate_final_risk_level(results)
            
        except Exception as e:
            print(f"[-] Error in ML analysis: {e}")
            results['threat_indicators'].append(f'ML analysis error: {str(e)}')
        
        return results
    
    def extract_features(self, request_data):
        """استخراج الميزات من بيانات الطلب"""
        features = {}
        
        # ميزات URL
        if 'url' in request_data:
            url_features = self.feature_extractors['url_features'].extract_features(request_data['url'])
            features.update(url_features)
        
        # ميزات الحمولة
        if 'payload' in request_data:
            payload_features = self.feature_extractors['payload_features'].extract_features(request_data['payload'])
            features.update(payload_features)
        
        # ميزات السلوك
        if 'behavior_data' in request_data:
            behavior_features = self.feature_extractors['behavior_features'].extract_features(request_data['behavior_data'])
            features.update(behavior_features)
        
        # ميزات زمنية
        if 'timestamp' in request_data:
            temporal_features = self.feature_extractors['temporal_features'].extract_features(request_data['timestamp'])
            features.update(temporal_features)
        
        # ميزات الشبكة
        if 'network_data' in request_data:
            network_features = self.feature_extractors['network_features'].extract_features(request_data['network_data'])
            features.update(network_features)
        
        return features
    
    def calculate_final_risk_level(self, results):
        """حساب مستوى الخطورة النهائي"""
        anomaly_score = results['anomaly_score']
        threat_count = len(results['threat_indicators'])
        confidence = results['confidence']
        
        # حساب درجة المخاطرة
        risk_score = 0
        
        # تأثير الشذوذ
        if anomaly_score > 0.8:
            risk_score += 30
        elif anomaly_score > 0.6:
            risk_score += 20
        elif anomaly_score > 0.4:
            risk_score += 10
        
        # تأثير عدد مؤشرات التهديد
        risk_score += min(threat_count * 5, 30)
        
        # تأثير الثقة في التنبؤ
        risk_score += confidence * 20
        
        # تحديد المستوى النهائي
        if risk_score >= 70:
            return 'CRITICAL'
        elif risk_score >= 50:
            return 'HIGH'
        elif risk_score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def train_models(self, training_data):
        """تدريب النماذج على بيانات تدريبية"""
        print("[*] Training ML models...")
        
        for model_name, model in self.models.items():
            if hasattr(model, 'train'):
                model.train(training_data.get(model_name, []))
        
        print("[+] ML models training completed")
    
    def save_models(self, filepath=None):
        """حفظ النماذج المدربة"""
        if filepath is None:
            filepath = f'ml_models_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pkl'
            
        # إنشاء دليل النماذج إذا لم يكن موجوداً
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else '.', exist_ok=True)
        
        model_data = {
            'models': self.models,
            'feature_extractors': self.feature_extractors,
            'threat_patterns': self.threat_patterns,
            'baseline_profiles': self.baseline_profiles,
            'training_data': self.training_data,
            'saved_at': datetime.now().isoformat()
        }
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            print(f"[+] Models saved to {filepath}")
            return filepath
        except Exception as e:
            print(f"[-] Error saving models: {e}")
            return None
    
    def load_models(self, filepath):
        """تحميل النماذج المحفوظة"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.models = model_data['models']
            self.feature_extractors = model_data['feature_extractors']
            self.threat_patterns = model_data['threat_patterns']
            self.baseline_profiles = model_data['baseline_profiles']
            self.training_data = model_data.get('training_data', {})
            
            print(f"[+] Models loaded from {filepath}")
            print(f"[+] Models saved at: {model_data.get('saved_at', 'Unknown')}")
            return True
        except Exception as e:
            print(f"[-] Error loading models: {e}")
            return False
    
    def export_training_data(self, filepath):
        """تصدير بيانات التدريب"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.training_data, f, ensure_ascii=False, indent=2)
            print(f"[+] Training data exported to {filepath}")
            return True
        except Exception as e:
            print(f"[-] Error exporting training data: {e}")
            return False
    
    def import_training_data(self, filepath):
        """استيراد بيانات التدريب"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                training_data = json.load(f)
            
            self.training_data.update(training_data)
            print(f"[+] Training data imported from {filepath}")
            return True
        except Exception as e:
            print(f"[-] Error importing training data: {e}")
            return False
    
    def get_model_statistics(self):
        """الحصول على إحصائيات النماذج"""
        stats = {
            'models_trained': {},
            'training_data_size': {},
            'model_performance': {}
        }
        
        for model_name, model in self.models.items():
            if hasattr(model, 'get_statistics'):
                stats['models_trained'][model_name] = model.get_statistics()
            
            if model_name in self.training_data:
                stats['training_data_size'][model_name] = len(self.training_data[model_name])
        
        return stats

class AnomalyDetector:
    """كاشف الشذوذ"""
    
    def __init__(self):
        self.baseline_stats = {}
        self.anomaly_threshold = 0.6
    
    def detect_anomalies(self, features):
        """الكشف عن الشذوذ في الميزات"""
        results = {
            'score': 0.0,
            'indicators': []
        }
        
        try:
            # تحليل شذوذ URL
            if 'url_length' in features:
                if features['url_length'] > 200:
                    results['indicators'].append('Unusually long URL detected')
                    results['score'] += 0.2
            
            # تحليل شذوذ المعلمات
            if 'param_count' in features:
                if features['param_count'] > 15:
                    results['indicators'].append('Excessive number of parameters')
                    results['score'] += 0.3
            
            # تحليل شذوذ الأحرف الخاصة
            if 'special_char_ratio' in features:
                if features['special_char_ratio'] > 0.3:
                    results['indicators'].append('High ratio of special characters')
                    results['score'] += 0.4
            
            # تحليل شذوذ التشفير
            if 'encoding_patterns' in features:
                if features['encoding_patterns'] > 3:
                    results['indicators'].append('Multiple encoding patterns detected')
                    results['score'] += 0.3
            
            # تحليل شذوذ الحمولة
            if 'payload_entropy' in features:
                if features['payload_entropy'] > 7.0:
                    results['indicators'].append('High entropy in payload (possible encrypted/obfuscated)')
                    results['score'] += 0.4
            
            # تحليل شذوذ التوقيت
            if 'request_rate' in features:
                if features['request_rate'] > 10:  # أكثر من 10 طلبات في الثانية
                    results['indicators'].append('Abnormally high request rate')
                    results['score'] += 0.5
            
            # تحليل شذوذ حجم الاستجابة
            if 'response_size_ratio' in features:
                if features['response_size_ratio'] > 10:  # استجابة أكبر 10 مرات من الطلب
                    results['indicators'].append('Unusual response size ratio')
                    results['score'] += 0.2
            
            # تطبيع الدرجة
            results['score'] = min(results['score'], 1.0)
            
        except Exception as e:
            results['indicators'].append(f'Anomaly detection error: {str(e)}')
        
        return results

class BehaviorAnalyzer:
    """محلل السلوك"""
    
    def __init__(self):
        self.behavior_patterns = {}
        self.suspicious_behaviors = []
    
    def analyze_behavior(self, features):
        """تحليل السلوك المشبوه"""
        results = {
            'indicators': []
        }
        
        try:
            # تحليل سلوك المسار
            if 'path_traversal_attempts' in features and features['path_traversal_attempts'] > 0:
                results['indicators'].append(f'Path traversal attempts detected: {features["path_traversal_attempts"]}')
            
            # تحليل سلوك المعلمات
            if 'suspicious_param_names' in features:
                if len(features['suspicious_param_names']) > 0:
                    results['indicators'].append(f'Suspicious parameter names: {", ".join(features["suspicious_param_names"][:3])}')
            
            # تحليل سلوك القيم
            if 'suspicious_values' in features:
                if len(features['suspicious_values']) > 0:
                    results['indicators'].append(f'Suspicious values detected: {len(features["suspicious_values"])}')
            
            # تحليل سلوك الرأس
            if 'suspicious_headers' in features:
                if len(features['suspicious_headers']) > 0:
                    results['indicators'].append(f'Suspicious headers: {", ".join(features["suspicious_headers"])}')
            
            # تحليل سلوك التكرار
            if 'repetition_patterns' in features:
                if features['repetition_patterns'] > 5:
                    results['indicators'].append('High repetition patterns (possible brute force)')
            
            # تحليل سلوك التسلسل
            if 'sequential_patterns' in features:
                if features['sequential_patterns'] > 10:
                    results['indicators'].append('Sequential patterns detected (possible enumeration)')
            
        except Exception as e:
            results['indicators'].append(f'Behavior analysis error: {str(e)}')
        
        return results

class ThreatClassifier:
    """مصنف التهديدات"""
    
    def __init__(self):
        self.threat_categories = {
            'injection': ['sql_injection', 'command_injection', 'ldap_injection', 'xpath_injection'],
            'authentication': ['brute_force', 'credential_stuffing', 'session_hijacking'],
            'access_control': ['privilege_escalation', 'directory_traversal', 'forceful_browsing'],
            'client_side': ['xss', 'csrf', 'clickjacking'],
            'server_side': ['ssrf', 'xxe', 'template_injection'],
            'data_exposure': ['information_disclosure', 'sensitive_data_exposure'],
            'availability': ['dos', 'ddos', 'resource_exhaustion']
        }
    
    def classify_threat(self, features):
        """تصنيف نوع التهديد"""
        results = {
            'predictions': {},
            'confidence': 0.0
        }
        
        try:
            predictions = {}
            total_score = 0
            
            # تصنيف التهديدات بناءً على الميزات
            for category, subcategories in self.threat_categories.items():
                category_score = 0
                
                if category == 'injection':
                    category_score += features.get('sql_patterns', 0) * 0.3
                    category_score += features.get('command_patterns', 0) * 0.3
                    category_score += features.get('special_char_ratio', 0) * 0.2
                    category_score += features.get('encoding_patterns', 0) * 0.2
                
                elif category == 'authentication':
                    category_score += features.get('repetition_patterns', 0) * 0.1
                    category_score += features.get('credential_patterns', 0) * 0.4
                    category_score += features.get('brute_force_indicators', 0) * 0.3
                    category_score += features.get('session_anomalies', 0) * 0.2
                
                elif category == 'access_control':
                    category_score += features.get('path_traversal_attempts', 0) * 0.4
                    category_score += features.get('privilege_escalation_patterns', 0) * 0.3
                    category_score += features.get('forceful_browsing_indicators', 0) * 0.3
                
                elif category == 'client_side':
                    category_score += features.get('xss_patterns', 0) * 0.4
                    category_score += features.get('csrf_patterns', 0) * 0.3
                    category_score += features.get('dom_manipulation', 0) * 0.3
                
                elif category == 'server_side':
                    category_score += features.get('ssrf_patterns', 0) * 0.4
                    category_score += features.get('xxe_patterns', 0) * 0.3
                    category_score += features.get('template_injection_patterns', 0) * 0.3
                
                elif category == 'data_exposure':
                    category_score += features.get('information_disclosure_patterns', 0) * 0.4
                    category_score += features.get('sensitive_data_patterns', 0) * 0.3
                    category_score += features.get('error_information_leakage', 0) * 0.3
                
                elif category == 'availability':
                    category_score += features.get('dos_patterns', 0) * 0.3
                    category_score += features.get('resource_exhaustion_indicators', 0) * 0.4
                    category_score += features.get('flooding_patterns', 0) * 0.3
                
                if category_score > 0:
                    predictions[category] = min(category_score, 1.0)
                    total_score += category_score
            
            # حساب الثقة العامة
            results['confidence'] = min(total_score / len(self.threat_categories), 1.0)
            results['predictions'] = predictions
            
        except Exception as e:
            results['predictions'] = {'error': str(e)}
        
        return results

class PredictiveAnalytics:
    """التحليل التنبؤي"""
    
    def __init__(self):
        self.risk_factors = {}
        self.historical_data = []
    
    def predict_risk(self, features):
        """التنبؤ بمستوى المخاطرة"""
        results = {
            'risk_level': 'LOW',
            'indicators': [],
            'risk_factors': {}
        }
        
        try:
            risk_score = 0
            risk_factors = {}
            
            # تحليل عوامل الخطر
            if 'request_rate' in features:
                if features['request_rate'] > 20:
                    risk_factors['high_request_rate'] = 0.8
                    risk_score += 25
                elif features['request_rate'] > 10:
                    risk_factors['elevated_request_rate'] = 0.6
                    risk_score += 15
            
            if 'error_rate' in features:
                if features['error_rate'] > 0.5:
                    risk_factors['high_error_rate'] = 0.7
                    risk_score += 20
                elif features['error_rate'] > 0.3:
                    risk_factors['elevated_error_rate'] = 0.5
                    risk_score += 10
            
            if 'payload_complexity' in features:
                if features['payload_complexity'] > 0.8:
                    risk_factors['complex_payload'] = 0.8
                    risk_score += 15
            
            if 'attack_vector_diversity' in features:
                if features['attack_vector_diversity'] > 5:
                    risk_factors['multiple_attack_vectors'] = 0.7
                    risk_score += 20
            
            if 'persistence_indicators' in features:
                if features['persistence_indicators'] > 3:
                    risk_factors['persistence_attempts'] = 0.8
                    risk_score += 25
            
            # تحديد مستوى الخطورة
            if risk_score >= 70:
                results['risk_level'] = 'CRITICAL'
            elif risk_score >= 50:
                results['risk_level'] = 'HIGH'
            elif risk_score >= 30:
                results['risk_level'] = 'MEDIUM'
            else:
                results['risk_level'] = 'LOW'
            
            # إنشاء مؤشرات
            for factor, confidence in risk_factors.items():
                if confidence > 0.6:
                    results['indicators'].append(f'High risk factor: {factor}')
            
            results['risk_factors'] = risk_factors
            
        except Exception as e:
            results['indicators'].append(f'Predictive analysis error: {str(e)}')
        
        return results

class AdvancedHeuristics:
    """الاستدلال المتقدم"""
    
    def __init__(self):
        self.heuristic_rules = self.load_heuristic_rules()
    
    def load_heuristic_rules(self):
        """تحميل قواعد الاستدلال"""
        return {
            'multi_stage_attack': {
                'indicators': ['reconnaissance', 'exploitation', 'persistence'],
                'threshold': 2
            },
            'advanced_persistence': {
                'indicators': ['backdoor', 'webshell', 'rootkit'],
                'threshold': 1
            },
            'data_exfiltration': {
                'indicators': ['large_response', 'unusual_data_access', 'external_communication'],
                'threshold': 2
            },
            'lateral_movement': {
                'indicators': ['network_scanning', 'privilege_escalation', 'service_enumeration'],
                'threshold': 2
            }
        }
    
    def analyze_heuristics(self, features):
        """تحليل الاستدلالات المتقدمة"""
        results = {
            'indicators': []
        }
        
        try:
            for heuristic_name, rules in self.heuristic_rules.items():
                matched_indicators = 0
                
                for indicator in rules['indicators']:
                    if self.check_indicator(features, indicator):
                        matched_indicators += 1
                
                if matched_indicators >= rules['threshold']:
                    results['indicators'].append(f'Advanced heuristic detected: {heuristic_name}')
            
            # استدلالات خاصة
            if self.detect_advanced_evasion(features):
                results['indicators'].append('Advanced evasion techniques detected')
            
            if self.detect_multi_vector_attack(features):
                results['indicators'].append('Multi-vector attack pattern detected')
            
            if self.detect_zero_day_indicators(features):
                results['indicators'].append('Possible zero-day exploitation attempt')
            
        except Exception as e:
            results['indicators'].append(f'Heuristic analysis error: {str(e)}')
        
        return results
    
    def check_indicator(self, features, indicator):
        """التحقق من وجود مؤشر"""
        indicator_features = {
            'reconnaissance': ['scanning_patterns', 'enumeration_attempts'],
            'exploitation': ['payload_delivery', 'vulnerability_exploitation'],
            'persistence': ['backdoor_installation', 'service_modification'],
            'backdoor': ['reverse_shell', 'command_execution'],
            'webshell': ['file_upload', 'code_execution'],
            'rootkit': ['system_modification', 'process_hiding'],
            'large_response': ['response_size_anomaly', 'data_volume'],
            'unusual_data_access': ['unauthorized_access', 'data_query_patterns'],
            'external_communication': ['outbound_connections', 'data_transmission'],
            'network_scanning': ['port_scanning', 'service_discovery'],
            'privilege_escalation': ['permission_changes', 'elevation_attempts'],
            'service_enumeration': ['service_listing', 'version_detection']
        }
        
        if indicator in indicator_features:
            for feature in indicator_features[indicator]:
                if feature in features and features[feature] > 0:
                    return True
        
        return False
    
    def detect_advanced_evasion(self, features):
        """الكشف عن تقنيات التهرب المتقدمة"""
        evasion_indicators = 0
        
        if features.get('encoding_layers', 0) > 2:
            evasion_indicators += 1
        
        if features.get('fragmentation_attempts', 0) > 0:
            evasion_indicators += 1
        
        if features.get('timing_evasion', 0) > 0:
            evasion_indicators += 1
        
        if features.get('protocol_manipulation', 0) > 0:
            evasion_indicators += 1
        
        return evasion_indicators >= 2
    
    def detect_multi_vector_attack(self, features):
        """الكشف عن هجمات متعددة الناقلات"""
        attack_vectors = 0
        
        vector_types = ['network_vector', 'application_vector', 'system_vector', 'user_vector']
        
        for vector in vector_types:
            if features.get(vector, 0) > 0:
                attack_vectors += 1
        
        return attack_vectors >= 3
    
    def detect_zero_day_indicators(self, features):
        """الكشف عن مؤشرات استغلال اليوم الصفري"""
        zero_day_indicators = 0
        
        if features.get('unknown_payload_patterns', 0) > 0:
            zero_day_indicators += 1
        
        if features.get('unusual_exploitation_methods', 0) > 0:
            zero_day_indicators += 1
        
        if features.get('previously_unseen_techniques', 0) > 0:
            zero_day_indicators += 1
        
        if features.get('exploitation_without_vulnerability_match', 0) > 0:
            zero_day_indicators += 1
        
        return zero_day_indicators >= 2

# مستخرجات الميزات
class URLFeatureExtractor:
    """مستخرج ميزات URL"""
    
    def extract_features(self, url):
        """استخراج ميزات من URL"""
        features = {}
        
        try:
            parsed = urlparse(url)
            
            # ميزات أساسية
            features['url_length'] = len(url)
            features['domain_length'] = len(parsed.netloc)
            features['path_length'] = len(parsed.path)
            features['query_length'] = len(parsed.query)
            
            # عدد المعلمات
            params = parse_qs(parsed.query)
            features['param_count'] = len(params)
            
            # نسبة الأحرف الخاصة
            special_chars = sum(1 for c in url if not c.isalnum() and c not in ['-', '_', '.'])
            features['special_char_ratio'] = special_chars / len(url) if len(url) > 0 else 0
            
            # أنماط التشفير
            encoding_patterns = 0
            if '%' in url:
                encoding_patterns += 1
            if '+' in parsed.query:
                encoding_patterns += 1
            if 'base64' in url.lower():
                encoding_patterns += 1
            features['encoding_patterns'] = encoding_patterns
            
            # أسماء المعلمات المشبوهة
            suspicious_params = ['exec', 'eval', 'system', 'cmd', 'command', 'shell']
            features['suspicious_param_names'] = [p for p in params.keys() if any(s in p.lower() for s in suspicious_params)]
            
            # محاولات الحقن
            injection_patterns = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'exec', 'script']
            features['injection_patterns'] = sum(1 for pattern in injection_patterns if pattern in url.lower())
            
            # محاولات الوصول إلى الملفات
            file_patterns = ['../', '..\\', '/etc/', 'windows', 'system32', 'win.ini']
            features['file_access_patterns'] = sum(1 for pattern in file_patterns if pattern in url.lower())
            
        except Exception as e:
            features['url_extraction_error'] = str(e)
        
        return features

class PayloadFeatureExtractor:
    """مستخرج ميزات الحمولة"""
    
    def extract_features(self, payload):
        """استخراج ميزات من الحمولة"""
        features = {}
        
        try:
            if not payload:
                return features
            
            # ميزات أساسية
            features['payload_length'] = len(payload)
            features['payload_entropy'] = self.calculate_entropy(payload)
            
            # نسبة الأحرف الخاصة
            special_chars = sum(1 for c in payload if not c.isalnum() and c not in [' ', '\t', '\n', '\r'])
            features['payload_special_ratio'] = special_chars / len(payload) if len(payload) > 0 else 0
            
            # أنماط SQL Injection
            sql_patterns = ['union', 'select', 'from', 'where', 'insert', 'update', 'delete', 'drop', 'exec']
            features['sql_patterns'] = sum(1 for pattern in sql_patterns if pattern in payload.lower())
            
            # أنماط XSS
            xss_patterns = ['<script', 'javascript:', 'onerror', 'onload', 'onclick', 'alert(', 'confirm(']
            features['xss_patterns'] = sum(1 for pattern in xss_patterns if pattern in payload.lower())
            
            # أنماط Command Injection
            cmd_patterns = ['&&', '||', ';', '`', '$(', '|', '>', '<', 'exec', 'system', 'passthru']
            features['command_patterns'] = sum(1 for pattern in cmd_patterns if pattern in payload)
            
            # أنماط التشفير/التشويش
            base64_pattern = r'^[A-Za-z0-9+/]*={0,2}$'
            hex_pattern = r'^[0-9a-fA-F]+$'
            
            features['base64_encoded'] = 1 if re.match(base64_pattern, payload) and len(payload) > 20 else 0
            features['hex_encoded'] = 1 if re.match(hex_pattern, payload) and len(payload) > 10 else 0
            
            # محاولات التهرب
            evasion_patterns = ['%252', '%00', '/**/', '[]', '\\x', '\\u', 'chr(', 'char(']
            features['evasion_patterns'] = sum(1 for pattern in evasion_patterns if pattern in payload)
            
        except Exception as e:
            features['payload_extraction_error'] = str(e)
        
        return features
    
    def calculate_entropy(self, data):
        """حساب الإنتروبيا"""
        if not data:
            return 0
        
        # حساب توزيع الأحرف
        char_counts = Counter(data)
        total_chars = len(data)
        
        # حساب الإنتروبيا
        entropy = 0
        for count in char_counts.values():
            probability = count / total_chars
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy

class BehaviorFeatureExtractor:
    """مستخرج ميزات السلوك"""
    
    def extract_features(self, behavior_data):
        """استخراج ميزات السلوك"""
        features = {}
        
        try:
            # معدل الطلبات
            if 'request_count' in behavior_data and 'time_window' in behavior_data:
                features['request_rate'] = behavior_data['request_count'] / behavior_data['time_window']
            
            # معدل الأخطاء
            if 'error_count' in behavior_data and 'request_count' in behavior_data:
                features['error_rate'] = behavior_data['error_count'] / behavior_data['request_count'] if behavior_data['request_count'] > 0 else 0
            
            # تنوع المسارات
            if 'unique_paths' in behavior_data and 'request_count' in behavior_data:
                features['path_diversity'] = len(behavior_data['unique_paths']) / behavior_data['request_count'] if behavior_data['request_count'] > 0 else 0
            
            # تنوع المعلمات
            if 'unique_params' in behavior_data:
                features['param_diversity'] = len(behavior_data['unique_params'])
            
            # محاولات الوصول غير المصرح بها
            if 'unauthorized_attempts' in behavior_data:
                features['unauthorized_attempts'] = behavior_data['unauthorized_attempts']
            
            # أنماط المسار
            if 'path_patterns' in behavior_data:
                features['path_traversal_attempts'] = sum(1 for path in behavior_data['path_patterns'] if '../' in path or '..\\' in path)
            
            # أنماط التسلسل
            if 'sequential_requests' in behavior_data:
                features['sequential_patterns'] = behavior_data['sequential_requests']
            
            # أنماط التكرار
            if 'repeated_requests' in behavior_data:
                features['repetition_patterns'] = behavior_data['repeated_requests']
            
        except Exception as e:
            features['behavior_extraction_error'] = str(e)
        
        return features

class TemporalFeatureExtractor:
    """مستخرج الميزات الزمنية"""
    
    def extract_features(self, timestamp_data):
        """استخراج الميزات الزمنية"""
        features = {}
        
        try:
            if isinstance(timestamp_data, (int, float)):
                # تحليل الأنماط الزمنية
                hour = datetime.fromtimestamp(timestamp_data).hour
                
                # أنشطة غير عادية في أوقات غير العمل
                if hour < 6 or hour > 22:
                    features['off_hours_activity'] = 1
                else:
                    features['off_hours_activity'] = 0
                
                # أنماط الدورية
                if 'request_intervals' in locals():
                    intervals = locals()['request_intervals']
                    if len(intervals) > 1:
                        features['interval_variance'] = np.var(intervals)
                        features['is_periodic'] = 1 if features['interval_variance'] < 0.1 else 0
                
            elif isinstance(timestamp_data, str):
                # تحليل أنماط التاريخ
                features['timestamp_format'] = self.detect_timestamp_format(timestamp_data)
                
        except Exception as e:
            features['temporal_extraction_error'] = str(e)
        
        return features
    
    def detect_timestamp_format(self, timestamp_str):
        """الكشف عن تنسيق الطابع الزمني"""
        formats = [
            (r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', 'iso8601'),
            (r'\d{2}/\d{2}/\d{4}', 'us_date'),
            (r'\d{2}-\d{2}-\d{4}', 'eu_date'),
            (r'\d{10}', 'unix_timestamp'),
            (r'\d{13}', 'unix_ms_timestamp')
        ]
        
        for pattern, format_name in formats:
            if re.match(pattern, timestamp_str):
                return format_name
        
        return 'unknown'

class NetworkFeatureExtractor:
    """مستخرج ميزات الشبكة"""
    
    def extract_features(self, network_data):
        """استخراج ميزات الشبكة"""
        features = {}
        
        try:
            # تحليل عنوان IP
            if 'source_ip' in network_data:
                features['is_private_ip'] = self.is_private_ip(network_data['source_ip'])
                features['is_tor_exit_node'] = self.check_tor_exit_node(network_data['source_ip'])
                features['ip_reputation_score'] = self.get_ip_reputation(network_data['source_ip'])
            
            # تحليل المنفذ
            if 'port' in network_data:
                features['unusual_port'] = 1 if network_data['port'] > 10000 or network_data['port'] < 1024 else 0
                features['common_web_port'] = 1 if network_data['port'] in [80, 443, 8080, 8443] else 0
            
            # تحليل حجم البيانات
            if 'request_size' in network_data and 'response_size' in network_data:
                features['size_ratio'] = network_data['response_size'] / network_data['request_size'] if network_data['request_size'] > 0 else 0
                features['large_response'] = 1 if network_data['response_size'] > 1000000 else 0  # أكبر من 1 ميغابايت
            
            # تحليل التأخير
            if 'response_time' in network_data:
                features['slow_response'] = 1 if network_data['response_time'] > 5 else 0
                features['very_slow_response'] = 1 if network_data['response_time'] > 10 else 0
            
            # تحليل البروتوكول
            if 'protocol' in network_data:
                features['secure_protocol'] = 1 if network_data['protocol'].lower() in ['https', 'tls', 'ssl'] else 0
            
        except Exception as e:
            features['network_extraction_error'] = str(e)
        
        return features
    
    def is_private_ip(self, ip):
        """التحقق مما إذا كان عنوان IP خاصاً"""
        private_ranges = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.'
        ]
        
        for pattern in private_ranges:
            if re.match(pattern, ip):
                return 1
        
        return 0
    
    def check_tor_exit_node(self, ip):
        """التحقق مما إذا كان عنوان IP هو عقدة خروج Tor"""
        # هذه دالة مبسطة - في التطبيق الفعلي، يجب استخدام قاعدة بيانات محدثة
        tor_patterns = [
            r'^192\.42\.116\.',
            r'^192\.99\.8\.',
            r'^199\.195\.248\.',
            r'^204\.8\.156\.'
        ]
        
        for pattern in tor_patterns:
            if re.match(pattern, ip):
                return 1
        
        return 0
    
    def get_ip_reputation(self, ip):
        """الحصول على سمعة عنوان IP"""
        # هذه دالة مبسطة - في التطبيق الفعلي، يجب استخدام خدمة سمعة IP حقيقية
        suspicious_octets = ['1.1.1.', '8.8.8.', '0.0.0.']
        
        for octet in suspicious_octets:
            if ip.startswith(octet):
                return 0.2  # درجة سمعة منخفضة
        
        return 0.8  # درجة سمعة عالية

# دالة مساعدة للاستخدام السريع
def analyze_with_ml(request_data):
    """دالة سريعة للتحليل باستخدام التعلم الآلي"""
    detector = MLThreatDetector()
    return detector.analyze_request(request_data)

if __name__ == '__main__':
    # مثال على الاستخدام
    sample_request = {
        'url': 'http://example.com/api/users?id=1 UNION SELECT * FROM admin--',
        'payload': "<script>alert('XSS')</script>",
        'behavior_data': {
            'request_count': 50,
            'time_window': 2,
            'error_count': 10,
            'unique_paths': ['/api/users', '/admin', '/login'],
            'unauthorized_attempts': 5
        },
        'timestamp': datetime.now().timestamp(),
        'network_data': {
            'source_ip': '192.168.1.100',
            'port': 80,
            'request_size': 256,
            'response_size': 1024,
            'response_time': 1.5,
            'protocol': 'HTTP'
        }
    }
    
    results = analyze_with_ml(sample_request)
    print("\n[+] ML Analysis Results:")
    print(f"Risk Level: {results['risk_level']}")
    print(f"Anomaly Score: {results['anomaly_score']:.2f}")
    print(f"Confidence: {results['confidence']:.2f}")
    print(f"Threat Indicators: {len(results['threat_indicators'])}")
    for indicator in results['threat_indicators'][:5]:  # أول 5 مؤشرات
        print(f"  - {indicator}")
    print(f"Predictions: {results['predictions']}")