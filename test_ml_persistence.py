#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script for ML model training and persistence
"""

from ml_threat_detection import MLThreatDetector
import json

def test_ml_model_persistence():
    """اختبار قابلية حفظ وتحميل نماذج التعلم الآلي"""
    print("[*] Testing ML Model Persistence...")
    
    # إنشاء كاشف تهديدات
    detector = MLThreatDetector()
    
    # بيانات تدريب نموذجية
    training_data = {
        'anomaly_detection': [
            {'url': '/login', 'params': {'user': 'admin'}, 'normal': True},
            {'url': '/admin', 'params': {'id': '1\' OR 1=1--'}, 'normal': False},
            {'url': '/search', 'params': {'q': '<script>alert(1)</script>'}, 'normal': False}
        ],
        'threat_classification': [
            {'features': {'sql_chars': 0.8, 'xss_chars': 0.1}, 'label': 'sql_injection'},
            {'features': {'sql_chars': 0.1, 'xss_chars': 0.9}, 'label': 'xss'},
            {'features': {'sql_chars': 0.0, 'xss_chars': 0.0}, 'label': 'normal'}
        ]
    }
    
    # تدريب النماذج
    print("[*] Training models...")
    detector.train_models(training_data)
    
    # حفظ النماذج
    print("[*] Saving models...")
    model_file = detector.save_models('test_models.pkl')
    
    if model_file:
        print(f"[+] Models saved to {model_file}")
        
        # تصدير بيانات التدريب
        print("[*] Exporting training data...")
        detector.export_training_data('training_data.json')
        
        # إنشاء كاشف جديد وتحميل النماذج
        print("[*] Creating new detector and loading models...")
        new_detector = MLThreatDetector()
        
        if new_detector.load_models(model_file):
            print("[+] Models loaded successfully")
            
            # اختبار الكشف
            test_request = {
                'url': '/admin',
                'method': 'GET',
                'params': {'id': '1\' OR 1=1--'},
                'headers': {'User-Agent': 'Mozilla/5.0'}
            }
            
            print("[*] Testing threat detection...")
            results = new_detector.analyze_request(test_request)
            
            print(f"[+] Detection Results:")
            print(f"    Risk Level: {results['risk_level']}")
            print(f"    Anomaly Score: {results['anomaly_score']:.2f}")
            print(f"    Confidence: {results['confidence']:.2f}")
            print(f"    Threat Indicators: {len(results['threat_indicators'])}")
            
            if results['predictions']:
                print(f"    Predictions: {results['predictions']}")
            
            # الحصول على إحصائيات النموذج
            print("[*] Getting model statistics...")
            stats = new_detector.get_model_statistics()
            print(f"[+] Model Statistics: {json.dumps(stats, indent=2)}")
            
            return True
        else:
            print("[-] Failed to load models")
            return False
    else:
        print("[-] Failed to save models")
        return False

if __name__ == "__main__":
    success = test_ml_model_persistence()
    if success:
        print("\n[+] ML Model Persistence Test PASSED")
    else:
        print("\n[-] ML Model Persistence Test FAILED")