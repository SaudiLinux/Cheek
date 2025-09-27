#!/usr/bin/env python3
"""
اختبار سريع للتحقق من رؤوس الأمان المفقودة
Quick Security Headers Test
"""

import requests

def quick_security_test():
    print("=== اختبار سريع لرؤوس الأمان ===")
    
    target = "http://httpbin.org"
    endpoints = ["/api/v1", "/api/v2", "/api", "/rest", "/rest/api"]
    
    all_missing_headers = []
    
    for endpoint in endpoints:
        print(f"\n[*] اختبار: {target}{endpoint}")
        
        try:
            response = requests.get(f"{target}{endpoint}", timeout=5)
            headers = response.headers
            
            # التحقق من الرؤوس المهمة
            missing = []
            
            if 'X-Frame-Options' not in headers:
                missing.append('X-Frame-Options')
            if 'X-Content-Type-Options' not in headers:
                missing.append('X-Content-Type-Options')
            if 'X-XSS-Protection' not in headers:
                missing.append('X-XSS-Protection')
            if 'Strict-Transport-Security' not in headers:
                missing.append('Strict-Transport-Security')
            if 'Content-Security-Policy' not in headers:
                missing.append('Content-Security-Policy')
            
            if missing:
                print(f"[!] رؤوس مفقودة: {', '.join(missing)}")
                all_missing_headers.extend(missing)
            else:
                print("[✓] جميع الرؤوس المهمة موجودة")
                
        except Exception as e:
            print(f"[-] خطأ: {e}")
    
    # تقرير نهائي
    print(f"\n{'='*50}")
    print("=== تقرير اختبار رؤوس الأمان ===")
    
    if all_missing_headers:
        from collections import Counter
        header_counts = Counter(all_missing_headers)
        print("[!] تم تأكيد وجود رؤوس أمان مفقودة:")
        for header, count in header_counts.items():
            print(f"  • {header}: مفقودة في {count} نقاط نهاية")
    else:
        print("[✓] لم يتم العثور على رؤوس مفقودة")

if __name__ == "__main__":
    quick_security_test()