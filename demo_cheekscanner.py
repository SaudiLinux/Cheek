#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Demo script for CheekScanner - Quick demonstration of all features
المبرمج: SayerLinux
الإيميل: SaudiSayer@gmail.com
"""

from cheekscanner import CheekScanner
import json

def demo_cheekscanner():
    """Demonstrate CheekScanner capabilities"""
    print("="*70)
    print("CheekScanner - Advanced Security Scanner Demo")
    print("="*70)
    
    # Create scanner instance
    scanner = CheekScanner()
    
    # Target for demo
    target = "scanme.nmap.org"
    
    print(f"[*] Starting comprehensive scan of {target}")
    print(f"[*] This will demonstrate:")
    print(f"    • Multi-phase security assessment")
    print(f"    • ML-based threat detection")
    print(f"    • Advanced vulnerability scanning")
    print(f"    • Cloud exploitation testing")
    print(f"    • Comprehensive reporting")
    
    # Run full scan
    results = scanner.run_full_scan(target)
    
    print("\n" + "="*70)
    print("SCAN COMPLETED SUCCESSFULLY!")
    print("="*70)
    
    # Display key results
    print(f"\n[+] Scan Duration: {results['duration']} seconds")
    print(f"[+] Vulnerabilities Found: {len(results['vulnerabilities'])}")
    print(f"[+] Security Issues: {len(results['security_issues'])}")
    print(f"[+] ML Detections: {len(results['ml_detections'])}")
    
    # Show ML detection results if any
    if results['ml_detections']:
        print(f"\n[+] ML Threat Detection Results:")
        for detection in results['ml_detections']:
            print(f"    • {detection['detection']['threat_type']}: {detection['detection']['confidence']:.2%}")
    
    # Show risk assessment
    if results['risk_assessment']:
        print(f"\n[+] Risk Assessment:")
        print(f"    • Overall Risk: {results['risk_assessment']['overall_risk']}")
        print(f"    • Recommendation: {results['risk_assessment']['recommendation']}")
    
    print(f"\n[+] Report saved to: cheekscanner_report_{target}_*.json")
    print(f"[+] All features working successfully!")
    
    return results

if __name__ == "__main__":
    try:
        results = demo_cheekscanner()
        print(f"\n[+] Demo completed! Check the generated report files.")
    except KeyboardInterrupt:
        print(f"\n[!] Demo interrupted by user")
    except Exception as e:
        print(f"\n[-] Demo error: {e}")
        print(f"[!] Make sure all dependencies are installed")