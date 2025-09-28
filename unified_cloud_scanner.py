#!/usr/bin/env python3
"""
Unified Cloud Security Scanner
A comprehensive tool for scanning and assessing cloud infrastructure security
"""

import json
import argparse
import datetime
import sys
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from exploits.cloud_exploits import CloudExploits
    from exploits.modern_vulnerabilities import ModernVulnerabilities
    from exploits.web_exploits import WebExploits
    from exploits.advanced_exploits import AdvancedExploits
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure all required modules are available")
    sys.exit(1)

@dataclass
class ScanResult:
    """Data class for scan results"""
    scan_type: str
    target: str
    findings: List[Dict[str, Any]]
    severity_counts: Dict[str, int]
    execution_time: float
    status: str
    error_message: Optional[str] = None

class UnifiedCloudScanner:
    """
    Comprehensive cloud security scanner that integrates multiple
    vulnerability assessment techniques
    """
    
    def __init__(self, target: str, output_dir: str = "reports"):
        self.target = target
        self.output_dir = output_dir
        self.scan_results = []
        self.start_time = None
        self.end_time = None
        
        # Initialize scanners
        self.cloud_exploits = CloudExploits(target)
        self.modern_vulns = ModernVulnerabilities(target)
        self.web_exploits = WebExploits(target)
        self.advanced_exploits = AdvancedExploits(target)
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
    def run_cloud_infrastructure_scan(self) -> ScanResult:
        """Scan for cloud infrastructure vulnerabilities"""
        print(f"🔍 Starting cloud infrastructure scan for {self.target}...")
        start_time = time.time()
        
        try:
            self.cloud_exploits.run_all_exploits()
            findings = self.cloud_exploits.get_findings()
            
            # Count severities
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for finding in findings:
                severity = finding.get("severity", "INFO").upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            execution_time = time.time() - start_time
            
            return ScanResult(
                scan_type="Cloud Infrastructure",
                target=self.target,
                findings=findings,
                severity_counts=severity_counts,
                execution_time=execution_time,
                status="COMPLETED"
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return ScanResult(
                scan_type="Cloud Infrastructure",
                target=self.target,
                findings=[],
                severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                execution_time=execution_time,
                status="FAILED",
                error_message=str(e)
            )
    
    def run_modern_vulnerability_scan(self) -> ScanResult:
        """Scan for modern web vulnerabilities"""
        print(f"🔍 Starting modern vulnerability scan for {self.target}...")
        start_time = time.time()
        
        try:
            # Run modern vulnerability tests
            findings = []
            
            # Test for common modern vulnerabilities
            tests = [
                self.modern_vulns.test_graphql_injection,
                self.modern_vulns.test_server_side_request_forgery,
                self.modern_vulns.test_insecure_deserialization,
                self.modern_vulns.test_api_security_issues,
                self.modern_vulns.test_container_vulnerabilities
            ]
            
            for test in tests:
                try:
                    result = test()
                    if result and result.get("vulnerable", False):
                        findings.append(result)
                except Exception as e:
                    print(f"⚠️  Test {test.__name__} failed: {e}")
                    continue
            
            # Count severities
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for finding in findings:
                severity = finding.get("severity", "INFO").upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            execution_time = time.time() - start_time
            
            return ScanResult(
                scan_type="Modern Vulnerabilities",
                target=self.target,
                findings=findings,
                severity_counts=severity_counts,
                execution_time=execution_time,
                status="COMPLETED"
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return ScanResult(
                scan_type="Modern Vulnerabilities",
                target=self.target,
                findings=[],
                severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                execution_time=execution_time,
                status="FAILED",
                error_message=str(e)
            )
    
    def run_web_security_scan(self) -> ScanResult:
        """Scan for web security issues"""
        print(f"🔍 Starting web security scan for {self.target}...")
        start_time = time.time()
        
        try:
            # Run web security tests
            findings = []
            
            # Test for web security issues
            tests = [
                self.web_exploits.test_security_headers,
                self.web_exploits.test_cors_configuration,
                self.web_exploits.test_ssl_configuration,
                self.web_exploits.test_authentication_bypass,
                self.web_exploits.test_authorization_issues
            ]
            
            for test in tests:
                try:
                    result = test()
                    if result and result.get("vulnerable", False):
                        findings.append(result)
                except Exception as e:
                    print(f"⚠️  Test {test.__name__} failed: {e}")
                    continue
            
            # Count severities
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for finding in findings:
                severity = finding.get("severity", "INFO").upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            execution_time = time.time() - start_time
            
            return ScanResult(
                scan_type="Web Security",
                target=self.target,
                findings=findings,
                severity_counts=severity_counts,
                execution_time=execution_time,
                status="COMPLETED"
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return ScanResult(
                scan_type="Web Security",
                target=self.target,
                findings=[],
                severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                execution_time=execution_time,
                status="FAILED",
                error_message=str(e)
            )
    
    def run_advanced_exploitation_scan(self) -> ScanResult:
        """Run advanced exploitation techniques"""
        print(f"🔍 Starting advanced exploitation scan for {self.target}...")
        start_time = time.time()
        
        try:
            # Run advanced exploitation tests
            findings = []
            
            # Test for advanced vulnerabilities
            tests = [
                self.advanced_exploits.test_advanced_sql_injection,
                self.advanced_exploits.test_advanced_xss,
                self.advanced_exploits.test_advanced_xxe,
                self.advanced_exploits.test_advanced_rce,
                self.advanced_exploits.test_advanced_lfi
            ]
            
            for test in tests:
                try:
                    result = test()
                    if result and result.get("vulnerable", False):
                        findings.append(result)
                except Exception as e:
                    print(f"⚠️  Test {test.__name__} failed: {e}")
                    continue
            
            # Count severities
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for finding in findings:
                severity = finding.get("severity", "INFO").upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            execution_time = time.time() - start_time
            
            return ScanResult(
                scan_type="Advanced Exploitation",
                target=self.target,
                findings=findings,
                severity_counts=severity_counts,
                execution_time=execution_time,
                status="COMPLETED"
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return ScanResult(
                scan_type="Advanced Exploitation",
                target=self.target,
                findings=[],
                severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                execution_time=execution_time,
                status="FAILED",
                error_message=str(e)
            )
    
    def run_comprehensive_scan(self, scan_types: List[str] = None) -> Dict[str, Any]:
        """Run comprehensive security scan"""
        print(f"🚀 Starting comprehensive security scan for {self.target}...")
        self.start_time = time.time()
        
        if scan_types is None:
            scan_types = ["cloud", "modern", "web", "advanced"]
        
        # Define scan functions
        scan_functions = {
            "cloud": self.run_cloud_infrastructure_scan,
            "modern": self.run_modern_vulnerability_scan,
            "web": self.run_web_security_scan,
            "advanced": self.run_advanced_exploitation_scan
        }
        
        results = []
        
        # Run scans in parallel for better performance
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_scan = {}
            
            for scan_type in scan_types:
                if scan_type in scan_functions:
                    future = executor.submit(scan_functions[scan_type])
                    future_to_scan[future] = scan_type
            
            # Collect results
            for future in as_completed(future_to_scan):
                scan_type = future_to_scan[future]
                try:
                    result = future.result()
                    results.append(result)
                    print(f"✅ {scan_type.upper()} scan completed")
                except Exception as e:
                    print(f"❌ {scan_type.upper()} scan failed: {e}")
        
        self.end_time = time.time()
        
        # Generate comprehensive report
        return self.generate_comprehensive_report(results)
    
    def generate_comprehensive_report(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Generate comprehensive security assessment report"""
        
        # Aggregate statistics
        total_findings = sum(len(result.findings) for result in results)
        total_execution_time = sum(result.execution_time for result in results)
        
        # Aggregate severity counts
        total_severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for result in results:
            for severity, count in result.severity_counts.items():
                total_severity_counts[severity] += count
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(total_severity_counts)
        risk_level = self.get_risk_level(risk_score)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(results)
        
        report = {
            "scan_metadata": {
                "target": self.target,
                "scan_date": datetime.datetime.now().isoformat(),
                "total_execution_time": total_execution_time,
                "scanner_version": "2.0.0",
                "scan_types": [result.scan_type for result in results]
            },
            "summary": {
                "total_findings": total_findings,
                "severity_breakdown": total_severity_counts,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "scan_status": "COMPLETED"
            },
            "detailed_results": [
                {
                    "scan_type": result.scan_type,
                    "target": result.target,
                    "findings_count": len(result.findings),
                    "severity_breakdown": result.severity_counts,
                    "execution_time": result.execution_time,
                    "status": result.status,
                    "error_message": result.error_message,
                    "findings": result.findings
                }
                for result in results
            ],
            "recommendations": recommendations,
            "next_steps": self.generate_next_steps(total_severity_counts, risk_level)
        }
        
        # Save report to file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"unified_cloud_scan_report_{self.target}_{timestamp}.json"
        report_path = os.path.join(self.output_dir, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"📊 Comprehensive report saved to: {report_path}")
        
        return report
    
    def calculate_risk_score(self, severity_counts: Dict[str, int]) -> int:
        """Calculate overall risk score based on severity counts"""
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
        score = 0
        
        for severity, count in severity_counts.items():
            score += weights.get(severity, 0) * count
        
        return min(score, 100)  # Cap at 100
    
    def get_risk_level(self, risk_score: int) -> str:
        """Get risk level based on risk score"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 30:
            return "MEDIUM"
        elif risk_score >= 10:
            return "LOW"
        else:
            return "MINIMAL"
    
    def generate_recommendations(self, results: List[ScanResult]) -> List[Dict[str, str]]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        for result in results:
            if result.findings:
                # Add recommendations based on scan type and findings
                if result.scan_type == "Cloud Infrastructure":
                    recommendations.extend([
                        {
                            "priority": "HIGH",
                            "category": "Cloud Security",
                            "recommendation": "Review cloud storage permissions and implement least privilege access",
                            "details": "Ensure all cloud storage buckets and containers have proper access controls"
                        },
                        {
                            "priority": "MEDIUM",
                            "category": "Container Security",
                            "recommendation": "Implement container image scanning and vulnerability management",
                            "details": "Regularly scan container images for known vulnerabilities"
                        }
                    ])
                
                elif result.scan_type == "Modern Vulnerabilities":
                    recommendations.extend([
                        {
                            "priority": "HIGH",
                            "category": "API Security",
                            "recommendation": "Implement proper API authentication and authorization",
                            "details": "Use OAuth 2.0 or similar protocols for API security"
                        },
                        {
                            "priority": "CRITICAL",
                            "category": "Input Validation",
                            "recommendation": "Implement comprehensive input validation and sanitization",
                            "details": "Validate all user inputs to prevent injection attacks"
                        }
                    ])
                
                elif result.scan_type == "Web Security":
                    recommendations.extend([
                        {
                            "priority": "HIGH",
                            "category": "Security Headers",
                            "recommendation": "Implement security headers (CSP, HSTS, X-Frame-Options)",
                            "details": "Add comprehensive security headers to prevent common attacks"
                        },
                        {
                            "priority": "MEDIUM",
                            "category": "SSL/TLS",
                            "recommendation": "Implement strong SSL/TLS configuration",
                            "details": "Use TLS 1.3 and strong cipher suites"
                        }
                    ])
                
                elif result.scan_type == "Advanced Exploitation":
                    recommendations.extend([
                        {
                            "priority": "CRITICAL",
                            "category": "Code Security",
                            "recommendation": "Implement secure coding practices and code review processes",
                            "details": "Regular code reviews and static analysis for security issues"
                        },
                        {
                            "priority": "HIGH",
                            "category": "Access Control",
                            "recommendation": "Implement proper access control mechanisms",
                            "details": "Use role-based access control (RBAC) for authorization"
                        }
                    ])
        
        return recommendations
    
    def generate_next_steps(self, severity_counts: Dict[str, int], risk_level: str) -> List[str]:
        """Generate next steps for remediation"""
        next_steps = []
        
        if severity_counts["CRITICAL"] > 0:
            next_steps.extend([
                "Immediately address all CRITICAL findings",
                "Implement emergency response procedures",
                "Conduct immediate security assessment"
            ])
        
        if severity_counts["HIGH"] > 0:
            next_steps.extend([
                "Prioritize HIGH severity findings for remediation",
                "Implement additional monitoring and logging",
                "Review security policies and procedures"
            ])
        
        if severity_counts["MEDIUM"] > 0:
            next_steps.extend([
                "Schedule MEDIUM severity findings for next maintenance window",
                "Implement additional security controls",
                "Conduct regular security training"
            ])
        
        # Always include these steps
        next_steps.extend([
            "Regular security assessments and penetration testing",
            "Implement continuous security monitoring",
            "Keep all systems and applications updated",
            "Regular security awareness training for staff"
        ])
        
        return next_steps
    
    def print_summary(self, report: Dict[str, Any]):
        """Print a summary of the scan results"""
        print("\n" + "="*60)
        print("🔒 UNIFIED CLOUD SECURITY SCAN SUMMARY")
        print("="*60)
        
        summary = report["summary"]
        metadata = report["scan_metadata"]
        
        print(f"🎯 Target: {metadata['target']}")
        print(f"📅 Scan Date: {metadata['scan_date']}")
        print(f"⏱️  Total Execution Time: {metadata['total_execution_time']:.2f} seconds")
        print(f"📊 Risk Level: {summary['risk_level']}")
        print(f"🔢 Risk Score: {summary['risk_score']}/100")
        print(f"🔍 Total Findings: {summary['total_findings']}")
        
        print("\n📈 Severity Breakdown:")
        for severity, count in summary["severity_breakdown"].items():
            if count > 0:
                print(f"   {severity}: {count}")
        
        print("\n🔍 Scan Types Performed:")
        for scan_type in metadata["scan_types"]:
            print(f"   ✅ {scan_type}")
        
        if report["recommendations"]:
            print(f"\n💡 Top Recommendations ({len(report['recommendations'])}):")
            for i, rec in enumerate(report["recommendations"][:3], 1):
                print(f"   {i}. [{rec['priority']}] {rec['recommendation']}")
        
        print("\n" + "="*60)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Unified Cloud Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python unified_cloud_scanner.py example.com
  python unified_cloud_scanner.py example.com --scan-types cloud,web
  python unified_cloud_scanner.py example.com --output-dir custom_reports
  python unified_cloud_scanner.py example.com --demo
        """
    )
    
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("--scan-types", 
                       help="Comma-separated list of scan types (cloud,modern,web,advanced)",
                       default="cloud,modern,web,advanced")
    parser.add_argument("--output-dir", 
                       help="Output directory for reports",
                       default="reports")
    parser.add_argument("--demo", 
                       action="store_true",
                       help="Run in demo mode with simulated results")
    parser.add_argument("--verbose", 
                       action="store_true",
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Parse scan types
    scan_types = [s.strip() for s in args.scan_types.split(",")]
    
    # Validate scan types
    valid_scan_types = ["cloud", "modern", "web", "advanced"]
    scan_types = [s for s in scan_types if s in valid_scan_types]
    
    if not scan_types:
        print("❌ No valid scan types specified")
        return 1
    
    print(f"🚀 Starting Unified Cloud Security Scanner")
    print(f"🎯 Target: {args.target}")
    print(f"🔍 Scan Types: {', '.join(scan_types)}")
    print(f"📁 Output Directory: {args.output_dir}")
    
    try:
        # Initialize scanner
        scanner = UnifiedCloudScanner(args.target, args.output_dir)
        
        # Run comprehensive scan
        if args.demo:
            print("🎮 Running in DEMO mode...")
            # In demo mode, we'll simulate results
            report = {
                "scan_metadata": {
                    "target": args.target,
                    "scan_date": datetime.datetime.now().isoformat(),
                    "total_execution_time": 15.5,
                    "scanner_version": "2.0.0",
                    "scan_types": scan_types
                },
                "summary": {
                    "total_findings": 12,
                    "severity_breakdown": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 5, "LOW": 2, "INFO": 1},
                    "risk_score": 68,
                    "risk_level": "HIGH",
                    "scan_status": "COMPLETED"
                },
                "recommendations": [
                    {
                        "priority": "CRITICAL",
                        "category": "Cloud Security",
                        "recommendation": "Review cloud storage permissions and implement least privilege access",
                        "details": "Ensure all cloud storage buckets have proper access controls"
                    }
                ],
                "next_steps": [
                    "Immediately address all CRITICAL findings",
                    "Prioritize HIGH severity findings for remediation",
                    "Implement additional monitoring and logging"
                ]
            }
        else:
            report = scanner.run_comprehensive_scan(scan_types)
        
        # Print summary
        scanner.print_summary(report)
        
        print("✅ Scan completed successfully!")
        return 0
        
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())