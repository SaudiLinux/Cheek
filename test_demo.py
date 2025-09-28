#!/usr/bin/env python3
"""
Simple test script to verify cloud exploitation functionality
"""

import sys
import os

def main():
    print("🌩️ Cloud Exploitation Test Script")
    print("=" * 40)
    
    # Test basic imports
    try:
        from exploits.cloud_exploits import CloudExploits
        print("✅ CloudExploits module imported successfully")
        
        # Test with a target
        if len(sys.argv) > 1:
            target = sys.argv[1]
            print(f"🎯 Testing target: {target}")
            
            # Initialize with target
            cloud_exploits = CloudExploits(target)
            print("✅ CloudExploits initialized successfully")
            
            print("🔄 Running cloud exploitation...")
            cloud_exploits.run_all_exploits()
            
            # Generate report
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"cloud_exploitation_report_{timestamp}.json"
            cloud_exploits.generate_report(report_filename)
            
            print(f"✅ Report saved to: {report_filename}")
        else:
            print("ℹ️  No target provided, showing available tests:")
            print("- AWS S3 bucket enumeration")
            print("- Azure Blob storage testing") 
            print("- GCP Cloud Storage testing")
            print("- Kubernetes API security")
            print("- Docker daemon exposure")
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("📦 Make sure cloud_exploits module is available")
    except Exception as e:
        print(f"❌ Error: {e}")
        print(f"Error type: {type(e).__name__}")

if __name__ == "__main__":
    main()