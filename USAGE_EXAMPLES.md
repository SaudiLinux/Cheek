# Cloud Security Tools - Usage Examples

This document provides comprehensive usage examples for all cloud security tools in this project.

## Table of Contents
- [Quick Start](#quick-start)
- [Cloud Vulnerability Scanner](#cloud-vulnerability-scanner)
- [Demonstrate Cloud Exploitation](#demonstrate-cloud-exploitation)
- [Unified Cloud Scanner](#unified-cloud-scanner)
- [Advanced Tests](#advanced-tests)
- [Security Testing Scenarios](#security-testing-scenarios)
- [CI/CD Integration](#cicd-integration)
- [Best Practices](#best-practices)

## Quick Start

### Prerequisites
```bash
# Install dependencies
pip install -r requirements.txt

# Or use the installation scripts
./install.sh  # Linux/Mac
install.bat   # Windows
```

### Basic Security Check
```bash
# Quick security assessment
python cloud_vulnerability_scanner.py example.com --quick-scan

# Detailed scan with verbose output
python cloud_vulnerability_scanner.py example.com --verbose
```

## Cloud Vulnerability Scanner

### Basic Usage
```bash
# Quick scan
python cloud_vulnerability_scanner.py target.com --quick-scan

# Deep scan with extended timeout
python cloud_vulnerability_scanner.py target.com --deep-scan

# Custom configuration
python cloud_vulnerability_scanner.py target.com --threads 20 --timeout 60 --verbose
```

### Advanced Examples

#### Production Environment Scan
```bash
# Conservative settings for production
python cloud_vulnerability_scanner.py prod.example.com \
  --threads 5 \
  --timeout 30 \
  --output-dir prod_reports
```

#### Comprehensive Security Audit
```bash
# Full assessment with all features
python cloud_vulnerability_scanner.comprehensive.com \
  --deep-scan \
  --threads 15 \
  --timeout 45 \
  --verbose \
  --output-dir audit_reports
```

#### Batch Processing
```bash
# Process multiple targets
for target in app1.com app2.com api.com; do
  python cloud_vulnerability_scanner.py "$target" --quick-scan
done
```

### Output Examples

#### Console Summary
```
=====================================================
🌩️ CLOUD VULNERABILITY SCAN SUMMARY
=====================================================
🎯 Target: example.com
⏱️  Execution Time: 123.45 seconds
🔍 Total Findings: 15
☁️  Cloud Services Found: 4
🐳 Container Services Found: 2

🎯 Risk Assessment:
   Risk Level: MEDIUM
   Risk Score: 72/100

📈 Severity Breakdown:
   HIGH: 2
   MEDIUM: 8
   LOW: 3
   INFO: 2

💡 Top Recommendations:
   1. [HIGH] Review S3 bucket permissions
   2. [MEDIUM] Enable container security scanning
   3. [MEDIUM] Implement API rate limiting
```

#### JSON Report Structure
```json
{
  "scan_metadata": {
    "target": "example.com",
    "risk_level": "MEDIUM",
    "risk_score": 72,
    "total_findings": 15
  },
  "cloud_services": [
    {
      "service_type": "s3",
      "platform": "aws",
      "accessible": true,
      "vulnerabilities": [...]
    }
  ],
  "recommendations": [...]
}
```

## Demonstrate Cloud Exploitation

### Demo Mode
```bash
# Run all exploitation scenarios in demo mode
python demonstrate_cloud_exploitation.py example.com --demo

# Specific scenario demo
python demonstrate_cloud_exploitation.py example.com --scenario s3_exposure --demo
```

### Real Scanning
```bash
# Real exploitation testing
python demonstrate_cloud_exploitation.py example.com --real-scan

# Specific cloud platform
python demonstrate_cloud_exploitation.py example.com --platform aws --real-scan
```

### Scenario-Based Testing

#### AWS S3 Exposure Test
```bash
python demonstrate_cloud_exploitation.py example.com --scenario s3_exposure
```

#### Multi-Platform Assessment
```bash
# Test all supported platforms
python demonstrate_cloud_exploitation.py example.com --scenario all --real-scan
```

### Output Examples

#### Demo Results
```
[*] Starting comprehensive cloud exploitation scan...
[*] Target: example.com

[+] AWS S3 Exposure Test
  ✓ S3 bucket 'example.com-assets' found
  ✓ Public read access detected
  ✓ List permissions granted to authenticated users
  Severity: HIGH

[+] Azure Blob Storage Test
  ✓ Storage account 'exampledata' accessible
  ✓ Anonymous read permissions enabled
  Severity: HIGH

[+] Container Security Test
  ✓ Docker daemon exposed on port 2375
  ✓ No authentication required
  Severity: CRITICAL

[*] Scan completed! Found 8 vulnerabilities across 6 scenarios
[*] Report saved to: reports/cloud_exploitation_demo_report_example.com_20250928_123456.json
```

## Unified Cloud Scanner

### Basic Usage
```bash
# Quick unified scan
python unified_cloud_scanner.py example.com --quick

# Specific scan types
python unified_cloud_scanner.py example.com --scan-type cloud,web

# Verbose output
python unified_cloud_scanner.py example.com --verbose
```

### Advanced Examples

#### Comprehensive Assessment
```bash
python unified_cloud_scanner.py example.com \
  --scan-type cloud,web,advanced \
  --verbose \
  --output-dir unified_reports
```

#### Targeted Cloud Scan
```bash
# Focus on cloud infrastructure
python unified_cloud_scanner.py example.com --scan-type cloud --verbose
```

## Advanced Tests

### Standalone Exploit Testing
```bash
# Test specific vulnerabilities
python advanced_tests.py example.com

# Test with custom configuration
python advanced_tests.py example.com --timeout 60 --verbose
```

### Individual Exploit Modules

#### Cloud Exploits
```bash
python exploits/cloud_exploits.py example.com
```

#### Web Exploits
```bash
python exploits/web_exploits.py example.com
```

#### Modern Vulnerabilities
```bash
python exploits/modern_vulnerabilities.py example.com
```

## Security Testing Scenarios

### Scenario 1: E-commerce Platform Assessment
```bash
#!/bin/bash
# E-commerce security assessment

DOMAIN="shop.example.com"

echo "🔒 Starting e-commerce security assessment for $DOMAIN"

# Quick initial scan
python cloud_vulnerability_scanner.py "$DOMAIN" --quick-scan

# Detailed cloud exploitation test
python demonstrate_cloud_exploitation.py "$DOMAIN" --demo

# Check for common vulnerabilities
python quick_security_test.py "$DOMAIN"

echo "✅ Assessment completed. Check reports/ directory for details."
```

### Scenario 2: API Infrastructure Testing
```bash
#!/bin/bash
# API infrastructure security testing

API_DOMAINS=("api1.example.com" "api2.example.com" "api3.example.com")

for api in "${API_DOMAINS[@]}"; do
    echo "🔍 Scanning API: $api"
    
    # Cloud vulnerability scan
    python cloud_vulnerability_scanner.py "$api" --verbose
    
    # Advanced vulnerability testing
    python unified_cloud_scanner.py "$api" --scan-type advanced --verbose
    
    # Modern vulnerability checks
    python exploits/modern_vulnerabilities.py "$api"
done
```

### Scenario 3: Multi-Environment Security Validation
```bash
#!/bin/bash
# Multi-environment security validation

ENVIRONMENTS=("dev" "staging" "prod")
BASE_DOMAIN="example.com"

for env in "${ENVIRONMENTS[@]}"; do
    TARGET="$env.$BASE_DOMAIN"
    echo "🌍 Scanning $env environment: $TARGET"
    
    case $env in
        "dev")
            # Aggressive scanning for dev
            python cloud_vulnerability_scanner.py "$TARGET" --deep-scan --verbose
            ;;
        "staging")
            # Balanced approach for staging
            python cloud_vulnerability_scanner.py "$TARGET" --threads 10 --timeout 45
            ;;
        "prod")
            # Conservative scanning for production
            python cloud_vulnerability_scanner.py "$TARGET" --threads 3 --timeout 30 --quick-scan
            ;;
    esac
done
```

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Security Scan
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday 2 AM
  push:
    branches: [ main, develop ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    
    - name: Run Cloud Security Scan
      run: |
        python cloud_vulnerability_scanner.py ${{ secrets.TARGET_DOMAIN }} --quick-scan --output-dir security_reports
    
    - name: Upload Security Report
      uses: actions/upload-artifact@v2
      with:
        name: security-report
        path: security_reports/
```

### Jenkins Pipeline Example
```groovy
pipeline {
    agent any
    
    triggers {
        cron('H 2 * * 1')  // Weekly trigger
    }
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Install dependencies
                    sh 'pip install -r requirements.txt'
                    
                    // Run security scan
                    sh """
                        python cloud_vulnerability_scanner.py \${TARGET_DOMAIN} \
                          --quick-scan \
                          --output-dir security_reports/
                    """
                    
                    // Archive reports
                    archiveArtifacts artifacts: 'security_reports/*.json', fingerprint: true
                }
            }
        }
    }
    
    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'security_reports',
                reportFiles: '*.json',
                reportName: 'Security Scan Report'
            ])
        }
    }
}
```

### Docker Integration
```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy security tools
COPY . .

# Run security scan
CMD ["python", "cloud_vulnerability_scanner.py", "${TARGET_DOMAIN}", "--quick-scan"]
```

## Best Practices

### 1. Target Preparation
```bash
# Validate target format
python -c "import socket; socket.gethostbyname('example.com')"

# Check connectivity
ping -c 1 example.com || echo "Target may be down"
```

### 2. Scanning Strategy
```bash
# Start with quick scan for initial assessment
python cloud_vulnerability_scanner.py target.com --quick-scan

# Analyze results before deep scanning
if [ -f "reports/*quick*" ]; then
    echo "Review quick scan results before proceeding"
fi

# Proceed with deep scan if needed
python cloud_vulnerability_scanner.py target.com --deep-scan --verbose
```

### 3. Result Management
```bash
# Organize reports by date
REPORT_DIR="reports/$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR"

# Run scan with organized output
python cloud_vulnerability_scanner.py target.com --output-dir "$REPORT_DIR"

# Create summary
find "$REPORT_DIR" -name "*.json" -exec basename {} \; > "$REPORT_DIR/summary.txt"
```

### 4. Performance Optimization
```bash
# For large-scale scanning
python cloud_vulnerability_scanner.py target.com \
  --threads 5 \
  --timeout 20 \
  --quick-scan

# For thorough assessment
python cloud_vulnerability_scanner.py target.com \
  --threads 15 \
  --timeout 60 \
  --deep-scan \
  --verbose
```

### 5. Error Handling
```bash
#!/bin/bash
# Robust scanning script

TARGET="$1"
MAX_RETRIES=3
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if python cloud_vulnerability_scanner.py "$TARGET" --quick-scan; then
        echo "✅ Scan completed successfully"
        break
    else
        RETRY_COUNT=$((RETRY_COUNT + 1))
        echo "⚠️  Scan failed, retry $RETRY_COUNT/$MAX_RETRIES"
        sleep 5
    fi
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "❌ Scan failed after $MAX_RETRIES attempts"
    exit 1
fi
```

## Troubleshooting

### Common Issues

#### Network Connectivity
```bash
# Test basic connectivity
curl -I https://target.com
nslookup target.com
```

#### Permission Issues
```bash
# Check file permissions
ls -la reports/
chmod 755 reports/
```

#### Module Import Errors
```bash
# Verify installation
pip list | grep -E "requests|urllib3"
python -c "import requests; print(requests.__version__)"
```

### Debug Mode
```bash
# Enable debug logging
python cloud_vulnerability_scanner.py target.com --verbose 2>&1 | tee debug.log
```

## Support and Contributing

For issues, feature requests, or contributions:
1. Check existing issues in the repository
2. Run diagnostics on your environment
3. Provide detailed error logs when reporting issues
4. Follow the project's contribution guidelines

---

*Last updated: $(date)*
*Version: 3.0.0*