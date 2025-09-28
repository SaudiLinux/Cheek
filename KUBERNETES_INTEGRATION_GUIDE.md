# Kubernetes/OpenShift Security Integration Guide
# دليل تكامل أمان Kubernetes و OpenShift

## 🔧 **تكامل مع أدوات الفحص الأمنية**

### 1. تكامل مع Cloud Vulnerability Scanner

#### إعداد المتغيرات البيئية
```bash
# قم بتعيين المتغيرات البيئية للوصول إلى Kubernetes
export KUBERNETES_SERVICE_ACCOUNT=cloud-security-scanner
export KUBERNETES_NAMESPACE=default
export KUBECONFIG_MODE=service-account

# تشغيل الماسح الضوئي مع Service Account
kubectl run vulnerability-scanner \
  --image=busybox \
  --serviceaccount=cloud-security-scanner \
  --restart=Never \
  --rm -i --tty \
  -- python cloud_vulnerability_scanner.py target.com --quick-scan --verbose
```

#### تعديل الكود للاستخدام مع Kubernetes
```python
# kubernetes_integration.py
import os
from kubernetes import client, config
from kubernetes.client.rest import ApiException

class KubernetesSecurityScanner:
    def __init__(self, namespace='default'):
        """Initialize Kubernetes client with service account"""
        try:
            # استخدام Service Account داخل الـ Pod
            config.load_incluster_config()
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.namespace = namespace
            print(f"✓ Connected to Kubernetes cluster")
        except:
            # fallback إلى kubeconfig خارج الـ Pod
            config.load_kube_config()
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.namespace = namespace
            print(f"✓ Connected to Kubernetes cluster via kubeconfig")
    
    def scan_pods_security(self):
        """Scan pods for security issues"""
        try:
            pods = self.v1.list_pod_for_all_namespaces()
            security_issues = []
            
            for pod in pods.items:
                # تحقق من إعدادات الأمان
                if not pod.spec.security_context:
                    security_issues.append({
                        'type': 'missing_security_context',
                        'pod': pod.metadata.name,
                        'namespace': pod.metadata.namespace,
                        'severity': 'HIGH'
                    })
                
                # تحقق من تشغيل كـ root
                if pod.spec.security_context and pod.spec.security_context.run_as_user == 0:
                    security_issues.append({
                        'type': 'running_as_root',
                        'pod': pod.metadata.name,
                        'namespace': pod.metadata.namespace,
                        'severity': 'CRITICAL'
                    })
                
                # تحقق من privileged containers
                for container in pod.spec.containers:
                    if container.security_context and container.security_context.privileged:
                        security_issues.append({
                            'type': 'privileged_container',
                            'pod': pod.metadata.name,
                            'namespace': pod.metadata.namespace,
                            'container': container.name,
                            'severity': 'CRITICAL'
                        })
            
            return security_issues
            
        except ApiException as e:
            print(f"Error scanning pods: {e}")
            return []
    
    def scan_services_exposure(self):
        """Scan services for external exposure"""
        try:
            services = self.v1.list_service_for_all_namespaces()
            exposed_services = []
            
            for service in services.items:
                # تحقق من الخدمات المعرضة للخارج
                if service.spec.type == 'LoadBalancer':
                    exposed_services.append({
                        'type': 'loadbalancer_service',
                        'service': service.metadata.name,
                        'namespace': service.metadata.namespace,
                        'severity': 'MEDIUM'
                    })
                
                # تحقق من المنافذ المفتوحة
                for port in service.spec.ports:
                    if port.port in [22, 23, 3389, 3306, 5432]:  # sensitive ports
                        exposed_services.append({
                            'type': 'sensitive_port_exposed',
                            'service': service.metadata.name,
                            'namespace': service.metadata.namespace,
                            'port': port.port,
                            'severity': 'HIGH'
                        })
            
            return exposed_services
            
        except ApiException as e:
            print(f"Error scanning services: {e}")
            return []
    
    def scan_network_policies(self):
        """Scan network policies"""
        try:
            from kubernetes.client import NetworkingV1Api
            net_api = NetworkingV1Api()
            policies = net_api.list_network_policy_for_all_namespaces()
            
            network_issues = []
            
            # تحقق من وجود سياسات الشبكة
            if not policies.items:
                network_issues.append({
                    'type': 'no_network_policies',
                    'severity': 'HIGH',
                    'description': 'No network policies found - all pods can communicate'
                })
            
            return network_issues
            
        except ApiException as e:
            print(f"Error scanning network policies: {e}")
            return []

# استخدام الكلاس
if __name__ == "__main__":
    scanner = KubernetesSecurityScanner()
    
    print("🔍 Scanning Kubernetes security...")
    
    # فحص الأمان في الـ Pods
    pod_issues = scanner.scan_pods_security()
    if pod_issues:
        print(f"\n⚠️  Found {len(pod_issues)} pod security issues:")
        for issue in pod_issues:
            print(f"  - {issue['type']}: {issue['pod']} (Severity: {issue['severity']})")
    
    # فحص التعرض في الخدمات
    service_issues = scanner.scan_services_exposure()
    if service_issues:
        print(f"\n⚠️  Found {len(service_issues)} service exposure issues:")
        for issue in service_issues:
            print(f"  - {issue['type']}: {issue['service']} (Severity: {issue['severity']})")
    
    # فحص سياسات الشبكة
    network_issues = scanner.scan_network_policies()
    if network_issues:
        print(f"\n⚠️  Found {len(network_issues)} network policy issues:")
        for issue in network_issues:
            print(f"  - {issue['type']}: {issue['description']}")
```

### 2. تكامل مع Demonstrate Cloud Exploitation

#### إعداد بيئة الاستغلال الآمنة
```python
# openshift_exploitation_integration.py
import subprocess
import json
from kubernetes import client, config

class OpenShiftExploitationTester:
    def __init__(self):
        """Initialize OpenShift exploitation tester"""
        config.load_incluster_config()
        self.v1 = client.CoreV1Api()
        self.security_api = client.SecurityV1Api()  # OpenShift Security API
    
    def test_privilege_escalation(self):
        """Test for privilege escalation vulnerabilities"""
        exploitation_scenarios = []
        
        # 1. اختبار SCC (Security Context Constraints)
        try:
            sccs = self.security_api.list_security_context_constraint()
            for scc in sccs.items:
                if scc.allow_privileged_container:
                    exploitation_scenarios.append({
                        'vulnerability': 'privileged_scc_allowed',
                        'scc_name': scc.metadata.name,
                        'severity': 'CRITICAL',
                        'description': f'SCC {scc.metadata.name} allows privileged containers'
                    })
                
                if scc.allow_host_dir_volume_plugin:
                    exploitation_scenarios.append({
                        'vulnerability': 'host_directory_access',
                        'scc_name': scc.metadata.name,
                        'severity': 'HIGH',
                        'description': f'SCC {scc.metadata.name} allows host directory access'
                    })
        
        except Exception as e:
            print(f"Error checking SCCs: {e}")
        
        # 2. اختبار Service Accounts مع صلاحيات مفرطة
        try:
            service_accounts = self.v1.list_service_account_for_all_namespaces()
            for sa in service_accounts.items:
                # تحقق من Service Accounts التي لديها صلاحيات cluster-admin
                if 'cluster-admin' in str(sa):
                    exploitation_scenarios.append({
                        'vulnerability': 'overprivileged_service_account',
                        'service_account': sa.metadata.name,
                        'namespace': sa.metadata.namespace,
                        'severity': 'HIGH',
                        'description': f'Service account {sa.metadata.name} may have excessive privileges'
                    })
        
        except Exception as e:
            print(f"Error checking service accounts: {e}")
        
        return exploitation_scenarios
    
    def test_container_escape(self):
        """Test for container escape vulnerabilities"""
        escape_scenarios = []
        
        try:
            pods = self.v1.list_pod_for_all_namespaces()
            for pod in pods.items:
                # تحقق من الحاويات التي تعمل مع capabilities خطيرة
                for container in pod.spec.containers:
                    if container.security_context:
                        if container.security_context.capabilities:
                            dangerous_caps = ['SYS_ADMIN', 'SYS_PTRACE', 'DAC_READ_SEARCH']
                            if any(cap in str(container.security_context.capabilities.add) for cap in dangerous_caps):
                                escape_scenarios.append({
                                    'vulnerability': 'dangerous_capabilities',
                                    'pod': pod.metadata.name,
                                    'namespace': pod.metadata.namespace,
                                    'container': container.name,
                                    'severity': 'CRITICAL',
                                    'description': f'Container has dangerous capabilities: {container.security_context.capabilities.add}'
                                })
                
                # تحقق من الحاويات التي لا تستخدم user namespaces
                if not pod.spec.security_context or not pod.spec.security_context.run_as_user:
                    escape_scenarios.append({
                        'vulnerability': 'missing_user_namespace',
                        'pod': pod.metadata.name,
                        'namespace': pod.metadata.namespace,
                        'severity': 'MEDIUM',
                        'description': 'Pod does not specify user to run as'
                    })
        
        except Exception as e:
            print(f"Error testing container escape: {e}")
        
        return escape_scenarios

# استخدام الكلاس
if __name__ == "__main__":
    tester = OpenShiftExploitationTester()
    
    print("🎯 Testing OpenShift exploitation scenarios...")
    
    # اختبار التصعيد الامتيازات
    privilege_issues = tester.test_privilege_escalation()
    if privilege_issues:
        print(f"\n⚠️  Found {len(privilege_issues)} privilege escalation issues:")
        for issue in privilege_issues:
            print(f"  - {issue['vulnerability']}: {issue['description']}")
    
    # اختبار الهروب من الحاوية
    escape_issues = tester.test_container_escape()
    if escape_issues:
        print(f"\n⚠️  Found {len(escape_issues)} container escape issues:")
        for issue in escape_issues:
            print(f"  - {issue['vulnerability']}: {issue['description']}")
```

### 3. تكامل مع Unified Cloud Scanner

#### إنشاء ماسح شامل للبنية التحتية
```python
# unified_kubernetes_scanner.py
import json
import datetime
from kubernetes_integration import KubernetesSecurityScanner
from openshift_exploitation_integration import OpenShiftExploitationTester

class UnifiedKubernetesScanner:
    def __init__(self):
        """Initialize unified scanner"""
        self.k8s_scanner = KubernetesSecurityScanner()
        self.openshift_tester = OpenShiftExploitationTester()
        self.scan_results = {}
    
    def run_comprehensive_scan(self):
        """Run comprehensive security scan"""
        print("🚀 Starting comprehensive Kubernetes/OpenShift security scan...")
        
        scan_start_time = datetime.datetime.now()
        
        # 1. فحص الأمان الأساسي
        print("📋 Scanning basic Kubernetes security...")
        pod_issues = self.k8s_scanner.scan_pods_security()
        service_issues = self.k8s_scanner.scan_services_exposure()
        network_issues = self.k8s_scanner.scan_network_policies()
        
        # 2. فحص الاستغلال (OpenShift specific)
        print("🎯 Scanning for exploitation scenarios...")
        privilege_issues = self.openshift_tester.test_privilege_escalation()
        escape_issues = self.openshift_tester.test_container_escape()
        
        scan_end_time = datetime.datetime.now()
        scan_duration = (scan_end_time - scan_start_time).total_seconds()
        
        # تجميع النتائج
        self.scan_results = {
            'scan_metadata': {
                'start_time': scan_start_time.isoformat(),
                'end_time': scan_end_time.isoformat(),
                'duration_seconds': scan_duration,
                'scanner_version': '1.0.0',
                'platform': 'kubernetes_openshift'
            },
            'summary': {
                'total_findings': len(pod_issues) + len(service_issues) + len(network_issues) + len(privilege_issues) + len(escape_issues),
                'critical_findings': self._count_by_severity(pod_issues + service_issues + network_issues + privilege_issues + escape_issues, 'CRITICAL'),
                'high_findings': self._count_by_severity(pod_issues + service_issues + network_issues + privilege_issues + escape_issues, 'HIGH'),
                'medium_findings': self._count_by_severity(pod_issues + service_issues + network_issues + privilege_issues + escape_issues, 'MEDIUM'),
                'low_findings': self._count_by_severity(pod_issues + service_issues + network_issues + privilege_issues + escape_issues, 'LOW')
            },
            'findings': {
                'pod_security': pod_issues,
                'service_exposure': service_issues,
                'network_policies': network_issues,
                'privilege_escalation': privilege_issues,
                'container_escape': escape_issues
            }
        }
        
        return self.scan_results
    
    def _count_by_severity(self, issues, severity):
        """Count issues by severity level"""
        return len([issue for issue in issues if issue.get('severity') == severity])
    
    def generate_report(self, output_file='kubernetes_security_report.json'):
        """Generate JSON report"""
        if not self.scan_results:
            print("⚠️  No scan results available. Run scan first.")
            return
        
        with open(output_file, 'w') as f:
            json.dump(self.scan_results, f, indent=2, default=str)
        
        print(f"✅ Report saved to: {output_file}")
        return output_file
    
    def print_summary(self):
        """Print scan summary"""
        if not self.scan_results:
            print("⚠️  No scan results available.")
            return
        
        summary = self.scan_results['summary']
        
        print("\n" + "="*60)
        print("🔍 KUBERNETES/OPENSHIFT SECURITY SCAN SUMMARY")
        print("="*60)
        print(f"⏱️  Scan Duration: {self.scan_results['scan_metadata']['duration_seconds']:.2f} seconds")
        print(f"📊 Total Findings: {summary['total_findings']}")
        print(f"🚨 Critical: {summary['critical_findings']}")
        print(f"⚠️  High: {summary['high_findings']}")
        print(f"⚡ Medium: {summary['medium_findings']}")
        print(f"ℹ️  Low: {summary['low_findings']}")
        print("="*60)

# استخدام الماسح الشامل
if __name__ == "__main__":
    scanner = UnifiedKubernetesScanner()
    
    # تشغيل الفحص الشامل
    results = scanner.run_comprehensive_scan()
    
    # طباعة الملخص
    scanner.print_summary()
    
    # إنشاء تقرير
    report_file = scanner.generate_report()
    
    print(f"\n🎯 Scan completed successfully!")
    print(f"📄 Full report available at: {report_file}")
```

## 🚀 **أوامر التشغيل السريعة**

### تطبيق الإعدادات الأمنية
```bash
# Linux/Mac
chmod +x apply_security_configs.sh
./apply_security_configs.sh

# Windows
apply_security_configs.bat
```

### التحقق من الصلاحيات
```bash
# اختبار صلاحيات Service Account
kubectl auth can-i get pods --as=system:serviceaccount:default:cloud-security-scanner
kubectl auth can-i list secrets --as=system:serviceaccount:default:cloud-security-scanner
kubectl auth can-i get nodes --as=system:serviceaccount:default:cloud-security-scanner
```

### تشغيل الماسح الضوئي
```bash
# تشغيل الماسح الضوئي داخل Kubernetes
kubectl run security-scanner \
  --image=python:3.9 \
  --serviceaccount=cloud-security-scanner \
  --restart=Never \
  --rm -i --tty \
  -- python unified_kubernetes_scanner.py

# أو استخدام Deployment
kubectl apply -f security-configs/scanner-deployment.yaml
```

### فحص OpenShift SCC
```bash
# التحقق من SCC (OpenShift فقط)
oc get scc cloud-security-scanner-scc
oc describe scc cloud-security-scanner-scc
```

## 📊 **مراقبة ومراجعة الأمان**

### تفعيل تسجيل التدقيق
```bash
# تفعيل تسجيل الأحداث الأمنية
kubectl audit-policy-file=/etc/kubernetes/audit-policy.yaml

# مراقبة أحداث RBAC
kubectl get events --field-selector involvedObject.kind=ServiceAccount
```

### مراجعة الصلاحيات بانتظام
```bash
# قائمة بجميع الصلاحيات الممنوحة
kubectl get clusterrolebindings -o wide | grep cloud-security-scanner
kubectl get rolebindings --all-namespaces | grep cloud-security-scanner

# مراجعة Network Policies
kubectl get networkpolicies --all-namespaces
```

---

## 🎯 **النتيجة النهائية**

✅ **تم إنشاء نظام أمان شامل لـ Kubernetes و OpenShift يشمل:**

- **RBAC Configurations** مع أقل الصلاحيات المطلوبة
- **Security Context Constraints** لـ OpenShift
- **Network Policies** لتقييد الوصول الشبكي
- **Service Account** مخصص للفحص الأمني
- **تكامل كامل** مع أدوات الفحص الأمنية
- **سكربتات تطبيق تلقائية** (Linux/Mac + Windows)
- **مراقبة ومراجعة** مستمرة للأمان

**الآن لديك بيئة آمنة ومحمية لأدوات فحص الأمان السحابي!** 🔐

---

*للمزيد من المعلومات والدعم، راجع الملفات:*
- `KUBERNETES_OPENSHIFT_SECURITY.md` - الوثائق الكاملة
- `apply_security_configs.sh` - سكربت التطبيق لـ Linux/Mac
- `apply_security_configs.bat` - سكربت التطبيق لـ Windows