# Kubernetes and OpenShift Security Configuration
# إعدادات الأمان لـ Kubernetes و OpenShift

## 🔐 RBAC Configurations for Cloud Security Scanner

### 1. Kubernetes RBAC Configuration

#### Service Account for Security Scanning
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cloud-security-scanner
  namespace: default
  labels:
    app: cloud-security-scanner
    role: security-audit
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cloud-security-scanner-role
  labels:
    app: cloud-security-scanner
    role: security-audit
rules:
# Read access to all resources for security auditing
- apiGroups: [""]
  resources: ["pods", "services", "endpoints", "persistentvolumeclaims", "events", "configmaps", "secrets", "namespaces", "nodes"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "replicasets", "statefulsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies", "ingresses"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["policy"]
  resources: ["podsecuritypolicies"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["security.openshift.io"]
  resources: ["securitycontextconstraints"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cloud-security-scanner-binding
  labels:
    app: cloud-security-scanner
    role: security-audit
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cloud-security-scanner-role
subjects:
- kind: ServiceAccount
  name: cloud-security-scanner
  namespace: default
```

#### Namespace-specific Role (Limited Access)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cloud-security-scanner-ns-role
  namespace: default
  labels:
    app: cloud-security-scanner
    role: security-audit
    scope: namespace
rules:
# Read access within specific namespace
- apiGroups: [""]
  resources: ["pods", "services", "endpoints", "persistentvolumeclaims", "events", "configmaps", "secrets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "replicasets", "statefulsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies", "ingresses"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cloud-security-scanner-ns-binding
  namespace: default
  labels:
    app: cloud-security-scanner
    role: security-audit
    scope: namespace
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cloud-security-scanner-ns-role
subjects:
- kind: ServiceAccount
  name: cloud-security-scanner
  namespace: default
```

### 2. OpenShift RBAC Configuration

#### Security Context Constraints (SCC) for OpenShift
```yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: cloud-security-scanner-scc
  annotations:
    kubernetes.io/description: "Security context constraints for cloud security scanner"
allowHostDirVolumePlugin: false
allowHostIPC: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: false
allowPrivilegedContainer: false
allowedCapabilities: null
defaultAddCapabilities: null
fsGroup:
  type: MustRunAs
  ranges:
  - min: 1000
    max: 1000
readOnlyRootFilesystem: false
requiredDropCapabilities:
- ALL
runAsUser:
  type: MustRunAsRange
  uidRangeMin: 1000
  uidRangeMax: 1000
seLinuxContext:
  type: MustRunAs
  uidRangeMin: 1000
  uidRangeMax: 1000
seccompProfiles:
- runtime/default
supplementalGroups:
  type: MustRunAs
  ranges:
  - min: 1000
    max: 1000
users:
- system:serviceaccount:default:cloud-security-scanner
volumes:
- configMap
- downwardAPI
- emptyDir
- persistentVolumeClaim
- projected
- secret
```

#### OpenShift-specific ClusterRole
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: openshift-security-scanner-role
  labels:
    app: cloud-security-scanner
    platform: openshift
rules:
# Standard Kubernetes resources
- apiGroups: [""]
  resources: ["pods", "services", "endpoints", "persistentvolumeclaims", "events", "configmaps", "secrets", "namespaces"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "replicasets", "statefulsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["route.openshift.io"]
  resources: ["routes"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["image.openshift.io"]
  resources: ["imagestreams", "imagestreamimages", "imagestreamtags"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["build.openshift.io"]
  resources: ["builds", "buildconfigs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["security.openshift.io"]
  resources: ["securitycontextconstraints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["project.openshift.io"]
  resources: ["projects"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["user.openshift.io"]
  resources: ["users", "groups"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["oauth.openshift.io"]
  resources: ["oauthclients"]
  verbs: ["get", "list", "watch"]
```

### 3. Network Policies for Enhanced Security

#### Kubernetes Network Policy
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloud-security-scanner-netpol
  namespace: default
  labels:
    app: cloud-security-scanner
    policy: network-security
spec:
  podSelector:
    matchLabels:
      app: cloud-security-scanner
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 8443
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 443   # HTTPS
    - protocol: TCP
      port: 80    # HTTP
    - protocol: TCP
      port: 53    # DNS
    - protocol: UDP
      port: 53    # DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 6443  # Kubernetes API
```

### 4. Pod Security Standards

#### Pod Security Policy (Deprecated but still used)
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: cloud-security-scanner-psp
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'docker/default,runtime/default'
    apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
    seccomp.security.alpha.kubernetes.io/defaultProfileName: 'runtime/default'
    apparmor.security.beta.kubernetes.io/defaultProfileName: 'runtime/default'
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true
```

## 🚀 Deployment Scripts

### Apply All Configurations
```bash
#!/bin/bash
# apply_security_configs.sh

echo "Applying Kubernetes/OpenShift security configurations..."

# Apply Service Account and RBAC
kubectl apply -f security-configs/service-account.yaml
kubectl apply -f security-configs/cluster-role.yaml
kubectl apply -f security-configs/cluster-role-binding.yaml

# Apply namespace-specific roles (optional)
kubectl apply -f security-configs/namespace-role.yaml
kubectl apply -f security-configs/namespace-role-binding.yaml

# Apply OpenShift specific configurations (if on OpenShift)
if kubectl api-versions | grep -q "security.openshift.io"; then
    echo "Detected OpenShift - applying OpenShift specific configs"
    kubectl apply -f security-configs/openshift-scc.yaml
    kubectl apply -f security-configs/openshift-cluster-role.yaml
fi

# Apply network policies
kubectl apply -f security-configs/network-policy.yaml

echo "Security configurations applied successfully!"
```

## 🔍 Verification Commands

### Check Service Account Permissions
```bash
# Test service account access
kubectl auth can-i get pods --as=system:serviceaccount:default:cloud-security-scanner
kubectl auth can-i list secrets --as=system:serviceaccount:default:cloud-security-scanner
kubectl auth can-i get nodes --as=system:serviceaccount:default:cloud-security-scanner
```

### Verify OpenShift SCC
```bash
# Check SCC assignment
oc get scc cloud-security-scanner-scc
oc describe scc cloud-security-scanner-scc

# Check if service account can create pods with the SCC
oc adm policy who-can use scc/cloud-security-scanner-scc
```

### Test Network Policies
```bash
# Create test pod with the security scanner labels
kubectl run test-security-scanner --image=busybox --labels="app=cloud-security-scanner" --rm -it -- /bin/sh

# From inside the pod, test network connectivity
wget -O- https://kubernetes.default.svc
nslookup google.com
```

## ⚠️ Security Best Practices

### 1. **Principle of Least Privilege**
- ✅ Grant only necessary permissions
- ✅ Use namespace-specific roles when possible
- ✅ Regular audit of permissions
- ✅ Time-based access controls

### 2. **Secret Management**
- 🔒 Never hardcode credentials
- 🔒 Use Kubernetes secrets or external secret managers
- 🔒 Rotate secrets regularly
- 🔒 Audit secret access

### 3. **Network Security**
- 🛡️ Implement network policies
- 🛡️ Restrict egress traffic
- 🛡️ Use private networks when possible
- 🛡️ Monitor network traffic

### 4. **Pod Security**
- 🔐 Run as non-root user
- 🔐 Use read-only root filesystem
- 🔐 Drop all capabilities
- 🔐 Apply security contexts

## 🔄 Integration with Cloud Security Scanner

### Update Scanner Configuration
```python
# Add to your cloud security scanner configuration
KUBERNETES_CONFIG = {
    'service_account': 'cloud-security-scanner',
    'namespace': 'default',
    'use_cluster_role': True,
    'verify_ssl': True,
    'timeout': 30,
    'max_retries': 3
}

OPENSHIFT_CONFIG = {
    'service_account': 'cloud-security-scanner',
    'namespace': 'default',
    'scc_name': 'cloud-security-scanner-scc',
    'use_scc': True,
    'verify_ssl': True
}
```

### Scanner Usage with RBAC
```bash
# Run scanner with service account
kubectl run cloud-security-scanner \
  --image=your-scanner-image \
  --serviceaccount=cloud-security-scanner \
  --labels="app=cloud-security-scanner" \
  --restart=Never \
  -- python cloud_vulnerability_scanner.py target.com --quick-scan

# Or use the deployment approach
kubectl apply -f security-configs/scanner-deployment.yaml
```

## 📋 Monitoring and Auditing

### Enable Audit Logging
```yaml
# Add to your audit policy
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  omitStages:
  - RequestReceived
  resources:
  - group: ""
    resources: ["pods", "services", "secrets"]
  namespaces: ["default"]
  verbs: ["get", "list", "watch"]
  users: ["system:serviceaccount:default:cloud-security-scanner"]
```

### Monitor RBAC Changes
```bash
# Watch for RBAC changes
kubectl get events --field-selector involvedObject.kind=ServiceAccount,involvedObject.name=cloud-security-scanner

# Audit role bindings
kubectl get rolebindings,clusterrolebindings -o wide | grep cloud-security-scanner
```

---

## 🎯 **النتيجة النهائية**

تم إنشاء إعدادات أمان شاملة لـ Kubernetes و OpenShift تشمل:

✅ **RBAC configurations** مع أقل الصلاحيات المطلوبة  
✅ **Security Context Constraints** لـ OpenShift  
✅ **Network Policies** لتقييد الوصول الشبكي  
✅ **Pod Security Standards** لتأمين الحاويات  
✅ **Deployment scripts** للتطبيق السهل  
✅ **Verification commands** للتحقق من الصلاحيات  
✅ **Integration guidelines** مع أدوات الفحص  

**الآن لديك بيئة آمنة ومنظمة لأدوات فحص الأمان السحابي!** 🔐