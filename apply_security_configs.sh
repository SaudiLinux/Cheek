#!/bin/bash
# apply_security_configs.sh - Apply comprehensive security configurations for Kubernetes/OpenShift
# سكربت لتطبيق إعدادات الأمان الشاملة لـ Kubernetes و OpenShift

set -e

# الألوان للإخراج الملون
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# دالة للطباعة الملونة
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# التحقق من وجود kubectl
if ! command -v kubectl &> /dev/null; then
    print_error "kubectl غير مثبت. يرجى تثبيت kubectl أولاً."
    exit 1
fi

# التحقق من الاتصال بالخادم
if ! kubectl cluster-info &> /dev/null; then
    print_error "لا يمكن الاتصال بخادم Kubernetes. يرجى التحقق من الاتصال."
    exit 1
fi

print_success "الاتصال بخادم Kubernetes ناجح"

# إنشاء دليل الإعدادات الأمنية إذا لم يكن موجوداً
mkdir -p security-configs

print_status "بدء تطبيق إعدادات الأمان..."

# 1. تطبيق Service Account
print_status "تطبيق Service Account..."
kubectl apply -f security-configs/service-account.yaml
if [ $? -eq 0 ]; then
    print_success "Service Account تم تطبيقه بنجاح"
else
    print_error "فشل في تطبيق Service Account"
    exit 1
fi

# 2. تطبيق ClusterRole
print_status "تطبيق ClusterRole..."
kubectl apply -f security-configs/cluster-role.yaml
if [ $? -eq 0 ]; then
    print_success "ClusterRole تم تطبيقه بنجاح"
else
    print_error "فشل في تطبيق ClusterRole"
    exit 1
fi

# 3. تطبيق ClusterRoleBinding
print_status "تطبيق ClusterRoleBinding..."
kubectl apply -f security-configs/cluster-role-binding.yaml
if [ $? -eq 0 ]; then
    print_success "ClusterRoleBinding تم تطبيقه بنجاح"
else
    print_error "فشل في تطبيق ClusterRoleBinding"
    exit 1
fi

# 4. التحقق من نوع المنصة (Kubernetes vs OpenShift)
print_status "التحقق من نوع المنصة..."
if kubectl api-versions | grep -q "security.openshift.io"; then
    print_success "تم اكتشاف OpenShift - سيتم تطبيق إعدادات OpenShift الخاصة"
    
    # تطبيق SCC (Security Context Constraints)
    print_status "تطبيق Security Context Constraints..."
    kubectl apply -f security-configs/openshift-scc.yaml
    if [ $? -eq 0 ]; then
        print_success "SCC تم تطبيقه بنجاح"
    else
        print_warning "فشل في تطبيق SCC، قد يكون لديك صلاحيات محدودة"
    fi
    
    # تطبيق ClusterRole الخاص بـ OpenShift
    print_status "تطبيق ClusterRole الخاص بـ OpenShift..."
    kubectl apply -f security-configs/openshift-cluster-role.yaml
    if [ $? -eq 0 ]; then
        print_success "ClusterRole الخاص بـ OpenShift تم تطبيقه بنجاح"
    else
        print_warning "فشل في تطبيق ClusterRole الخاص بـ OpenShift"
    fi
    
    IS_OPENSHIFT=true
else
    print_status "تم اكتشاف Kubernetes قياسي"
    IS_OPENSHIFT=false
fi

# 5. تطبيق Network Policy (اختياري)
print_status "تطبيق Network Policy..."
kubectl apply -f security-configs/network-policy.yaml
if [ $? -eq 0 ]; then
    print_success "Network Policy تم تطبيقه بنجاح"
else
    print_warning "فشل في تطبيق Network Policy، قد يكون لديك صلاحيات محدودة أو CNI لا يدعم NetworkPolicy"
fi

# 6. التحقق من الصلاحيات
print_status "التحقق من صلاحيات Service Account..."
SERVICE_ACCOUNT="system:serviceaccount:default:cloud-security-scanner"

echo ""
print_status "اختبار الصلاحيات:"
echo "----------------------------------------"

# اختبار الوصول إلى Pods
if kubectl auth can-i get pods --as="$SERVICE_ACCOUNT"; then
    print_success "✓ صلاحية الوصول إلى Pods"
else
    print_error "✗ لا توجد صلاحية للوصول إلى Pods"
fi

# اختبار الوصول إلى Services
if kubectl auth can-i list services --as="$SERVICE_ACCOUNT"; then
    print_success "✓ صلاحية الوصول إلى Services"
else
    print_error "✗ لا توجد صلاحية للوصول إلى Services"
fi

# اختبار الوصول إلى Secrets
if kubectl auth can-i get secrets --as="$SERVICE_ACCOUNT"; then
    print_success "✓ صلاحية الوصول إلى Secrets"
else
    print_error "✗ لا توجد صلاحية للوصول إلى Secrets"
fi

# اختبار الوصول إلى Namespaces
if kubectl auth can-i list namespaces --as="$SERVICE_ACCOUNT"; then
    print_success "✓ صلاحية الوصول إلى Namespaces"
else
    print_error "✗ لا توجد صلاحية للوصول إلى Namespaces"
fi

# اختبار الوصول إلى Nodes (Cluster-level)
if kubectl auth can-i get nodes --as="$SERVICE_ACCOUNT"; then
    print_success "✓ صلاحية الوصول إلى Nodes"
else
    print_warning "✗ لا توجد صلاحية للوصول إلى Nodes (قد تكون محدودة عمداً)"
fi

# 7. إذا كانت OpenShift، تحقق من SCC
if [ "$IS_OPENSHIFT" = true ]; then
    print_status "التحقق من Security Context Constraints في OpenShift..."
    if kubectl get scc cloud-security-scanner-scc &> /dev/null; then
        print_success "✓ SCC موجود ويعمل"
        echo ""
        kubectl get scc cloud-security-scanner-scc
    else
        print_error "✗ SCC غير موجود أو غير متاح"
    fi
fi

echo ""
echo "========================================"
print_success "تم اكتمال تطبيق إعدادات الأمان بنجاح!"
echo "========================================"
echo ""
echo "📋 **ملخص الإعدادات:**"
echo "• Service Account: cloud-security-scanner"
echo "• Namespace: default"
echo "• ClusterRole: cloud-security-scanner-role"
echo "• Network Policy: cloud-security-scanner-netpol"
if [ "$IS_OPENSHIFT" = true ]; then
    echo "• SCC: cloud-security-scanner-scc"
    echo "• OpenShift ClusterRole: openshift-security-scanner-role"
fi
echo ""
echo "🚀 **الخطوات التالية:**"
echo "1. يمكنك الآن تشغيل أدوات الفحص الأمني باستخدام Service Account الجديد"
echo "2. استخدم: kubectl apply -f security-configs/scanner-deployment.yaml"
echo "3. أو استخدم الأدوات المخصصة مع الإعدادات الجديدة"
echo ""
echo "⚠️ **ملاحظات مهمة:**"
echo "• تم تطبيق مبدأ أقل الصلاحيات (Principle of Least Privilege)"
echo "• تم تقييد الوصول الشبكي باستخدام NetworkPolicy"
echo "• تم تطبيق معايير الأمان للحاويات"
echo "• يمكنك تعديل الإعدادات حسب احتياجاتك الخاصة"
echo ""

# حفظ تقرير الإعداد
REPORT_FILE="security_setup_report_$(date +%Y%m%d_%H%M%S).txt"
cat > "$REPORT_FILE" << EOF
Cloud Security Scanner - Security Configuration Report
Generated on: $(date)

Platform: $([ "$IS_OPENSHIFT" = true ] && echo "OpenShift" || echo "Kubernetes")
Service Account: cloud-security-scanner
Namespace: default

Applied Configurations:
- Service Account: ✓
- ClusterRole: ✓
- ClusterRoleBinding: ✓
- Network Policy: ✓
$([ "$IS_OPENSHIFT" = true ] && echo "- OpenShift SCC: ✓")
$([ "$IS_OPENSHIFT" = true ] && echo "- OpenShift ClusterRole: ✓")

Permissions Test Results:
$(kubectl auth can-i get pods --as="$SERVICE_ACCOUNT" && echo "✓ Pods access" || echo "✗ Pods access denied")
$(kubectl auth can-i list services --as="$SERVICE_ACCOUNT" && echo "✓ Services access" || echo "✗ Services access denied")
$(kubectl auth can-i get secrets --as="$SERVICE_ACCOUNT" && echo "✓ Secrets access" || echo "✗ Secrets access denied")
$(kubectl auth can-i list namespaces --as="$SERVICE_ACCOUNT" && echo "✓ Namespaces access" || echo "✗ Namespaces access denied")
$(kubectl auth can-i get nodes --as="$SERVICE_ACCOUNT" && echo "✓ Nodes access" || echo "✗ Nodes access denied")

Next Steps:
1. Deploy scanner using: kubectl apply -f security-configs/scanner-deployment.yaml
2. Test with your security scanning tools
3. Monitor and audit regularly

Security Notes:
- Applied principle of least privilege
- Network policies implemented
- Security contexts configured
- Regular audit recommended
EOF

print_success "تم حفظ تقرير الإعداد في: $REPORT_FILE"
echo ""
print_status "للمساعدة أو الدعم، راجع الملف KUBERNETES_OPENSHIFT_SECURITY.md"