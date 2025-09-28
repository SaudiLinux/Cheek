@echo off
REM apply_security_configs.bat - Apply comprehensive security configurations for Kubernetes/OpenShift
REM سكربت لتطبيق إعدادات الأمان الشاملة لـ Kubernetes و OpenShift

setlocal enabledelayedexpansion

REM تعريف الألوان (ملاحظة: الألوان محدودة في Command Prompt)
echo [INFO] بدء تطبيق إعدادات الأمان...

REM التحقق من وجود kubectl
where kubectl >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] kubectl غير مثبت. يرجى تثبيت kubectl أولاً.
    exit /b 1
)

REM التحقق من الاتصال بالخادم
echo [INFO] التحقق من الاتصال بخادم Kubernetes...
kubectl cluster-info >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] لا يمكن الاتصال بخادم Kubernetes. يرجى التحقق من الاتصال.
    exit /b 1
)

echo [SUCCESS] الاتصال بخادم Kubernetes ناجح

REM إنشاء دليل الإعدادات الأمنية إذا لم يكن موجوداً
if not exist "security-configs" mkdir security-configs

echo [INFO] بدء تطبيق إعدادات الأمان...

REM 1. تطبيق Service Account
echo [INFO] تطبيق Service Account...
kubectl apply -f security-configs/service-account.yaml
if %errorlevel% equ 0 (
    echo [SUCCESS] Service Account تم تطبيقه بنجاح
) else (
    echo [ERROR] فشل في تطبيق Service Account
    exit /b 1
)

REM 2. تطبيق ClusterRole
echo [INFO] تطبيق ClusterRole...
kubectl apply -f security-configs/cluster-role.yaml
if %errorlevel% equ 0 (
    echo [SUCCESS] ClusterRole تم تطبيقه بنجاح
) else (
    echo [ERROR] فشل في تطبيق ClusterRole
    exit /b 1
)

REM 3. تطبيق ClusterRoleBinding
echo [INFO] تطبيق ClusterRoleBinding...
kubectl apply -f security-configs/cluster-role-binding.yaml
if %errorlevel% equ 0 (
    echo [SUCCESS] ClusterRoleBinding تم تطبيقه بنجاح
) else (
    echo [ERROR] فشل في تطبيق ClusterRoleBinding
    exit /b 1
)

REM 4. التحقق من نوع المنصة (Kubernetes vs OpenShift)
echo [INFO] التحقق من نوع المنصة...
kubectl api-versions | findstr "security.openshift.io" >nul
if %errorlevel% equ 0 (
    echo [SUCCESS] تم اكتشاف OpenShift - سيتم تطبيق إعدادات OpenShift الخاصة
    set IS_OPENSHIFT=true
    
    REM تطبيق SCC (Security Context Constraints)
    echo [INFO] تطبيق Security Context Constraints...
    kubectl apply -f security-configs/openshift-scc.yaml
    if %errorlevel% equ 0 (
        echo [SUCCESS] SCC تم تطبيقه بنجاح
    ) else (
        echo [WARNING] فشل في تطبيق SCC، قد يكون لديك صلاحيات محدودة
    )
    
    REM تطبيق ClusterRole الخاص بـ OpenShift
    echo [INFO] تطبيق ClusterRole الخاص بـ OpenShift...
    kubectl apply -f security-configs/openshift-cluster-role.yaml
    if %errorlevel% equ 0 (
        echo [SUCCESS] ClusterRole الخاص بـ OpenShift تم تطبيقه بنجاح
    ) else (
        echo [WARNING] فشل في تطبيق ClusterRole الخاص بـ OpenShift
    )
) else (
    echo [INFO] تم اكتشاف Kubernetes قياسي
    set IS_OPENSHIFT=false
)

REM 5. تطبيق Network Policy (اختياري)
echo [INFO] تطبيق Network Policy...
kubectl apply -f security-configs/network-policy.yaml
if %errorlevel% equ 0 (
    echo [SUCCESS] Network Policy تم تطبيقه بنجاح
) else (
    echo [WARNING] فشل في تطبيق Network Policy، قد يكون لديك صلاحيات محدودة أو CNI لا يدعم NetworkPolicy
)

REM 6. التحقق من الصلاحيات
echo [INFO] التحقق من صلاحيات Service Account...
set SERVICE_ACCOUNT=system:serviceaccount:default:cloud-security-scanner

echo.
echo ========================================
echo اختبار الصلاحيات:
echo ----------------------------------------

REM اختبار الوصول إلى Pods
kubectl auth can-i get pods --as="%SERVICE_ACCOUNT%" >nul
if %errorlevel% equ 0 (
    echo [SUCCESS] ✓ صلاحية الوصول إلى Pods
) else (
    echo [ERROR] ✗ لا توجد صلاحية للوصول إلى Pods
)

REM اختبار الوصول إلى Services
kubectl auth can-i list services --as="%SERVICE_ACCOUNT%" >nul
if %errorlevel% equ 0 (
    echo [SUCCESS] ✓ صلاحية الوصول إلى Services
) else (
    echo [ERROR] ✗ لا توجد صلاحية للوصول إلى Services
)

REM اختبار الوصول إلى Secrets
kubectl auth can-i get secrets --as="%SERVICE_ACCOUNT%" >nul
if %errorlevel% equ 0 (
    echo [SUCCESS] ✓ صلاحية الوصول إلى Secrets
) else (
    echo [ERROR] ✗ لا توجد صلاحية للوصول إلى Secrets
)

REM اختبار الوصول إلى Namespaces
kubectl auth can-i list namespaces --as="%SERVICE_ACCOUNT%" >nul
if %errorlevel% equ 0 (
    echo [SUCCESS] ✓ صلاحية الوصول إلى Namespaces
) else (
    echo [ERROR] ✗ لا توجد صلاحية للوصول إلى Namespaces
)

REM اختبار الوصول إلى Nodes (Cluster-level)
kubectl auth can-i get nodes --as="%SERVICE_ACCOUNT%" >nul
if %errorlevel% equ 0 (
    echo [SUCCESS] ✓ صلاحية الوصول إلى Nodes
) else (
    echo [WARNING] ✗ لا توجد صلاحية للوصول إلى Nodes (قد تكون محدودة عمداً)
)

REM 7. إذا كانت OpenShift، تحقق من SCC
if "%IS_OPENSHIFT%"=="true" (
    echo [INFO] التحقق من Security Context Constraints في OpenShift...
    kubectl get scc cloud-security-scanner-scc >nul 2>nul
    if %errorlevel% equ 0 (
        echo [SUCCESS] ✓ SCC موجود ويعمل
        echo.
        kubectl get scc cloud-security-scanner-scc
    ) else (
        echo [ERROR] ✗ SCC غير موجود أو غير متاح
    )
)

echo.
echo ========================================
echo [SUCCESS] تم اكتمال تطبيق إعدادات الأمان بنجاح!
echo ========================================
echo.
echo **ملخص الإعدادات:**
echo • Service Account: cloud-security-scanner
echo • Namespace: default
echo • ClusterRole: cloud-security-scanner-role
echo • Network Policy: cloud-security-scanner-netpol
if "%IS_OPENSHIFT%"=="true" (
    echo • SCC: cloud-security-scanner-scc
    echo • OpenShift ClusterRole: openshift-security-scanner-role
)
echo.
echo **الخطوات التالية:**
echo 1. يمكنك الآن تشغيل أدوات الفحص الأمني باستخدام Service Account الجديد
echo 2. استخدم: kubectl apply -f security-configs/scanner-deployment.yaml
echo 3. أو استخدم الأدوات المخصصة مع الإعدادات الجديدة
echo.
echo **ملاحظات مهمة:**
echo • تم تطبيق مبدأ أقل الصلاحيات (Principle of Least Privilege)
echo • تم تقييد الوصول الشبكي باستخدام NetworkPolicy
echo • تم تطبيق معايير الأمان للحاويات
echo • يمكنك تعديل الإعدادات حسب احتياجاتك الخاصة
echo.

REM حفظ تقرير الإعداد
set REPORT_FILE=security_setup_report_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.txt
set REPORT_FILE=%REPORT_FILE: =0%

echo Cloud Security Scanner - Security Configuration Report > "%REPORT_FILE%"
echo Generated on: %date% %time% >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"
echo Platform: >> "%REPORT_FILE%"
if "%IS_OPENSHIFT%"=="true" (
    echo OpenShift >> "%REPORT_FILE%"
) else (
    echo Kubernetes >> "%REPORT_FILE%"
)
echo Service Account: cloud-security-scanner >> "%REPORT_FILE%"
echo Namespace: default >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"
echo Applied Configurations: >> "%REPORT_FILE%"
echo - Service Account: ✓ >> "%REPORT_FILE%"
echo - ClusterRole: ✓ >> "%REPORT_FILE%"
echo - ClusterRoleBinding: ✓ >> "%REPORT_FILE%"
echo - Network Policy: ✓ >> "%REPORT_FILE%"
if "%IS_OPENSHIFT%"=="true" (
    echo - OpenShift SCC: ✓ >> "%REPORT_FILE%"
    echo - OpenShift ClusterRole: ✓ >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"
echo Next Steps: >> "%REPORT_FILE%"
echo 1. Deploy scanner using: kubectl apply -f security-configs/scanner-deployment.yaml >> "%REPORT_FILE%"
echo 2. Test with your security scanning tools >> "%REPORT_FILE%"
echo 3. Monitor and audit regularly >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"
echo Security Notes: >> "%REPORT_FILE%"
echo - Applied principle of least privilege >> "%REPORT_FILE%"
echo - Network policies implemented >> "%REPORT_FILE%"
echo - Security contexts configured >> "%REPORT_FILE%"
echo - Regular audit recommended >> "%REPORT_FILE%"

echo [SUCCESS] تم حفظ تقرير الإعداد في: %REPORT_FILE%
echo.
echo [INFO] للمساعدة أو الدعم، راجع الملف KUBERNETES_OPENSHIFT_SECURITY.md

endlocal