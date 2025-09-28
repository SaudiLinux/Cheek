# دليل الاستخدام الشامل لجميع أدوات الأمان السحابي
# Complete Cloud Security Tools Usage Guide

## 📋 **جدول المحتويات**
1. [أدوات الفحص الأساسية](#أدوات-الفحص-الأساسية)
2. [أدوات الاستغلال والاختبار](#أدوات-الاستغلال-والاختبار)
3. [الماسحات الشاملة](#الماسحات-الشاملة)
4. [سكربتات الأتمتة](#سكربتات-الأتمتة)
5. [إعدادات Kubernetes/OpenShift](#إعدادات-kubernetesopenshift)
6. [الأدوات المساعدة](#الأدوات-المساعدة)
7. [أمثلة الاستخدام المتقدمة](#أمثلة-الاستخدام-المتقدمة)

---

## 🔧 **أدوات الفحص الأساسية**

### 1. Cloud Vulnerability Scanner
**الوصف:** أداة فحص الثغرات الأمنية في الخدمات السحابية
**الملف:** `cloud_vulnerability_scanner.py`

#### ✅ **التثبيت والمتطلبات**
```bash
# تثبيت المتطلبات
pip install -r requirements.txt

# أو تثبيت الحزم المطلوبة يدوياً
pip install requests beautifulsoup4 urllib3 dnspython python-nmap selenium
```

#### 🚀 **أوامر التشغيل الأساسية**
```bash
# الفحص السريع (Quick Scan)
python cloud_vulnerability_scanner.py target.com --quick-scan

# الفحص العميق (Deep Scan)
python cloud_vulnerability_scanner.py target.com --deep-scan

# فحص مخصص بعدد مواضيع ووقت محدد
python cloud_vulnerability_scanner.py target.com --threads 20 --timeout 60 --verbose

# فحص مع حفظ النتائج في مجلد محدد
python cloud_vulnerability_scanner.py target.com --output-dir ./reports --verbose

# فحص شامل مع جميع الخيارات
python cloud_vulnerability_scanner.py target.com --deep-scan --threads 30 --timeout 120 --output-dir ./reports --verbose
```

#### 📊 **خيارات الأوامر**
```
الوسائط:
  target                  الهدف المراد فحصه (نطاق أو IP)

الخيارات الاختيارية:
  -h, --help             عرض رسالة المساعدة
  --threads N            عدد المواضيع للفحص (افتراضي: 10)
  --timeout N            مهلة الاتصال بالثواني (افتراضي: 30)
  --output-dir DIR       مجلد حفظ التقارير (افتراضي: reports)
  --verbose              عرض معلومات مفصلة أثناء الفحص
  --quick-scan           فحص سريع (يفحص الخدمات الأساسية فقط)
  --deep-scan            فحص عميق (يفحص جميع الخدمات والثغرات)
```

---

## 🎯 **أدوات الاستغلال والاختبار**

### 2. Demonstrate Cloud Exploitation
**الوصف:** أداة اختبار الاستغلال والثغرات الأمنية
**الملف:** `demonstrate_cloud_exploitation.py`

#### 🚀 **أوامر التشغيل**
```bash
# وضع العرض التوضيحي (الأكثر أماناً)
python demonstrate_cloud_exploitation.py target.com --demo-mode --verbose

# فحص شامل مع جميع أنواع الاستغلال
python demonstrate_cloud_exploitation.py target.com --exploit-type all --verbose

# فحص نوع محدد من الاستغلال
python demonstrate_cloud_exploitation.py target.com --exploit-type web --verbose

# فحص مع عدد مواضيع محدد
python demonstrate_cloud_exploitation.py target.com --threads 15 --timeout 90 --verbose

# فحص مع حفظ التقرير في موقع مخصد
python demonstrate_cloud_exploitation.py target.com --output-dir ./exploitation-reports --verbose
```

#### 📊 **خيارات الأوامر**
```
الوسائط:
  target                  الهدف المراد اختباره

الخيارات الاختيارية:
  -h, --help             عرض رسالة المساعدة
  --threads N            عدد المواضيع (افتراضي: 10)
  --timeout N            مهلة الاتصال (افتراضي: 30)
  --output-dir DIR       مجلد حفظ التقارير (افتراضي: reports)
  --verbose              وضح التفاصيل
  --demo-mode            وضع العرض التوضيحي (آمن)
  --exploit-type TYPE    نوع الاستغلال (web/cloud/infrastructure/all)
```

---

## 🔍 **الماسحات الشاملة**

### 3. Unified Cloud Scanner
**الوصف:** ماسح شامل يجمع بين الفحص الأمني والاستغلال
**الملف:** `unified_cloud_scanner.py`

#### 🚀 **أوامر التشغيل**
```bash
# فحص شامل أساسي
python unified_cloud_scanner.py target.com --verbose

# فحص مع أنواع محددة
python unified_cloud_scanner.py target.com --scan-types "web,modern" --verbose

# فحص شامل مع جميع الخيارات
python unified_cloud_scanner.py target.com --scan-types "web,modern,exploitation,advanced" --threads 25 --timeout 100 --verbose

# فحص مع حفظ النتائج
python unified_cloud_scanner.py target.com --output-dir ./unified-reports --scan-types all --verbose
```

#### 📊 **خيارات الأوامر**
```
الوسائط:
  target                  الهدف المراد فحصه

الخيارات الاختيارية:
  -h, --help             عرض رسالة المساعدة
  --threads N            عدد المواضيع (افتراضي: 15)
  --timeout N            مهلة الاتصال (افتراضي: 45)
  --output-dir DIR       مجلد التقارير (افتراضي: reports)
  --verbose              وضح التفاصيل
  --scan-types TYPES     أنواع الفحص (web/modern/exploitation/advanced/all)
```

---

## 🤖 **سكربتات الأتمتة**

### 4. Cloud Security Scanner Script (Linux/Mac)
**الملف:** `cloud_security_scanner.sh`

#### 🚀 **الاستخدام**
```bash
# منح الصلاحية التنفيذية
chmod +x cloud_security_scanner.sh

# عرض المساعدة
./cloud_security_scanner.sh --help

# فحص سريع
./cloud_security_scanner.sh target.com quick

# فحص شامل
./cloud_security_scanner.sh target.com full

# فحص توضيحي
./cloud_security_scanner.sh target.com demo

# فحص مخصص بعدد مواضيع ووقت محدد
./cloud_security_scanner.sh target.com full --threads 20 --timeout 60

# فحص مع تثبيت المتطلبات تلقائياً
./cloud_security_scanner.sh target.com full --install

# فحص مع إخراج مخصص
./cloud_security_scanner.sh target.com full --output ./my-reports
```

#### 📊 **الخيارات المتقدمة**
```bash
# فحص شامل مع جميع الخيارات
./cloud_security_scanner.sh target.com full \
  --threads 30 \
  --timeout 120 \
  --output ./custom-reports \
  --install \
  --verbose
```

---

### 5. Cloud Security Scanner Script (Windows)
**الملف:** `cloud_security_scanner.bat`

#### 🚀 **الاستخدام**
```cmd
# عرض المساعدة
cloud_security_scanner.bat --help

# فحص سريع
cloud_security_scanner.bat target.com quick

# فحص شامل
cloud_security_scanner.bat target.com full

# فحص توضيحي
cloud_security_scanner.bat target.com demo

# فحص مخصص
cloud_security_scanner.bat target.com full --threads 20 --timeout 60

# فحص مع تثبيت المتطلبات
cloud_security_scanner.bat target.com full --install
```

---

## ☸️ **إعدادات Kubernetes/OpenShift**

### 6. Apply Security Configs Script
**الملفات:** `apply_security_configs.sh` (Linux/Mac) | `apply_security_configs.bat` (Windows)

#### 🚀 **قبل التشغيل - المتطلبات الأساسية**
```bash
# التحقق من وجود kubectl
kubectl version --client

# التحقق من الاتصال بالخادم
kubectl cluster-info

# التحقق من الصلاحيات
kubectl auth can-i create serviceaccounts
kubectl auth can-i create clusterroles
kubectl auth can-i create networkpolicies
```

#### 🚀 **تطبيق الإعدادات الأمنية**
```bash
# Linux/Mac
chmod +x apply_security_configs.sh
./apply_security_configs.sh

# Windows
apply_security_configs.bat
```

#### 📋 **ما الذي يفعله السكربت:**
1. **يُنشئ Service Account** مخصص للفحص الأمني
2. **يُنشئ ClusterRole** بأقل الصلاحيات المطلوبة
3. **يُنشئ ClusterRoleBinding** لربط الحساب بالصلاحيات
4. **يُنشئ NetworkPolicy** لتأمين الوصول الشبكي
5. **يُنشئ SCC** (لـ OpenShift) لمعايير الأمان
6. **يختبر الصلاحيات** للتأكد من العمل الصحيح

#### ✅ **التحقق من النتائج**
```bash
# التحقق من Service Account
kubectl get serviceaccount cloud-security-scanner

# التحقق من الصلاحيات
kubectl auth can-i get pods --as=system:serviceaccount:default:cloud-security-scanner
kubectl auth can-i list services --as=system:serviceaccount:default:cloud-security-scanner
kubectl auth can-i get secrets --as=system:serviceaccount:default:cloud-security-scanner

# التحقق من Network Policy
kubectl get networkpolicy cloud-security-scanner-netpol

# إذا كنت تستخدم OpenShift
oc get scc cloud-security-scanner-scc
```

---

## 🧪 **الأدوات المساعدة**

### 7. Advanced Tests
**الملف:** `advanced_tests.py`

#### 🚀 **الاستخدام**
```bash
# تشغيل جميع الاختبارات المتقدمة
python advanced_tests.py

# تشغيل اختبار محدد
python advanced_tests.py --test-type security

# تشغيل مع إخراج مفصل
python advanced_tests.py --verbose
```

---

### 8. Quick Security Test
**الملف:** `quick_security_test.py`

#### 🚀 **الاستخدام**
```bash
# اختبار أمان سريع
python quick_security_test.py target.com

# اختبار مع خيارات
python quick_security_test.py target.com --timeout 30 --verbose
```

---

### 9. Cloud Demo
**الملف:** `cloud_demo.py`

#### 🚀 **الاستخدام**
```bash
# تشغيل العرض التوضيحي
python cloud_demo.py

# عرض توضيحي مع هدف محدد
python cloud_demo.py --target example.com
```

---

## 🎯 **أمثلة الاستخدام المتقدمة**

### مثال 1: فحص أمني شامل لموقع ويب
```bash
#!/bin/bash
# comprehensive_scan.sh

TARGET="example.com"
OUTPUT_DIR="./reports/$(date +%Y%m%d_%H%M%S)"

echo "بدء الفحص الأمني الشامل لـ $TARGET..."

# 1. فحص الثغرات
echo "1. فحص الثغرات الأمنية..."
python cloud_vulnerability_scanner.py $TARGET \
  --deep-scan \
  --threads 20 \
  --timeout 60 \
  --output-dir "$OUTPUT_DIR/vulnerability" \
  --verbose

# 2. اختبار الاستغلال
echo "2. اختبار الاستغلال..."
python demonstrate_cloud_exploitation.py $TARGET \
  --demo-mode \
  --threads 15 \
  --timeout 90 \
  --output-dir "$OUTPUT_DIR/exploitation" \
  --verbose

# 3. فحص شامل
echo "3. فحص شامل..."
python unified_cloud_scanner.py $TARGET \
  --scan-types all \
  --threads 25 \
  --timeout 120 \
  --output-dir "$OUTPUT_DIR/unified" \
  --verbose

echo "اكتمل الفحص! النتائج في: $OUTPUT_DIR"
```

### مثال 2: فحص Kubernetes/OpenShift
```bash
#!/bin/bash
# kubernetes_security_scan.sh

# 1. تطبيق الإعدادات الأمنية
echo "تطبيق إعدادات الأمان..."
./apply_security_configs.sh

# 2. انتظار التطبيق
sleep 10

# 3. تشغيل الماسح الضوئي داخل Kubernetes
echo "تشغيل الماسح الضوئي..."
kubectl run security-scanner \
  --image=python:3.9 \
  --serviceaccount=cloud-security-scanner \
  --restart=Never \
  --rm -i --tty \
  -- python unified_kubernetes_scanner.py

# 4. أو استخدام Deployment
echo "استخدام Deployment..."
kubectl apply -f security-configs/scanner-deployment.yaml
```

### مثال 3: أتمتة الفحص باستخدام السكربتات
```bash
#!/bin/bash
# automated_scan.sh

# استخدام السكربت التلقائي مع جميع الخيارات
./cloud_security_scanner.sh target.com full \
  --threads 30 \
  --timeout 120 \
  --output ./automated-reports \
  --install \
  --verbose

# أو استخدام السكربت على Windows
cloud_security_scanner.bat target.com full \
  --threads 30 \
  --timeout 120 \
  --output ./automated-reports \
  --install
```

---

## ⚠️ **نصائح مهمة للاستخدام**

### 🔒 **السلامة والأمان**
- استخدم وضع العرض التوضيحي (--demo-mode) للاختبار الأولي
- لا تقم بفحص أنظمة لا تملك صلاحية الوصول إليها
- استخدم أوقات انتظار مناسبة لتجنب حجب الاتصال
- احفظ التقارير في مواقع آمنة

### ⚙️ **الأداء والكفاءة**
- ابدأ بالفحص السريع ثم انتقل للعميق إذا لزم الأمر
- استخدم عدد مواضيع مناسب حسب قدرة النظام (5-20 موضوع)
- حدد أوقات الانتظار حسب سرعة الاتصال
- استخدم الخيار --verbose للمتابعة أثناء الفحص

### 📊 **تحليل النتائج**
- راجع التقارير JSON للحصول على تفاصيل كاملة
- انتبه للثغرات الحرجة (CRITICAL) والعالية (HIGH) أولاً
- استخدم ملفات السجل للتتبع والمراجعة
- قارن بين نتائج الفحوصات المختلفة

### 🔄 **الصيانة المستمرة**
- قم بالفحص بانتظام (أسبوعي/شهري)
- حدث الأدوات باستمرار
- راقب التغييرات في البنية التحتية
- وثق جميع النتائج والإجراءات

---

## 🆘 **استكشاف الأخطاء وإصلاحها**

### مشكلة شائعة: "Permission Denied"
```bash
# الحل لأنظمة Linux/Mac
chmod +x *.sh
chmod +x *.py

# التحقق من صلاحيات الملفات
ls -la *.sh *.py
```

### مشكلة شائعة: "Module Not Found"
```bash
# تثبيت جميع المتطلبات
pip install -r requirements.txt

# أو تثبيت حزم محددة
pip install requests beautifulsoup4 urllib3 dnspython python-nmap selenium
```

### مشكلة شائعة: "Connection Timeout"
```bash
# زيادة وقت الانتظار
--timeout 120

# تقليل عدد المواضيع
--threads 5

# التحقق من الاتصال بالإنترنت
ping target.com
```

---

## 📞 **الدعم والمساعدة**

إذا واجهت مشاكل:
1. تحقق من أن جميع المتطلبات مثبتة
2. تأكد من صلاحيات التشغيل
3. راجع رسائل الخطأ بدقة
4. استخدم الخيار --verbose للحصول على تفاصيل أكثر
5. تحقق من ملفات التقارير للحصول على معلومات إضافية

**ملاحظة:** جميع الأدوات مصممة للاستخدام الأخلاقي والقانوني فقط. تأكد من أن لديك صلاحية الوصول إلى الأنظمة التي تفحصها.