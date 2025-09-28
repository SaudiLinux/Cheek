# دليل الاستخدام المحدث - أدوات الأمان السحابي

## 🚀 تشغيل الأدوات بجميع الميزات

### 1. فاحص الثغرات السحابية (Cloud Vulnerability Scanner)

#### الأوامر الأساسية:
```bash
# فحص سريع
python cloud_vulnerability_scanner.py example.com --quick-scan

# فحص شامل مع جميع الميزات
python cloud_vulnerability_scanner.py example.com --deep-scan --threads 20 --timeout 60 --verbose

# فحص مخصص للإنتاج
python cloud_vulnerability_scanner.py example.com --threads 5 --timeout 30 --output-dir production_reports
```

#### أوامر متقدمة:
```bash
# فحص شامل متعدد المنصات
python cloud_vulnerability_scanner.py example.com \
  --deep-scan \
  --threads 15 \
  --timeout 45 \
  --verbose \
  --output-dir comprehensive_reports

# فحص سريع مع تقارير مفصلة
python cloud_vulnerability_scanner.py example.com --quick-scan --verbose

# فحص متعدد الأهداف
for target in api.example.com app.example.com db.example.com; do
    python cloud_vulnerability_scanner.py "$target" --quick-scan
done
```

### 2. أداة استغلال السحابة (Demonstrate Cloud Exploitation)

#### أوضاع التشغيل:
```bash
# الوضع التجريبي - عرض جميع السيناريوهات
python demonstrate_cloud_exploitation.py example.com --demo --verbose

# الوضع الحقيقي - فحص فعلي
python demonstrate_cloud_exploitation.py example.com --real-scan

# سيناريو محدد
python demonstrate_cloud_exploitation.py example.com --scenario s3_exposure --demo

# جميع السيناريوهات
python demonstrate_cloud_exploitation.py example.com --scenario all --demo
```

#### أنواع الاستغلال:
```bash
# استغلال AWS
python demonstrate_cloud_exploitation.py example.com --platform aws --real-scan

# استغلال Azure
python demonstrate_cloud_exploitation.py example.com --platform azure --real-scan

# استغلال GCP
python demonstrate_cloud_exploitation.py example.com --platform gcp --real-scan

# استغلال الحاويات
python demonstrate_cloud_exploitation.py example.com --scenario container_exploitation --demo
```

### 3. الفاحص السحابي الموحد (Unified Cloud Scanner)

#### أوامر التشغيل:
```bash
# فحص موحد شامل
python unified_cloud_scanner.py example.com --verbose

# فحص محدد النوع
python unified_cloud_scanner.py example.com --scan-type cloud,web --verbose

# فحص شامل مع تقارير مخصصة
python unified_cloud_scanner.py example.com --output-dir unified_reports
```

## 📋 طرق الاستخدام المحدثة

### طريقة 1: الفحص السريع للأمان (Quick Security Assessment)

```bash
#!/bin/bash
# فحص أمان سريع لموقع ويب

echo "🔒 بدء الفحص الأمني السريع..."

# فحص سحابي سريع
python cloud_vulnerability_scanner.py "$1" --quick-scan --verbose

# فحص استغلال تجريبي
python demonstrate_cloud_exploitation.py "$1" --demo

echo "✅ اكتمل الفحص الأمني السريع"
echo "📊 تم حفظ التقارير في مجلد reports/"
```

### طريقة 2: التقييم الشامل للأمان (Comprehensive Security Audit)

```bash
#!/bin/bash
# تقييم شامل للبنية التحتية السحابية

echo "🚀 بدء التقييم الأمني الشامل..."

# إنشاء مجلد للتقارير
REPORT_DIR="security_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

# فحص شامل للثغرات السحابية
echo "🔍 فحص الثغرات السحابية..."
python cloud_vulnerability_scanner.py "$1" \
  --deep-scan \
  --threads 10 \
  --timeout 60 \
  --verbose \
  --output-dir "$REPORT_DIR"

# فحص الاستغلال التجريبي
echo "🔬 فحص استغلال السحابة..."
python demonstrate_cloud_exploitation.py "$1" \
  --demo \
  --verbose

# فحص موحد
echo "🌩️ فحص موحد..."
python unified_cloud_scanner.py "$1" \
  --verbose \
  --output-dir "$REPORT_DIR"

echo "✅ اكتمل التقييم الأمني الشامل"
echo "📊 جميع التقارير محفوظة في: $REPORT_DIR"
```

### طريقة 3: المراقبة المستمرة (Continuous Monitoring)

```bash
#!/bin/bash
# مراقبة مستمرة للأمان السحابي

TARGETS=("api.example.com" "app.example.com" "db.example.com")
REPORT_DIR="continuous_monitoring_$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR"

for target in "${TARGETS[@]}"; do
    echo "🔍 مراقبة $target..."
    
    # فحص سريع
    python cloud_vulnerability_scanner.py "$target" \
      --quick-scan \
      --output-dir "$REPORT_DIR" \
      2>&1 | tee "$REPORT_DIR/${target}_scan.log"
    
    # فحص استغلال تجريبي
    python demonstrate_cloud_exploitation.py "$target" \
      --demo \
      2>&1 | tee "$REPORT_DIR/${target}_exploitation.log"
done

echo "✅ اكتملت المراقبة المستمرة"
```

### طريقة 4: فحص ما قبل الإنتاج (Pre-Production Testing)

```bash
#!/bin/bash
# فحص أمان شامل قبل النشر

ENVIRONMENTS=("staging" "pre-prod")

for env in "${ENVIRONMENTS[@]}"; do
    TARGET="$env.example.com"
    echo "🔍 فحص بيئة $env: $TARGET"
    
    # إعدادات محافظة للبيئات الحساسة
    python cloud_vulnerability_scanner.py "$TARGET" \
      --threads 3 \
      --timeout 30 \
      --quick-scan \
      --verbose \
      --output-dir "preprod_scan_$env"
    
    # فحص استغلال تجريبي
    python demonstrate_cloud_exploitation.py "$TARGET" \
      --demo \
      --scenario s3_exposure,azure_blob,gcp_storage
      
done
```

## 🔧 أوامر التشغيل السريعة

### القائمة السريعة للأوامر:

```bash
# 1. فحص سريع
python cloud_vulnerability_scanner.py example.com --quick-scan

# 2. فحص شامل
python cloud_vulnerability_scanner.py example.com --deep-scan --verbose

# 3. استغلال سحابي تجريبي
python demonstrate_cloud_exploitation.py example.com --demo

# 4. فحص موحد
python unified_cloud_scanner.py example.com --verbose

# 5. فحص مخصص للإنتاج
python cloud_vulnerability_scanner.py example.com --threads 5 --timeout 30

# 6. فحص متعدد الأنظمة الأساسية
python demonstrate_cloud_exploitation.py example.com --platform aws,azure,gcp --demo

# 7. فحص الحاويات
python demonstrate_cloud_exploitation.py example.com --scenario container_exploitation --demo

# 8. فحص شامل مع تقارير
python cloud_vulnerability_scanner.py example.com --deep-scan --output-dir full_reports
```

## 📊 تفسير النتائج

### مستويات الخطر:
- **CRITICAL**: خطر حرج - يتطلب إصلاح فوري
- **HIGH**: خطر عالٍ - يجب إصلاحه في أقرب وقت
- **MEDIUM**: خطر متوسط - خطط للإصلاح قريبًا
- **LOW**: خطر منخفض - يمكن تأجيل الإصلاح
- **INFO**: معلومات - للمراجعة والتوثيق

### نطاق درجات الخطر (0-100):
- **90-100**: خطر حرج
- **70-89**: خطر عالٍ
- **40-69**: خطر متوسط
- **10-39**: خطر منخفض
- **0-9**: خطر ضئيل

## 🔄 أتمتة الفحص

### سكريبت أتمتة شامل:

```bash
#!/bin/bash
# سكريبت أتمتة الفحص الأمني السحابي

# إعداد المتغيرات
TARGET="${1:-example.com}"
SCAN_TYPE="${2:-full}"
REPORT_DIR="security_scan_$(date +%Y%m%d_%H%M%S)"

# إنشاء مجلد التقارير
mkdir -p "$REPORT_DIR"

echo "🚀 بدء الفحص الأمني السحابي لـ $TARGET"
echo "📁 مجلد التقارير: $REPORT_DIR"

case $SCAN_TYPE in
    "quick")
        echo "⚡ وضع الفحص السريع"
        python cloud_vulnerability_scanner.py "$TARGET" --quick-scan --verbose
        ;;
    "full")
        echo "🔍 وضع الفحص الشامل"
        python cloud_vulnerability_scanner.py "$TARGET" --deep-scan --threads 15 --timeout 60 --verbose --output-dir "$REPORT_DIR"
        python demonstrate_cloud_exploitation.py "$TARGET" --demo --verbose
        python unified_cloud_scanner.py "$TARGET" --verbose --output-dir "$REPORT_DIR"
        ;;
    "demo")
        echo "🎮 وضع العرض التوضيحي"
        python demonstrate_cloud_exploitation.py "$TARGET" --scenario all --demo --verbose
        ;;
    *)
        echo "❌ نوع فحص غير معروف: $SCAN_TYPE"
        echo "✅ الأنواع المتاحة: quick, full, demo"
        exit 1
        ;;
esac

echo "✅ اكتمل الفحص الأمني"
echo "📊 التقارير محفوظة في: $REPORT_DIR"

# إنشاء ملخص
echo "📋 ملخص الفحص:" > "$REPORT_DIR/summary.txt"
echo "الهدف: $TARGET" >> "$REPORT_DIR/summary.txt"
echo "تاريخ الفحص: $(date)" >> "$REPORT_DIR/summary.txt"
echo "نوع الفحص: $SCAN_TYPE" >> "$REPORT_DIR/summary.txt"
```

### استخدام السكريبت:

```bash
# جعل السكريبت قابلاً للتنفيذ
chmod +x cloud_security_scanner.sh

# فحص سريع
./cloud_security_scanner.sh example.com quick

# فحص شامل
./cloud_security_scanner.sh example.com full

# عرض توضيحي
./cloud_security_scanner.sh example.com demo
```

## ⚠️ ملاحظات مهمة

1. **الفحص الأخلاقي**: استخدم هذه الأدوات فقط على المواقع التي تملكها أو لديك إذن بفحصها
2. **أوقات الفحص**: تجنب الفحص خلال أوقات الذروة للمواقع الإنتاجية
3. **إعدادات المحافظة**: استخدم عدد أقل من الخيوط (threads) ووقت أقل (timeout) للمواقع الحساسة
4. **مراجعة التقارير**: راجع جميع التقارير الم-generatedة قبل اتخاذ إجراءات
5. **النسخ الاحتياطي**: قم بإنشاء نسخ احتياطية قبل إجراء أي تغييرات بناءً على النتائج

## 📞 الدعم والمساعدة

إذا واجهت مشاكل في التشغيل:
1. تأكد من تثبيت جميع المتطلبات: `pip install -r requirements.txt`
2. تحقق من اتصال الإنترنت
3. تأكد من صيغة الهدف (domain.com أو IP)
4. راجع سجلات الأخطاء في التقارير
5. استخدم الخيار `--verbose` لمزيد من التفاصيل

---

**✅ تم تحديث الدليل بتاريخ: $(date)**
**🔧 الإصدار: 3.0.0 - مع جميع الميزات المحدثة**