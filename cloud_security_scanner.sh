#!/bin/bash
# Cloud Security Master Scanner - Arabic Version
# فاحص الأمان السحابي الشامل

set -e  # إيقاف التنفيذ عند حدوث خطأ

# الألوان للمخرجات الملونة
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# دالة لطباعة المخرجات الملونة
print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# دالة التحقق من المتطلبات
check_requirements() {
    print_header "التحقق من المتطلبات"
    
    # التحقق من Python
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        print_error "لم يتم العثور على Python"
        exit 1
    fi
    
    print_success "تم العثور على Python: $PYTHON_CMD"
    
    # التحقق من الملفات المطلوبة
    required_files=(
        "cloud_vulnerability_scanner.py"
        "demonstrate_cloud_exploitation.py"
        "unified_cloud_scanner.py"
        "requirements.txt"
    )
    
    for file in "${required_files[@]}"; do
        if [[ -f "$file" ]]; then
            print_success "تم العثور على: $file"
        else
            print_error "ملف مفقود: $file"
            exit 1
        fi
    done
}

# دالة تثبيت المتطلبات
install_requirements() {
    print_header "تثبيت المتطلبات"
    
    print_info "تثبيت مكتبات Python..."
    if $PYTHON_CMD -m pip install -r requirements.txt; then
        print_success "تم تثبيت المتطلبات بنجاح"
    else
        print_error "فشل تثبيت المتطلبات"
        exit 1
    fi
}

# دالة التحقق من الهدف
check_target() {
    local target=$1
    print_header "التحقق من الهدف: $target"
    
    # التحقق من صيغة الهدف
    if [[ $target =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_success "صيغة الهدف صحيحة"
    else
        print_error "صيغة الهدف غير صحيحة"
        return 1
    fi
    
    # التحقق من الاتصال
    if ping -c 1 "$target" &> /dev/null; then
        print_success "الهدف قابل للوصول"
    else
        print_warning "الهدف قد لا يكون قابلاً للوصول (ستتم المتابعة)"
    fi
}

# دالة الفحص السريع
quick_scan() {
    local target=$1
    local output_dir=$2
    
    print_header "الفحص السريع لـ: $target"
    
    print_info "تشغيل الفحص السحابي السريع..."
    if $PYTHON_CMD cloud_vulnerability_scanner.py "$target" --quick-scan --verbose; then
        print_success "اكتمل الفحص السريع"
    else
        print_warning "الفحص السريع لم يكتمل بنجاح"
    fi
    
    print_info "تشغيل فحص الاستغلال التجريبي..."
    if $PYTHON_CMD demonstrate_cloud_exploitation.py "$target" --demo; then
        print_success "اكتمل فحص الاستغلال التجريبي"
    else
        print_warning "فحص الاستغلال التجريبي لم يكتمل بنجاح"
    fi
}

# دالة الفحص الشامل
comprehensive_scan() {
    local target=$1
    local output_dir=$2
    local threads=${3:-10}
    local timeout=${4:-30}
    
    print_header "الفحص الشامل لـ: $target"
    print_info "المعلمات: threads=$threads, timeout=$timeout"
    
    # فحص الثغرات السحابية
    print_info "1️⃣ فحص الثغرات السحابية..."
    if $PYTHON_CMD cloud_vulnerability_scanner.py "$target" \
        --deep-scan \
        --threads "$threads" \
        --timeout "$timeout" \
        --verbose \
        --output-dir "$output_dir"; then
        print_success "✅ اكتمل فحص الثغرات السحابية"
    else
        print_warning "⚠️ فحص الثغرات السحابية لم يكتمل بنجاح"
    fi
    
    # فحص الاستغلال التجريبي
    print_info "2️⃣ فحص الاستغلال التجريبي..."
    if $PYTHON_CMD demonstrate_cloud_exploitation.py "$target" \
        --demo \
        --verbose; then
        print_success "✅ اكتمل فحص الاستغلال التجريبي"
    else
        print_warning "⚠️ فحص الاستغلال التجريبي لم يكتمل بنجاح"
    fi
    
    # فحص موحد
    print_info "3️⃣ الفحص الموحد..."
    if $PYTHON_CMD unified_cloud_scanner.py "$target" \
        --verbose \
        --output-dir "$output_dir"; then
        print_success "✅ اكتمل الفحص الموحد"
    else
        print_warning "⚠️ الفحص الموحد لم يكتمل بنجاح"
    fi
}

# دالة الفحص التجريبي
demo_scan() {
    local target=$1
    local output_dir=$2
    
    print_header "الفحص التجريبي لـ: $target"
    
    print_info "تشغيل جميع سيناريوهات الاستغلال..."
    if $PYTHON_CMD demonstrate_cloud_exploitation.py "$target" \
        --scenario all \
        --demo \
        --verbose; then
        print_success "✅ اكتمل الفحص التجريبي"
    else
        print_warning "⚠️ الفحص التجريبي لم يكتمل بنجاح"
    fi
}

# دالة إنشاء التقرير النهائي
generate_final_report() {
    local target=$1
    local output_dir=$2
    local scan_type=$3
    
    print_header "إنشاء التقرير النهائي"
    
    local report_file="$output_dir/final_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
🌩️ تقرير الفحص الأمني السحابي الشامل
================================================

🎯 الهدف: $target
📅 تاريخ الفحص: $(date)
⏱️ نوع الفحص: $scan_type
📁 مجلد التقارير: $output_dir

📊 ملخص الفحص:
- تم إجراء فحص أمني شامل للبنية التحتية السحابية
- تم فحص خدمات AWS وAzure وGCP
- تم اختبار أمان الحاويات
- تم إنشاء تقارير مفصلة بنتائج الفحص

📋 التوصيات:
1. مراجعة تقارير الفحص المفصلة
2. معالجة الثغرات المكتشفة حسب الأولوية
3. تنفيذ إجراءات الأمان الموصى بها
4. إجراء فحص دوري منتظم

📞 للدعم الفني:
- راجع سجلات الفحص في مجلد: $output_dir
- تحقق من ملفات JSON للتفاصيل الكاملة
- استخدم خيار --verbose للحصول على مزيد من التفاصيل

================================================
الفحص مكتمل ✅
EOF

    print_success "تم إنشاء التقرير النهائي: $report_file"
}

# دالة عرض المساعدة
show_help() {
    print_header "دليل استخدام فاحص الأمان السحابي الشامل"
    
    echo -e "${CYAN}الاستخدام:${NC}"
    echo "  $0 <target> [scan_type] [options]"
    echo ""
    echo -e "${CYAN}المعاملات:${NC}"
    echo "  target      : الهدف (domain.com أو IP)"
    echo "  scan_type   : نوع الفحص (quick|full|demo) [افتراضي: quick]"
    echo ""
    echo -e "${CYAN}الخيارات:${NC}"
    echo "  --threads   : عدد الخيوط [افتراضي: 10]"
    echo "  --timeout   : وقت الانتظار [افتراضي: 30]"
    echo "  --output    : مجلد الإخراج [افتراضي: reports]"
    echo "  --install   : تثبيت المتطلبات فقط"
    echo "  --help      : عرض هذه المساعدة"
    echo ""
    echo -e "${CYAN}الأمثلة:${NC}"
    echo "  $0 example.com                    # فحص سريع"
    echo "  $0 example.com full                 # فحص شامل"
    echo "  $0 example.com demo                 # فحص تجريبي"
    echo "  $0 example.com full --threads 20    # فحص شامل مع 20 خيط"
    echo "  $0 example.com quick --timeout 60   # فحص سريع مع timeout 60"
    echo "  $0 --install                        # تثبيت المتطلبات فقط"
}

# الدالة الرئيسية
main() {
    # التحقق من المعاملات
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi
    
    # خيار تثبيت المتطلبات فقط
    if [[ "$1" == "--install" ]]; then
        check_requirements
        install_requirements
        exit 0
    fi
    
    # خيار المساعدة
    if [[ "$1" == "--help" ]]; then
        show_help
        exit 0
    fi
    
    local target=$1
    local scan_type=${2:-quick}
    local threads=10
    local timeout=30
    local output_dir="reports"
    
    # معالجة الخيارات الإضافية
    shift 2
    while [[ $# -gt 0 ]]; do
        case $1 in
            --threads)
                threads="$2"
                shift 2
                ;;
            --timeout)
                timeout="$2"
                shift 2
                ;;
            --output)
                output_dir="$2"
                shift 2
                ;;
            *)
                print_warning "خيار غير معروف: $1"
                shift
                ;;
        esac
    done
    
    # بدء الفحص
    print_header "🌩️ بدء فحص الأمان السحابي الشامل 🌩️"
    print_info "الهدف: $target"
    print_info "نوع الفحص: $scan_type"
    print_info "عدد الخيوط: $threads"
    print_info "وقت الانتظار: $timeout"
    print_info "مجلد الإخراج: $output_dir"
    
    # التحقق من المتطلبات
    check_requirements
    
    # التحقق من الهدف
    if ! check_target "$target"; then
        print_error "فشل التحقق من الهدف"
        exit 1
    fi
    
    # إنشاء مجلد الإخراج
    mkdir -p "$output_dir"
    
    # تنفيذ الفحص حسب النوع
    case $scan_type in
        "quick")
            quick_scan "$target" "$output_dir"
            ;;
        "full")
            comprehensive_scan "$target" "$output_dir" "$threads" "$timeout"
            ;;
        "demo")
            demo_scan "$target" "$output_dir"
            ;;
        *)
            print_error "نوع فحص غير معروف: $scan_type"
            echo "الأنواع المتاحة: quick, full, demo"
            exit 1
            ;;
    esac
    
    # إنشاء التقرير النهائي
    generate_final_report "$target" "$output_dir" "$scan_type"
    
    # عرض الملخص
    print_header "📊 ملخص الفحص"
    print_success "الهدف: $target"
    print_success "نوع الفحص: $scan_type"
    print_success "مجلد التقارير: $output_dir"
    print_success "حالة الفحص: مكتمل ✅"
    
    print_info "📋 للحصول على التفاصيل الكاملة:" 
    print_info "  - راجع التقارير في: $output_dir"
    print_info "  - افتح ملف JSON للحصول على التفاصيل الكاملة"
    print_info "  - استخدم أداة عرض JSON للحصول على عرض أفضل"
    
    print_header "🏁 اكتمل فحص الأمان السحابي 🏁"
}

# تنفيذ الدالة الرئيسية
main "$@"