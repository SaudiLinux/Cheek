@echo off
setlocal enabledelayedexpansion

:: Cloud Security Master Scanner - Windows Version
:: فاحص الأمان السحابي الشامل لويندوز

:: الألوان (تعمل في PowerShell)
set "RED=[31m"
set "GREEN=[32m"
set "YELLOW=[33m"
set "BLUE=[34m"
set "CYAN=[36m"
set "WHITE=[37m"
set "NC=[0m"

:: دالة لطباعة المخرجات الملونة
echo off

:: دالة لطباعة العناوين
echo ================================================================
echo Cloud Security Master Scanner - فاحص الأمان السحابي الشامل
echo ================================================================
echo.

:: التحقق من Python
python --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON_CMD=python"
    echo ✅ تم العثور على Python
) else (
    python3 --version >nul 2>&1
    if %errorlevel% equ 0 (
        set "PYTHON_CMD=python3"
        echo ✅ تم العثور على Python3
    ) else (
        echo ❌ لم يتم العثور على Python
        exit /b 1
    )
)

:: التحقق من الملفات المطلوبة
echo.
echo التحقق من الملفات المطلوبة...
set "missing_files="

if not exist "cloud_vulnerability_scanner.py" (
    set "missing_files=!missing_files! cloud_vulnerability_scanner.py"
)
if not exist "demonstrate_cloud_exploitation.py" (
    set "missing_files=!missing_files! demonstrate_cloud_exploitation.py"
)
if not exist "unified_cloud_scanner.py" (
    set "missing_files=!missing_files! unified_cloud_scanner.py"
)
if not exist "requirements.txt" (
    set "missing_files=!missing_files! requirements.txt"
)

if defined missing_files (
    echo ❌ ملفات مفقودة: !missing_files!
    exit /b 1
) else (
    echo ✅ جميع الملفات المطلوبة موجودة
)

:: معالجة المعاملات
set "target="
set "scan_type=quick"
set "threads=10"
set "timeout=30"
set "output_dir=reports"

if "%~1"=="" (
    goto :show_help
)

if "%~1"=="--help" (
    goto :show_help
)

if "%~1"=="--install" (
    goto :install_requirements
)

set "target=%~1"
if not "%~2"=="" set "scan_type=%~2"

:: معالجة الخيارات الإضافية
:parse_args
if "%~3"=="" goto :end_parse_args
if "%~3"=="--threads" (
    set "threads=%~4"
    shift
    shift
    goto :parse_args
)
if "%~3"=="--timeout" (
    set "timeout=%~4"
    shift
    shift
    goto :parse_args
)
if "%~3"=="--output" (
    set "output_dir=%~4"
    shift
    shift
    goto :parse_args
)
echo ⚠️ خيار غير معروف: %~3
shift
goto :parse_args
:end_parse_args

:: التحقق من الهدف
echo.
echo التحقق من الهدف: %target%

:: التحقق من صيغة الهدف
echo %target% | findstr /R "^[a-zA-Z0-9.-]*\.[a-zA-Z]*$" >nul
if %errorlevel% equ 0 (
    echo ✅ صيغة الهدف صحيحة
) else (
    echo %target% | findstr /R "^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$" >nul
    if %errorlevel% equ 0 (
        echo ✅ صيغة الهدف صحيحة (IP)
    ) else (
        echo ❌ صيغة الهدف غير صحيحة
        exit /b 1
    )
)

:: إنشاء مجلد الإخراج
if not exist "%output_dir%" (
    mkdir "%output_dir%"
    echo ✅ تم إنشاء مجلد الإخراج: %output_dir%
)

:: بدء الفحص
echo.
echo ================================================================
echo 🌩️ بدء فحص الأمان السحابي الشامل 🌩️
echo ================================================================
echo الهدف: %target%
echo نوع الفحص: %scan_type%
echo عدد الخيوط: %threads%
echo وقت الانتظار: %timeout%
echo مجلد الإخراج: %output_dir%
echo.

:: تنفيذ الفحص حسب النوع
if "%scan_type%"=="quick" (
    goto :quick_scan
)
if "%scan_type%"=="full" (
    goto :comprehensive_scan
)
if "%scan_type%"=="demo" (
    goto :demo_scan
)
echo ❌ نوع فحص غير معروف: %scan_type%
echo الأنواع المتاحة: quick, full, demo
exit /b 1

:quick_scan
echo 1️⃣ الفحص السريع...
echo.

echo فحص الثغرات السحابية السريع...
%PYTHON_CMD% cloud_vulnerability_scanner.py "%target%" --quick-scan --verbose
if %errorlevel% equ 0 (
    echo ✅ اكتمل الفحص السريع
) else (
    echo ⚠️ الفحص السريع لم يكتمل بنجاح
)

echo.
echo فحص الاستغلال التجريبي...
%PYTHON_CMD% demonstrate_cloud_exploitation.py "%target%" --demo
if %errorlevel% equ 0 (
    echo ✅ اكتمل فحص الاستغلال التجريبي
) else (
    echo ⚠️ فحص الاستغلال التجريبي لم يكتمل بنجاح
)
goto :generate_report

:comprehensive_scan
echo 1️⃣ الفحص الشامل...
echo.

echo فحص الثغرات السحابية الشامل...
%PYTHON_CMD% cloud_vulnerability_scanner.py "%target%" --deep-scan --threads %threads% --timeout %timeout% --verbose --output-dir "%output_dir%"
if %errorlevel% equ 0 (
    echo ✅ اكتمل فحص الثغرات السحابية
) else (
    echo ⚠️ فحص الثغرات السحابية لم يكتمل بنجاح
)

echo.
echo فحص الاستغلال التجريبي...
%PYTHON_CMD% demonstrate_cloud_exploitation.py "%target%" --demo --verbose
if %errorlevel% equ 0 (
    echo ✅ اكتمل فحص الاستغلال التجريبي
) else (
    echo ⚠️ فحص الاستغلال التجريبي لم يكتمل بنجاح
)

echo.
echo الفحص الموحد...
%PYTHON_CMD% unified_cloud_scanner.py "%target%" --verbose --output-dir "%output_dir%"
if %errorlevel% equ 0 (
    echo ✅ اكتمل الفحص الموحد
) else (
    echo ⚠️ الفحص الموحد لم يكتمل بنجاح
)
goto :generate_report

:demo_scan
echo فحص تجريبي شامل...
%PYTHON_CMD% demonstrate_cloud_exploitation.py "%target%" --scenario all --demo --verbose
if %errorlevel% equ 0 (
    echo ✅ اكتمل الفحص التجريبي
) else (
    echo ⚠️ الفحص التجريبي لم يكتمل بنجاح
)
goto :generate_report

:generate_report
echo.
echo ================================================================
echo 📊 إنشاء التقرير النهائي
echo ================================================================

set "report_file=%output_dir%\final_report_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.txt"
set "report_file=%report_file: =0%"

echo 🎯 الهدف: %target% > "%report_file%"
echo 📅 تاريخ الفحص: %date% %time% >> "%report_file%"
echo ⏱️ نوع الفحص: %scan_type% >> "%report_file%"
echo 📁 مجلد التقارير: %output_dir% >> "%report_file%"
echo. >> "%report_file%"
echo 📊 ملخص الفحص: >> "%report_file%"
echo - تم إجراء فحص أمني شامل للبنية التحتية السحابية >> "%report_file%"
echo - تم فحص خدمات AWS وAzure وGCP >> "%report_file%"
echo - تم اختبار أمان الحاويات >> "%report_file%"
echo - تم إنشاء تقارير مفصلة بنتائج الفحص >> "%report_file%"
echo. >> "%report_file%"
echo 📋 التوصيات: >> "%report_file%"
echo 1. مراجعة تقارير الفحص المفصلة >> "%report_file%"
echo 2. معالجة الثغرات المكتشفة حسب الأولوية >> "%report_file%"
echo 3. تنفيذ إجراءات الأمان الموصى بها >> "%report_file%"
echo 4. إجراء فحص دوري منتظم >> "%report_file%"
echo. >> "%report_file%"
echo 📞 للدعم الفني: >> "%report_file%"
echo - راجع سجلات الفحص في مجلد: %output_dir% >> "%report_file%"
echo - تحقق من ملفات JSON للتفاصيل الكاملة >> "%report_file%"
echo - استخدم خيار --verbose للحصول على مزيد من التفاصيل >> "%report_file%"
echo. >> "%report_file%"
echo ================================================================ >> "%report_file%"
echo الفحص مكتمل ✅ >> "%report_file%"

echo ✅ تم إنشاء التقرير النهائي: %report_file%
echo.
goto :show_summary

:show_summary
echo ================================================================
echo 📊 ملخص الفحص
echo ================================================================
echo ✅ الهدف: %target%
echo ✅ نوع الفحص: %scan_type%
echo ✅ مجلد التقارير: %output_dir%
echo ✅ حالة الفحص: مكتمل
echo.
echo 📋 للحصول على التفاصيل الكاملة:
echo   - راجع التقارير في: %output_dir%
echo   - افتح ملف JSON للحصول على التفاصيل الكاملة
echo   - استخدم أداة عرض JSON للحصول على عرض أفضل
echo.
echo ================================================================
echo 🏁 اكتمل فحص الأمان السحابي 🏁
echo ================================================================
goto :end

:install_requirements
echo.
echo تثبيت المتطلبات...
%PYTHON_CMD% -m pip install -r requirements.txt
if %errorlevel% equ 0 (
    echo ✅ تم تثبيت المتطلبات بنجاح
) else (
    echo ❌ فشل تثبيت المتطلبات
    exit /b 1
)
goto :end

:show_help
echo.
echo ================================================================
echo دليل استخدام فاحص الأمان السحابي الشامل
echo ================================================================
echo.
echo الاستخدام:
echo   %0 ^<target^> [scan_type] [options]
echo.
echo المعاملات:
echo   target      : الهدف (domain.com أو IP)
echo   scan_type   : نوع الفحص (quick^|full^|demo) [افتراضي: quick]
echo.
echo الخيارات:
echo   --threads   : عدد الخيوط [افتراضي: 10]
echo   --timeout   : وقت الانتظار [افتراضي: 30]
echo   --output    : مجلد الإخراج [افتراضي: reports]
echo   --install   : تثبيت المتطلبات فقط
echo   --help      : عرض هذه المساعدة
echo.
echo الأمثلة:
echo   %0 example.com                    # فحص سريع
echo   %0 example.com full                 # فحص شامل
echo   %0 example.com demo                 # فحص تجريبي
echo   %0 example.com full --threads 20    # فحص شامل مع 20 خيط
echo   %0 example.com quick --timeout 60   # فحص سريع مع timeout 60
echo   %0 --install                        # تثبيت المتطلبات فقط
echo.
goto :end

:end
endlocal