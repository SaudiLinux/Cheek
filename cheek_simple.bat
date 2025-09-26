@echo off
chcp 65001 >nul
color 0A

echo.
echo  ██████╗██╗  ██╗███████╗███████╗███████╗
echo ██╔════╝██║  ██║██╔════╝██╔════╝██╔════╝
echo ██║     ███████║█████╗  █████╗  █████╗  
echo ██║     ██╔══██║██╔══╝  ██╔══╝  ██╔══╝  
echo ╚██████╗██║  ██║███████╗███████╗███████╗
echo  ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
echo.
echo     أداة فحص أمني شاملة
echo     Comprehensive Security Scanner
echo.
echo المبرمج: SayerLinux
echo الإيميل: SaudiSayer@gmail.com
echo.

set /p target=ادخل اسم النطاق أو IP المستهدف: 

if "%target%"=="" (
    echo [!] يجب إدخال هدف للفحص
    pause
    exit /b 1
)

echo.
echo ======================================
echo [*] بدء الفحص الأمني لـ %target%
echo ======================================
echo.

echo [1] فحص المنافذ الشائعة...
echo.

set ports=21 22 23 25 53 80 110 143 443 993 995 1433 3306 3389 5432 6379 8080 8443 27017
set open_ports=

for %%p in (%ports%) do (
    echo | set /p=Testing port %%p... 
    
    powershell -Command "try { $tcp = New-Object System.Net.Sockets.TcpClient; $tcp.Connect('%target%', %%p); if($tcp.Connected) { Write-Host 'OPEN' -ForegroundColor Green; exit 0 } } catch { Write-Host 'CLOSED' -ForegroundColor Red; exit 1 }" >nul 2>&1
    
    if !errorlevel! equ 0 (
        echo [+] المنفذ %%p مفتوح
        set open_ports=!open_ports! %%p
    ) else (
        echo [-] المنفذ %%p مغلق
    )
)

echo.
echo [2] فحص خادم الويب...
echo.

powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://%target%' -TimeoutSec 5 -UseBasicParsing; Write-Host '[+] تم الاتصال بخادم الويب' -ForegroundColor Green; Write-Host '[+] حالة الاستجابة:' $response.StatusCode; if($response.Headers.Server) { Write-Host '[+] خادم الويب:' $response.Headers.Server } } catch { Write-Host '[-] لا يمكن الاتصال بخادم الويب' -ForegroundColor Red }"

echo.
echo [3] فحص رؤوس الأمان...
echo.

powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://%target%' -TimeoutSec 5 -UseBasicParsing; $headers = $response.Headers; Write-Host '[+] رؤوس الأمان المكتشفة:' -ForegroundColor Yellow; foreach($header in $headers.GetEnumerator()) { if($header.Key -match 'X-.*' -or $header.Key -match '.*Security.*') { Write-Host '    -' $header.Key ':' $header.Value } } } catch { Write-Host '[-] لا يمكن فحص الرؤوس' -ForegroundColor Red }"

echo.
echo [4] فحص تقنيات الويب...
echo.

powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://%target%' -TimeoutSec 5 -UseBasicParsing; $content = $response.Content; if($content -match 'wordpress') { Write-Host '[+] WordPress مكتشف' -ForegroundColor Green } elseif($content -match 'joomla') { Write-Host '[+] Joomla مكتشف' -ForegroundColor Green } elseif($content -match 'drupal') { Write-Host '[+] Drupal مكتشف' -ForegroundColor Green } elseif($content -match 'laravel') { Write-Host '[+] Laravel مكتشف' -ForegroundColor Green } else { Write-Host '[i] لا توجد تقنيات ويب واضحة' -ForegroundColor Cyan } } catch { Write-Host '[-] لا يمكن فحص التقنيات' -ForegroundColor Red }"

echo.
echo [5] فحص المسارات الحساسة...
echo.

set paths=/admin /login /config /backup /test /dev /api /wp-admin /phpmyadmin

for %%p in (%paths%) do (
    echo | set /p=فحص المسار %%p... 
    
    powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://%target%%%p' -TimeoutSec 3 -UseBasicParsing; if($response.StatusCode -eq 200) { Write-Host 'FOUND' -ForegroundColor Green } else { Write-Host 'NOT FOUND' -ForegroundColor Gray } } catch { Write-Host 'NOT FOUND' -ForegroundColor Gray }" >nul 2>&1
)

echo.
echo ======================================
echo [*] انتهى الفحص الأمني
echo ======================================
echo.
echo المبرمج: SayerLinux
echo الإيميل: SaudiSayer@gmail.com
echo.
echo شكراً لاستخدام أداة Cheek!
pause