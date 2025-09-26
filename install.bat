@echo off
echo ======================================
echo Cheek Security Scanner - Installation
echo ======================================
echo.

echo [1/3] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not installed or not in PATH
    echo Please install Python 3.6+ from https://www.python.org/
    pause
    exit /b 1
)
echo [+] Python found

echo.
echo [2/3] Installing required packages...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [!] Failed to install packages
    pause
    exit /b 1
)
echo [+] Packages installed successfully

echo.
echo [3/3] Setting up executable permissions...
echo [+] Installation completed successfully!
echo.
echo ======================================
echo You can now run Cheek using:
echo   python cheek.py [target]
echo.
echo Example:
echo   python cheek.py example.com
echo ======================================
pause