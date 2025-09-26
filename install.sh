#!/bin/bash

echo "======================================"
echo "Cheek Security Scanner - Installation"
echo "======================================"
echo

# Check Python installation
echo "[1/3] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 is not installed"
    echo "Please install Python 3.6+ using your package manager"
    exit 1
fi
echo "[+] Python3 found"

# Check pip installation
echo "[2/3] Checking pip installation..."
if ! command -v pip3 &> /dev/null; then
    echo "[!] pip3 is not installed"
    echo "Please install pip3 using your package manager"
    exit 1
fi
echo "[+] pip3 found"

# Install requirements
echo "[3/3] Installing required packages..."
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[!] Failed to install packages"
    exit 1
fi
echo "[+] Packages installed successfully"

# Make cheek.py executable
chmod +x cheek.py

echo
echo "======================================"
echo "Installation completed successfully!"
echo
echo "You can now run Cheek using:"
echo "  ./cheek.py [target]"
echo "  python3 cheek.py [target]"
echo
echo "Example:"
echo "  ./cheek.py example.com"
echo "====================================="