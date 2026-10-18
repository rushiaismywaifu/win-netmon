@echo off
chcp 65001 >nul
REM ============================================================
REM  Win-NetMon：以系統管理員身分啟動 GUI（層級 1~4 建議用這個）
REM  封包擷取與檢視所有程式連線都需要管理員權限。
REM ============================================================
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在要求系統管理員權限...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

python -c "import psutil, scapy" 2>nul
if %errorlevel% neq 0 (
    echo 正在安裝所需套件 psutil / scapy ...
    python -m pip install -r requirements.txt
)

python main.py
if %errorlevel% neq 0 pause
