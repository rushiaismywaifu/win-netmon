@echo off
chcp 65001 >nul
REM Win-NetMon：一般身分啟動 GUI（層級 1、2 可用；層級 3~5 請用 run_as_admin.bat）
cd /d "%~dp0"

python -c "import psutil, scapy, pydivert" 2>nul
if %errorlevel% neq 0 (
    echo 正在安裝所需套件 psutil / scapy / pydivert ...
    python -m pip install -r requirements.txt
)

python main.py
if %errorlevel% neq 0 pause
