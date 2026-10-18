@echo off
chcp 65001 >nul
REM Win-NetMon：一般身分啟動 GUI（層級 1、2 可用；層級 3/4 建議用 run_as_admin.bat）
cd /d "%~dp0"

python -c "import psutil, scapy" 2>nul
if %errorlevel% neq 0 (
    echo 正在安裝所需套件 psutil / scapy ...
    python -m pip install -r requirements.txt
)

python main.py
if %errorlevel% neq 0 pause
