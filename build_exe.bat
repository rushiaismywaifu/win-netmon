@echo off
chcp 65001 >nul
REM ============================================================
REM  （選用）用 PyInstaller 打包成 WinNetMon.exe
REM  --uac-admin：雙擊 exe 會自動要求系統管理員權限
REM  注意：Npcap 免費版授權禁止再散布、也不能靜默安裝，無法合法打包進 exe；
REM  WinNetMon.exe 首次執行時可在「封包擷取」頁一鍵從官網下載安裝（或 --install-npcap）。
REM  層級 5 的 WinDivert 驅動則會隨 pydivert 一併打包。
REM ============================================================
cd /d "%~dp0"

python -m pip install -r requirements.txt pyinstaller
if %errorlevel% neq 0 ( echo 安裝套件失敗 & pause & exit /b 1 )

python -m PyInstaller --noconfirm --onefile --windowed --uac-admin ^
    --name WinNetMon ^
    --collect-submodules scapy --collect-all pydivert ^
    main.py
if %errorlevel% neq 0 ( echo 打包失敗 & pause & exit /b 1 )

echo.
echo 完成：dist\WinNetMon.exe
pause
