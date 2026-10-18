@echo off
chcp 65001 >nul
REM ============================================================
REM  （選用）用 PyInstaller 打包成 WinNetMon.exe
REM  --uac-admin：雙擊 exe 會自動要求系統管理員權限
REM  注意：Npcap 免費版授權禁止再散布、也不能靜默安裝，無法合法打包進 exe；
REM  WinNetMon.exe 首次執行時可在「封包擷取」頁一鍵從官網下載安裝（或 --install-npcap）。
REM  WinDivert 驅動會隨 pydivert 一併打包：沒裝 Npcap 時，層級 3/4 會自動改用
REM  WinDivert 後端擷取 IP 層封包（無 Ethernet/ARP），層級 5 攔截也用同一個驅動。
REM ============================================================
cd /d "%~dp0"

python -m pip install -r requirements.txt pyinstaller
if %errorlevel% neq 0 ( echo 安裝套件失敗 & pause & exit /b 1 )

REM 若 assets/icon.ico 存在則自動帶上圖示並將 assets 一併收進 exe（供視窗標題列/工作列載入）
if exist assets\icon.ico (
    set ICON_OPT=--icon assets\icon.ico --add-data "assets;assets"
) else (
    set ICON_OPT=
)

python -m PyInstaller --noconfirm --onefile --windowed --uac-admin ^
    --name WinNetMon %ICON_OPT% ^
    --collect-submodules scapy --collect-all pydivert ^
    main.py
if %errorlevel% neq 0 ( echo 打包失敗 & pause & exit /b 1 )

echo.
echo 完成：dist\WinNetMon.exe
pause
