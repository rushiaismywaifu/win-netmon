@echo off
chcp 65001 >nul
REM ============================================================
REM  （選用）用 PyInstaller 打包成 WinNetMon.exe
REM  --uac-admin：雙擊 exe 會自動要求系統管理員權限
REM  注意：仍需安裝 Npcap 才能使用層級 3、4；層級 5 的 WinDivert 驅動會一併打包（pydivert 內含）。
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
