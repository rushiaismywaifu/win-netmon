"""Npcap 一鍵安裝輔助：從官方站下載安裝程式並啟動（不隨程式散布）。

為什麼不把 Npcap 打包進 exe？
  1. 技術面：Npcap 是核心驅動（NDIS LWF + WFP callout），必須經由它的
     安裝程式把簽章驅動註冊進系統，光把 DLL 塞進 PyInstaller 封裝無法使用。
  2. 授權面：Npcap 免費版明文禁止再散布（redistribution），而且免費版
     安裝程式沒有靜默安裝（/S）功能 — 這兩項都是付費 Npcap OEM 授權的
     賣點。所以「把官方免費安裝檔直接包進我們的 exe 發布」是違反授權的。
合法且體驗最接近的做法（也是 Npcap 官方歡迎的做法）：在使用者自己的
電腦上，經使用者同意，從 https://npcap.com 下載官方安裝程式、驗證
數位簽章後，以互動模式啟動安裝（使用者在安裝程式中接受其授權）。

本模組純 stdlib（urllib/subprocess），不依賴 Scapy/psutil，方便測試；
所有網路/程序操作都有可注入接點（opener/runner/popen）。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

NPCAP_HOME = "https://npcap.com"
FALLBACK_VERSION = "1.89"  # 查不到官網最新版時的回退（寫作時的最新版）
FALLBACK_INSTALLER_URL = f"{NPCAP_HOME}/dist/npcap-{FALLBACK_VERSION}.exe"
NPCAP_LICENSE_NOTE = (
    "Npcap 免費版授權：終端使用者可免費安裝於最多 5 台系統"
    "（僅與 Nmap/Wireshark 等搭配時不限台數），"
    "詳細條款會在安裝程式中顯示，請在安裝時確認接受。"
)
_USER_AGENT = "Win-NetMon (+https://github.com/rushiaismywaifu/win-netmon)"
_INSTALLER_RE = re.compile(r"dist/npcap-(\d+)\.(\d+)\.exe")
_INSTALLER_PATH_RE = re.compile(r"^/dist/npcap-\d+\.\d+\.exe$")


# ---------------------------------------------------------------------------
# 官方安裝檔 URL 的發現與驗證
# ---------------------------------------------------------------------------

def validate_installer_url(url: str) -> bool:
    """只接受 https://npcap.com/dist/npcap-X.YY.exe（防止被導去奇怪來源）。"""
    try:
        parsed = urlparse(url or "")
    except Exception:
        return False
    return (
        parsed.scheme == "https"
        and (parsed.hostname or "") == "npcap.com"
        and bool(_INSTALLER_PATH_RE.match(parsed.path or ""))
    )


def parse_latest_installer_url(html: str) -> str | None:
    """從 npcap.com 首頁 HTML 找出版本最高的安裝檔連結。"""
    found: list[tuple[tuple[int, int], str]] = []
    for major, minor in _INSTALLER_RE.findall(html or ""):
        version = (int(major), int(minor))
        found.append((version, f"{NPCAP_HOME}/dist/npcap-{major}.{minor}.exe"))
    if not found:
        return None
    found.sort(key=lambda item: item[0], reverse=True)
    return found[0][1]


def _default_opener(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    return urllib.request.urlopen(request, timeout=30)


def discover_installer_url(opener: Callable | None = None) -> str:
    """查官網首頁找最新版安裝檔；任何失敗就回退到已知版本，永不拋錯。"""
    opener = opener or _default_opener
    try:
        with opener(NPCAP_HOME) as resp:
            html = resp.read(512 * 1024).decode("utf-8", errors="replace")
        url = parse_latest_installer_url(html)
        if url and validate_installer_url(url):
            return url
    except Exception:
        pass
    return FALLBACK_INSTALLER_URL


# ---------------------------------------------------------------------------
# 下載（串流 + 進度回呼 + 完整性基本檢查）
# ---------------------------------------------------------------------------

ProgressCallback = Callable[[int, int], None]  # (已下載 bytes, 總 bytes; 0=未知)

_MIN_INSTALLER_BYTES = 300_000  # Npcap 安裝檔約 1MB+，太小的檔案視為下載異常


def download_installer(url: str | None = None, dest_dir: str | Path | None = None,
                       progress: ProgressCallback | None = None,
                       opener: Callable | None = None) -> Path:
    """下載官方安裝檔到暫存資料夾，回傳檔案路徑。失敗拋出例外（訊息可直接顯示）。"""
    opener = opener or _default_opener
    url = url or discover_installer_url(opener)
    if not validate_installer_url(url):
        raise ValueError(f"拒絕下載非官方來源：{url}")

    folder = Path(dest_dir) if dest_dir else Path(tempfile.gettempdir()) / "Win-NetMon"
    folder.mkdir(parents=True, exist_ok=True)
    filename = Path(urlparse(url).path).name
    dest = folder / filename
    part = folder / (filename + ".part")

    downloaded = 0
    total = 0
    try:
        with opener(url) as resp, open(part, "wb") as fh:
            try:
                total = int(resp.headers.get("Content-Length") or 0)
            except (TypeError, ValueError, AttributeError):
                total = 0
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                downloaded += len(chunk)
                if progress is not None:
                    try:
                        progress(downloaded, total)
                    except Exception:
                        pass
    except Exception as exc:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"下載 Npcap 失敗（網路問題？）：{exc}") from exc

    if total and downloaded != total:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"下載不完整：{downloaded}/{total} bytes，請重試")
    if downloaded < _MIN_INSTALLER_BYTES:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"下載的檔案異常地小（{downloaded} bytes），已捨棄")
    os.replace(part, dest)
    return dest


# ---------------------------------------------------------------------------
# Authenticode 簽章驗證（Windows / PowerShell）
# ---------------------------------------------------------------------------

Runner = Callable[[list[str]], tuple[int, str]]


def _default_runner(cmd: list[str]) -> tuple[int, str]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform.startswith("win") else 0
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=60, creationflags=flags)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)
    raw = (proc.stdout or b"") + (proc.stderr or b"")
    return proc.returncode, raw.decode("utf-8", errors="replace")


def verify_authenticode(path: str | Path, runner: Runner | None = None,
                        check_platform: bool = True) -> tuple[bool | None, str]:
    """驗證安裝檔簽章。

    回傳 (True, 說明) 簽章有效且簽署者為 Nmap 專案；(False, 說明) 驗證
    明確失敗或簽署者不符，應拒絕執行；(None, 說明) 無法驗證（環境問題），
    由呼叫方決定去留。
    """
    if check_platform and not sys.platform.startswith("win"):
        return None, "非 Windows 環境，無法驗證 Authenticode 簽章"
    path_text = str(path).replace("'", "''")  # PowerShell 單引號跳脫
    script = (
        f"$s = Get-AuthenticodeSignature -LiteralPath '{path_text}'; "
        "Write-Output ($s.Status.ToString() + '|' + $s.SignerCertificate.Subject)"
    )
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    code, output = (runner or _default_runner)(cmd)
    line = next((ln.strip() for ln in output.splitlines() if "|" in ln), "")
    if code != 0 or not line:
        return None, f"無法執行簽章檢查（PowerShell 回傳 {code}）"
    status, _, subject = line.partition("|")
    status = status.strip()
    if status != "Valid":
        return False, f"數位簽章狀態為「{status}」，不是有效的官方安裝檔"
    if "nmap" not in subject.lower():
        return False, f"簽章有效但簽署者不是 Nmap 專案：{subject or '（未知）'}"
    return True, f"簽章有效（{subject.strip()}）"


# ---------------------------------------------------------------------------
# 啟動安裝程式 + 一站式流程
# ---------------------------------------------------------------------------

def launch_installer(path: str | Path, popen=None,
                     check_platform: bool = True) -> tuple[bool, str]:
    """啟動 Npcap 互動式安裝程式（免費版不支援靜默 /S，所以不加任何參數）。"""
    target = Path(path)
    if not target.is_file():
        return False, f"找不到安裝檔：{target}"
    if check_platform and not sys.platform.startswith("win"):
        return False, "僅 Windows 可執行 Npcap 安裝程式"
    try:
        (popen or subprocess.Popen)([str(target)], close_fds=True)
    except OSError as exc:
        return False, f"啟動安裝程式失敗：{exc}"
    return True, "已啟動 Npcap 安裝程式，請依精靈完成安裝（建議勾 WinPcap 相容模式），完成後請重啟 Win-NetMon。"


def install_npcap(progress: ProgressCallback | None = None, opener=None,
                  runner: Runner | None = None, popen=None,
                  allow_unverified: bool = False,
                  check_platform: bool = True) -> tuple[bool, str, Path | None]:
    """一站式：下載 → 驗簽 → 啟動安裝。回傳 (成功, 說明, 安裝檔路徑)。"""
    try:
        path = download_installer(progress=progress, opener=opener)
    except Exception as exc:  # noqa: BLE001 - 統一轉訊息給呼叫方
        return False, str(exc), None
    verified, detail = verify_authenticode(path, runner=runner,
                                            check_platform=check_platform)
    if verified is False:
        return False, f"拒絕執行：{detail}", path
    if verified is None and not allow_unverified:
        return False, (f"無法驗證簽章（{detail}）。檔案在 {path}，"
                       "請到 https://npcap.com 手動下載安裝。"), path
    ok, msg = launch_installer(path, popen=popen, check_platform=check_platform)
    if ok and verified:
        msg += f"（{detail}）"
    return ok, msg, path
