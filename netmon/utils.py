"""共用工具：格式化、權限檢查、本機 IP、hex dump。"""
from __future__ import annotations

import os
import socket
import sys

_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"]


def fmt_bytes(num: float, suffix: str = "") -> str:
    """把 byte 數格式化成人類可讀字串，例如 1536 -> '1.5 KB'。"""
    try:
        value = float(num)
    except (TypeError, ValueError):
        return "0 B"
    sign = "-" if value < 0 else ""
    value = abs(value)
    unit = _UNITS[0]
    for unit in _UNITS:
        if value < 1024.0:
            break
        value /= 1024.0
    if unit == "B":
        text = f"{value:.0f}"
    elif value >= 100:
        text = f"{value:.0f}"
    elif value >= 10:
        text = f"{value:.1f}"
    else:
        text = f"{value:.2f}"
    return f"{sign}{text} {unit}{suffix}"


def fmt_rate(bytes_per_sec: float) -> str:
    """格式化速率，例如 2048 -> '2.00 KB/s'。"""
    return fmt_bytes(bytes_per_sec) + "/s"


def fmt_count(num: float) -> str:
    """格式化封包數等計數：1234567 -> '1,234,567'。"""
    try:
        return f"{int(num):,}"
    except (TypeError, ValueError):
        return "0"


def fmt_time(timestamp: float) -> str:
    """Unix 時間戳 -> 'HH:MM:SS.mmm'。"""
    import time

    lt = time.localtime(timestamp)
    ms = int((timestamp - int(timestamp)) * 1000)
    return time.strftime("%H:%M:%S", lt) + f".{ms:03d}"


def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_admin() -> bool:
    """目前程序是否以系統管理員（Windows）/ root（Unix）身分執行。"""
    if is_windows():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def relaunch_as_admin() -> bool:
    """（僅 Windows）以系統管理員身分重新啟動本程式，成功回傳 True。"""
    if not is_windows():
        return False
    try:
        import ctypes

        exe = sys.executable
        # 若是被 PyInstaller 打包的 exe，sys.argv[0] 就是程式本體
        if getattr(sys, "frozen", False):
            params = " ".join(f'"{a}"' for a in sys.argv[1:])
            target = sys.argv[0]
        else:
            params = " ".join(f'"{a}"' for a in sys.argv)
            target = exe
        ret = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", target, params, None, 1
        )
        return ret > 32
    except Exception:
        return False


def check_npcap() -> tuple[bool, str]:
    """（僅 Windows）檢查 Npcap 是否已安裝，回傳 (是否可用, 說明)。"""
    if not is_windows():
        return True, "非 Windows 系統，不需要 Npcap"
    candidates = [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SysWOW64", "Npcap", "wpcap.dll"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wpcap.dll"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return True, f"已偵測 Npcap：{path}"
    return False, "找不到 Npcap（wpcap.dll），封包擷取需要先安裝：https://npcap.com"


def get_local_ips() -> set[str]:
    """取得本機所有 IPv4/IPv6 位址（用於判斷封包方向）。"""
    ips: set[str] = {"127.0.0.1", "::1"}
    try:
        import psutil

        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    # IPv6 可能帶 scope id（如 fe80::1%12），去掉
                    ips.add(addr.address.split("%")[0])
    except Exception:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                ips.add(info[4][0].split("%")[0])
        except Exception:
            pass
    return ips


def hexdump(data: bytes, width: int = 16, max_bytes: int = 4096) -> str:
    """產生類似 Wireshark 的 hex + ASCII 對照表。"""
    if not data:
        return "（無資料）"
    truncated = len(data) > max_bytes
    view = data[:max_bytes]
    lines: list[str] = []
    for offset in range(0, len(view), width):
        chunk = view[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part}  |{ascii_part}|")
    if truncated:
        lines.append(f"...（僅顯示前 {max_bytes} bytes，共 {len(data)} bytes）")
    return "\n".join(lines)
