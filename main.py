"""Win-NetMon 入口。

用法：
    python main.py            開啟 GUI（層級 1~5，建議以系統管理員身分執行）
    python main.py --check    環境診斷（psutil / Scapy / Npcap / pydivert / 管理員權限）
    python main.py --cli      命令列模式：列出連線清單並即時顯示網速（README 範例 1）
    python main.py --install-npcap  從官方 npcap.com 下載並啟動 Npcap 安裝（Windows）
"""
from __future__ import annotations

import argparse
import sys
import time


def _enable_dpi_awareness() -> None:
    """（Windows）在高 DPI 螢幕上讓 GUI 不要糊掉。"""
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
    except Exception:
        try:
            import ctypes

            ctypes.windll.user32.SetProcessDPIAware()  # type: ignore[attr-defined]
        except Exception:
            pass


def run_check() -> int:
    from netmon.utils import check_npcap, is_admin, is_windows

    print("=== Win-NetMon 環境診斷 ===")
    print(f"Python：{sys.version.split()[0]}（{sys.executable}）")
    print(f"作業系統：{'Windows' if is_windows() else sys.platform}")
    print(f"系統管理員身分：{'是' if is_admin() else '否（建議用 run_as_admin.bat 啟動）'}")

    overall_ok = True
    try:
        import psutil

        print(f"psutil：已安裝 v{psutil.__version__}（層級 1、2 可用）")
    except ImportError:
        overall_ok = False
        print("psutil：未安裝 → pip install psutil")

    try:
        import tkinter  # noqa: F401

        print("tkinter：可用（GUI 可開啟）")
    except ImportError:
        overall_ok = False
        print("tkinter：不可用（Windows 官方 Python 安裝檔有內建，安裝時請勾選 Tcl/Tk）")

    from netmon.capture import (
        SCAPY_AVAILABLE, SCAPY_ERROR, any_capture_availability, backend_availability,
        list_interfaces,
    )

    if SCAPY_AVAILABLE:
        print("Scapy：已安裝")
    else:
        print(f"Scapy：載入失敗（{SCAPY_ERROR}）→ pip install scapy")

    npcap_ok, npcap_msg = check_npcap()
    if is_windows():
        print(f"Npcap：{'已安裝' if npcap_ok else '未偵測到'} — {npcap_msg}")
        if not npcap_ok:
            print("  → 可執行 `python main.py --install-npcap`，或在 GUI「📦 封包擷取」頁"
                  "按一鍵安裝（從官方下載，Npcap 授權不允許我們直接打包它）")
    backs = backend_availability()
    for key, label in (("npcap", "Npcap 後端（Ethernet 完整擷取）"),
                       ("windivert", "WinDivert 後端（免 Npcap、IP 層）")):
        b_ok, b_msg = backs[key]
        print(f"  {label}：{'就緒' if b_ok else '不可用'} — {b_msg}")
    ok, msg = any_capture_availability()
    print(f"封包擷取（層級 3、4）：{'就緒' if ok else '不可用'} — {msg}")
    if not ok:
        print("  （不影響層級 1、2；裝 Npcap 或備妥 pydivert/WinDivert 並以管理員執行即可）")

    from netmon.divert_engine import divert_availability, pydivert_installed
    from netmon.win_firewall import firewall_availability

    print(f"pydivert/WinDivert：{'已安裝' if pydivert_installed() else '未安裝（層級 5 即時攔截）→ pip install pydivert'}")
    _ok, _msg = divert_availability()
    print(f"即時封包管制（層級 5a）：{'就緒' if _ok else '不可用'} — {_msg}")
    _ok, _msg = firewall_availability()
    print(f"系統防火牆封鎖（層級 5b）：{'就緒' if _ok else '不可用'} — {_msg}")

    if SCAPY_AVAILABLE:
        ifaces = list_interfaces()
        print(f"可擷取介面（{len(ifaces)} 個）：")
        for iface in ifaces:
            print(f"  - {iface['label']}")
    print("=== 診斷結束 ===" + ("" if overall_ok else "（有項目需要處理，請看上方提示）"))
    return 0 if overall_ok else 1


def run_install_npcap() -> int:
    """命令列版一鍵安裝：經使用者確認後，從官網下載、驗簽並啟動 Npcap 精靈。"""
    from netmon.npcap_install import NPCAP_LICENSE_NOTE, install_npcap
    from netmon.utils import check_npcap, fmt_bytes, is_windows

    if not is_windows():
        print("只有 Windows 需要 Npcap。")
        return 1
    ok, msg = check_npcap()
    if ok:
        print(f"Npcap 已安裝：{msg}，不需要再裝一次。")
        return 0
    print("將從官方網站 https://npcap.com 下載最新版 Npcap 安裝程式，")
    print("驗證數位簽章後啟動它的互動安裝精靈（免費版不支援靜默安裝，需手動按完）。")
    print(NPCAP_LICENSE_NOTE)
    try:
        answer = input("確定要下載並安裝嗎？ [y/N] ").strip().lower()
    except EOFError:
        answer = ""
    if answer not in ("y", "yes"):
        print("已取消。你也可以到 https://npcap.com 手動下載。")
        return 1

    def progress(downloaded: int, total: int) -> None:
        pct = f"{downloaded * 100 // total}%" if total else "-"
        print(f"\r下載中… {fmt_bytes(downloaded)} / {fmt_bytes(total) if total else '?'}（{pct}）",
              end="", flush=True)

    success, message, path = install_npcap(progress=progress)
    print()
    if not success:
        print(message)
        return 1
    print(message)
    return 0


def run_cli() -> int:
    import psutil

    from netmon.connections import get_connections
    from netmon.speed_monitor import SpeedMonitor
    from netmon.utils import fmt_bytes, fmt_rate

    print(f"{'程式':<26}{'PID':<8}{'協定':<6}{'本機位址':<24}{'遠端位址':<24}{'狀態'}")
    rows = [r for r in get_connections() if r.remote_ip]
    for rec in rows[:60]:
        print(f"{rec.process_name:<26}{(rec.pid or ''):<8}{rec.protocol:<6}"
              f"{rec.local:<24}{rec.remote:<24}{rec.status}")
    if len(rows) > 60:
        print(f"...（共 {len(rows)} 條，僅顯示前 60 條）")

    print("\n即時網速（Ctrl+C 結束）：")
    mon = SpeedMonitor()
    try:
        while True:
            time.sleep(1)
            s = mon.sample()
            print(f"\r↑ {fmt_rate(s.up_rate):>12}   ↓ {fmt_rate(s.down_rate):>12}   "
                  f"(累計 ↑{fmt_bytes(s.total_sent)} ↓{fmt_bytes(s.total_recv)})   ",
                  end="", flush=True)
    except KeyboardInterrupt:
        print("\n結束。")
    _ = psutil  # 避免未使用警告（診斷友善）
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Win-NetMon：Windows 網路流量監測/管制（層級 1~5）")
    parser.add_argument("--check", action="store_true", help="環境診斷後結束")
    parser.add_argument("--cli", action="store_true", help="命令列模式（不開 GUI）")
    parser.add_argument("--install-npcap", action="store_true",
                        help="從官方 npcap.com 下載並啟動 Npcap 安裝（僅 Windows）")
    args = parser.parse_args(argv)

    if args.check:
        return run_check()
    if args.cli:
        return run_cli()
    if args.install_npcap:
        return run_install_npcap()

    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("錯誤：找不到 tkinter，無法開啟 GUI。\n"
              "Windows：請用 python.org 官方安裝檔並勾選 Tcl/Tk；或先以命令列模式執行：python main.py --cli")
        return 1

    _enable_dpi_awareness()
    from netmon.gui.app import run

    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
