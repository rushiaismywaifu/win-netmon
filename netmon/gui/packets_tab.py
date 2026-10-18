"""層級 4 分頁：封包擷取與解析（Npcap 完整後端 / WinDivert 免 Npcap 後端）。

功能：介面選擇、BPF 過濾、即時封包列表（協定著色）、逐層解析、
Hex dump、Payload 預覽、TLS SNI / DNS 摘要、存取 .pcap、協定分佈統計。
HTTPS 內容為加密的，只能看到 IP、埠、網域（SNI）與大小（同 Wireshark 未解密時）。
"""
from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from ..capture import PacketRecord, backend_availability, list_interfaces
from ..npcap_install import (
    NPCAP_LICENSE_NOTE, download_installer, launch_installer, verify_authenticode,
)
from ..utils import check_npcap, fmt_bytes, fmt_count, fmt_time, hexdump, is_windows
from . import theme
from .widgets import copy_text, make_tree

MAX_RECORDS = 10000

BPF_PRESETS = {
    "全部封包": "",
    "HTTPS（tcp 443）": "tcp port 443",
    "HTTP（tcp 80）": "tcp port 80",
    "DNS（udp 53）": "udp port 53",
    "ICMP（ping）": "icmp",
    "ARP": "arp",
    "指定主機 host 8.8.8.8": "host 8.8.8.8",
}

# WinDivert 過濾語法預設（IP 層；沒有 ARP/Ethernet 類別）
WD_PRESETS = {
    "全部封包": "",
    "HTTPS（tcp 443）": "tcp.DstPort == 443 or tcp.SrcPort == 443",
    "HTTP（tcp 80）": "tcp.DstPort == 80 or tcp.SrcPort == 80",
    "DNS（udp 53）": "udp.DstPort == 53 or udp.SrcPort == 53",
    "ICMP（ping）": "icmp",
    "只看上傳（outbound）": "outbound",
    "只看下載（inbound）": "inbound",
    "指定主機 8.8.8.8": "ip.DstAddr == 8.8.8.8 or ip.SrcAddr == 8.8.8.8",
}

BACKEND_OPTIONS = {
    "自動選擇": "auto",
    "Npcap（完整）": "npcap",
    "WinDivert（免 Npcap）": "windivert",
}

_BACKEND_HINTS = {
    "auto": "Npcap 優先；沒裝 Npcap 自動改用 WinDivert（常見 BPF 會自動轉譯）",
    "npcap": "Ethernet 完整擷取（含 ARP/MAC、可選介面）",
    "windivert": "所有介面一次看（IP 層，無 Ethernet/ARP）",
}


class PacketsTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        fonts = app.fonts
        self._records: list[PacketRecord] = []
        self._by_iid: dict[str, PacketRecord] = {}   # 樹上列 iid -> 紀錄（選取查找 O(1)）
        self._proto_counts: dict[str, int] = {}
        self._ifaces: list[dict] = []
        self._last_stat = (time.time(), 0)  # (時間, 封包數) 用於估算 pps

        # ---------- 可用性提示 ----------
        backs = backend_availability()
        npc_ok, npc_msg = backs["npcap"]
        wd_ok, wd_msg = backs["windivert"]
        ok = npc_ok or wd_ok
        self._available = ok
        self._running_ui = False
        self.avail_label = ttk.Label(self, text="", style="Muted.TLabel")
        if not ok:
            self.avail_label.config(
                text=f"⚠ 封包擷取目前不可用：Npcap 路徑（{npc_msg}）；WinDivert 路徑（{wd_msg}）\n"
                     "層級 1（網速）與層級 2（連線清單）仍可正常使用；層級 3 需要層級 4 的封包來歸屬流量。",
                foreground=theme.YELLOW)
            self.avail_label.pack(anchor="w", padx=12, pady=(8, 0))
        elif not npc_ok and wd_ok:
            self.avail_label.config(
                text="ℹ 未偵測到 Npcap，將用免 Npcap 的 WinDivert 後端擷取 IP 層封包"
                     "（DNS/TLS 網域/程式歸屬照常，但沒有 Ethernet/ARP）。"
                     "想要完整擷取可用下方一鍵安裝 Npcap。")
            self.avail_label.pack(anchor="w", padx=12, pady=(8, 0))

        # Npcap 一鍵安裝（只在 Windows 且偵測不到 Npcap 時顯示；widget 一律先建好方便測試）
        self._npcap_busy = False
        npcap_row = ttk.Frame(self)
        self.npcap_btn = ttk.Button(
            npcap_row, text="⬇ 一鍵下載並安裝 Npcap（官方 npcap.com）",
            style="Accent.TButton", command=self._install_npcap_clicked)
        self.npcap_btn.pack(side="left")
        self.npcap_status = ttk.Label(
            npcap_row,
            text="從官方下載並安裝 Npcap（需同意授權，免費版為互動安裝）。"
                 "未安裝仍可用 WinDivert 後端；詳細說明見「📖 幫助」。",
            style="Muted.TLabel")
        self.npcap_status.pack(side="left", padx=8)
        self._npcap_missing = bool(is_windows() and not check_npcap()[0])
        if self._npcap_missing:
            npcap_row.pack(anchor="w", padx=12, pady=(4, 0))

        # ---------- 工具列 1：擷取控制 ----------
        bar1 = ttk.Frame(self)
        bar1.pack(fill="x", padx=10, pady=(8, 2))
        ttk.Label(bar1, text="介面：").pack(side="left")
        self.iface_var = tk.StringVar(value="所有介面")
        self.iface_box = ttk.Combobox(bar1, textvariable=self.iface_var, width=34,
                                      values=["所有介面"], state="readonly")
        self.iface_box.pack(side="left", padx=4)

        self.filter_label = ttk.Label(bar1, text="BPF 過濾：")
        self.filter_label.pack(side="left", padx=(10, 0))
        self.preset_var = tk.StringVar(value="全部封包")
        self.preset_box = ttk.Combobox(bar1, textvariable=self.preset_var, width=20,
                                       values=list(BPF_PRESETS), state="readonly")
        self.preset_box.pack(side="left", padx=4)
        self.preset_box.bind("<<ComboboxSelected>>", self._apply_preset)
        self.bpf_var = tk.StringVar()
        self.bpf_entry = ttk.Entry(bar1, textvariable=self.bpf_var, width=28)
        self.bpf_entry.pack(side="left", padx=4)

        self.capture_btn = ttk.Button(bar1, text="▶ 開始擷取", style="Accent.TButton",
                                      command=self._toggle_capture)
        self.capture_btn.pack(side="left", padx=(10, 4))
        if not ok:
            self.capture_btn.config(state="disabled")
        ttk.Button(bar1, text="清除", command=self.clear).pack(side="left", padx=4)
        ttk.Button(bar1, text="儲存 pcap", command=self._save_pcap).pack(side="left", padx=4)
        ttk.Button(bar1, text="開啟 pcap", command=self._load_pcap).pack(side="left")

        # ---------- 工具列 2：顯示控制 ----------
        bar2 = ttk.Frame(self)
        bar2.pack(fill="x", padx=10, pady=2)
        ttk.Label(bar2, text="擷取後端：").pack(side="left")
        self.backend_var = tk.StringVar(value="自動選擇")
        self.backend_box = ttk.Combobox(bar2, textvariable=self.backend_var, width=22,
                                        values=list(BACKEND_OPTIONS), state="readonly")
        self.backend_box.pack(side="left", padx=4)
        self.backend_box.bind("<<ComboboxSelected>>", self._on_backend_changed)
        self.backend_hint = ttk.Label(bar2, text=_BACKEND_HINTS["auto"], style="Muted.TLabel")
        self.backend_hint.pack(side="left", padx=(2, 12))
        ttk.Label(bar2, text="顯示篩選：").pack(side="left")
        self.display_filter_var = tk.StringVar()
        filter_entry = ttk.Entry(bar2, textvariable=self.display_filter_var, width=30)
        filter_entry.pack(side="left", padx=4)
        filter_entry.bind("<Return>", lambda _e: self._rebuild())
        ttk.Button(bar2, text="套用", command=self._rebuild).pack(side="left", padx=2)
        self.autoscroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar2, text="自動捲動", variable=self.autoscroll_var).pack(side="left", padx=(10, 0))
        self.pause_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar2, text="暫停顯示（仍續抓）", variable=self.pause_var,
                        command=self._on_pause_toggled).pack(side="left", padx=4)
        self.stats_label = ttk.Label(bar2, text="", style="Muted.TLabel")
        self.stats_label.pack(side="right")

        # ---------- 主區域：上=封包列表、下=解析 ----------
        paned = ttk.Panedwindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        list_frame = ttk.Frame(paned)
        self.tree = make_tree(list_frame, [
            ("no", "No.", 64, "e"),
            ("time", "時間", 110, "w"),
            ("dir", "方向", 50, "center"),
            ("src", "來源", 200, "w"),
            ("dst", "目的", 200, "w"),
            ("proto", "協定", 84, "center"),
            ("len", "長度", 70, "e"),
            ("proc", "程式", 150, "w"),
            ("info", "資訊", 460, "w"),
        ], height=14)
        for proto, color in theme.PROTO_TAG_COLORS.items():
            self.tree.tag_configure(f"proto_{proto}", foreground=color)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._on_select())
        self.tree.bind("<Button-3>", self._context_menu)
        paned.add(list_frame, weight=3)

        detail_outer = ttk.Frame(paned)
        self.summary_label = ttk.Label(detail_outer, text="點選上方任一封包，這裡會顯示逐層解析與 Hex dump。",
                                       style="Muted.TLabel")
        self.summary_label.pack(anchor="w", pady=(2, 4))
        detail_paned = ttk.Panedwindow(detail_outer, orient="horizontal")
        detail_paned.pack(fill="both", expand=True)

        left = ttk.Labelframe(detail_paned, text="逐層解析（Packet Dissection）")
        self.dissect_text = scrolledtext.ScrolledText(
            left, font=fonts["mono"], bg=theme.PANEL, fg=theme.TEXT,
            insertbackground=theme.TEXT, wrap="none", height=10,
            selectbackground=theme.SELECT)
        self.dissect_text.pack(fill="both", expand=True, padx=4, pady=4)
        detail_paned.add(left, weight=1)

        right = ttk.Labelframe(detail_paned, text="原始位元組（Hex Dump）")
        self.hex_text = scrolledtext.ScrolledText(
            right, font=fonts["mono"], bg=theme.PANEL, fg=theme.TEXT,
            insertbackground=theme.TEXT, wrap="none", height=10,
            selectbackground=theme.SELECT)
        self.hex_text.pack(fill="both", expand=True, padx=4, pady=4)
        detail_paned.add(right, weight=1)
        paned.add(detail_outer, weight=2)

        self._menu = tk.Menu(self, tearoff=0, bg=theme.PANEL_ALT, fg=theme.TEXT,
                             activebackground=theme.SELECT, activeforeground="#ffffff")
        self._menu.add_command(label="複製來源 IP", command=lambda: self._copy("src"))
        self._menu.add_command(label="複製目的 IP", command=lambda: self._copy("dst"))
        self._menu.add_command(label="複製整行摘要", command=lambda: self._copy("line"))
        self._menu.add_separator()
        self._menu.add_command(label="🚫 對遠端 IP 建封鎖（系統防火牆）", command=self._block_remote_firewall)
        self._menu.add_command(label="⚡ 對遠端建即時攔截規則（WinDivert）", command=self._block_remote_divert)

        self.after(50, self._load_interfaces_async)

    # ------------------------------------------------------------- 介面
    # ------------------------------------------------------------- Npcap 一鍵安裝
    def _install_npcap_clicked(self) -> None:
        if self._npcap_busy:
            return
        if not messagebox.askyesno(
                "下載並安裝 Npcap",
                "將從官方網站 https://npcap.com 下載最新版安裝程式，"
                "驗證數位簽章後啟動它的安裝精靈（需要你手動按完，免費版不支援靜默安裝）。\n\n"
                + NPCAP_LICENSE_NOTE + "\n\n確定要下載並安裝嗎？", parent=self):
            return
        self._npcap_busy = True
        self.npcap_btn.config(state="disabled")
        self.npcap_status.config(text="正在查詢官網最新版本…")
        pct_state = {"pct": -1}

        def progress(downloaded: int, total: int) -> None:
            pct = int(downloaded * 100 / total) if total else 0
            if abs(pct - pct_state["pct"]) >= 5 or downloaded == total:
                pct_state["pct"] = pct
                text = (f"下載中… {fmt_bytes(downloaded)} / {fmt_bytes(total)}（{pct}%）"
                        if total else f"下載中… {fmt_bytes(downloaded)}")
                self.app.call_in_ui(lambda t=text: self.npcap_status.config(text=t))

        def worker() -> None:
            try:
                path = download_installer(progress=progress)
            except Exception as exc:  # noqa: BLE001
                self.app.call_in_ui(lambda e=exc: self._npcap_failed(str(e)))
                return
            verified, detail = verify_authenticode(path)
            self.app.call_in_ui(lambda: self._npcap_download_done(path, verified, detail))

        threading.Thread(target=worker, daemon=True).start()

    def _npcap_failed(self, message: str) -> None:
        self._npcap_busy = False
        self.npcap_btn.config(state="normal")
        self.npcap_status.config(text=f"下載失敗：{message}（也可到 https://npcap.com 手動安裝）")
        messagebox.showerror("Npcap 下載失敗", message + "\n\n你也可以到 https://npcap.com 手動下載安裝。",
                             parent=self)

    def _npcap_download_done(self, path, verified, detail: str) -> None:
        self._npcap_busy = False
        self.npcap_btn.config(state="normal")
        if verified is False:
            self.npcap_status.config(text=f"已拒絕執行（{detail}），檔案保留在：{path}")
            messagebox.showerror("簽章驗證失敗", f"拒絕執行這個檔案：{detail}\n\n檔案位置：{path}",
                                 parent=self)
            return
        if verified is None:
            if not messagebox.askyesno(
                    "無法驗證數位簽章",
                    f"{detail}。\n\n檔案已由 https://npcap.com（官方 TLS 網站）下載至：\n{path}\n\n"
                    "仍要執行這個安裝程式嗎？", parent=self):
                self.npcap_status.config(text=f"已下載但未執行：{path}（可自行檢查後手動安裝）")
                return
        ok, msg = launch_installer(path)
        if ok:
            self.npcap_status.config(text=msg)
            self.app.set_status(msg)
            messagebox.showinfo("Npcap 安裝", msg, parent=self)
        else:
            self._npcap_failed(msg)

    def _load_interfaces_async(self) -> None:
        def worker():
            ifaces = list_interfaces()
            self.app.call_in_ui(lambda: self._apply_interfaces(ifaces))
        threading.Thread(target=worker, daemon=True).start()

    def _apply_interfaces(self, ifaces: list[dict]) -> None:
        self._ifaces = ifaces
        labels = ["所有介面"] + [i["label"] for i in ifaces]
        self.iface_box.config(values=labels)
        # 預設選第一個有 IPv4 又不是 loopback 的介面，擷取品質最好
        for iface in ifaces:
            ip = iface.get("ip") or ""
            if ip and ip != "0.0.0.0" and not ip.startswith("127."):
                self.iface_var.set(iface["label"])
                break

    def selected_iface(self) -> str | None:
        label = self.iface_var.get()
        if label == "所有介面":
            return None
        for iface in self._ifaces:
            if iface["label"] == label:
                return iface["name"]
        return None

    # ------------------------------------------------------------- 擷取控制
    def selected_backend(self) -> str:
        return BACKEND_OPTIONS.get(self.backend_var.get(), "auto")

    def _active_presets(self) -> dict:
        return WD_PRESETS if self.selected_backend() == "windivert" else BPF_PRESETS

    def _on_backend_changed(self, _event=None) -> None:
        backend = self.selected_backend()
        windivert = backend == "windivert"
        self.filter_label.config(text="WinDivert 過濾：" if windivert else "BPF 過濾：")
        self.preset_box.config(values=list(self._active_presets()))
        self.preset_var.set("全部封包")
        self.bpf_var.set("")
        self.backend_hint.config(text=_BACKEND_HINTS.get(backend, ""))
        if not self._running_ui:
            # WinDivert 擷取所有介面，介面選單不適用
            self.iface_box.config(state="disabled" if windivert else "readonly")

    def capture_request(self) -> dict:
        """組出 CaptureEngine.start() 的參數（依後端決定過濾欄位的語法）。"""
        backend = self.selected_backend()
        text = self.bpf_var.get().strip()
        if backend == "windivert":
            return {"iface": None, "bpf_filter": "", "backend": "windivert",
                    "divert_filter": text}
        return {"iface": self.selected_iface(), "bpf_filter": text, "backend": backend}

    def _apply_preset(self, _event=None) -> None:
        self.bpf_var.set(self._active_presets().get(self.preset_var.get(), ""))

    def _toggle_capture(self) -> None:
        self.app.toggle_capture()

    def set_capturing_ui(self, running: bool, starting: bool = False) -> None:
        """更新擷取相關控項狀態。

        starting=True 表示後端正在背景緒程開啟（不凍結 GUI），
        此時把按鈕鎖住避免重複點擊，其他設定項也比照「擷取中」不可改。
        """
        self._running_ui = running or starting
        if starting:
            self.capture_btn.config(text="⏳ 正在啟動…", state="disabled")
        elif running:
            self.capture_btn.config(text="⏹ 停止擷取", style="Danger.TButton", state="normal")
        else:
            self.capture_btn.config(text="▶ 開始擷取", style="Accent.TButton",
                                    state="normal" if self._available else "disabled")
        self.backend_box.config(state="disabled" if self._running_ui else "readonly")
        if self._running_ui or self.selected_backend() == "windivert":
            self.iface_box.config(state="disabled")
        else:
            self.iface_box.config(state="readonly")
        self.bpf_entry.config(state="disabled" if self._running_ui else "normal")

    # ------------------------------------------------------------- 資料
    def _matches(self, rec: PacketRecord, keyword: str | None = None) -> bool:
        if keyword is None:
            keyword = self.display_filter_var.get().strip().lower()
        if not keyword:
            return True
        haystack = (f"{rec.src_endpoint} {rec.dst_endpoint} {rec.protocol} "
                    f"{rec.info} {rec.process_name}").lower()
        return keyword in haystack

    def add_records(self, batch: list[PacketRecord]) -> None:
        """把一批新封包加進列表（GUI 主緒程每 200ms 呼叫）。

        高流量下這是熱路徑：超過上限時只「刪掉最舊的幾列」而不是整表重建，
        且整批只查一次顯示篩選字串（每次 .get() 都是一趟 Tcl 呼叫）。
        """
        if not batch:
            return
        for rec in batch:
            self._proto_counts[rec.protocol] = self._proto_counts.get(rec.protocol, 0) + 1
        prev_len = len(self._records)
        self._records.extend(batch)
        # 超過上限：丟棄最舊的紀錄，並只刪除它們對應的表格列（增量，不重建整表）
        excess = len(self._records) - MAX_RECORDS
        first_kept = 0
        if excess > 0:
            for rec in self._records[:excess]:
                self._remove_row(rec)
            del self._records[:excess]
            # 這批自己也可能「還沒顯示就被裁掉」，那些也不必插入
            first_kept = max(excess - prev_len, 0)
        if self.pause_var.get():
            return
        keyword = self.display_filter_var.get().strip().lower()
        last_iid = None
        for rec in batch[first_kept:]:
            if self._matches(rec, keyword):
                last_iid = self._insert(rec)
        if last_iid and self.autoscroll_var.get():
            self.tree.see(last_iid)

    def _remove_row(self, rec: PacketRecord) -> None:
        """移除單一紀錄的表格列（若它有顯示在樹上）。"""
        iid = getattr(rec, "_iid", "")
        if iid and self._by_iid.get(iid) is rec:
            del self._by_iid[iid]
            try:
                self.tree.delete(iid)
            except tk.TclError:
                pass

    def _insert(self, rec: PacketRecord) -> str:
        iid = f"r{rec.index}_{id(rec) % 100000}"
        rec._iid = iid  # type: ignore[attr-defined]
        self._by_iid[iid] = rec
        tag = f"proto_{rec.protocol}"
        return self.tree.insert("", "end", iid=iid, tags=(tag,), values=(
            rec.index, fmt_time(rec.timestamp), rec.direction_arrow,
            rec.src_endpoint, rec.dst_endpoint, rec.protocol, rec.length,
            rec.process_name, rec.info,
        ))

    def _rebuild(self) -> None:
        keyword = self.display_filter_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        self._by_iid.clear()
        last_iid = None
        for rec in self._records:
            if self._matches(rec, keyword):
                last_iid = self._insert(rec)
        if last_iid and self.autoscroll_var.get():
            self.tree.see(last_iid)

    def clear(self) -> None:
        self._records.clear()
        self._by_iid.clear()
        self._proto_counts.clear()
        self.tree.delete(*self.tree.get_children())
        self._set_detail("點選上方任一封包，這裡會顯示逐層解析與 Hex dump。", "", "")
        self.app.on_packets_cleared()

    def _on_pause_toggled(self) -> None:
        if not self.pause_var.get():
            self._rebuild()

    # ------------------------------------------------------------- 詳細
    def _record_from_iid(self, iid: str) -> PacketRecord | None:
        return self._by_iid.get(iid)

    def _current_record(self) -> PacketRecord | None:
        sel = self.tree.selection()
        return self._record_from_iid(sel[0]) if sel else None

    def _on_select(self) -> None:
        rec = self._current_record()
        if rec is None:
            return
        summary = (f"No.{rec.index}｜{fmt_time(rec.timestamp)}｜"
                   f"{rec.src_endpoint} → {rec.dst_endpoint}｜{rec.protocol}｜"
                   f"{rec.length} bytes｜程式：{rec.process_name}"
                   + (f"（PID {rec.pid}）" if rec.pid else "") +
                   f"｜{rec.info}")
        dissect = rec.dissect()
        if rec.payload:
            dissect += "\n" + self._payload_preview(rec)
        self._set_detail(summary, dissect, hexdump(rec.raw or rec.payload))

    @staticmethod
    def _payload_preview(rec: PacketRecord) -> str:
        payload = rec.payload
        text = payload[:1500].decode("utf-8", errors="replace")
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        header = "---- Payload 預覽 ----"
        if text and printable / max(len(text), 1) > 0.8:
            return f"{header}\n{text}"
        return (f"{header}\n（二進位或已加密資料，共 {len(payload)} bytes，"
                "請見右側 Hex Dump；TLS/HTTPS 加密看不到明文是正常的。）")

    def _set_detail(self, summary: str, dissect: str, hex_text: str) -> None:
        self.summary_label.config(text=summary)
        for widget, content in ((self.dissect_text, dissect), (self.hex_text, hex_text)):
            widget.delete("1.0", "end")
            widget.insert("1.0", content)
            widget.see("1.0")

    # ------------------------------------------------------------- 統計/選單
    def update_stats(self, running: bool, total_packets: int, total_bytes: int,
                     elapsed: float, backend: str = "", starting: bool = False) -> None:
        now = time.time()
        last_t, last_n = self._last_stat
        pps = (total_packets - last_n) / max(now - last_t, 0.001) if running else 0.0
        self._last_stat = (now, total_packets)
        top = sorted(self._proto_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
        proto_text = "、".join(f"{k} {v:,}" for k, v in top) or "尚無封包"
        names = {"npcap": "Npcap", "windivert": "WinDivert・IP 層"}
        if starting:
            state = "⏳ 正在啟動擷取後端…"
        elif running:
            state = f"● 擷取中（{names.get(backend, backend)}）"
        else:
            state = "已停止"
        self.stats_label.config(
            text=f"{state}｜已擷取 {fmt_count(total_packets)} 封包 / {fmt_bytes(total_bytes)}"
                 f"｜{pps:.0f} pps｜顯示 {len(self._by_iid):,} 筆｜協定：{proto_text}")

    def _context_menu(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self._on_select()
            self._menu.tk_popup(event.x_root, event.y_root)

    # ---------- 層級 5 帶入（只填表單，不會直接封鎖） ----------
    def _remote_of(self, rec):
        if rec.direction == "out":
            return rec.dst, rec.dst_port
        return rec.src, rec.src_port

    def _block_remote_firewall(self) -> None:
        rec = self._current_record()
        if rec is None:
            return
        ip, _port = self._remote_of(rec)
        if ip:
            self.app.request_block_remote_ip(ip)

    def _block_remote_divert(self) -> None:
        rec = self._current_record()
        if rec is None:
            return
        ip, port = self._remote_of(rec)
        process = "" if rec.process_name.startswith("(") else rec.process_name
        if ip:
            self.app.request_intercept_rule(remote_ip=ip,
                                            remote_port=str(port or ""),
                                            process_name=process)

    def _copy(self, what: str) -> None:
        rec = self._current_record()
        if rec is None:
            return
        if what == "src":
            copy_text(self, rec.src)
        elif what == "dst":
            copy_text(self, rec.dst)
        else:
            copy_text(self, f"{rec.index} {fmt_time(rec.timestamp)} {rec.src_endpoint} -> "
                            f"{rec.dst_endpoint} {rec.protocol} {rec.length} {rec.info}")

    # ------------------------------------------------------------- pcap
    def _save_pcap(self) -> None:
        if not self._records:
            messagebox.showinfo("儲存 pcap", "目前沒有封包可以儲存。", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".pcap", initialfile="capture.pcap",
            filetypes=(("pcap 檔", "*.pcap"), ("所有檔案", "*.*")))
        if not path:
            return
        records = list(self._records)
        engine = self.app.capture_engine

        def worker():
            try:
                count = engine.save_pcap(path, records)
                self.app.call_in_ui(lambda: messagebox.showinfo(
                    "儲存完成", f"已寫入 {count:,} 個封包：\n{path}\n（可用 Wireshark 開啟）",
                    parent=self))
            except Exception as exc:  # noqa: BLE001 - 顯示給使用者
                self.app.call_in_ui(lambda exc=exc: messagebox.showerror(
                    "儲存失敗", str(exc), parent=self))
        threading.Thread(target=worker, daemon=True).start()

    def _load_pcap(self) -> None:
        path = filedialog.askopenfilename(
            parent=self, filetypes=(("pcap 檔", "*.pcap *.pcapng *.cap"),
                                    ("所有檔案", "*.*")))
        if not path:
            return
        engine = self.app.capture_engine

        def worker():
            try:
                records = engine.load_pcap(path)
                self.app.call_in_ui(lambda: self._loaded(records, path))
            except Exception as exc:  # noqa: BLE001
                self.app.call_in_ui(lambda exc=exc: messagebox.showerror(
                    "讀取失敗", str(exc), parent=self))
        threading.Thread(target=worker, daemon=True).start()

    def _loaded(self, records: list[PacketRecord], path: str) -> None:
        self.add_records(records)
        messagebox.showinfo("讀取完成", f"已載入 {len(records):,} 個封包：\n{path}", parent=self)
