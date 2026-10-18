"""主視窗：把層級 1～5 串起來。

排程模型（全部在 GUI 主緒程用 after() 輪詢，封包擷取在背景緒程）：
  - 每 200ms：排空封包佇列 -> 歸屬到層級 3 統計、加入層級 4 列表
  - 每 1 秒：層級 1 網速取樣、層級 3 排行刷新、封包統計
  - 每 2 秒：層級 2 連線表刷新（背景緒程抓取），同時更新層級 3 的連線索引
"""
from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

from .. import __app_name__, __version__
from ..capture import CaptureEngine, PacketRecord, capture_availability
from ..connections import get_connections
from ..divert_engine import DivertEngine, divert_availability
from ..rule_engine import RuleEngine, build_divert_filter
from ..rule_store import RuleStore
from ..speed_monitor import SpeedMonitor
from ..traffic import ConnectionIndex, TrafficAggregator
from ..win_firewall import FirewallManager, resolve_program_path
from ..utils import fmt_rate, is_admin, is_windows, relaunch_as_admin
from . import theme
from .connections_tab import ConnectionsTab
from .dashboard_tab import DashboardTab
from .firewall_tab import FirewallTab
from .packets_tab import PacketsTab
from .processes_tab import ProcessesTab

DRAIN_MS = 200
TICK_MS = 1000


class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{__app_name__} — Windows 網路流量監測（層級 1~5）")
        self.geometry("1280x840")
        self.minsize(1024, 640)
        self.configure(bg=theme.BG)

        self.fonts = theme.pick_fonts(self)
        theme.apply_theme(self, self.fonts)

        # ---------- 共用核心 ----------
        self.speed_monitor = SpeedMonitor()
        self.conn_index = ConnectionIndex()
        self.aggregator = TrafficAggregator()
        self.capture_engine = CaptureEngine(self.conn_index)
        # 層級 5 核心：規則檔（持久化到 %APPDATA%/Win-NetMon/rules.json）、
        # 規則引擎、WinDivert 攔截引擎、WFP 防火牆管理器
        self.rule_store = RuleStore()
        self.rule_store.load()
        self.rule_engine = RuleEngine(list(self.rule_store.intercept_rules))
        self.divert_engine = DivertEngine(self.rule_engine, self.conn_index)
        self.firewall_manager = FirewallManager()
        self._packet_queue: queue.Queue[PacketRecord] = queue.Queue(maxsize=50000)
        self.capture_engine.on_packet = self._enqueue_packet
        # 背景緒程要回主緒程更新 GUI 時一律走這個佇列（tkinter 非 thread-safe，
        # 不能從其他緒程直接呼叫 widget/after）
        self._ui_queue: queue.Queue = queue.Queue()
        self._last_connections: list = []
        self._conn_counts: dict[int, int] = {}
        self._conn_thread_running = False
        self._tick_count = 0
        self._closing = False

        # ---------- 介面 ----------
        self._build_header()
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)
        self.notebook = notebook
        self.dashboard_tab = DashboardTab(notebook, self)
        self.connections_tab = ConnectionsTab(notebook, self)
        self.processes_tab = ProcessesTab(notebook, self)
        self.packets_tab = PacketsTab(notebook, self)
        self.firewall_tab = FirewallTab(notebook, self)
        notebook.add(self.dashboard_tab, text="📊 總覽（層級 1）")
        notebook.add(self.connections_tab, text="🔌 連線清單（層級 2）")
        notebook.add(self.processes_tab, text="🏆 程式流量（層級 3）")
        notebook.add(self.packets_tab, text="📦 封包擷取（層級 4）")
        notebook.add(self.firewall_tab, text="🛡 封鎖/管制（層級 5）")
        self._build_statusbar()
        if self.rule_store.load_error:
            self.set_status(self.rule_store.load_error)
        fw_count = len(self.rule_store.firewall_rules)
        if fw_count:
            self.set_status(f"提醒：你有 {fw_count} 條由本程式寫入的系統防火牆封鎖仍在生效中，"
                            "可在「🛡 封鎖/管制（層級 5）」的系統防火牆子分頁管理或清除。")

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(300, lambda: self.refresh_connections(manual=True))
        self.after(DRAIN_MS, self._drain_loop)
        self.after(TICK_MS, self._tick_loop)

    # ------------------------------------------------------------- 介面組件
    def _build_header(self) -> None:
        header = tk.Frame(self, bg=theme.HEADER)
        header.pack(fill="x")
        left = tk.Frame(header, bg=theme.HEADER)
        left.pack(side="left", padx=14, pady=8)
        tk.Label(left, text="🌐 Win-NetMon", bg=theme.HEADER, fg="#ffffff",
                 font=self.fonts["title"]).pack(anchor="w")
        tk.Label(left, text="整體網速 → 連線清單 → 每程式流量 → 封包解析 → 封鎖/限速",
                 bg=theme.HEADER, fg=theme.MUTED, font=self.fonts["ui_small"]).pack(anchor="w")

        chips = tk.Frame(header, bg=theme.HEADER)
        chips.pack(side="left", expand=True)
        self.chip_down = self._make_chip(chips, "↓ --", theme.DOWN_COLOR)
        self.chip_up = self._make_chip(chips, "↑ --", theme.UP_COLOR)
        self.chip_down.pack(side="left", padx=6)
        self.chip_up.pack(side="left", padx=6)

        right = tk.Frame(header, bg=theme.HEADER)
        right.pack(side="right", padx=14, pady=8)
        admin = is_admin()
        badge_text = "🛡 系統管理員" if admin else "👤 一般使用者"
        badge_color = theme.GREEN if admin else theme.YELLOW
        tk.Label(right, text=badge_text, bg=theme.HEADER, fg=badge_color,
                 font=self.fonts["ui_bold"]).pack(anchor="e")
        avail_ok, _msg = capture_availability()
        self.capture_badge = tk.Label(
            right,
            text="封包擷取：未啟動" if avail_ok else "封包擷取：不可用（缺 Scapy/Npcap）",
            bg=theme.HEADER, fg=theme.MUTED if avail_ok else theme.RED,
            font=self.fonts["ui_small"])
        self.capture_badge.pack(anchor="e")
        divert_ok, _dmsg = divert_availability()
        self.divert_badge = tk.Label(
            right,
            text="封包管制（層級 5）：未啟動" if divert_ok else "封包管制（層級 5）：WinDivert 未就緒",
            bg=theme.HEADER, fg=theme.MUTED if divert_ok else theme.RED,
            font=self.fonts["ui_small"])
        self.divert_badge.pack(anchor="e")
        if is_windows() and not admin:
            ttk.Button(right, text="以系統管理員身分重新啟動",
                       command=self._relaunch).pack(anchor="e", pady=(4, 0))

        if is_windows() and not admin:
            banner = tk.Label(
                self,
                text="⚠ 目前不是以系統管理員身分執行：可能看不到全部程式的連線、也無法擷取封包。建議用 run_as_admin.bat 啟動。",
                bg="#3a2f14", fg=theme.YELLOW, font=self.fonts["ui_small"],
                anchor="w", padx=12, pady=4)
            banner.pack(fill="x")

    @staticmethod
    def _make_chip(parent, text: str, color: str) -> tk.Label:
        return tk.Label(parent, text=text, bg=theme.PANEL_ALT, fg=color,
                        font=("Consolas", 11, "bold"), padx=12, pady=6)

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self, bg=theme.HEADER)
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(
            value="就緒：層級 1–2 已自動運作；層級 3/4 用「📦 封包擷取」開始擷取；層級 5「🛡 封鎖/管制」可封鎖與限速（需管理員）。僅用於自己的電腦。")
        tk.Label(bar, textvariable=self.status_var, bg=theme.HEADER, fg=theme.MUTED,
                 font=self.fonts["ui_small"], anchor="w").pack(side="left", padx=12, pady=4)
        tk.Label(bar, text=f"v{__version__}", bg=theme.HEADER, fg=theme.MUTED,
                 font=self.fonts["ui_small"]).pack(side="right", padx=12)

    def set_status(self, text: str) -> None:
        self.status_var.set(text)

    # ------------------------------------------------------------- 排程
    def call_in_ui(self, fn) -> None:
        """供背景緒程使用：把函式排入佇列，由 GUI 主緒程執行。"""
        self._ui_queue.put(fn)

    def _enqueue_packet(self, rec: PacketRecord) -> None:
        try:
            self._packet_queue.put_nowait(rec)
        except queue.Full:
            pass  # 佇列爆滿時丟棄以保護擷取緒程（極高速流量才會發生）

    def _drain_loop(self) -> None:
        if self._closing:
            return
        # 先處理背景緒程排入的 UI 工作
        try:
            while True:
                fn = self._ui_queue.get_nowait()
                try:
                    fn()
                except Exception:
                    pass
        except queue.Empty:
            pass
        batch: list[PacketRecord] = []
        try:
            while len(batch) < 4000:
                batch.append(self._packet_queue.get_nowait())
        except queue.Empty:
            pass
        if batch:
            for rec in batch:
                self.aggregator.add_packet(
                    rec.pid, rec.process_name, rec.length,
                    sent=(rec.direction == "out"),
                    remote_endpoint=rec.remote_endpoint)
            self.packets_tab.add_records(batch)
        self.after(DRAIN_MS, self._drain_loop)

    def _tick_loop(self) -> None:
        if self._closing:
            return
        self._tick_count += 1
        try:
            sample = self.speed_monitor.sample()
            self.dashboard_tab.update_sample(sample, self.speed_monitor)
            self.chip_down.config(text=f"↓ {fmt_rate(sample.down_rate)}")
            self.chip_up.config(text=f"↑ {fmt_rate(sample.up_rate)}")
        except Exception:
            pass
        self.aggregator.update_rates()
        self.refresh_processes_view()
        engine = self.capture_engine
        elapsed = (time.time() - engine.started_at) if engine.running and engine.started_at else 0.0
        self.packets_tab.update_stats(engine.running, engine.total_packets,
                                      engine.total_bytes, elapsed)
        # 層級 5：自動停止到期檢查 + 攔截統計/紀錄刷新
        if self.divert_engine.deadline_exceeded():
            self.stop_divert_interception(reason="自動停止時間已到，即時攔截已停止（網路恢復正常）。")
        if self.divert_engine.running or self._tick_count % 2 == 0:
            self.firewall_tab.tick_refresh()
        if self._tick_count % 2 == 0:
            self.refresh_connections()
        self.after(TICK_MS, self._tick_loop)

    # ------------------------------------------------------------- 連線表
    def refresh_connections(self, manual: bool = False) -> None:
        if self._conn_thread_running or self._closing:
            return
        if not manual and not self.capture_engine.running and not self.divert_engine.running:
            if not self.connections_tab.auto_var.get():
                return
        if not manual and str(self.notebook.select()) not in (
                str(self.connections_tab), str(self.processes_tab)):
            if not self.capture_engine.running and not self.divert_engine.running:
                return
        self._conn_thread_running = True

        def worker():
            try:
                records = get_connections(include_listening=True)
            except Exception:
                records = []
            def apply():
                self._conn_thread_running = False
                if self._closing:
                    return
                self._last_connections = records
                self.conn_index.refresh(records)
                self._conn_counts = self.aggregator.connection_counts(records)
                self.connections_tab.set_data(records)
            self.call_in_ui(apply)
        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------- 擷取控制
    def toggle_capture(self) -> None:
        engine = self.capture_engine
        if engine.running:
            engine.stop()
            self.packets_tab.set_capturing_ui(False)
            self.capture_badge.config(text="封包擷取：已停止", fg=theme.MUTED)
            self.set_status(f"封包擷取已停止（共 {engine.total_packets:,} 個封包）。可儲存 pcap 用 Wireshark 開啟分析。")
            self.refresh_processes_view()
            return
        iface = self.packets_tab.selected_iface()
        bpf = self.packets_tab.bpf_var.get()
        try:
            engine.start(iface=iface, bpf_filter=bpf)
        except Exception as exc:  # noqa: BLE001 - 錯誤訊息直接呈現給使用者
            messagebox.showerror(
                "無法開始擷取", f"{exc}\n\n常見原因：\n"
                "1) 未以系統管理員身分執行\n2) 未安裝 Npcap（https://npcap.com）\n"
                "3) BPF 過濾語法錯誤\n4) 介面被其他程式占用", parent=self)
            return
        self.packets_tab.set_capturing_ui(True)
        self.capture_badge.config(text="● 封包擷取中", fg=theme.GREEN)
        self.set_status("封包擷取中：層級 3「程式流量」與層級 4「封包擷取」即時更新中。提醒：僅監控自己的電腦/網路。")
        self.refresh_connections(manual=True)  # 立即更新歸屬索引，提高層級 3 命中率
        self.refresh_processes_view()

    # ------------------------------------------------------------- 層級 5 控制
    def toggle_divert_interception(self) -> None:
        engine = self.divert_engine
        if engine.running:
            self.stop_divert_interception(reason="即時攔截已停止，網路恢復正常（延遲佇列中未送出的封包已丟棄，TCP 會重傳）。")
            return
        # 廣域攔截確認：有無條件規則時，所有符合方向的封包都會進 Python
        exclude_loopback, auto_stop = self.firewall_tab.divert_options()
        filter_preview = build_divert_filter(self.rule_engine.get_rules(), exclude_loopback)
        if "(true)" in filter_preview:
            if not messagebox.askyesno(
                    "全流量攔截確認",
                    "你有一條（含）無條件（不限 IP/埠/協定/程式）的規則，"
                    "將攔截全部符合方向的網路流量。\n\n"
                    "每個封包都會經 Python 判斷，高速下載時可能降速或增加延遲。"
                    "確定還是要開始嗎？", parent=self):
                return
        self.set_status("正在開啟 WinDivert（第一次會載入驅動，請稍候）…")
        self.update_idletasks()
        try:
            filter_string = engine.start(exclude_loopback, auto_stop_seconds=auto_stop)
        except Exception as exc:  # noqa: BLE001 - 錯誤直接呈現
            messagebox.showerror("無法開始攔截", str(exc), parent=self)
            self.set_status("即時攔截啟動失敗，詳見對話框說明（系統防火牆子分頁不受影響）。")
            return
        self.firewall_tab.set_divert_ui(True)
        self.divert_badge.config(text="🚨 封包管制中（層級 5）", fg=theme.RED)
        self.set_status(f"即時攔截進行中（WinDivert）：{filter_string[:120]}"
                        f"{'…' if len(filter_string) > 120 else ''}。停止或關閉程式即完全恢復。")
        self.refresh_connections(manual=True)  # 讓依「程式」比對的規則盡快有索引
        self.firewall_tab.tick_refresh()

    def stop_divert_interception(self, reason: str = "") -> None:
        self.divert_engine.stop()
        self.firewall_tab.set_divert_ui(False)
        self.divert_badge.config(text="封包管制（層級 5）：已停止", fg=theme.MUTED)
        if reason:
            self.set_status(reason)
        self.firewall_tab.tick_refresh()

    # ----- 其他分頁 → 層級 5 的帶入（只填表單，使用者確認後才生效） -----
    def request_block_process(self, pid, process_name: str) -> None:
        path = resolve_program_path(pid)
        self.notebook.select(self.firewall_tab)
        if not path:
            messagebox.showinfo("查不到程式路徑",
                                "這個行程可能已結束或權限不足，無法自動帶入路徑；"
                                "可用系統防火牆表單的「瀏覽…」手動選 .exe。", parent=self)
            self.firewall_tab.prefill_firewall_program("", process_name)
            return
        self.firewall_tab.prefill_firewall_program(path, process_name)
        self.set_status(f"已帶入 {process_name} 的路徑，請確認後再寫入系統防火牆（尚未封鎖）。")

    def request_block_remote_ip(self, ip: str) -> None:
        self.notebook.select(self.firewall_tab)
        self.firewall_tab.prefill_firewall_ip(ip)
        self.set_status(f"已帶入遠端 IP {ip}，請確認後再寫入系統防火牆（尚未封鎖）。")

    def request_intercept_rule(self, remote_ip: str = "", remote_port: str = "",
                               process_name: str = "") -> None:
        self.notebook.select(self.firewall_tab)
        host = remote_ip or remote_port or process_name
        self.firewall_tab.prefill_intercept(
            name=f"封鎖 {host}" if host else "即時封鎖",
            remote_ip=remote_ip, remote_port=remote_port, process_name=process_name)
        self.set_status("已帶入即時攔截規則表單，請檢查後按「＋ 新增規則」再開始攔截（尚未生效）。")

    def on_packets_cleared(self) -> None:
        self.capture_engine.reset_counters()

    def refresh_processes_view(self) -> None:
        self.processes_tab.refresh(self.aggregator, self._conn_counts,
                                   self.capture_engine.running)

    def show_connections_for(self, process_name: str) -> None:
        self.notebook.select(self.connections_tab)
        self.connections_tab.set_search(process_name)

    # ------------------------------------------------------------- 其他
    def _relaunch(self) -> None:
        if relaunch_as_admin():
            self._on_close()
        else:
            messagebox.showwarning("重新啟動失敗",
                                   "無法自動取得管理員權限，請關閉後用 run_as_admin.bat 啟動。",
                                   parent=self)

    def _on_close(self) -> None:
        self._closing = True
        # 先停層級 5 即時攔截，確保關閉時網路立即恢復正常
        try:
            self.divert_engine.stop()
        except Exception:
            pass
        try:
            self.capture_engine.stop()
        except Exception:
            pass
        self.destroy()


def run() -> None:
    app = MainApp()
    app.mainloop()
