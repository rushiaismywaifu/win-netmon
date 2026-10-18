"""主視窗：把層級 1～5 串起來 — 現代精緻版。

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
from ..capture import CaptureEngine, PacketRecord, any_capture_availability
from ..connections import get_connections
from ..divert_engine import DivertEngine, divert_availability
from ..rule_engine import RuleEngine, build_divert_filter
from ..rule_store import RuleStore
from ..speed_monitor import SpeedMonitor
from ..traffic import ConnectionIndex, TrafficAggregator
from ..utils import fmt_rate, is_admin, is_windows, relaunch_as_admin
from ..win_firewall import FirewallManager, resolve_program_path
from . import theme
from .connections_tab import ConnectionsTab
from .dashboard_tab import DashboardTab
from .firewall_tab import FirewallTab
from .help_tab import HelpTab
from .packets_tab import PacketsTab
from .processes_tab import ProcessesTab

DRAIN_MS = 200
TICK_MS = 1000


class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{__app_name__} — Windows 網路流量監測（層級 1~5）")
        self.geometry("1360x900")
        self.minsize(1120, 700)
        self.configure(bg=theme.BG)
        self._set_app_icon()

        self.fonts = theme.pick_fonts(self)
        theme.apply_theme(self, self.fonts)

        # ---------- 共用核心 ----------
        self.speed_monitor = SpeedMonitor()
        self.conn_index = ConnectionIndex()
        self.aggregator = TrafficAggregator()
        self.capture_engine = CaptureEngine(self.conn_index)
        self.rule_store = RuleStore()
        self.rule_store.load()
        self.rule_engine = RuleEngine(list(self.rule_store.intercept_rules))
        self.divert_engine = DivertEngine(self.rule_engine, self.conn_index)
        self.firewall_manager = FirewallManager()
        self._packet_queue: queue.Queue[PacketRecord] = queue.Queue(maxsize=50000)
        self.capture_engine.on_packet = self._enqueue_packet
        self._ui_queue: queue.Queue = queue.Queue()
        self._last_connections: list = []
        self._conn_counts: dict[int, int] = {}
        self._conn_thread_running = False
        self._tick_count = 0
        self._closing = False
        self._capture_starting = False      # 擷取後端正在背景緒程開啟
        self._capture_was_running = False   # 前一次 tick 時擷取是否在跑（偵測非預期中斷）

        # ---------- 選單列 ----------
        self._build_menu()
        # 頂部細線點綴（品牌感）
        self._accent_line = tk.Frame(self, bg=theme.ACCENT, height=3)
        self._accent_line.pack(fill="x", side="top")

        # ---------- 介面 ----------
        self._build_header()
        # 分隔線
        tk.Frame(self, bg=theme.BORDER, height=1).pack(fill="x")
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=4, pady=(6, 0))
        self.notebook = notebook
        self.dashboard_tab = DashboardTab(notebook, self)
        self.connections_tab = ConnectionsTab(notebook, self)
        self.processes_tab = ProcessesTab(notebook, self)
        self.packets_tab = PacketsTab(notebook, self)
        self.firewall_tab = FirewallTab(notebook, self)
        self.help_tab = HelpTab(notebook, self)
        notebook.add(self.dashboard_tab, text="  📊 總覽（層級 1）  ")
        notebook.add(self.connections_tab, text="  🔌 連線清單（層級 2）  ")
        notebook.add(self.processes_tab, text="  🏆 程式流量（層級 3）  ")
        notebook.add(self.packets_tab, text="  📦 封包擷取（層級 4）  ")
        notebook.add(self.firewall_tab, text="  🛡 封鎖/管制（層級 5）  ")
        notebook.add(self.help_tab, text="  📖 幫助  ")
        # 首次切到「封包擷取」分頁時，順勢預熱 Npcap 介面清單（含 Scapy 延遲載入）
        notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        # 分隔線 + 狀態列
        tk.Frame(self, bg=theme.BORDER, height=1).pack(fill="x", side="bottom")
        self._build_statusbar()
        if self.rule_store.load_error:
            self.set_status(self.rule_store.load_error)
        fw_count = len(self.rule_store.firewall_rules)
        if fw_count:
            self.set_status(
                f"提醒：你有 {fw_count} 條由本程式寫入的系統防火牆封鎖仍在生效中，"
                "可在「🛡 封鎖/管制（層級 5）」的系統防火牆子分頁管理或清除。"
            )

        # 快捷鍵與關閉行為
        self.protocol("WM_DELETE_WINDOW", self._confirm_exit)
        self.bind("<Control-q>", lambda e: self._confirm_exit())
        self.bind("<Control-Q>", lambda e: self._confirm_exit())
        # F5 刷新連線
        self.bind("<F5>", lambda e: self.refresh_connections(manual=True))

        self.after(300, lambda: self.refresh_connections(manual=True))
        self.after(DRAIN_MS, self._drain_loop)
        self.after(TICK_MS, self._tick_loop)

    def _on_tab_changed(self, _event=None) -> None:
        """首次切到「封包擷取」分頁時，順勢預熱 Npcap 介面清單（含 Scapy 延遲載入）。"""
        try:
            if self.notebook.select() == str(self.packets_tab):
                self.packets_tab.ensure_interfaces_loaded()
        except Exception:
            pass

    # ------------------------------------------------------------- 選單
    def _build_menu(self) -> None:
        try:
            menubar = tk.Menu(self, bg=theme.PANEL_ALT, fg=theme.TEXT, activebackground=theme.SELECT, bd=0)
            file_menu = tk.Menu(menubar, tearoff=0, bg=theme.PANEL_ALT, fg=theme.TEXT, activebackground=theme.SELECT, activeforeground="#ffffff", bd=0)
            file_menu.add_command(label="重新整理連線（F5）", command=lambda: self.refresh_connections(manual=True))
            file_menu.add_separator()
            file_menu.add_command(label="結束程式  (Ctrl+Q)", command=self._confirm_exit)
            menubar.add_cascade(label="  檔案  ", menu=file_menu)

            help_menu = tk.Menu(menubar, tearoff=0, bg=theme.PANEL_ALT, fg=theme.TEXT, activebackground=theme.SELECT, activeforeground="#ffffff", bd=0)
            help_menu.add_command(label=f"關於 {__app_name__}  v{__version__}", command=self._show_about)
            menubar.add_cascade(label="  說明  ", menu=help_menu)

            self.config(menu=menubar)
            self._menubar = menubar
        except Exception:
            pass

    def _show_about(self) -> None:
        messagebox.showinfo(
            f"關於 {__app_name__}",
            f"{__app_name__}  v{__version__}\n\n"
            "Windows 網路流量監測與管制（層級 1~5）\n"
            "整體網速 → 連線清單 → 每程式流量 → 封包解析 → 封鎖/限速\n\n"
            "提示：按 Ctrl+Q 或右上角「結束程式」可優雅退出，\n"
            "程式會自動停止擷取與攔截，確保網路立即恢復。",
            parent=self,
        )

    # ------------------------------------------------------------- 頂部 Header
    def _build_header(self) -> None:
        header = tk.Frame(self, bg=theme.HEADER)
        header.pack(fill="x")
        # 內層左右佈局
        left = tk.Frame(header, bg=theme.HEADER)
        left.pack(side="left", padx=16, pady=10)

        # Logo 圓形圖標（Canvas 模擬圓角）
        logo_wrap = tk.Frame(left, bg=theme.HEADER)
        logo_wrap.pack(side="left")
        try:
            logo_canvas = tk.Canvas(logo_wrap, width=46, height=46, bg=theme.HEADER, highlightthickness=0)
            # 外圓陰影
            logo_canvas.create_oval(2, 4, 44, 46, fill="#070a14", outline="", stipple="")
            # 主圓
            logo_canvas.create_oval(1, 1, 43, 43, fill=theme.ACCENT, outline=theme.ACCENT_HOVER, width=1)
            # 內部符號
            logo_canvas.create_text(22, 22, text="⬡", fill="#ffffff", font=("Segoe UI", 18, "bold"))
            logo_canvas.pack(side="left")
        except Exception:
            tk.Label(logo_wrap, text="⬡", bg=theme.ACCENT, fg="#ffffff", font=self.fonts["title"], padx=10, pady=6).pack(side="left")

        # 標題文字
        titles = tk.Frame(left, bg=theme.HEADER)
        titles.pack(side="left", padx=(12, 0))
        title_row = tk.Frame(titles, bg=theme.HEADER)
        title_row.pack(anchor="w")
        tk.Label(title_row, text="Win-NetMon", bg=theme.HEADER, fg="#ffffff", font=self.fonts["title_large"]).pack(side="left")
        # 版本小膠囊
        ver_capsule = tk.Frame(title_row, bg=theme.ACCENT_SOFT, highlightbackground=theme.BORDER, highlightthickness=1)
        # 模擬圓角膠囊：用 Label 包起來
        tk.Label(ver_capsule, text=f"  v{__version__}  ", bg=theme.ACCENT_SOFT, fg=theme.ACCENT_HOVER, font=self.fonts["ui_small"]).pack()
        ver_capsule.pack(side="left", padx=(10, 0), pady=2)

        tk.Label(titles, text="Windows 網路流量監測與管制中心  ·  層級 1-5 全方位洞察", bg=theme.HEADER, fg=theme.MUTED, font=self.fonts["ui_small"]).pack(anchor="w", pady=(1, 0))
        # 權限徽章在第二行
        admin = is_admin()
        badge_row = tk.Frame(titles, bg=theme.HEADER)
        badge_row.pack(anchor="w", pady=(4, 0))
        badge_text = "🛡️ 系統管理員模式" if admin else "👤 一般使用者模式"
        badge_bg = "#1a3a2a" if admin else "#3a2f14"
        badge_fg = theme.GREEN if admin else theme.YELLOW
        badge = tk.Frame(badge_row, bg=badge_bg, highlightbackground=badge_fg, highlightthickness=1)
        tk.Label(badge, text=badge_text, bg=badge_bg, fg=badge_fg, font=self.fonts["ui_small"], padx=8, pady=2).pack()
        badge.pack(side="left")
        if is_windows() and not admin:
            tk.Label(badge_row, text="  建議以系統管理員身分執行以解鎖完整功能", bg=theme.HEADER, fg=theme.SUBTLE, font=self.fonts["ui_small"]).pack(side="left")

        # ── 中間：即時速率膠囊 ──
        center = tk.Frame(header, bg=theme.HEADER)
        center.pack(side="left", expand=True, padx=16)
        chips_wrap = tk.Frame(center, bg=theme.HEADER)
        chips_wrap.pack(anchor="center")
        self.chip_down = self._make_chip(chips_wrap, "↓ --", theme.DOWN_COLOR)
        self.chip_up = self._make_chip(chips_wrap, "↑ --", theme.UP_COLOR)
        self.chip_down.pack(side="left", padx=6)
        self.chip_up.pack(side="left", padx=6)
        # 小提示
        tk.Label(center, text="即時速率  ·  每秒更新", bg=theme.HEADER, fg=theme.SUBTLE, font=self.fonts["caption"]).pack(pady=(6, 0))

        # ── 右側：狀態 + 操作 ──
        right = tk.Frame(header, bg=theme.HEADER)
        right.pack(side="right", padx=16, pady=8)

        # 狀態標籤（擷取/管制）
        status_col = tk.Frame(right, bg=theme.HEADER)
        status_col.pack(side="left", padx=(0, 14))
        avail_ok, _msg = any_capture_availability()
        divert_ok, _dmsg = divert_availability()
        self.capture_badge = tk.Label(
            status_col,
            text="● 封包擷取：待機" if avail_ok else "● 封包擷取：不可用",
            bg=theme.HEADER,
            fg=theme.MUTED if avail_ok else theme.RED,
            font=self.fonts["ui_small"],
            anchor="e",
        )
        self.capture_badge.pack(anchor="e")
        self.divert_badge = tk.Label(
            status_col,
            text="● 封包管制：待機" if divert_ok else "● 封包管制：未就緒",
            bg=theme.HEADER,
            fg=theme.MUTED if divert_ok else theme.RED,
            font=self.fonts["ui_small"],
            anchor="e",
        )
        self.divert_badge.pack(anchor="e", pady=(2, 0))
        if is_windows() and not admin:
            # 小按鈕：提權
            ttk.Button(status_col, text="↗ 以系統管理員重新啟動", style="Ghost.TButton", command=self._relaunch).pack(anchor="e", pady=(6, 0))

        # 右側操作按鈕區（垂直）
        actions = tk.Frame(right, bg=theme.HEADER)
        actions.pack(side="left")
        # 結束程式按鈕 — 醒目紅色
        self.exit_btn = ttk.Button(actions, text="⏻  結束程式", style="Exit.TButton", command=self._confirm_exit)
        self.exit_btn.pack(fill="x", pady=(0, 6), ipady=2)
        # 次要操作：最小化
        ttk.Button(actions, text="—  最小化", style="Ghost.TButton", command=self._minimize).pack(fill="x")
        # 快捷提示
        tk.Label(actions, text="Ctrl+Q 亦可結束", bg=theme.HEADER, fg=theme.SUBTLE, font=self.fonts["caption"]).pack(pady=(4, 0))

        # 非系統管理員警告橫幅
        if is_windows() and not admin:
            banner = tk.Frame(self, bg="#3a2f14", highlightbackground="#6b5a1f", highlightthickness=1)
            banner.pack(fill="x", padx=10, pady=(0, 6))
            tk.Label(
                banner,
                text="  ⚠  目前不是以系統管理員身分執行：可能看不到全部程式的連線、也無法擷取封包。建議用 run_as_admin.bat 啟動。",
                bg="#3a2f14",
                fg=theme.YELLOW,
                font=self.fonts["ui_small"],
                anchor="w",
                padx=10,
                pady=6,
            ).pack(fill="x")

    def _minimize(self) -> None:
        try:
            self.iconify()
        except Exception:
            pass

    @staticmethod
    def _make_chip(parent, text: str, color: str):
        """建立速率膠囊：圓點 + 數值，帶細邊框，模擬 pill。"""
        # 外層 pill
        pill = tk.Frame(parent, bg=theme.PANEL_ALT, highlightbackground=theme.BORDER, highlightthickness=1)
        # 為避免 tk 真圓角，用高對比邊框 + 內距模擬
        inner = tk.Frame(pill, bg=theme.PANEL_ALT)
        inner.pack(padx=1, pady=1)
        # 圓點
        try:
            dot = tk.Canvas(inner, width=10, height=10, bg=theme.PANEL_ALT, highlightthickness=0)
            dot.create_oval(1, 1, 9, 9, fill=color, outline=color)
            dot.pack(side="left", padx=(10, 6), pady=7)
        except Exception:
            tk.Label(inner, text="●", bg=theme.PANEL_ALT, fg=color, font=("Segoe UI", 9)).pack(side="left", padx=(10, 4))
        label = tk.Label(inner, text=text, bg=theme.PANEL_ALT, fg=color, font=("Consolas", 11, "bold"), padx=4)
        label.pack(side="left", padx=(0, 10), pady=6)
        # 讓 pill 支援 .value_label 與 .config 轉送，保持舊介面相容
        pill.value_label = label  # type: ignore[attr-defined]

        orig_config = pill.config

        def _forward_config(**kw):  # type: ignore[no-untyped-def]
            if "text" in kw:
                label.config(text=kw.pop("text"))
            if kw:
                try:
                    orig_config(**kw)
                except Exception:
                    pass

        pill.config = _forward_config  # type: ignore[attr-defined]
        return pill

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self, bg=theme.HEADER, height=36)
        bar.pack(fill="x", side="bottom")
        try:
            bar.pack_propagate(False)  # type: ignore[attr-defined]
        except Exception:
            pass

        # 左：狀態文字
        left = tk.Frame(bar, bg=theme.HEADER)
        left.pack(side="left", fill="both", expand=True, padx=12)
        # 圖示
        tk.Label(left, text="ⓘ", bg=theme.HEADER, fg=theme.ACCENT, font=self.fonts["ui_bold"]).pack(side="left", padx=(0, 6))
        self.status_var = tk.StringVar(
            value="就緒：層級 1–2 已自動運作；層級 3/4 用「📦 封包擷取」開始擷取；層級 5「🛡 封鎖/管制」可封鎖與限速（需管理員）。僅用於自己的電腦。"
        )
        tk.Label(bar, textvariable=self.status_var, bg=theme.HEADER, fg=theme.MUTED, font=self.fonts["ui_small"], anchor="w", wraplength=760, justify="left").pack(side="left", padx=0, pady=4)

        # 中/右：版本與操作
        right = tk.Frame(bar, bg=theme.HEADER)
        right.pack(side="right", padx=8, pady=4)
        tk.Label(right, text=f"v{__version__}", bg=theme.HEADER, fg=theme.SUBTLE, font=self.fonts["caption"]).pack(side="left", padx=8)
        # 分隔線
        tk.Frame(right, bg=theme.BORDER, width=1, height=18).pack(side="left", padx=6, fill="y")
        ttk.Button(right, text="— 最小化", style="Ghost.TButton", command=self._minimize).pack(side="left", padx=4)
        ttk.Button(right, text="⏻ 結束", style="Exit.TButton", command=self._confirm_exit).pack(side="left", padx=(4, 8))

    def set_status(self, text: str) -> None:
        self.status_var.set(text)

    # ------------------------------------------------------------- 結束程式
    def _confirm_exit(self) -> None:
        """優雅結束：如有擷取/攔截進行中先提示，其餘直接退出；可取消。"""
        if self._closing:
            return
        # 若有正在執行的攔截/擷取，給予明確提示
        divert_running = getattr(self.divert_engine, "running", False)
        capture_running = getattr(self.capture_engine, "running", False)
        if divert_running or capture_running:
            parts = []
            if capture_running:
                parts.append("• 封包擷取正在進行")
            if divert_running:
                parts.append("• 即時攔截正在管制網路")
            detail = "\n".join(parts)
            proceed = messagebox.askyesno(
                "確定要結束程式嗎？",
                f"以下功能仍在運行：\n{detail}\n\n結束程式會自動停止擷取與攔截，網路將恢復正常。\n確定要結束嗎？",
                parent=self,
            )
            if not proceed:
                return
        else:
            # 一般情況仍給輕量確認，避免誤觸（可按取消）
            # 若想無確認直接關閉，改為直接呼叫 _on_close 即可
            # 這裡保留確認以符合「結束程式按鈕」明確操作的預期
            proceed = messagebox.askyesno("結束程式", "確定要結束 Win-NetMon 嗎？", parent=self)
            if not proceed:
                return
        self._on_close()

    # ------------------------------------------------------------- 排程
    def call_in_ui(self, fn) -> None:
        """供背景緒程使用：把函式排入佇列，由 GUI 主緒程執行。"""
        self._ui_queue.put(fn)

    def _enqueue_packet(self, rec: PacketRecord) -> None:
        try:
            self._packet_queue.put_nowait(rec)
        except queue.Full:
            pass

    def _drain_loop(self) -> None:
        try:
            if self._closing:
                return
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
                entries = ((rec.pid, rec.process_name, rec.length, rec.direction == "out",
                            rec.remote_endpoint) for rec in batch)
                self.aggregator.add_batch(entries)
                self.packets_tab.add_records(batch)
        finally:
            # 不論這次處理發生什麼事，都要把下一次排程排上去（心跳不能斷）
            if not self._closing:
                self.after(DRAIN_MS, self._drain_loop)

    def _tick_loop(self) -> None:
        try:
            if self._closing:
                return
            self._tick_count += 1
            try:
                sample = self.speed_monitor.sample()
                self.dashboard_tab.update_sample(sample, self.speed_monitor)
                # 相容新舊 chip 實作
                for chip, rate in ((self.chip_down, sample.down_rate), (self.chip_up, sample.up_rate)):
                    text = f"↓ {fmt_rate(rate)}" if chip is self.chip_down else f"↑ {fmt_rate(rate)}"
                    try:
                        if hasattr(chip, "value_label"):
                            chip.value_label.config(text=text)  # type: ignore[attr-defined]
                        else:
                            chip.config(text=text)
                    except Exception:
                        pass
            except Exception:
                pass
            self.aggregator.update_rates()
            self.refresh_processes_view()
            engine = self.capture_engine
            if not self._capture_starting:
                # 啟動中不做「中斷」判定：背景緒程的完成回呼會接手更新 UI
                if self._capture_was_running and not engine.running:
                    self.packets_tab.set_capturing_ui(False)
                    try:
                        self.capture_badge.config(text="● 封包擷取：已中斷", fg=theme.RED)
                    except Exception:
                        pass
                    if engine.last_error:
                        self.set_status(f"封包擷取已中斷：{engine.last_error}")
                self._capture_was_running = engine.running
            elapsed = (time.time() - engine.started_at) if engine.running and engine.started_at else 0.0
            self.packets_tab.update_stats(engine.running, engine.total_packets, engine.total_bytes, elapsed,
                                          engine.backend, starting=self._capture_starting)
            if self.divert_engine.deadline_exceeded():
                self.stop_divert_interception(reason="自動停止時間已到，即時攔截已停止（網路恢復正常）。")
            if self.divert_engine.running or self._tick_count % 2 == 0:
                self.firewall_tab.tick_refresh()
            if self._tick_count % 2 == 0:
                self.refresh_connections()
        finally:
            if not self._closing:
                self.after(TICK_MS, self._tick_loop)

    # ------------------------------------------------------------- 連線表
    def refresh_connections(self, manual: bool = False) -> None:
        if self._conn_thread_running or self._closing:
            return
        if not manual and not self.capture_engine.running and not self.divert_engine.running:
            if not self.connections_tab.auto_var.get():
                return
        if not manual and str(self.notebook.select()) not in (str(self.connections_tab), str(self.processes_tab)):
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
        if self._capture_starting:
            return  # 啟動中一律忽略（按鈕已鎖住，這裡是保底）
        engine = self.capture_engine
        if engine.running:
            engine.stop()
            self._capture_was_running = False
            self._capture_starting = False
            self.packets_tab.set_capturing_ui(False)
            try:
                self.capture_badge.config(text="● 封包擷取：已停止", fg=theme.MUTED)
            except Exception:
                pass
            self.set_status(f"封包擷取已停止（共 {engine.total_packets:,} 個封包）。可儲存 pcap 用 Wireshark 開啟分析。")
            self.refresh_processes_view()
            return

        request = self.packets_tab.capture_request()
        self._capture_starting = True
        self.packets_tab.set_capturing_ui(False, starting=True)
        self.set_status("正在開啟擷取後端（第一次載入驅動可能要等幾秒）…")

        def worker() -> None:
            # 這個緒程只負責「開後端」（含等驅動就緒的 sleep），
            # 完成後把結果丟回 GUI 主緒程，畫面才不會在這幾百毫秒內凍結。
            try:
                engine.start(**request)
            except Exception as exc:  # noqa: BLE001
                detail = str(exc)
                self.call_in_ui(lambda: self._capture_start_failed(detail))
                return
            if self._closing:  # 啟動期間使用者關掉了程式
                try:
                    engine.stop()
                except Exception:
                    pass
                return
            self.call_in_ui(self._capture_start_done)

        threading.Thread(target=worker, daemon=True, name="netmon-capture-start").start()

    def _capture_start_done(self) -> None:
        """背景啟動成功（GUI 主緒程）：切換成「擷取中」狀態。"""
        if self._closing:
            return
        self._capture_starting = False
        engine = self.capture_engine
        if not engine.running:  # 啟動後立刻停止的保底
            self.packets_tab.set_capturing_ui(False)
            return
        self._capture_was_running = True
        self.packets_tab.set_capturing_ui(True)
        backend_name = "WinDivert・IP 層" if engine.backend == "windivert" else "Npcap"
        try:
            self.capture_badge.config(text=f"● 擷取中（{backend_name}）", fg=theme.GREEN)
        except Exception:
            pass
        extra = "（WinDivert 後端無 Ethernet/ARP）" if engine.backend == "windivert" else ""
        self.set_status(f"封包擷取中（後端：{backend_name}）：層級 3「程式流量」與層級 4「封包擷取」即時更新中{extra}。提醒：僅監控自己的電腦/網路。")
        self.refresh_connections(manual=True)
        self.refresh_processes_view()

    def _capture_start_failed(self, message: str) -> None:
        """背景啟動失敗（GUI 主緒程）：還原 UI 並顯示原因。"""
        if self._closing:
            return
        self._capture_starting = False
        self.packets_tab.set_capturing_ui(False)
        self.set_status("封包擷取啟動失敗，詳見對話框說明。")
        messagebox.showerror(
            "無法開始擷取",
            f"{message}\n\n常見原因：\n1) 未以系統管理員身分執行\n2) Npcap 未安裝（可用封包頁一鍵安裝，或把擷取後端改成 WinDivert 免 Npcap）\n3) 過濾語法錯誤（Npcap 用 BPF、WinDivert 用它自己的語法）\n4) 介面被其他程式占用",
            parent=self,
        )

    # ------------------------------------------------------------- 層級 5 控制
    def toggle_divert_interception(self) -> None:
        engine = self.divert_engine
        if engine.running:
            self.stop_divert_interception(reason="即時攔截已停止，網路恢復正常（延遲佇列中未送出的封包已丟棄，TCP 會重傳）。")
            return
        exclude_loopback, auto_stop = self.firewall_tab.divert_options()
        filter_preview = build_divert_filter(self.rule_engine.get_rules(), exclude_loopback)
        if "(true)" in filter_preview:
            if not messagebox.askyesno(
                "全流量攔截確認",
                "你有一條（含）無條件（不限 IP/埠/協定/程式）的規則，將攔截全部符合方向的網路流量。\n\n每個封包都會經 Python 判斷，高速下載時可能降速或增加延遲。確定還是要開始嗎？",
                parent=self,
            ):
                return
        self.set_status("正在開啟 WinDivert（第一次會載入驅動，請稍候）…")
        self.update_idletasks()
        try:
            filter_string = engine.start(exclude_loopback, auto_stop_seconds=auto_stop)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("無法開始攔截", str(exc), parent=self)
            self.set_status("即時攔截啟動失敗，詳見對話框說明（系統防火牆子分頁不受影響）。")
            return
        self.firewall_tab.set_divert_ui(True)
        try:
            self.divert_badge.config(text="▲ 管制中（攔截生效）", fg=theme.RED)
        except Exception:
            pass
        self.set_status(f"即時攔截進行中（WinDivert）：{filter_string[:120]}{'…' if len(filter_string) > 120 else ''}。停止或關閉程式即完全恢復。")
        self.refresh_connections(manual=True)
        self.firewall_tab.tick_refresh()

    def stop_divert_interception(self, reason: str = "") -> None:
        self.divert_engine.stop()
        self.firewall_tab.set_divert_ui(False)
        try:
            self.divert_badge.config(text="● 封包管制：已停止", fg=theme.MUTED)
        except Exception:
            pass
        if reason:
            self.set_status(reason)
        self.firewall_tab.tick_refresh()

    def request_block_process(self, pid, process_name: str) -> None:
        path = resolve_program_path(pid)
        self.notebook.select(self.firewall_tab)
        if not path:
            messagebox.showinfo("查不到程式路徑", "這個行程可能已結束或權限不足，無法自動帶入路徑；可用系統防火牆表單的「瀏覽…」手動選 .exe。", parent=self)
            self.firewall_tab.prefill_firewall_program("", process_name)
            return
        self.firewall_tab.prefill_firewall_program(path, process_name)
        self.set_status(f"已帶入 {process_name} 的路徑，請確認後再寫入系統防火牆（尚未封鎖）。")

    def request_block_remote_ip(self, ip: str) -> None:
        self.notebook.select(self.firewall_tab)
        self.firewall_tab.prefill_firewall_ip(ip)
        self.set_status(f"已帶入遠端 IP {ip}，請確認後再寫入系統防火牆（尚未封鎖）。")

    def request_intercept_rule(self, remote_ip: str = "", remote_port: str = "", process_name: str = "") -> None:
        self.notebook.select(self.firewall_tab)
        host = remote_ip or remote_port or process_name
        self.firewall_tab.prefill_intercept(name=f"封鎖 {host}" if host else "即時封鎖", remote_ip=remote_ip, remote_port=remote_port, process_name=process_name)
        self.set_status("已帶入即時攔截規則表單，請檢查後按「＋ 新增規則」再開始攔截（尚未生效）。")

    def on_packets_cleared(self) -> None:
        self.capture_engine.reset_counters()

    def refresh_processes_view(self) -> None:
        self.processes_tab.refresh(self.aggregator, self._conn_counts, self.capture_engine.running)

    def show_connections_for(self, process_name: str) -> None:
        self.notebook.select(self.connections_tab)
        self.connections_tab.set_search(process_name)

    def _set_app_icon(self) -> None:
        """嘗試載入應用程式圖示（assets/icon.png），失敗則忽略（無頭測試環境）。"""
        try:
            from pathlib import Path

            # 可能的圖示位置（依執行目錄不同）
            candidates = [
                Path(__file__).resolve().parents[2] / "assets" / "icon.png",
                Path(__file__).resolve().parents[2] / "assets" / "icon-simple.png",
                Path.cwd() / "assets" / "icon.png",
            ]
            icon_path = next((p for p in candidates if p.is_file()), None)
            if icon_path is None:
                return
            # Tkinter 僅原生支援 PNG/GIF，SVG 需轉檔；這裡用 PhotoImage 載入 PNG
            img = tk.PhotoImage(file=str(icon_path))
            # 保留引用避免被 GC
            self._icon_img = img  # type: ignore[attr-defined]
            try:
                self.iconphoto(True, img)
            except Exception:
                pass
            # Windows 工作列圖示（若有 .ico 也可加）
            try:
                ico_candidates = [
                    Path(__file__).resolve().parents[2] / "assets" / "icon.ico",
                ]
                ico = next((p for p in ico_candidates if p.is_file()), None)
                if ico:
                    self.iconbitmap(str(ico))
            except Exception:
                pass
        except Exception:
            pass

    def _relaunch(self) -> None:
        if relaunch_as_admin():
            self._on_close()
        else:
            messagebox.showwarning("重新啟動失敗", "無法自動取得管理員權限，請關閉後用 run_as_admin.bat 啟動。", parent=self)

    def _on_close(self) -> None:
        self._closing = True
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
