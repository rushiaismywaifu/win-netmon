"""層級 3 分頁：程式流量排行 — 每個程式各用了多少流量。

統計來自層級 4 的封包擷取 + 連線表比對（netmon.traffic），
因此必須先開始擷取；未擷取時顯示說明與快捷按鈕。
"""
from __future__ import annotations

import time
import tkinter as tk
from tkinter import ttk

from ..traffic import ProcessTraffic, TrafficAggregator, process_traffic_to_csv
from ..utils import fmt_bytes, fmt_count, fmt_rate
from . import theme
from .widgets import TopBarChart, make_tree, save_text_file


def _ago(ts: float) -> str:
    if not ts:
        return "-"
    delta = time.time() - ts
    if delta < 3:
        return "剛剛"
    if delta < 60:
        return f"{int(delta)} 秒前"
    if delta < 3600:
        return f"{int(delta // 60)} 分前"
    return f"{int(delta // 3600)} 小時前"


class ProcessesTab(ttk.Frame):
    SORT_KEYS = {
        "name": lambda p: p.name.lower(),
        "pid": lambda p: p.pid,
        "down_rate": lambda p: p.down_rate,
        "up_rate": lambda p: p.up_rate,
        "down": lambda p: p.bytes_recv,
        "up": lambda p: p.bytes_sent,
        "total": lambda p: p.total_bytes,
        "packets": lambda p: p.total_packets,
        "conns": lambda p: 0,
        "last": lambda p: p.last_seen,
    }

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        fonts = app.fonts
        self._items: list[ProcessTraffic] = []
        self._conn_counts: dict[int, int] = {}
        self._sort_col = "total"
        self._sort_reverse = True

        # --- 狀態/操作列 ---
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=10, pady=(10, 4))
        self.status_label = ttk.Label(
            bar, text="尚未開始擷取：按下「開始擷取」後，流量會依「封包＋連線表比對」自動歸屬到各程式。",
            style="Muted.TLabel")
        self.status_label.pack(side="left", fill="x", expand=True)
        self.start_btn = ttk.Button(bar, text="▶ 開始擷取", style="Accent.TButton",
                                    command=self._toggle_capture)
        self.start_btn.pack(side="left", padx=4)
        ttk.Button(bar, text="重置統計", command=self._reset).pack(side="left", padx=4)
        ttk.Button(bar, text="匯出 CSV", command=self._export).pack(side="left")

        # --- Top 圖表 ---
        chart_frame = ttk.Labelframe(self, text="流量排行 Top 8（↓ 藍 = 下載、↑ 橘 = 上傳）")
        chart_frame.pack(fill="x", padx=10, pady=6)
        self.chart = TopBarChart(chart_frame, fonts)
        self.chart.pack(fill="both", expand=True, padx=6, pady=6)

        # --- 排行表 ---
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=10, pady=(2, 4))
        self.tree = make_tree(body, [
            ("rank", "#", 44, "center"),
            ("name", "程式", 200, "w"),
            ("pid", "PID", 70, "e"),
            ("down_rate", "↓ 速率", 110, "e"),
            ("up_rate", "↑ 速率", 110, "e"),
            ("down", "↓ 總量", 120, "e"),
            ("up", "↑ 總量", 120, "e"),
            ("total", "總流量", 130, "e"),
            ("packets", "封包數", 100, "e"),
            ("conns", "目前連線", 84, "center"),
            ("last", "最後活動", 96, "w"),
        ], on_sort=self._on_sort)
        self.tree.bind("<Double-Button-1>", self._on_double_click)
        ttk.Label(self, text="連按兩下程式列 → 跳到「連線清單」看它連到哪裡。"
                             " 查不到歸屬的封包會列在「(未歸屬 / 系統)」。",
                  style="Muted.TLabel").pack(anchor="w", padx=12, pady=(0, 6))

    # ------------------------------------------------------------- 資料
    def refresh(self, aggregator: TrafficAggregator, conn_counts: dict[int, int],
                capturing: bool) -> None:
        self._conn_counts = conn_counts
        self.SORT_KEYS["conns"] = lambda p: self._conn_counts.get(p.pid, 0)
        ranked = aggregator.ranking()          # 已依總流量排序（給圖表用）
        items = list(ranked)
        items.sort(key=self.SORT_KEYS.get(self._sort_col, self.SORT_KEYS["total"]),
                   reverse=self._sort_reverse)
        self._items = items
        self.chart.set_data(ranked)            # 圖表固定依總流量排

        sent, recv, unknown = aggregator.totals()
        attributed = sent + recv
        total = attributed + unknown
        ratio = (attributed / total * 100) if total else 0.0
        elapsed = int(time.time() - aggregator.started_at)
        if capturing:
            self.status_label.config(
                text=f"● 擷取中（已 {elapsed // 60} 分 {elapsed % 60} 秒）｜已歸屬流量 "
                     f"{fmt_bytes(attributed)}（{ratio:.0f}%）｜未歸屬 {fmt_bytes(unknown)}｜"
                     f"共 {len(items)} 個程式有網路活動")
            self.start_btn.config(text="⏹ 停止擷取", style="Danger.TButton")
        else:
            self.start_btn.config(text="▶ 開始擷取", style="Accent.TButton")
            if total:
                self.status_label.config(
                    text=f"擷取已停止｜已歸屬流量 {fmt_bytes(attributed)}（{ratio:.0f}%）｜"
                         f"未歸屬 {fmt_bytes(unknown)}，按「開始擷取」可繼續累計。")
            else:
                self.status_label.config(
                    text="尚未開始擷取：按下「開始擷取」後，流量會依「封包＋連線表比對」自動歸屬到各程式。")

        tree = self.tree
        sel_key = None
        sel = tree.selection()
        if sel:
            try:
                prev_items = getattr(self, "_prev_display", [])
                proc = prev_items[int(sel[0])]
                sel_key = (proc.pid, proc.name)
            except Exception:
                pass
        tree.delete(*tree.get_children())
        for i, proc in enumerate(items):
            iid = tree.insert("", "end", iid=str(i), values=(
                i + 1, proc.name, proc.pid or "-",
                fmt_rate(proc.down_rate), fmt_rate(proc.up_rate),
                fmt_bytes(proc.bytes_recv), fmt_bytes(proc.bytes_sent),
                fmt_bytes(proc.total_bytes), fmt_count(proc.total_packets),
                self._conn_counts.get(proc.pid, 0) if proc.pid else "-",
                _ago(proc.last_seen),
            ))
            if sel_key == (proc.pid, proc.name):
                tree.selection_set(iid)
        self._prev_display = items

    # ------------------------------------------------------------- 互動
    def _on_sort(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = col not in ("name",)
        self.app.refresh_processes_view()

    def _toggle_capture(self) -> None:
        self.app.toggle_capture()

    def _reset(self) -> None:
        self.app.aggregator.reset()
        self.app.refresh_processes_view()

    def _export(self) -> None:
        save_text_file(self, process_traffic_to_csv(self.app.aggregator.ranking()),
                       "process_traffic.csv")

    def _on_double_click(self, _event) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        try:
            proc = self._items[int(sel[0])]
        except (ValueError, IndexError):
            return
        if proc.pid:
            self.app.show_connections_for(proc.name)
