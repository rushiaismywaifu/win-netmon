"""層級 1 分頁：總覽儀表板 — 即時網速圖 + 統計卡 + 每介面卡明細。"""
from __future__ import annotations

import time
import tkinter as tk
from tkinter import ttk

from ..speed_monitor import SpeedMonitor, SpeedSample, nic_details
from ..utils import fmt_bytes, fmt_rate
from . import theme
from .widgets import SpeedChart, StatCard, make_tree


class DashboardTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        fonts = app.fonts
        self._nic_cache: list[dict] = []
        self._nic_cache_at = 0.0
        self._nic_render_at = 0.0   # 明細表重繪節流（約 2 秒一次就夠了）

        # --- 統計卡 ---
        cards = ttk.Frame(self)
        cards.pack(fill="x", padx=10, pady=(10, 4))
        self.card_down = StatCard(cards, fonts, "↓ 下載速率", theme.DOWN_COLOR)
        self.card_up = StatCard(cards, fonts, "↑ 上傳速率", theme.UP_COLOR)
        self.card_down_total = StatCard(cards, fonts, "本次下載總量", theme.DOWN_COLOR)
        self.card_up_total = StatCard(cards, fonts, "本次上傳總量", theme.UP_COLOR)
        for i, card in enumerate((self.card_down, self.card_up,
                                  self.card_down_total, self.card_up_total)):
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 8, 0))
            cards.columnconfigure(i, weight=1)

        # --- 網速圖 ---
        chart_frame = ttk.Labelframe(self, text="即時網速（最近 120 秒）")
        chart_frame.pack(fill="both", expand=True, padx=10, pady=6)
        self.chart = SpeedChart(chart_frame, fonts)
        self.chart.pack(fill="both", expand=True, padx=6, pady=6)

        # --- 介面卡明細 ---
        nic_frame = ttk.Labelframe(self, text="網路介面卡明細")
        nic_frame.pack(fill="both", expand=True, padx=10, pady=(2, 10))
        inner = ttk.Frame(nic_frame)
        inner.pack(fill="both", expand=True, padx=6, pady=6)
        self.tree = make_tree(inner, [
            ("name", "介面", 200, "w"),
            ("status", "狀態", 64, "center"),
            ("ipv4", "IPv4 位址", 140, "w"),
            ("speed", "連結速度", 100, "center"),
            ("down_rate", "↓ 目前速率", 120, "e"),
            ("up_rate", "↑ 目前速率", 120, "e"),
            ("down_total", "↓ 累計下載", 130, "e"),
            ("up_total", "↑ 累計上傳", 130, "e"),
        ], height=7)

    def update_sample(self, sample: SpeedSample, monitor: SpeedMonitor) -> None:
        self.card_down.set(fmt_rate(sample.down_rate),
                           f"尖峰 {fmt_rate(monitor.peak_down)}")
        self.card_up.set(fmt_rate(sample.up_rate),
                         f"尖峰 {fmt_rate(monitor.peak_up)}")
        self.card_down_total.set(fmt_bytes(monitor.session_recv),
                                 f"開機以來累計 {fmt_bytes(sample.total_recv)}")
        self.card_up_total.set(fmt_bytes(monitor.session_sent),
                               f"開機以來累計 {fmt_bytes(sample.total_sent)}")
        self.chart.set_history(monitor.history)
        self._update_nics(sample)

    def _update_nics(self, sample: SpeedSample) -> None:
        now = time.time()
        if now - self._nic_render_at < 1.9:
            return  # 節流：速率本來就不是逐秒變化，整表重繪沒必要每秒做
        self._nic_render_at = now
        if now - self._nic_cache_at > 10 or not self._nic_cache:
            try:
                self._nic_cache = nic_details()
            except Exception:
                self._nic_cache = []
            self._nic_cache_at = now
        selected = self.tree.selection()
        selected_name = None
        if selected:
            values = self.tree.item(selected[0], "values")
            if values:
                selected_name = values[0]
        self.tree.delete(*self.tree.get_children())
        for nic in self._nic_cache:
            rate = sample.per_nic.get(nic["name"])
            if rate is None:
                continue
            speed = nic["speed_mbps"]
            speed_text = f"{speed} Mbps" if speed else "-"
            if speed and speed >= 1000:
                speed_text = f"{speed / 1000:g} Gbps"
            iid = self.tree.insert("", "end", values=(
                nic["name"],
                "🟢 啟用" if nic["isup"] else "⚪ 停用",
                nic["ipv4"] or "-",
                speed_text,
                fmt_rate(rate.down_rate), fmt_rate(rate.up_rate),
                fmt_bytes(rate.total_recv), fmt_bytes(rate.total_sent),
            ))
            if selected_name == nic["name"]:
                self.tree.selection_set(iid)
