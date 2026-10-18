"""自訂元件：統計卡、即時網速圖、程式流量長條圖、可排序表格輔助。"""
from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..utils import fmt_bytes, fmt_rate
from . import theme


class StatCard(tk.Frame):
    """儀表板上的一張統計卡：標題 + 大數字 + 副標。"""

    def __init__(self, parent, fonts: dict, title: str, accent: str = theme.ACCENT):
        super().__init__(parent, bg=theme.PANEL, highlightbackground=theme.GRID,
                         highlightthickness=1)
        bar = tk.Frame(self, bg=accent, width=4)
        bar.pack(side="left", fill="y")
        inner = tk.Frame(self, bg=theme.PANEL)
        inner.pack(side="left", fill="both", expand=True, padx=12, pady=8)
        tk.Label(inner, text=title, bg=theme.PANEL, fg=theme.MUTED,
                 font=fonts["ui_small"]).pack(anchor="w")
        self._value = tk.Label(inner, text="-", bg=theme.PANEL, fg=theme.TEXT,
                               font=fonts["big_value"])
        self._value.pack(anchor="w")
        self._sub = tk.Label(inner, text="", bg=theme.PANEL, fg=theme.MUTED,
                             font=fonts["ui_small"])
        self._sub.pack(anchor="w")

    def set(self, value: str, sub: str = "") -> None:
        self._value.config(text=value)
        self._sub.config(text=sub)


class SpeedChart(tk.Canvas):
    """即時上/下行速率折線圖（自動縮放 Y 軸）。"""

    def __init__(self, parent, fonts: dict, height: int = 240):
        super().__init__(parent, height=height, bg=theme.PANEL,
                         highlightthickness=1, highlightbackground=theme.GRID)
        self._fonts = fonts
        self._history: list[tuple[float, float, float]] = []
        self.bind("<Configure>", lambda _e: self.draw())

    def set_history(self, history) -> None:
        self._history = list(history)
        self.draw()

    def draw(self) -> None:
        self.delete("all")
        w = max(self.winfo_width(), 10)
        h = max(self.winfo_height(), 10)
        pad_l, pad_r, pad_t, pad_b = 74, 14, 16, 22
        plot_w = max(w - pad_l - pad_r, 10)
        plot_h = max(h - pad_t - pad_b, 10)

        data = self._history
        peak = 1024.0  # 最小刻度 1 KB/s，避免平地時圖表亂跳
        for _t, up, down in data:
            peak = max(peak, up, down)
        peak *= 1.15

        # 水平格線 + Y 軸標籤
        for i in range(5):
            y = pad_t + plot_h * i / 4
            value = peak * (1 - i / 4)
            self.create_line(pad_l, y, pad_l + plot_w, y, fill=theme.GRID)
            self.create_text(pad_l - 6, y, anchor="e", fill=theme.MUTED,
                             font=self._fonts["ui_small"], text=fmt_rate(value))
        self.create_text(pad_l, h - 6, anchor="w", fill=theme.MUTED,
                         font=self._fonts["ui_small"], text="-120 秒")
        self.create_text(pad_l + plot_w, h - 6, anchor="e", fill=theme.MUTED,
                         font=self._fonts["ui_small"], text="現在")

        if len(data) >= 2:
            n = len(data)

            def points(idx: int) -> list[float]:
                pts: list[float] = []
                for i, sample in enumerate(data):
                    x = pad_l + plot_w * i / (n - 1)
                    y = pad_t + plot_h - (sample[idx] / peak) * plot_h
                    pts += [x, y]
                return pts

            base_y = pad_t + plot_h
            for idx, color in ((2, theme.DOWN_COLOR), (1, theme.UP_COLOR)):
                pts = points(idx)
                area = [pad_l, base_y] + pts + [pad_l + plot_w, base_y]
                self.create_polygon(area, fill=color, stipple="gray25", outline="")
                self.create_line(pts, fill=color, width=2, smooth=True)
        else:
            self.create_text(w / 2, h / 2, fill=theme.MUTED, font=self._fonts["ui"],
                             text="取樣中…")

        # 圖例
        legend_y = 10
        x = w - pad_r
        for label, color in (("上傳 ↑", theme.UP_COLOR), ("下載 ↓", theme.DOWN_COLOR)):
            self.create_text(x, legend_y, anchor="ne", fill=color,
                             font=self._fonts["ui_small"], text=label)
            x -= 76


class TopBarChart(tk.Canvas):
    """層級 3：Top N 程式流量水平長條圖（下行藍 + 上行橘堆疊）。"""

    def __init__(self, parent, fonts: dict, height: int = 196, top_n: int = 8):
        super().__init__(parent, height=height, bg=theme.PANEL,
                         highlightthickness=1, highlightbackground=theme.GRID)
        self._fonts = fonts
        self._top_n = top_n
        self._data: list[tuple[str, int, int]] = []  # (name, recv, sent)
        self.bind("<Configure>", lambda _e: self.draw())

    def set_data(self, items) -> None:
        self._data = [(p.name, p.bytes_recv, p.bytes_sent)
                      for p in list(items)[: self._top_n]]
        self.draw()

    def draw(self) -> None:
        self.delete("all")
        w = max(self.winfo_width(), 10)
        h = max(self.winfo_height(), 10)
        if not self._data:
            self.create_text(w / 2, h / 2, fill=theme.MUTED, font=self._fonts["ui"],
                             text="尚無資料 — 請先到「封包擷取」分頁（或按下方按鈕）開始擷取，\n程式流量將自動依「封包＋連線表比對」歸屬統計。")
            return
        pad_l, pad_r, pad_t = 150, 110, 10
        plot_w = max(w - pad_l - pad_r, 10)
        row_h = max((h - pad_t * 2) / max(len(self._data), 1), 12)
        peak = max((recv + sent) for _n, recv, sent in self._data) or 1
        for i, (name, recv, sent) in enumerate(self._data):
            y = pad_t + row_h * i + row_h / 2
            display = name if len(name) <= 18 else name[:17] + "…"
            self.create_text(pad_l - 8, y, anchor="e", fill=theme.TEXT,
                             font=self._fonts["ui_small"], text=display)
            bar_h = min(row_h * 0.55, 16)
            down_w = plot_w * recv / peak
            up_w = plot_w * sent / peak
            if down_w > 0:
                self.create_rectangle(pad_l, y - bar_h / 2, pad_l + down_w,
                                      y + bar_h / 2, fill=theme.DOWN_COLOR, outline="")
            if up_w > 0:
                self.create_rectangle(pad_l + down_w, y - bar_h / 2,
                                      pad_l + down_w + up_w, y + bar_h / 2,
                                      fill=theme.UP_COLOR, outline="")
            total = recv + sent
            self.create_text(pad_l + down_w + up_w + 8, y, anchor="w",
                             fill=theme.MUTED, font=self._fonts["ui_small"],
                             text=f"{fmt_bytes(total)}（↓{fmt_bytes(recv)} ↑{fmt_bytes(sent)}）")


def make_tree(parent, columns: list[tuple[str, str, int, str]],
              on_sort=None, height: int = 12) -> ttk.Treeview:
    """建立帶捲軸的 Treeview。

    columns: [(id, 標題, 寬度, anchor), ...]
    on_sort: 點擊欄位標題時呼叫 on_sort(欄位 id)
    """
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True)
    ids = [c[0] for c in columns]
    tree = ttk.Treeview(frame, columns=ids, show="headings", height=height,
                        selectmode="browse")
    for col_id, title, width, anchor in columns:
        cmd = (lambda c=col_id: on_sort(c)) if on_sort else None
        tree.heading(col_id, text=title, command=cmd)
        tree.column(col_id, width=width, anchor=anchor, stretch=True)  # type: ignore[arg-type]
    vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    return tree


def save_text_file(parent, content: str, default_name: str,
                   filetypes=(("CSV 檔", "*.csv"), ("所有檔案", "*.*"))) -> None:
    """跳出存檔對話框並寫入文字（UTF-8）。"""
    path = filedialog.asksaveasfilename(parent=parent, defaultextension=".csv",
                                        initialfile=default_name, filetypes=filetypes)
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
        messagebox.showinfo("匯出完成", f"已儲存：\n{path}", parent=parent)
    except OSError as exc:
        messagebox.showerror("匯出失敗", str(exc), parent=parent)


def copy_text(root: tk.Misc, text: str) -> None:
    root.clipboard_clear()
    root.clipboard_append(text)
