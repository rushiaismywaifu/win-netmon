"""深色主題與字體（ttk clam 主題自訂色票）。"""
from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

# ---- 色票 ----
BG = "#1a1b26"          # 主背景
PANEL = "#222433"       # 面板背景
PANEL_ALT = "#2a2d42"   # 面板（亮）
HEADER = "#16161e"      # 頂欄
TEXT = "#e6e9f0"        # 主文字
MUTED = "#9aa5ce"       # 次要文字
ACCENT = "#7aa2f7"      # 主強調（藍）
DOWN_COLOR = "#4cc2ff"  # 下載
UP_COLOR = "#ff9e64"    # 上傳
GREEN = "#9ece6a"
RED = "#f7768e"
YELLOW = "#e0af68"
PURPLE = "#bb9af7"
GRID = "#333652"
SELECT = "#364a82"

# 封包列表協定著色（前景）
PROTO_TAG_COLORS = {
    "DNS": GREEN, "mDNS": GREEN,
    "TLS": PURPLE, "HTTPS/TLS": PURPLE, "QUIC": PURPLE,
    "HTTP": "#7dcfff",
    "UDP": YELLOW,
    "ICMP": RED, "ICMPv6": RED,
    "ARP": "#ff9e64",
    "TCP": TEXT,
}


def pick_fonts(root: tk.Tk) -> dict[str, tuple]:
    """挑選可用字體：Windows 優先微軟正黑體，退回系統預設。"""
    families = set(tkfont.families(root))
    ui = next((f for f in ("Microsoft JhengHei UI", "Microsoft JhengHei",
                           "Segoe UI", "Noto Sans CJK TC", "PingFang TC")
               if f in families), "TkDefaultFont")
    mono = next((f for f in ("Consolas", "Cascadia Mono", "Cascadia Code",
                             "DejaVu Sans Mono", "Courier New")
                 if f in families), "TkFixedFont")
    return {
        "ui": (ui, 10),
        "ui_small": (ui, 9),
        "ui_bold": (ui, 10, "bold"),
        "title": (ui, 15, "bold"),
        "big_value": (ui, 17, "bold"),
        "mono": (mono, 9),
    }


def apply_theme(root: tk.Tk, fonts: dict[str, tuple]) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(".", background=BG, foreground=TEXT, font=fonts["ui"],
                    bordercolor=GRID, troughcolor=PANEL, focuscolor=ACCENT)
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=fonts["ui_small"])
    style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
    style.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED,
                    font=fonts["ui_small"])
    style.configure("TLabelframe", background=BG, foreground=MUTED,
                    bordercolor=GRID, relief="groove")
    style.configure("TLabelframe.Label", background=BG, foreground=MUTED,
                    font=fonts["ui_bold"])

    style.configure("TButton", background=PANEL_ALT, foreground=TEXT,
                    bordercolor=GRID, padding=(10, 5), font=fonts["ui"])
    style.map("TButton",
              background=[("active", SELECT), ("disabled", PANEL)],
              foreground=[("disabled", MUTED)])
    style.configure("Accent.TButton", background="#2f4a8f", foreground="#ffffff",
                    font=fonts["ui_bold"], padding=(12, 6))
    style.map("Accent.TButton", background=[("active", "#3d5cae"), ("disabled", PANEL)])
    style.configure("Danger.TButton", background="#7a2d3f", foreground="#ffffff",
                    font=fonts["ui_bold"], padding=(12, 6))
    style.map("Danger.TButton", background=[("active", "#9a3a50"), ("disabled", PANEL)])

    style.configure("TEntry", fieldbackground=PANEL_ALT, foreground=TEXT,
                    insertcolor=TEXT, bordercolor=GRID, padding=4)
    style.configure("TCombobox", fieldbackground=PANEL_ALT, foreground=TEXT,
                    background=PANEL_ALT, bordercolor=GRID, padding=4,
                    arrowcolor=TEXT)
    root.option_add("*TCombobox*Listbox.background", PANEL_ALT)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", SELECT)

    style.configure("TCheckbutton", background=BG, foreground=TEXT, font=fonts["ui"])
    style.map("TCheckbutton", background=[("active", BG)],
              indicatorcolor=[("selected", ACCENT)])

    style.configure("TNotebook", background=BG, bordercolor=GRID, tabmargins=(6, 6, 6, 0))
    style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                    padding=(16, 8), font=fonts["ui_bold"], bordercolor=GRID)
    style.map("TNotebook.Tab",
              background=[("selected", PANEL_ALT)],
              foreground=[("selected", "#ffffff")])

    style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=TEXT, bordercolor=GRID, rowheight=24,
                    font=fonts["ui_small"])
    style.configure("Treeview.Heading", background=PANEL_ALT, foreground=TEXT,
                    font=fonts["ui_bold"], bordercolor=GRID, padding=(4, 5))
    style.map("Treeview",
              background=[("selected", SELECT)],
              foreground=[("selected", "#ffffff")])
    style.map("Treeview.Heading", background=[("active", SELECT)])

    style.configure("Vertical.TScrollbar", background=PANEL_ALT, troughcolor=PANEL,
                    bordercolor=GRID, arrowcolor=MUTED, width=14)
    style.configure("Horizontal.TScrollbar", background=PANEL_ALT, troughcolor=PANEL,
                    bordercolor=GRID, arrowcolor=MUTED, width=14)
    style.configure("TPanedwindow", background=GRID)
    style.configure("TSeparator", background=GRID)
    return style
