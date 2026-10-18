"""深色主題與字體（ttk clam 主題自訂色票）。"""
from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

BG = "#0f111a"
PANEL = "#1a1b26"
PANEL_ALT = "#24283b"
HEADER = "#0b0d14"
CARD = "#1e2030"
TEXT = "#e6e9f0"
MUTED = "#9aa5ce"
SUBTLE = "#565f89"
ACCENT = "#7aa2f7"
ACCENT_HOVER = "#89b4fa"
DOWN_COLOR = "#4cc2ff"
UP_COLOR = "#ff9e64"
GREEN = "#9ece6a"
RED = "#f7768e"
YELLOW = "#e0af68"
PURPLE = "#bb9af7"
CYAN = "#7dcfff"
GRID = "#333652"
BORDER = "#414868"
SELECT = "#364a82"
SELECT_HOVER = "#4a5fa8"

PROTO_TAG_COLORS = {
    "DNS": GREEN, "mDNS": GREEN,
    "TLS": PURPLE, "HTTPS/TLS": PURPLE, "QUIC": PURPLE,
    "HTTP": CYAN,
    "UDP": YELLOW,
    "ICMP": RED, "ICMPv6": RED,
    "ARP": UP_COLOR,
    "TCP": TEXT,
}


def pick_fonts(root: tk.Tk) -> dict[str, tuple]:
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
        "title": (ui, 16, "bold"),
        "subtitle": (ui, 10),
        "big_value": (ui, 20, "bold"),
        "mono": (mono, 9),
        "mono_small": (mono, 8),
    }


def apply_theme(root: tk.Tk, fonts: dict[str, tuple]) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(".", background=BG, foreground=TEXT, font=fonts["ui"],
                    bordercolor=BORDER, troughcolor=PANEL, focuscolor=ACCENT,
                    padding=2)
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("Card.TFrame", background=CARD, relief="flat")
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED,
                    font=fonts["ui_small"])
    style.configure("Subtle.TLabel", background=BG, foreground=SUBTLE,
                    font=fonts["ui_small"])
    style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
    style.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED,
                    font=fonts["ui_small"])
    style.configure("Card.TLabel", background=CARD, foreground=TEXT)
    style.configure("CardMuted.TLabel", background=CARD, foreground=MUTED,
                    font=fonts["ui_small"])
    style.configure("Title.TLabel", background=BG, foreground=TEXT,
                    font=fonts["title"])
    style.configure("Subtitle.TLabel", background=BG, foreground=MUTED,
                    font=fonts["subtitle"])
    style.configure("TLabelframe", background=BG, foreground=MUTED,
                    bordercolor=BORDER, relief="groove", padding=6)
    style.configure("TLabelframe.Label", background=BG, foreground=MUTED,
                    font=fonts["ui_bold"])
    style.configure("Card.TLabelframe", background=CARD, foreground=MUTED,
                    bordercolor=BORDER, relief="groove", padding=6)
    style.configure("Card.TLabelframe.Label", background=CARD, foreground=MUTED,
                    font=fonts["ui_bold"])

    style.configure("TButton", background=PANEL_ALT, foreground=TEXT,
                    bordercolor=BORDER, padding=(12, 6), font=fonts["ui"],
                    relief="flat")
    style.map("TButton",
              background=[("active", SELECT), ("pressed", SELECT_HOVER),
                          ("disabled", PANEL)],
              foreground=[("disabled", MUTED)])
    style.configure("Accent.TButton", background="#3d59a1", foreground="#ffffff",
                    font=fonts["ui_bold"], padding=(14, 7), relief="flat",
                    bordercolor="#3d59a1")
    style.map("Accent.TButton",
              background=[("active", "#4a69bd"), ("pressed", "#364a8f"),
                          ("disabled", PANEL)],
              foreground=[("disabled", MUTED)])
    style.configure("Danger.TButton", background="#9b3a4a", foreground="#ffffff",
                    font=fonts["ui_bold"], padding=(14, 7), relief="flat",
                    bordercolor="#9b3a4a")
    style.map("Danger.TButton",
              background=[("active", "#b3465a"), ("pressed", "#873240"),
                          ("disabled", PANEL)],
              foreground=[("disabled", MUTED)])

    style.configure("TEntry", fieldbackground=PANEL_ALT, foreground=TEXT,
                    insertcolor=TEXT, bordercolor=BORDER, padding=5,
                    lightcolor=BORDER, darkcolor=BORDER)
    style.configure("TCombobox", fieldbackground=PANEL_ALT, foreground=TEXT,
                    background=PANEL_ALT, bordercolor=BORDER, padding=5,
                    arrowcolor=TEXT)
    root.option_add("*TCombobox*Listbox.background", PANEL_ALT)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", SELECT)

    style.configure("TCheckbutton", background=BG, foreground=TEXT,
                    font=fonts["ui"])
    style.map("TCheckbutton", background=[("active", BG)],
              indicatorcolor=[("selected", ACCENT), ("!selected", PANEL_ALT)])

    style.configure("TNotebook", background=BG, bordercolor=BORDER,
                    tabmargins=(8, 8, 8, 0))
    style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                    padding=(18, 10), font=fonts["ui_bold"], bordercolor=BORDER)
    style.map("TNotebook.Tab",
              background=[("selected", PANEL_ALT), ("active", CARD)],
              foreground=[("selected", "#ffffff"), ("active", TEXT)])

    style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=TEXT, bordercolor=BORDER, rowheight=26,
                    font=fonts["ui_small"])
    style.configure("Treeview.Heading", background=PANEL_ALT, foreground=TEXT,
                    font=fonts["ui_bold"], bordercolor=BORDER, padding=(6, 6))
    style.map("Treeview",
              background=[("selected", SELECT)],
              foreground=[("selected", "#ffffff")])
    style.map("Treeview.Heading", background=[("active", SELECT)])

    style.configure("Vertical.TScrollbar", background=PANEL_ALT, troughcolor=PANEL,
                    bordercolor=BORDER, arrowcolor=MUTED, width=12)
    style.configure("Horizontal.TScrollbar", background=PANEL_ALT, troughcolor=PANEL,
                    bordercolor=BORDER, arrowcolor=MUTED, width=12)
    style.configure("TPanedwindow", background=BORDER)
    style.configure("TSeparator", background=BORDER)
    return style
