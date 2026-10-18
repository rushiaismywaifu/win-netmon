"""深色主題與字體（ttk clam 主題自訂色票）— 現代化精緻版。"""

from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

# ── 基礎色票 ──────────────────────────────────────────────
BG = "#0d111f"
PANEL = "#181d2f"
PANEL_ALT = "#232842"
HEADER = "#0a0e1e"
HEADER_LIGHT = "#141a33"
CARD = "#1e243b"
CARD_HOVER = "#252d4a"
TEXT = "#e6e9f0"
MUTED = "#9aa5c6"
SUBTLE = "#5f6b8f"
ACCENT = "#6c8cff"
ACCENT_HOVER = "#849dff"
ACCENT_DEEP = "#4a5fcf"
ACCENT_SOFT = "#2a3358"
DOWN_COLOR = "#4cc2ff"
UP_COLOR = "#ff9e64"
GREEN = "#7ed67e"
RED = "#ff6b81"
RED_DEEP = "#c53030"
YELLOW = "#e8c46a"
PURPLE = "#b794f6"
CYAN = "#76e4f7"
GRID = "#2a3150"
BORDER = "#2e365a"
BORDER_LIGHT = "#3a4470"
SELECT = "#33407a"
SELECT_HOVER = "#3e52a0"
EXIT_BG = "#e53e3e"
EXIT_HOVER = "#c53030"
SHADOW = "#070a14"

PROTO_TAG_COLORS = {
    "DNS": GREEN,
    "mDNS": GREEN,
    "TLS": PURPLE,
    "HTTPS/TLS": PURPLE,
    "QUIC": PURPLE,
    "HTTP": CYAN,
    "UDP": YELLOW,
    "ICMP": RED,
    "ICMPv6": RED,
    "ARP": UP_COLOR,
    "TCP": TEXT,
}


def pick_fonts(root: tk.Tk) -> dict[str, tuple]:
    families = set(tkfont.families(root))
    ui = next(
        (
            f
            for f in (
                "Microsoft JhengHei UI",
                "Microsoft JhengHei",
                "Segoe UI",
                "Noto Sans CJK TC",
                "PingFang TC",
            )
            if f in families
        ),
        "TkDefaultFont",
    )
    mono = next(
        (
            f
            for f in (
                "Consolas",
                "Cascadia Code",
                "Cascadia Mono",
                "JetBrains Mono",
                "DejaVu Sans Mono",
                "Courier New",
            )
            if f in families
        ),
        "TkFixedFont",
    )
    return {
        "ui": (ui, 10),
        "ui_small": (ui, 9),
        "ui_bold": (ui, 10, "bold"),
        "ui_large": (ui, 11),
        "ui_large_bold": (ui, 11, "bold"),
        "title": (ui, 15, "bold"),
        "title_large": (ui, 18, "bold"),
        "subtitle": (ui, 9),
        "caption": (ui, 8),
        "big_value": (ui, 20, "bold"),
        "mono": (mono, 9),
        "mono_small": (mono, 8),
        "mono_bold": (mono, 10, "bold"),
        "mono_large": (mono, 11, "bold"),
    }


def apply_theme(root: tk.Tk, fonts: dict[str, tuple]) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    # ── 基礎 ──
    style.configure(
        ".",
        background=BG,
        foreground=TEXT,
        font=fonts["ui"],
        bordercolor=BORDER,
        troughcolor=PANEL,
        focuscolor=ACCENT,
        padding=2,
    )
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("Card.TFrame", background=CARD, relief="flat")
    style.configure("Header.TFrame", background=HEADER)

    # ── 標籤 ──
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=fonts["ui_small"])
    style.configure("Subtle.TLabel", background=BG, foreground=SUBTLE, font=fonts["ui_small"])
    style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
    style.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED, font=fonts["ui_small"])
    style.configure("Card.TLabel", background=CARD, foreground=TEXT)
    style.configure("CardMuted.TLabel", background=CARD, foreground=MUTED, font=fonts["ui_small"])
    style.configure("Title.TLabel", background=BG, foreground=TEXT, font=fonts["title"])
    style.configure("Subtitle.TLabel", background=BG, foreground=MUTED, font=fonts["subtitle"])
    style.configure("Header.TLabel", background=HEADER, foreground=TEXT)
    style.configure("HeaderMuted.TLabel", background=HEADER, foreground=MUTED, font=fonts["ui_small"])
    style.configure("Version.TLabel", background=HEADER, foreground=SUBTLE, font=fonts["caption"])

    # Labelframe
    style.configure(
        "TLabelframe",
        background=BG,
        foreground=MUTED,
        bordercolor=BORDER,
        relief="groove",
        padding=8,
    )
    style.configure("TLabelframe.Label", background=BG, foreground=MUTED, font=fonts["ui_bold"])
    style.configure(
        "Card.TLabelframe", background=CARD, foreground=MUTED, bordercolor=BORDER, relief="groove", padding=8
    )
    style.configure("Card.TLabelframe.Label", background=CARD, foreground=MUTED, font=fonts["ui_bold"])

    # ── 按鈕 ──
    style.configure(
        "TButton",
        background=PANEL_ALT,
        foreground=TEXT,
        bordercolor=BORDER,
        padding=(14, 7),
        font=fonts["ui"],
        relief="flat",
    )
    style.map(
        "TButton",
        background=[("active", CARD_HOVER), ("pressed", SELECT), ("disabled", PANEL)],
        foreground=[("disabled", MUTED)],
        bordercolor=[("active", BORDER_LIGHT)],
    )

    style.configure(
        "Accent.TButton",
        background=ACCENT,
        foreground="#ffffff",
        font=fonts["ui_bold"],
        padding=(16, 8),
        relief="flat",
        bordercolor=ACCENT,
    )
    style.map(
        "Accent.TButton",
        background=[("active", ACCENT_HOVER), ("pressed", ACCENT_DEEP), ("disabled", PANEL)],
        foreground=[("disabled", MUTED)],
    )

    style.configure(
        "Danger.TButton",
        background="#9b3a4a",
        foreground="#ffffff",
        font=fonts["ui_bold"],
        padding=(14, 7),
        relief="flat",
        bordercolor="#9b3a4a",
    )
    style.map(
        "Danger.TButton",
        background=[("active", "#b3465a"), ("pressed", "#873240"), ("disabled", PANEL)],
        foreground=[("disabled", MUTED)],
    )

    style.configure(
        "Exit.TButton",
        background=EXIT_BG,
        foreground="#ffffff",
        font=fonts["ui_bold"],
        padding=(18, 8),
        relief="flat",
        bordercolor=EXIT_BG,
    )
    style.map(
        "Exit.TButton",
        background=[("active", "#f05a5a"), ("pressed", RED_DEEP), ("disabled", PANEL)],
        foreground=[("disabled", MUTED)],
    )

    style.configure(
        "Ghost.TButton",
        background=PANEL,
        foreground=MUTED,
        font=fonts["ui_small"],
        padding=(10, 5),
        relief="flat",
        bordercolor=BORDER,
    )
    style.map(
        "Ghost.TButton",
        background=[("active", PANEL_ALT), ("pressed", CARD)],
        foreground=[("active", TEXT), ("disabled", SUBTLE)],
    )

    # ── 輸入 ──
    style.configure(
        "TEntry",
        fieldbackground=PANEL_ALT,
        foreground=TEXT,
        insertcolor=TEXT,
        bordercolor=BORDER,
        padding=6,
        lightcolor=BORDER,
        darkcolor=BORDER,
    )
    style.configure(
        "TCombobox",
        fieldbackground=PANEL_ALT,
        foreground=TEXT,
        background=PANEL_ALT,
        bordercolor=BORDER,
        padding=6,
        arrowcolor=TEXT,
    )
    root.option_add("*TCombobox*Listbox.background", PANEL_ALT)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", SELECT)
    root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

    style.configure("TCheckbutton", background=BG, foreground=TEXT, font=fonts["ui"])
    style.map(
        "TCheckbutton",
        background=[("active", BG)],
        indicatorcolor=[("selected", ACCENT), ("!selected", PANEL_ALT)],
    )

    # ── Notebook ──
    style.configure("TNotebook", background=BG, bordercolor=BORDER, tabmargins=(10, 8, 10, 0))
    style.configure(
        "TNotebook.Tab",
        background=PANEL,
        foreground=MUTED,
        padding=(20, 11),
        font=fonts["ui_bold"],
        bordercolor=BORDER,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", PANEL_ALT), ("active", CARD)],
        foreground=[("selected", "#ffffff"), ("active", TEXT)],
        bordercolor=[("selected", ACCENT)],
        padding=[("selected", (22, 12))],
    )

    # ── Treeview ──
    style.configure(
        "Treeview",
        background=PANEL,
        fieldbackground=PANEL,
        foreground=TEXT,
        bordercolor=BORDER,
        rowheight=26,
        font=fonts["ui_small"],
    )
    style.configure(
        "Treeview.Heading",
        background=PANEL_ALT,
        foreground=TEXT,
        font=fonts["ui_bold"],
        bordercolor=BORDER,
        padding=(8, 7),
    )
    style.map("Treeview", background=[("selected", SELECT)], foreground=[("selected", "#ffffff")])
    style.map("Treeview.Heading", background=[("active", SELECT)])

    # ── Scrollbar / Separator ──
    style.configure("Vertical.TScrollbar", background=PANEL_ALT, troughcolor=PANEL, bordercolor=BORDER, arrowcolor=MUTED)
    style.configure("Horizontal.TScrollbar", background=PANEL_ALT, troughcolor=PANEL, bordercolor=BORDER, arrowcolor=MUTED)
    style.configure("TPanedwindow", background=BORDER)
    style.configure("TSeparator", background=BORDER)

    return style
