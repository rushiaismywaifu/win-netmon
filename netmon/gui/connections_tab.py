"""層級 2 分頁：連線清單 — 哪些程式連到哪些 IP（psutil.net_connections）。"""
from __future__ import annotations

import socket
import threading
import tkinter as tk
from tkinter import ttk

from ..connections import ConnectionRecord, connections_to_csv
from . import theme
from .widgets import copy_text, make_tree, save_text_file


class HostnameResolver:
    """反向 DNS 查詢（背景執行、快取結果，避免卡住 UI）。"""

    def __init__(self):
        self._cache: dict[str, str] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()

    def get(self, ip: str) -> str:
        if not ip or ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
            return "-"
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
            if ip in self._pending or len(self._pending) > 32:
                return "查詢中…"
            self._pending.add(ip)
        threading.Thread(target=self._resolve, args=(ip,), daemon=True).start()
        return "查詢中…"

    def _resolve(self, ip: str) -> None:
        try:
            host = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            host = "-"
        with self._lock:
            self._cache[ip] = host
            self._pending.discard(ip)


class ConnectionsTab(ttk.Frame):
    SORT_KEYS = {
        "name": lambda r: r.process_name.lower(),
        "pid": lambda r: r.pid or 0,
        "proto": lambda r: r.protocol,
        "local": lambda r: (r.local_ip, r.local_port),
        "remote": lambda r: (r.remote_ip, r.remote_port or 0),
        "host": lambda r: r.remote_ip,
        "status": lambda r: r.status,
    }

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._records: list[ConnectionRecord] = []
        self._displayed: list[ConnectionRecord] = []
        self._sort_col = "name"
        self._sort_reverse = False
        self._sel_key: tuple | None = None
        self._resolver = HostnameResolver()

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(bar, text="搜尋：").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.render())
        ttk.Entry(bar, textvariable=self.search_var, width=26).pack(side="left", padx=4)
        ttk.Label(bar, text="協定：").pack(side="left", padx=(10, 0))
        self.proto_var = tk.StringVar(value="全部")
        proto_box = ttk.Combobox(bar, textvariable=self.proto_var, width=8,
                                 values=["全部", "TCP", "UDP"], state="readonly")
        proto_box.pack(side="left", padx=4)
        proto_box.bind("<<ComboboxSelected>>", lambda _e: self.render())

        self.listen_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="顯示 LISTEN", variable=self.listen_var,
                        command=self.render).pack(side="left", padx=(10, 0))
        self.host_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="解析主機名", variable=self.host_var,
                        command=self.render).pack(side="left", padx=4)
        self.auto_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="自動刷新（2 秒）", variable=self.auto_var).pack(side="left", padx=4)

        ttk.Button(bar, text="立即刷新", command=lambda: app.refresh_connections(manual=True)
                   ).pack(side="left", padx=(10, 4))
        ttk.Button(bar, text="匯出 CSV", command=self._export).pack(side="left")
        self.count_label = ttk.Label(bar, text="", style="Muted.TLabel")
        self.count_label.pack(side="right")

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=10, pady=(2, 10))
        self.tree = make_tree(body, [
            ("name", "程式", 190, "w"),
            ("pid", "PID", 70, "e"),
            ("proto", "協定", 64, "center"),
            ("local", "本機位址", 190, "w"),
            ("remote", "遠端位址", 210, "w"),
            ("host", "遠端主機名", 230, "w"),
            ("status", "狀態", 120, "w"),
        ], on_sort=self._on_sort)
        self.tree.bind("<Button-3>", self._context_menu)
        self.tree.bind("<Double-Button-1>", self._on_double_click)

        ttk.Label(self,
                  text="提示：以系統管理員身分執行才看得到全部程式的 PID。連按兩下可篩選該程式。",
                  style="Muted.TLabel").pack(anchor="w", padx=12, pady=(0, 6))

        self._menu = tk.Menu(self, tearoff=0, bg=theme.PANEL_ALT, fg=theme.TEXT,
                             activebackground=theme.SELECT, activeforeground="#ffffff")
        self._menu.add_command(label="複製遠端 IP", command=lambda: self._copy_field("remote_ip"))
        self._menu.add_command(label="複製整行", command=self._copy_row)
        self._menu.add_separator()
        self._menu.add_command(label="🚫 封鎖此程式連外網（層級 5）", command=self._block_process)
        self._menu.add_command(label="🚫 封鎖此遠端 IP（層級 5）", command=self._block_ip)
        self._menu.add_command(label="⚡ 以此遠端建立即時攔截規則（層級 5）", command=self._intercept_remote)

    # ------------------------------------------------------------- 資料
    def set_data(self, records: list[ConnectionRecord]) -> None:
        self._records = records
        self.render()

    def set_search(self, text: str) -> None:
        self.search_var.set(text)

    def render(self) -> None:
        keyword = self.search_var.get().strip().lower()
        proto = self.proto_var.get()
        show_listen = self.listen_var.get()
        resolve = self.host_var.get()
        out: list[ConnectionRecord] = []
        for rec in self._records:
            if proto != "全部" and rec.protocol != proto:
                continue
            if not show_listen and rec.status == "LISTEN":
                continue
            if not show_listen and rec.protocol == "UDP" and not rec.remote_ip:
                continue
            if keyword:
                haystack = (f"{rec.process_name} {rec.pid} {rec.local} "
                            f"{rec.remote} {rec.status}").lower()
                if keyword not in haystack:
                    continue
            out.append(rec)
        out.sort(key=self.SORT_KEYS.get(self._sort_col, self.SORT_KEYS["name"]),
                 reverse=self._sort_reverse)
        self._displayed = out

        # 記住目前選取的連線（tuple key），刷新後盡量恢復選取
        if self.tree.selection():
            self._current()
        selected_key = self._sel_key
        self.tree.delete(*self.tree.get_children())
        for i, rec in enumerate(out):
            host = self._resolver.get(rec.remote_ip) if resolve else "-"
            iid = self.tree.insert("", "end", iid=str(i), values=(
                rec.process_name, rec.pid or "", rec.protocol,
                rec.local, rec.remote, host, rec.status,
            ))
            if selected_key is not None and rec.tuple_key() == selected_key:
                self.tree.selection_set(iid)
                self._sel_key = selected_key
        self.count_label.config(text=f"共 {len(out)} 條連線（全部 {len(self._records)} 條）")

    # ------------------------------------------------------------- 互動
    def _on_sort(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col, self._sort_reverse = col, False
        self.render()

    def _current(self) -> ConnectionRecord | None:
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            rec = self._displayed[int(sel[0])]
        except (ValueError, IndexError):
            return None
        self._sel_key = rec.tuple_key()
        return rec

    def _context_menu(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self._current()
            self._menu.tk_popup(event.x_root, event.y_root)

    def _on_double_click(self, _event) -> None:
        rec = self._current()
        if rec:
            self.search_var.set(rec.process_name)

    def _copy_field(self, field_name: str) -> None:
        rec = self._current()
        if rec:
            copy_text(self, getattr(rec, field_name) or "")

    def _copy_row(self) -> None:
        rec = self._current()
        if rec:
            copy_text(self, f"{rec.process_name} (PID {rec.pid}) {rec.protocol} "
                            f"{rec.local} -> {rec.remote} {rec.status}")

    # ---------- 層級 5 帶入（只填表單，不會直接封鎖） ----------
    def _block_process(self) -> None:
        rec = self._current()
        if rec and rec.pid:
            self.app.request_block_process(rec.pid, rec.process_name)

    def _block_ip(self) -> None:
        rec = self._current()
        if rec and rec.remote_ip:
            self.app.request_block_remote_ip(rec.remote_ip)

    def _intercept_remote(self) -> None:
        rec = self._current()
        if rec and rec.remote_ip:
            self.app.request_intercept_rule(
                remote_ip=rec.remote_ip,
                remote_port=str(rec.remote_port or ""),
                process_name="" if rec.process_name.startswith("(") else rec.process_name)

    def _export(self) -> None:
        save_text_file(self, connections_to_csv(self._displayed or self._records),
                       "connections.csv")
