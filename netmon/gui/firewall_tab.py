"""層級 5 分頁：封鎖 / 管制流量。

兩個子系統（子分頁）：
  A. 即時攔截（WinDivert）：規則表 + 開始/停止。命中封包可封鎖/限速/
     弱網路模擬/轉址。關閉程式或停止即恢復，不留系統痕跡。
  B. 系統防火牆（WFP）：把封鎖規則寫入 Windows 防火牆（依程式/IP/埠），
     核心直接強制、重開機仍在，必須從這裡（或系統防火牆介面）移除。
底部是即時攔截的封鎖紀錄。
"""
from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..divert_engine import divert_availability
from ..rule_engine import ACTION_LABELS, InterceptRule, build_divert_filter
from ..utils import fmt_bytes, fmt_count, fmt_time
from ..win_firewall import (SystemFirewallRule, firewall_availability,
                            sanitize_label)
from . import theme
from .widgets import make_tree

ACTION_BY_LABEL = {v: k for k, v in ACTION_LABELS.items()}
DIR_LABELS = {"out": "出向 ↑", "in": "入向 ↓", "both": "雙向"}
DIR_BY_LABEL = {v: k for k, v in DIR_LABELS.items()}
PROTO_LABELS = {"any": "全部", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}
PROTO_BY_LABEL = {v: k for k, v in PROTO_LABELS.items()}
FW_KIND_LABELS = {"program": "程式（.exe）", "ip": "遠端 IP / CIDR", "port": "遠端埠"}
FW_KIND_BY_LABEL = {v: k for k, v in FW_KIND_LABELS.items()}
AUTO_STOP_OPTIONS = {"10 分鐘後": 600, "5 分鐘後": 300, "30 分鐘後": 1800,
                     "60 分鐘後": 3600, "不自動停止": 0}
VERDICT_LABELS = {"pass": "放行", "drop": "🚫 丟棄", "delay": "⏱ 延遲",
                  "redirect": "↪ 轉址", "redirect_reverse": "↩ 回程還原"}


def _num(text: str, default: float = 0.0) -> float:
    text = (text or "").strip()
    return float(text) if text else default


class FirewallTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._rules: list[InterceptRule] = list(app.rule_store.intercept_rules)
        self._editing_id = ""          # 正在表單中編輯的規則 id（空 = 新增模式）
        self._fw_status: dict[str, str] = {}   # id -> 存在/不存在/未知
        self._fw_busy = False
        self._last_log_render = -1

        banner = tk.Label(
            self,
            text="⚠ 層級 5 會實際影響網路：規則寫錯可能斷線。攔截預設 10 分鐘自動停止、關閉程式即恢復；"
                 "系統防火牆規則則長期有效（可用下方「全部移除」清除）。不要封鎖你不認識的系統程式。",
            bg="#3a2f14", fg=theme.YELLOW, font=app.fonts["ui_small"],
            anchor="w", wraplength=1200, justify="left", padx=10, pady=5)
        banner.pack(fill="x", padx=10, pady=(8, 4))

        sub = ttk.Notebook(self)
        sub.pack(fill="both", expand=True, padx=10)
        self.sub_notebook = sub
        intercept_frame = ttk.Frame(sub)
        fw_frame = ttk.Frame(sub)
        sub.add(intercept_frame, text="⚡ 即時攔截（WinDivert）")
        sub.add(fw_frame, text="🧱 系統防火牆（WFP / netsh）")
        self.intercept_frame = intercept_frame
        self.fw_frame = fw_frame
        self._edit_widgets: list[tk.Widget] = []
        self._build_intercept(intercept_frame)
        self._build_firewall(fw_frame)
        self._build_log()
        self.render_rules()
        self.render_firewall_rules()

    # =====================================================================
    # A. 即時攔截（WinDivert）
    # =====================================================================
    def _build_intercept(self, parent) -> None:
        app = self.app
        ok, msg = divert_availability()
        self._divert_ok = ok
        status_row = ttk.Frame(parent)
        status_row.pack(fill="x", padx=8, pady=(8, 2))
        text = f"WinDivert 狀態：{msg}" if ok else \
            f"⚠ WinDivert 目前不可啟動：{msg}（系統防火牆子分頁不受影響）"
        ttk.Label(status_row, text=text,
                  foreground=theme.TEXT if ok else theme.YELLOW).pack(anchor="w")

        ctl = ttk.Frame(parent)
        ctl.pack(fill="x", padx=8, pady=4)
        self.divert_btn = ttk.Button(ctl, text="▶ 開始即時攔截", style="Accent.TButton",
                                     command=lambda: app.toggle_divert_interception())
        self.divert_btn.pack(side="left")
        if not ok:
            self.divert_btn.config(state="disabled")
        ttk.Label(ctl, text="自動停止：").pack(side="left", padx=(14, 0))
        self.auto_stop_var = tk.StringVar(value="10 分鐘後")
        stop_box = ttk.Combobox(ctl, textvariable=self.auto_stop_var, width=12,
                                values=list(AUTO_STOP_OPTIONS), state="readonly")
        stop_box.pack(side="left", padx=4)
        self.loopback_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctl, text="排除本機 loopback", variable=self.loopback_var,
                        command=self._update_filter_preview).pack(side="left", padx=8)
        self.divert_stats_label = ttk.Label(ctl, text="尚未啟動", style="Muted.TLabel")
        self.divert_stats_label.pack(side="right")

        self.filter_label = ttk.Label(parent, text="", style="Muted.TLabel")
        self.filter_label.pack(anchor="w", padx=10)

        # ---- 規則表單 ----
        form = ttk.Labelframe(parent, text="攔截規則編輯（條件全空 = 全部流量，慎用）")
        form.pack(fill="x", padx=8, pady=4)
        grid = ttk.Frame(form)
        grid.pack(fill="x", padx=6, pady=6)

        self.f_name = tk.StringVar()
        self.f_action = tk.StringVar(value=ACTION_LABELS["block"])
        self.f_direction = tk.StringVar(value=DIR_LABELS["out"])
        self.f_protocol = tk.StringVar(value=PROTO_LABELS["any"])
        self.f_remote_ip = tk.StringVar()
        self.f_remote_port = tk.StringVar()
        self.f_local_port = tk.StringVar()
        self.f_process = tk.StringVar()
        self.f_domain = tk.StringVar()
        self.f_limit_kb = tk.StringVar()
        self.f_delay = tk.StringVar()
        self.f_loss = tk.StringVar()
        self.f_redirect_ip = tk.StringVar()
        self.f_redirect_port = tk.StringVar()

        def field(row, col, label, var, width=16):
            ttk.Label(grid, text=label).grid(row=row, column=col * 2, sticky="e", padx=(10, 4), pady=3)
            entry = ttk.Entry(grid, textvariable=var, width=width)
            entry.grid(row=row, column=col * 2 + 1, sticky="w", pady=3)
            self._edit_widgets.append(entry)
            return entry

        def combo(row, col, label, var, values, width=16):
            ttk.Label(grid, text=label).grid(row=row, column=col * 2, sticky="e", padx=(10, 4), pady=3)
            box = ttk.Combobox(grid, textvariable=var, width=width, values=values, state="readonly")
            box.grid(row=row, column=col * 2 + 1, sticky="w", pady=3)
            self._edit_widgets.append(box)
            return box

        field(0, 0, "名稱：", self.f_name, 20)
        combo(0, 1, "動作：", self.f_action, list(ACTION_LABELS.values()), 18)
        combo(0, 2, "方向：", self.f_direction, list(DIR_LABELS.values()), 10)
        combo(0, 3, "協定：", self.f_protocol, list(PROTO_LABELS.values()), 10)
        field(1, 0, "遠端 IP/CIDR：", self.f_remote_ip, 20)
        field(1, 1, "遠端埠：", self.f_remote_port, 14)
        field(1, 2, "本機埠：", self.f_local_port, 14)
        field(1, 3, "程式名：", self.f_process, 16)
        field(2, 0, "網域（DNS）：", self.f_domain, 20)
        field(2, 1, "限速 KB/s：", self.f_limit_kb, 10)
        field(2, 2, "延遲 ms：", self.f_delay, 10)
        field(2, 3, "丟包 %：", self.f_loss, 10)
        field(3, 0, "轉址 IP：", self.f_redirect_ip, 20)
        field(3, 1, "轉址埠：", self.f_redirect_port, 10)

        btns = ttk.Frame(form)
        btns.pack(fill="x", padx=6, pady=(0, 6))
        add_btn = ttk.Button(btns, text="＋ 新增規則", style="Accent.TButton",
                             command=lambda: self._add_or_update(new=True))
        add_btn.pack(side="left", padx=4)
        upd_btn = ttk.Button(btns, text="套用至所選規則",
                             command=lambda: self._add_or_update(new=False))
        upd_btn.pack(side="left", padx=4)
        load_btn = ttk.Button(btns, text="載入所選到表單", command=self._load_selected_to_form)
        load_btn.pack(side="left", padx=4)
        clear_btn = ttk.Button(btns, text="清除表單", command=self._clear_form)
        clear_btn.pack(side="left", padx=4)
        ttk.Label(btns, text="範本：", style="Muted.TLabel").pack(side="left", padx=(16, 2))
        for label, preset in (("封鎖網域", "domain"), ("弱網路模擬", "impair"),
                              ("全域限速 1MB/s", "limit"), ("封鎖全部出向", "block_all")):
            btn = ttk.Button(btns, text=label, command=lambda p=preset: self._apply_preset(p))
            btn.pack(side="left", padx=2)
            self._edit_widgets.append(btn)
        self._edit_widgets += [add_btn, upd_btn, load_btn]
        self.editing_label = ttk.Label(form, text="", style="Muted.TLabel")
        self.editing_label.pack(anchor="w", padx=10)

        # ---- 規則清單 ----
        list_row = ttk.Frame(parent)
        list_row.pack(fill="x", padx=8, pady=(4, 0))
        ttk.Label(list_row, text="規則依由上而下的順序比對（第一條命中為準）。"
                                  "點「啟用」欄兩下切換啟用；攔截中需先停止才能改規則。").pack(side="left")
        for label, cmd in (("↑ 上移", lambda: self._move_rule(-1)),
                           ("↓ 下移", lambda: self._move_rule(1)),
                           ("啟用/停用", self._toggle_selected_rule),
                           ("刪除", self._delete_selected_rule)):
            btn = ttk.Button(list_row, text=label, command=cmd)
            btn.pack(side="right", padx=2)
            self._edit_widgets.append(btn)

        body = ttk.Frame(parent)
        body.pack(fill="both", expand=True, padx=8, pady=(2, 8))
        self.rules_tree = make_tree(body, [
            ("enabled", "啟用", 52, "center"),
            ("rank", "#", 40, "center"),
            ("name", "名稱", 170, "w"),
            ("action", "動作", 130, "w"),
            ("cond", "條件", 430, "w"),
            ("params", "參數", 160, "w"),
            ("hits", "命中", 76, "e"),
            ("dropped", "丟棄", 76, "e"),
        ], height=9)
        self.rules_tree.bind("<Double-Button-1>", self._on_rules_double_click)

    def _apply_preset(self, preset: str) -> None:
        self._clear_form(keep_name=False)
        if preset == "domain":
            self.f_name.set("封鎖指定網域")
            self.f_action.set(ACTION_LABELS["block"])
            self.f_domain.set("example-ads.com")
        elif preset == "impair":
            self.f_name.set("模擬弱網路")
            self.f_action.set(ACTION_LABELS["impair"])
            self.f_direction.set(DIR_LABELS["both"])
            self.f_delay.set("150")
            self.f_loss.set("5")
        elif preset == "limit":
            self.f_name.set("全域限速 1MB/s")
            self.f_action.set(ACTION_LABELS["limit"])
            self.f_direction.set(DIR_LABELS["both"])
            self.f_limit_kb.set("1024")
        elif preset == "block_all":
            self.f_name.set("⛔ 封鎖全部出向流量")
            self.f_action.set(ACTION_LABELS["block"])
            self.f_direction.set(DIR_LABELS["out"])
        self.editing_label.config(text="已帶入範本到表單，請檢查後按「＋ 新增規則」。")

    # ---------- 表單 <-> 規則 ----------
    def _rule_from_form(self, keep_id: str = "") -> InterceptRule:
        rule = InterceptRule(id=keep_id or InterceptRule().id)
        rule.name = self.f_name.get().strip()
        rule.action = ACTION_BY_LABEL.get(self.f_action.get(), "block")
        rule.direction = DIR_BY_LABEL.get(self.f_direction.get(), "out")
        rule.protocol = PROTO_BY_LABEL.get(self.f_protocol.get(), "any")
        rule.remote_ip = self.f_remote_ip.get().strip()
        rule.remote_port = self.f_remote_port.get().strip()
        rule.local_port = self.f_local_port.get().strip()
        rule.process_name = self.f_process.get().strip()
        rule.domain = self.f_domain.get().strip()
        try:
            rule.limit_bytes_per_sec = int(_num(self.f_limit_kb.get()) * 1024)
            rule.delay_ms = int(_num(self.f_delay.get()))
            rule.loss_percent = float(_num(self.f_loss.get()))
            rule.redirect_port = int(_num(self.f_redirect_port.get()))
        except ValueError:
            raise ValueError("數值欄位（限速/延遲/丟包/轉址埠）只能輸入數字") from None
        rule.redirect_ip = self.f_redirect_ip.get().strip()
        return rule

    def _form_from_rule(self, rule: InterceptRule) -> None:
        self._editing_id = rule.id
        self.f_name.set(rule.name)
        self.f_action.set(ACTION_LABELS.get(rule.action, ACTION_LABELS["block"]))
        self.f_direction.set(DIR_LABELS.get(rule.direction, DIR_LABELS["out"]))
        self.f_protocol.set(PROTO_LABELS.get(rule.protocol, PROTO_LABELS["any"]))
        self.f_remote_ip.set(rule.remote_ip)
        self.f_remote_port.set(rule.remote_port)
        self.f_local_port.set(rule.local_port)
        self.f_process.set(rule.process_name)
        self.f_domain.set(rule.domain)
        self.f_limit_kb.set(f"{rule.limit_bytes_per_sec / 1024:g}" if rule.limit_bytes_per_sec else "")
        self.f_delay.set(str(rule.delay_ms) if rule.delay_ms else "")
        self.f_loss.set(f"{rule.loss_percent:g}" if rule.loss_percent else "")
        self.f_redirect_ip.set(rule.redirect_ip)
        self.f_redirect_port.set(str(rule.redirect_port) if rule.redirect_port else "")
        self.editing_label.config(text=f"編輯中：{rule.name}（改完按「套用至所選規則」）")

    def _clear_form(self, keep_name: bool = True) -> None:
        self._editing_id = ""
        for var in (self.f_remote_ip, self.f_remote_port, self.f_local_port,
                    self.f_process, self.f_domain, self.f_limit_kb, self.f_delay,
                    self.f_loss, self.f_redirect_ip, self.f_redirect_port):
            var.set("")
        if not keep_name:
            self.f_name.set("")
        self.f_action.set(ACTION_LABELS["block"])
        self.f_direction.set(DIR_LABELS["out"])
        self.f_protocol.set(PROTO_LABELS["any"])
        self.editing_label.config(text="")

    def _sync_rules(self) -> None:
        """把清單同步到規則引擎 + 規則檔 + 畫面。"""
        self.app.rule_engine.set_rules(self._rules)
        self.app.rule_store.set_intercept_rules(self._rules)
        self.render_rules()

    def _add_or_update(self, new: bool) -> None:
        try:
            rule = self._rule_from_form("" if new else self._selected_rule_id())
        except ValueError as exc:
            messagebox.showerror("規則不合法", str(exc), parent=self)
            return
        errors = rule.validate()
        if errors:
            messagebox.showerror("規則不合法", "\n".join("・" + e for e in errors), parent=self)
            return
        if new:
            self._rules.append(rule)
            self._editing_id = rule.id
        else:
            idx = next((i for i, r in enumerate(self._rules) if r.id == rule.id), -1)
            if idx < 0:
                messagebox.showinfo("未選擇規則", "請先在下方清單點選要修改的規則。", parent=self)
                return
            old = self._rules[idx]
            rule.hits, rule.dropped, rule.passed = old.hits, old.dropped, old.passed
            rule.created_at = old.created_at
            self._rules[idx] = rule
        self._sync_rules()
        try:
            self.rules_tree.selection_set(rule.id)
        except Exception:
            pass
        self.app.set_status(f"已{'新增' if new else '更新'}攔截規則：{rule.name}。按「開始即時攔截」生效。")

    def _selected_rule_id(self) -> str:
        sel = self.rules_tree.selection()
        return sel[0] if sel else self._editing_id

    def _selected_rule(self) -> InterceptRule | None:
        rid = self._selected_rule_id()
        return next((r for r in self._rules if r.id == rid), None)

    def _load_selected_to_form(self) -> None:
        rule = self._selected_rule()
        if rule:
            self._form_from_rule(rule)

    def _toggle_selected_rule(self) -> None:
        rule = self._selected_rule()
        if rule:
            rule.enabled = not rule.enabled
            self._sync_rules()

    def _delete_selected_rule(self) -> None:
        rule = self._selected_rule()
        if rule and messagebox.askyesno("刪除規則", f"確定要刪除「{rule.name}」？", parent=self):
            self._rules = [r for r in self._rules if r.id != rule.id]
            self._sync_rules()

    def _move_rule(self, delta: int) -> None:
        rid = self._selected_rule_id()
        idx = next((i for i, r in enumerate(self._rules) if r.id == rid), -1)
        target = idx + delta
        if idx < 0 or not (0 <= target < len(self._rules)):
            return
        self._rules[idx], self._rules[target] = self._rules[target], self._rules[idx]
        self._sync_rules()
        try:
            self.rules_tree.selection_set(rid)
        except Exception:
            pass

    def _on_rules_double_click(self, event) -> None:
        try:
            column = self.rules_tree.identify_column(event.x)
        except Exception:
            column = ""
        if str(column) == "#1":
            self._toggle_selected_rule()
        else:
            self._load_selected_to_form()

    def render_rules(self) -> None:
        selected = self._selected_rule_id()
        tree = self.rules_tree
        tree.delete(*tree.get_children())
        for idx, rule in enumerate(self._rules):
            iid = tree.insert("", "end", iid=rule.id, values=(
                "☑" if rule.enabled else "☐", idx + 1, rule.name,
                ACTION_LABELS.get(rule.action, rule.action),
                rule.condition_summary(), rule.params_summary(),
                fmt_count(rule.hits), fmt_count(rule.dropped),
            ))
            if rule.id == (selected or self._editing_id):
                try:
                    tree.selection_set(iid)
                except Exception:
                    pass
        self._update_filter_preview()

    def _update_filter_preview(self) -> None:
        filt = build_divert_filter(self._rules, self.loopback_var.get())
        warn = " ⚠ 含無條件規則，將攔截全部符合方向的流量（效能影響大）" if "(true)" in filt else ""
        shown = filt if len(filt) <= 170 else filt[:170] + "…"
        enabled = sum(1 for r in self._rules if r.enabled)
        self.filter_label.config(
            text=f"共 {len(self._rules)} 條規則（{enabled} 啟用）。WinDivert 範圍：{shown}{warn}")

    # ---------- 攔截 UI 狀態（由 app 呼叫） ----------
    def set_divert_ui(self, running: bool) -> None:
        if running:
            self.divert_btn.config(text="⏹ 停止即時攔截（立即恢復網路）",
                                   style="Danger.TButton", state="normal")
        else:
            self.divert_btn.config(text="▶ 開始即時攔截", style="Accent.TButton",
                                   state="normal" if self._divert_ok else "disabled")
        for widget in self._edit_widgets:
            try:
                widget.config(state="disabled" if running else "normal")
            except Exception:
                pass
        # Combobox 在 normal 下最好維持 readonly 行為（避免手打怪值）
        if not running:
            for widget in self._edit_widgets:
                if isinstance(widget, ttk.Combobox):
                    try:
                        widget.config(state="readonly")
                    except Exception:
                        pass

    def divert_options(self) -> tuple[bool, int]:
        seconds = AUTO_STOP_OPTIONS.get(self.auto_stop_var.get(), 600)
        return bool(self.loopback_var.get()), int(seconds)

    # =====================================================================
    # B. 系統防火牆（WFP / netsh）
    # =====================================================================
    def _build_firewall(self, parent) -> None:
        ok, msg = firewall_availability()
        self._fw_ok = ok
        ttk.Label(parent, text=(f"Windows 防火牆狀態：{msg}" if ok else f"⚠ {msg}")
                  ).pack(anchor="w", padx=8, pady=(8, 2))
        ttk.Label(parent, text="寫入的是系統防火牆封鎖規則（名稱 Win-NetMon-*）：重開機仍在"
                               "，關閉本程式也不會自動移除 — 請用「全部移除」清理。"
                               "依「程式」封鎖是核心層最可靠的擋法（不限 IP/埠）。",
                  style="Muted.TLabel").pack(anchor="w", padx=8)

        form = ttk.Labelframe(parent, text="新增系統防火牆封鎖")
        form.pack(fill="x", padx=8, pady=6)
        grid = ttk.Frame(form)
        grid.pack(fill="x", padx=6, pady=6)
        self.w_kind = tk.StringVar(value=FW_KIND_LABELS["program"])
        self.w_label = tk.StringVar()
        self.w_program = tk.StringVar()
        self.w_remote_ip = tk.StringVar()
        self.w_remote_port = tk.StringVar()
        self.w_protocol = tk.StringVar(value=PROTO_LABELS["any"])
        self.w_direction = tk.StringVar(value=DIR_LABELS["out"])

        ttk.Label(grid, text="種類：").grid(row=0, column=0, sticky="e", padx=(10, 4), pady=3)
        ttk.Combobox(grid, textvariable=self.w_kind, width=18, state="readonly",
                     values=list(FW_KIND_LABELS.values())).grid(row=0, column=1, sticky="w")
        ttk.Label(grid, text="顯示名稱：").grid(row=0, column=2, sticky="e", padx=(10, 4), pady=3)
        ttk.Entry(grid, textvariable=self.w_label, width=22).grid(row=0, column=3, sticky="w")
        ttk.Label(grid, text="方向：").grid(row=0, column=4, sticky="e", padx=(10, 4), pady=3)
        ttk.Combobox(grid, textvariable=self.w_direction, width=10, state="readonly",
                     values=[DIR_LABELS["out"], DIR_LABELS["in"]]).grid(row=0, column=5, sticky="w")

        ttk.Label(grid, text="程式路徑：").grid(row=1, column=0, sticky="e", padx=(10, 4), pady=3)
        ttk.Entry(grid, textvariable=self.w_program, width=44).grid(row=1, column=1, columnspan=2, sticky="w")
        ttk.Button(grid, text="瀏覽…", command=self._browse_program).grid(row=1, column=3, sticky="w", padx=4)
        ttk.Label(grid, text="協定：").grid(row=1, column=4, sticky="e", padx=(10, 4), pady=3)
        ttk.Combobox(grid, textvariable=self.w_protocol, width=10, state="readonly",
                     values=[PROTO_LABELS["any"], "TCP", "UDP"]).grid(row=1, column=5, sticky="w")

        ttk.Label(grid, text="遠端 IP/CIDR：").grid(row=2, column=0, sticky="e", padx=(10, 4), pady=3)
        ttk.Entry(grid, textvariable=self.w_remote_ip, width=22).grid(row=2, column=1, sticky="w")
        ttk.Label(grid, text="遠端埠：").grid(row=2, column=2, sticky="e", padx=(10, 4), pady=3)
        ttk.Entry(grid, textvariable=self.w_remote_port, width=14).grid(row=2, column=3, sticky="w")
        ttk.Label(grid, text="埠需選 TCP/UDP", style="Muted.TLabel").grid(row=2, column=4, columnspan=2, sticky="w")

        btns = ttk.Frame(form)
        btns.pack(fill="x", padx=6, pady=(0, 6))
        self.fw_add_btn = ttk.Button(btns, text="🧱 寫入系統防火牆（封鎖）",
                                     style="Accent.TButton", command=self._add_firewall)
        self.fw_add_btn.pack(side="left", padx=4)
        if not ok:
            self.fw_add_btn.config(state="disabled")
        ttk.Button(btns, text="移除所選", command=self._remove_firewall).pack(side="left", padx=4)
        ttk.Button(btns, text="全部移除", style="Danger.TButton",
                   command=self._remove_all_firewall).pack(side="left", padx=4)
        ttk.Button(btns, text="重新檢查系統狀態", command=self._refresh_firewall_status
                   ).pack(side="left", padx=4)
        self.fw_info = ttk.Label(btns, text="", style="Muted.TLabel")
        self.fw_info.pack(side="right")

        body = ttk.Frame(parent)
        body.pack(fill="both", expand=True, padx=8, pady=(2, 8))
        self.fw_tree = make_tree(body, [
            ("label", "名稱", 180, "w"),
            ("kind", "種類", 110, "w"),
            ("summary", "封鎖內容", 420, "w"),
            ("sysname", "系統規則名", 170, "w"),
            ("status", "系統狀態", 100, "center"),
            ("created", "建立時間", 150, "w"),
        ], height=9)

    def _browse_program(self) -> None:
        path = filedialog.askopenfilename(
            parent=self, title="選擇要封鎖的程式",
            filetypes=(("程式檔", "*.exe"), ("所有檔案", "*.*")))
        if path:
            self.w_program.set(path.replace("/", "\\"))

    def _firewall_from_form(self) -> SystemFirewallRule:
        rule = SystemFirewallRule()
        rule.kind = FW_KIND_BY_LABEL.get(self.w_kind.get(), "program")
        rule.direction = DIR_BY_LABEL.get(self.w_direction.get(), "out")
        proto_label = self.w_protocol.get()
        rule.protocol = PROTO_BY_LABEL.get(proto_label, proto_label.lower())
        rule.program_path = self.w_program.get().strip()
        rule.remote_ip = self.w_remote_ip.get().strip()
        rule.remote_port = self.w_remote_port.get().strip()
        label = sanitize_label(self.w_label.get())
        rule.label = label if self.w_label.get().strip() else rule.summary()
        return rule

    def _add_firewall(self) -> None:
        if self._fw_busy:
            return
        rule = self._firewall_from_form()
        errors = rule.validate()
        if errors:
            messagebox.showerror("輸入不合法", "\n".join("・" + e for e in errors), parent=self)
            return
        if not messagebox.askyesno(
                "確認寫入系統防火牆",
                f"即將寫入 Windows 防火牆封鎖規則：\n\n{rule.summary()}"
                f"\n系統規則名：{rule.system_name}\n\n"
                "此規則長期有效（重開機/關閉本程式都在），確定要寫入嗎？", parent=self):
            return
        self._fw_busy = True
        self.fw_info.config(text="寫入中…")

        def worker():
            success, msg = self.app.firewall_manager.add(rule)
            def done():
                self._fw_busy = False
                if success:
                    self.app.rule_store.upsert_firewall(rule)
                    self._fw_status[rule.id] = "存在 ✅"
                    self.render_firewall_rules()
                    self.app.set_status(f"已寫入系統防火牆封鎖：{rule.summary()}（長期有效，不需保持程式開啟）。")
                    messagebox.showinfo("完成", msg, parent=self)
                else:
                    self.fw_info.config(text="")
                    messagebox.showerror("寫入失敗", msg, parent=self)
            self.app.call_in_ui(done)
        threading.Thread(target=worker, daemon=True).start()

    def _selected_firewall(self) -> SystemFirewallRule | None:
        sel = self.fw_tree.selection()
        if not sel:
            return None
        return next((r for r in self.app.rule_store.firewall_rules
                     if r.id == sel[0]), None)

    def _remove_firewall(self) -> None:
        rule = self._selected_firewall()
        if rule is None or self._fw_busy:
            return
        if not messagebox.askyesno("移除防火牆規則",
                                    f"移除「{rule.label}」的系統封鎖？\n（{rule.summary()}）",
                                    parent=self):
            return
        self._fw_busy = True

        def worker():
            success, msg = self.app.firewall_manager.remove(rule)
            def done():
                self._fw_busy = False
                if success:
                    self.app.rule_store.remove_firewall(rule.id)
                    self.render_firewall_rules()
                    self.app.set_status(f"已移除系統防火牆封鎖：{rule.label}")
                elif messagebox.askyesno(
                        "移除失敗", f"{msg}\n\n要只移除本程式內的紀錄嗎？"
                        "（系統規則可能還在，請之後到 Windows 防火牆進階設定檢查）",
                        parent=self):
                    self.app.rule_store.remove_firewall(rule.id)
                    self.render_firewall_rules()
            self.app.call_in_ui(done)
        threading.Thread(target=worker, daemon=True).start()

    def _remove_all_firewall(self) -> None:
        rules = list(self.app.rule_store.firewall_rules)
        if not rules or self._fw_busy:
            return
        if not messagebox.askyesno("全部移除",
                                    f"要移除本程式寫入的全部 {len(rules)} 條系統防火牆封鎖嗎？",
                                    parent=self):
            return
        self._fw_busy = True
        self.fw_info.config(text="移除中…")

        def worker():
            removed, errors = self.app.firewall_manager.remove_all(rules)
            def done():
                self._fw_busy = False
                self.fw_info.config(text="")
                if not errors:
                    self.app.rule_store.set_firewall_rules([])
                    self._fw_status.clear()
                self.render_firewall_rules()
                note = f"已移除 {removed} 條" + (f"，失敗 {len(errors)} 條：{errors[0]}" if errors else "")
                messagebox.showinfo("全部移除", note, parent=self)
                self.app.set_status(note + "。")
            self.app.call_in_ui(done)
        threading.Thread(target=worker, daemon=True).start()

    def _refresh_firewall_status(self) -> None:
        if self._fw_busy:
            return
        rules = list(self.app.rule_store.firewall_rules)
        self.fw_info.config(text="檢查中…")

        def worker():
            statuses = {}
            for rule in rules:
                statuses[rule.id] = "存在 ✅" if self.app.firewall_manager.exists(rule) else "不存在 ⚠"
            def done():
                self._fw_status.update(statuses)
                self.fw_info.config(text="")
                self.render_firewall_rules()
            self.app.call_in_ui(done)
        threading.Thread(target=worker, daemon=True).start()

    def render_firewall_rules(self) -> None:
        selected = self.fw_tree.selection()
        sel_id = selected[0] if selected else ""
        tree = self.fw_tree
        tree.delete(*tree.get_children())
        rules = self.app.rule_store.firewall_rules
        for rule in rules:
            iid = tree.insert("", "end", iid=rule.id, values=(
                rule.label, FW_KIND_LABELS.get(rule.kind, rule.kind), rule.summary(),
                rule.system_name, self._fw_status.get(rule.id, "未知"),
                time.strftime("%Y-%m-%d %H:%M", time.localtime(rule.created_at)),
            ))
            if rule.id == sel_id:
                try:
                    tree.selection_set(iid)
                except Exception:
                    pass
        if rules and str(self.fw_info.cget("text")) == "":
            self.fw_info.config(text=f"目前共 {len(rules)} 條本程式的封鎖")

    # =====================================================================
    # C. 攔截紀錄 + 週期刷新（app 每秒呼叫 tick_refresh）
    # =====================================================================
    def _build_log(self) -> None:
        frame = ttk.Labelframe(self, text="即時攔截紀錄（封鎖 / 延遲 / 轉址）")
        frame.pack(fill="x", padx=10, pady=(4, 10))
        head = ttk.Frame(frame)
        head.pack(fill="x", padx=6, pady=(4, 0))
        ttk.Button(head, text="清除紀錄與統計", command=self._clear_logs).pack(side="right")
        body = ttk.Frame(frame)
        body.pack(fill="both", expand=True, padx=6, pady=4)
        self.log_tree = make_tree(body, [
            ("time", "時間", 110, "w"),
            ("rule", "規則", 170, "w"),
            ("verdict", "處置", 110, "center"),
            ("flow", "流量", 330, "w"),
            ("proc", "程式", 160, "w"),
            ("reason", "原因", 330, "w"),
        ], height=6)

    def _clear_logs(self) -> None:
        self.app.divert_engine.clear_logs()
        self.app.divert_engine.reset_stats()
        for rule in self._rules:
            rule.hits = rule.dropped = rule.passed = 0
        self._last_log_render = -1
        self.render_rules()
        self._render_logs([])

    def _render_logs(self, entries) -> None:
        tree = self.log_tree
        tree.delete(*tree.get_children())
        last_iid = None
        for i, entry in enumerate(entries):
            last_iid = tree.insert("", "end", iid=f"log{i}", values=(
                fmt_time(entry.timestamp), entry.rule_name,
                VERDICT_LABELS.get(entry.verdict, entry.verdict),
                entry.flow, entry.process_name, entry.reason,
            ))
        if last_iid:
            try:
                tree.see(last_iid)
            except Exception:
                pass

    def tick_refresh(self) -> None:
        engine = self.app.divert_engine
        stats = engine.snapshot_stats()
        if engine.running:
            remain = engine.seconds_remaining()
            remain_s = f"｜自動停止剩 {int(remain) // 60}:{int(remain) % 60:02d}" if remain is not None else ""
            self.divert_stats_label.config(
                text=f"● 攔截中{remain_s}｜已攔 {fmt_count(stats.intercepted)}"
                     f"｜放行 {fmt_count(stats.passed)}"
                     f"｜丟棄 {fmt_count(stats.dropped)}（{fmt_bytes(stats.dropped_bytes)}）"
                     f"｜延遲 {fmt_count(stats.delayed)}｜轉址 {fmt_count(stats.redirected)}")
        elif stats.intercepted:
            self.divert_stats_label.config(
                text=f"已停止｜共攔 {fmt_count(stats.intercepted)}｜丟棄 {fmt_count(stats.dropped)}")
        elif engine.last_error:
            self.divert_stats_label.config(text=f"上次錯誤：{engine.last_error}")
        # 規則命中數就地更新（不重刷整表）
        try:
            for rule in self._rules:
                self.rules_tree.set(rule.id, "hits", fmt_count(rule.hits))
                self.rules_tree.set(rule.id, "dropped", fmt_count(rule.dropped))
        except Exception:
            pass
        # 紀錄有變才重繪
        entries = engine.recent_logs(200)
        marker = len(entries) + (int(entries[-1].timestamp * 10) if entries else 0)
        if marker != self._last_log_render:
            self._last_log_render = marker
            self._render_logs(entries)

    # =====================================================================
    # 供其他分頁帶入（app 中轉）：只填表單、不自動執行，由使用者確認
    # =====================================================================
    def prefill_firewall_program(self, program_path: str, label: str) -> None:
        self.sub_notebook.select(self.fw_frame)
        self.w_kind.set(FW_KIND_LABELS["program"])
        self.w_program.set(program_path)
        self.w_label.set(sanitize_label(f"封鎖 {label}"))
        self.w_remote_ip.set("")
        self.w_remote_port.set("")
        self.fw_info.config(text="已由連線清單帶入程式路徑，請確認後按「寫入系統防火牆」。")

    def prefill_firewall_ip(self, ip: str) -> None:
        self.sub_notebook.select(self.fw_frame)
        self.w_kind.set(FW_KIND_LABELS["ip"])
        self.w_remote_ip.set(ip)
        self.w_label.set(sanitize_label(f"封鎖 {ip}"))
        self.fw_info.config(text="已帶入遠端 IP，請確認後按「寫入系統防火牆」。")

    def prefill_intercept(self, name: str = "", remote_ip: str = "",
                          remote_port: str = "", process_name: str = "") -> None:
        self.sub_notebook.select(self.intercept_frame)
        self._clear_form(keep_name=False)
        self.f_name.set(name or "即時封鎖")
        self.f_remote_ip.set(remote_ip)
        self.f_remote_port.set(remote_port)
        self.f_process.set(process_name)
        self.editing_label.config(text="已由其他分頁帶入條件，請檢查後按「＋ 新增規則」，再開始攔截。")
