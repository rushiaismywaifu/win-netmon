"""層級 5：規則持久化（rules.json）。

存兩種東西：
  - intercept: WinDivert 即時攔截規則（InterceptRule）
  - firewall:  已寫入 Windows 防火牆規則的中繼資料（SystemFirewallRule）
儲存位置：%APPDATA%\\Win-NetMon\\rules.json（沒有 APPDATA 則 ~/.win-netmon/rules.json）。
寫入用暫存檔 + os.replace 的原子方式，避免中途當機把規則檔寫壞。
"""
from __future__ import annotations

import json
import os
import sys
import threading

from .rule_engine import InterceptRule
from .win_firewall import SystemFirewallRule

STORE_VERSION = 1


def default_store_path() -> str:
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        folder = os.path.join(base, "Win-NetMon")
    else:
        folder = os.path.join(os.path.expanduser("~"), ".win-netmon")
    return os.path.join(folder, "rules.json")


class RuleStore:
    def __init__(self, path: str | None = None):
        self.path = path or default_store_path()
        self._lock = threading.Lock()
        self.intercept_rules: list[InterceptRule] = []
        self.firewall_rules: list[SystemFirewallRule] = []
        self.load_error: str = ""

    # ------------------------------------------------------------- 讀取
    def load(self) -> None:
        self.load_error = ""
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            self.intercept_rules = []
            self.firewall_rules = []
            return
        except (OSError, json.JSONDecodeError) as exc:
            self.intercept_rules = []
            self.firewall_rules = []
            self.load_error = f"讀取規則檔失敗（{exc}），已以空規則啟動"
            return
        with self._lock:
            self.intercept_rules = [
                InterceptRule.from_dict(item)
                for item in data.get("intercept", []) if isinstance(item, dict)
            ]
            self.firewall_rules = [
                SystemFirewallRule.from_dict(item)
                for item in data.get("firewall", []) if isinstance(item, dict)
            ]

    # ------------------------------------------------------------- 寫入
    def save(self) -> bool:
        with self._lock:
            payload = {
                "version": STORE_VERSION,
                "intercept": [r.to_dict() for r in self.intercept_rules],
                "firewall": [r.to_dict() for r in self.firewall_rules],
            }
            folder = os.path.dirname(os.path.abspath(self.path))
            try:
                os.makedirs(folder, exist_ok=True)
                tmp = self.path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, ensure_ascii=False, indent=2)
                os.replace(tmp, self.path)
                return True
            except OSError:
                return False

    # ------------------------------------------------------------- 操作
    def set_intercept_rules(self, rules: list[InterceptRule]) -> None:
        with self._lock:
            self.intercept_rules = list(rules)
        self.save()

    def set_firewall_rules(self, rules: list[SystemFirewallRule]) -> None:
        with self._lock:
            self.firewall_rules = list(rules)
        self.save()

    def upsert_firewall(self, rule: SystemFirewallRule) -> None:
        with self._lock:
            self.firewall_rules = [r for r in self.firewall_rules if r.id != rule.id]
            self.firewall_rules.append(rule)
        self.save()

    def remove_firewall(self, rule_id: str) -> None:
        with self._lock:
            self.firewall_rules = [r for r in self.firewall_rules if r.id != rule_id]
        self.save()
