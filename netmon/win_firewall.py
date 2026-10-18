"""層級 5（長效封鎖部分）：Windows 防火牆（WFP）規則管理。

透過系統內建的 netsh advfirewall 操作 Windows Defender 防火牆 —
它建構在 WFP（Windows Filtering Platform）之上，由核心直接強制執行，
最大優勢是能精確「依程式路徑」封鎖（封包層技術如 WinDivert 的
NETWORK 層沒有 PID 資訊，做不到這種指定）。

安全設計：
  - 本程式建立的規則名稱一律是 "Win-NetMon-<8碼>"（無空白、無引號問題）。
  - 只管理/刪除自己建立的規則，絕不碰系統既有規則。
  - 所有輸入先驗證/清理；指令用參數陣列傳給 subprocess（不經 shell）。
  - 規則在關閉本程式後仍然有效 — GUI 會清楚說明，並提供一鍵全清。
  - 友好名稱等中繼資料存在本機 rules.json；存在檢查靠 show rule
    輸出內搜規則名，避開 netsh 輸出的語言在地化解析地雷。
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field

from .rule_engine import new_id, parse_ip_spec, parse_port_spec
from .utils import is_admin, is_windows

RULE_NAME_PREFIX = "Win-NetMon-"


def system_rule_name(rule_id: str) -> str:
    return f"{RULE_NAME_PREFIX}{rule_id}"


def sanitize_label(text: str, max_len: int = 40) -> str:
    """清理使用者輸入的顯示名稱（只存本機 JSON，不進指令參數名）。"""
    cleaned = re.sub(r'["\r\n\t\x00-\x1f]', " ", text or "").strip()
    return cleaned[:max_len] or "未命名封鎖"


def firewall_availability() -> tuple[bool, str]:
    """Windows 防火牆規則管理是否可用。"""
    if not is_windows():
        return False, "僅支援 Windows（目前系統無法使用 netsh advfirewall）"
    if not is_admin():
        return False, "需要系統管理員身分才能增刪防火牆規則，請用 run_as_admin.bat 啟動"
    return True, "Windows 防火牆（WFP）可用"


@dataclass
class SystemFirewallRule:
    """一條寫進 Windows 防火牆的封鎖規則（中繼資料存在 rules.json）。"""

    id: str = field(default_factory=new_id)
    label: str = ""                 # 在 GUI 顯示的友好名稱
    kind: str = "program"          # program / ip / port
    direction: str = "out"         # out / in
    protocol: str = "any"          # any / tcp / udp
    program_path: str = ""         # kind=program（也可和 port 組合）
    remote_ip: str = ""            # kind=ip：IP 或 CIDR
    remote_port: str = ""          # kind=port（或 program 組合）：埠規格
    created_at: float = field(default_factory=time.time)

    @property
    def system_name(self) -> str:
        return system_rule_name(self.id)

    def summary(self) -> str:
        dir_s = "出向 ↑" if self.direction == "out" else "入向 ↓"
        if self.kind == "program":
            base = os.path.basename(self.program_path) or self.program_path or "(未指定)"
            text = f"封鎖程式 {base}"
            if self.remote_port:
                text += f"（遠端埠 {self.remote_port}）"
            return f"{dir_s} — {text}"
        if self.kind == "ip":
            text = f"封鎖遠端 {self.remote_ip}"
            if self.remote_port:
                text += f"（埠 {self.remote_port}）"
            return f"{dir_s} — {text}"
        proto = "全部協定" if self.protocol == "any" else self.protocol.upper()
        return f"{dir_s} — 封鎖 {proto} 遠端埠 {self.remote_port}"

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.kind not in ("program", "ip", "port"):
            errors.append(f"未知規則種類：{self.kind}")
        if self.direction not in ("out", "in"):
            errors.append("方向必須是出向或入向")
        if self.protocol not in ("any", "tcp", "udp"):
            errors.append(f"協定不正確：{self.protocol}")
        if self.kind == "program":
            if not self.program_path.strip():
                errors.append("請指定程式路徑（.exe）")
            elif not self.program_path.lower().strip().endswith(".exe"):
                errors.append("程式路徑應以 .exe 結尾")
            elif is_windows() and not os.path.isfile(self.program_path):
                errors.append(f"找不到這個程式檔案：{self.program_path}")
        if self.kind == "ip":
            try:
                if parse_ip_spec(self.remote_ip) is None:
                    errors.append("請輸入遠端 IP 或 CIDR（例如 1.2.3.4 或 10.0.0.0/8）")
            except ValueError:
                errors.append(f"遠端 IP/CIDR 不正確：{self.remote_ip!r}")
        if self.kind == "port" and not self.remote_port.strip():
            errors.append("請輸入遠端埠（例如 443 或 8000-9000）")
        if self.remote_port.strip():
            try:
                parse_port_spec(self.remote_port)
                port_ok = True
            except (ValueError, TypeError):
                errors.append(f"遠端埠規格不正確：{self.remote_port!r}")
                port_ok = False
            if port_ok and self.protocol == "any":
                errors.append("指定埠號時協定請選 TCP 或 UDP（netsh 不允許埠 + 任意協定）")
        return errors

    # ---- netsh 參數組裝 ----
    def add_command(self) -> list[str]:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f'name="{self.system_name}"',
            f"dir={self.direction}",
            "action=block",
            "enable=yes",
            "profile=any",
            'description="Blocked by Win-NetMon (win-netmon)"',
        ]
        if self.program_path.strip():
            cmd.append(f'program="{self.program_path.strip()}"')
        if self.protocol in ("tcp", "udp"):
            cmd.append(f"protocol={self.protocol.upper()}")
        if self.kind == "ip" and self.remote_ip.strip():
            cmd.append(f"remoteip={self.remote_ip.strip()}")
        if self.remote_port.strip() and self.protocol in ("tcp", "udp"):
            # netsh remoteport 接受逗號清單與範圍，格式與本專案的埠規格相容
            cmd.append(f"remoteport={self.remote_port.replace(' ', '')}")
        return cmd

    def delete_command(self) -> list[str]:
        return ["netsh", "advfirewall", "firewall", "delete", "rule",
                f'name="{self.system_name}"']

    def show_command(self) -> list[str]:
        return ["netsh", "advfirewall", "firewall", "show", "rule",
                f'name="{self.system_name}"']

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "SystemFirewallRule":
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in (data or {}).items() if k in allowed})


def _default_runner(cmd: list[str]) -> tuple[int, str]:
    """實際執行 netsh，回傳 (結束碼, 合併輸出)。隱藏主控台視窗。"""
    creationflags = 0
    if is_windows():
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=30, creationflags=creationflags)
    except FileNotFoundError:
        return 127, "找不到 netsh（僅 Windows 內建）"
    except subprocess.TimeoutExpired:
        return 124, "netsh 執行逾時（30 秒）"
    raw = (proc.stdout or b"") + (proc.stderr or b"")
    # netsh 在中文 Windows 用 Big5/CP950 輸出；退而求其次用系統編碼與 utf-8 都試試
    for enc in ("utf-8", "cp950", "mbcs", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    else:
        text = raw.decode("utf-8", errors="replace")
    return proc.returncode, text


def _looks_success(code: int, output: str) -> bool:
    """netsh 新增/刪除成功時輸出 '確定。' / 'Ok.'，結束碼 0。寬鬆判定即可。"""
    if code != 0:
        return False
    lowered = output.lower()
    bad_markers = ("error", "錯誤", "失敗", "requires elevation", "存取被拒", "access is denied")
    return not any(m in lowered for m in bad_markers)


class FirewallManager:
    """增刪查詢本程式的 Windows 防火牆規則。

    runner 可注入以做單元測試（注入時 check_platform 應給 False，
    讓測試在非 Windows 上也能跑）。
    """

    def __init__(self, runner=None, check_platform: bool = True):
        self._runner = runner or _default_runner
        self._check_platform = check_platform

    def _platform_ok(self) -> tuple[bool, str]:
        if not self._check_platform:
            return True, ""
        return firewall_availability()

    def add(self, rule: SystemFirewallRule) -> tuple[bool, str]:
        ok, why = self._platform_ok()
        if not ok:
            return False, why
        code, output = self._runner(rule.add_command())
        if _looks_success(code, output):
            return True, f"已建立防火牆規則 {rule.system_name}"
        return False, f"netsh 回報失敗（code={code}）：{output.strip()[:300] or '無輸出'}"

    def remove(self, rule: SystemFirewallRule) -> tuple[bool, str]:
        ok, why = self._platform_ok()
        if not ok:
            return False, why
        code, output = self._runner(rule.delete_command())
        # 刪除時規則不存在也視為完成（目標狀態就是沒有它）
        if _looks_success(code, output) or not self.exists(rule):
            return True, f"已移除防火牆規則 {rule.system_name}"
        return False, f"netsh 回報失敗（code={code}）：{output.strip()[:300] or '無輸出'}"

    def exists(self, rule: SystemFirewallRule) -> bool:
        ok, _why = self._platform_ok()
        if not ok:
            return False
        code, output = self._runner(rule.show_command())
        # 規則名不受在地化影響 — 它出現在輸出裡就代表規則存在
        return code == 0 and rule.system_name in output

    def remove_all(self, rules: list[SystemFirewallRule]) -> tuple[int, list[str]]:
        removed = 0
        errors: list[str] = []
        for rule in rules:
            ok, msg = self.remove(rule)
            if ok:
                removed += 1
            else:
                errors.append(msg)
        return removed, errors



def resolve_program_path(pid: int | None) -> str:
    """由 PID 反查程式 .exe 完整路徑（給「從連線清單封鎖此程式」用）。"""
    if not pid:
        return ""
    try:
        import psutil

        return psutil.Process(int(pid)).exe() or ""
    except Exception:
        return ""


def is_valid_ip_or_cidr(text: str) -> bool:
    try:
        return parse_ip_spec(text) is not None
    except (ValueError, TypeError):
        return False
