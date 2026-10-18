"""層級 5（即時攔截部分）：封包管制規則引擎。

職責：給一個封包的抽象檢視（PacketView），依規則順序決定要
PASS（放行）/DROP（丟棄）/DELAY（延遲後放行）/REDIRECT（改寫目的）。
本模組不碰任何驅動或 GUI，完全可單元測試；實際把封包從核心
抓出來處理的是 netmon.divert_engine（WinDivert）。

支援的動作（action）：
  allow    直接放行，不再比對後面規則（做例外用）
  block    丟棄封包
  limit    以令牌桶限速（bytes/秒），超過的封包丟棄（TCP 會自然降速）
  impair   模擬弱網路：延遲 delay_ms 毫秒 + 以 loss_percent 機率丟棄
  redirect 把出向封包的目的 IP/埠改寫（回程自動還原，見反向對照表）

比對欄位：方向、協定、遠端/本機 IP(CIDR)、遠端/本機埠（清單與範圍）、
程式名稱（需連線表歸屬，見 traffic.ConnectionIndex）、
DNS 查詢網域（drop 掉就等於封鎖解析，僅對明文 DNS 有效）。
"""
from __future__ import annotations

import ipaddress
import random
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from functools import lru_cache

from .packet_info import parse_dns

# ---- 決策種類 ----
VERDICT_PASS = "pass"
VERDICT_DROP = "drop"
VERDICT_DELAY = "delay"
VERDICT_REDIRECT = "redirect"
VERDICT_REDIRECT_REVERSE = "redirect_reverse"

ACTIONS = ("allow", "block", "limit", "impair", "redirect")
ACTION_LABELS = {
    "allow": "✅ 放行（例外）",
    "block": "🚫 封鎖（丟棄）",
    "limit": "🐌 限速",
    "impair": "📶 弱網路模擬",
    "redirect": "↪ 轉址",
}
DIRECTIONS = ("out", "in", "both")
PROTOCOLS = ("any", "tcp", "udp", "icmp")


def new_id() -> str:
    return uuid.uuid4().hex[:8]


def parse_port_spec(spec: str) -> list[tuple[int, int]]:
    """'80, 443, 8000-9000' -> [(80,80),(443,443),(8000,9000)]；空字串 -> []。"""
    spec = (spec or "").strip()
    if not spec:
        return []
    ranges: list[tuple[int, int]] = []
    for part in spec.replace("；", ",").replace("，", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
        else:
            lo = hi = int(part)
        if not (0 <= lo <= hi <= 65535):
            raise ValueError(f"埠號範圍不正確：{part!r}（必須在 0~65535 且前小後大）")
        ranges.append((lo, hi))
    return ranges


def port_in_spec(port: int | None, ranges: list[tuple[int, int]]) -> bool:
    if not ranges:
        return True
    if port is None:
        return False
    return any(lo <= port <= hi for lo, hi in ranges)


def parse_ip_spec(spec: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """單一 IP 或 CIDR -> network 物件；空字串 -> None（不限制）。"""
    spec = (spec or "").strip()
    if not spec:
        return None
    return ipaddress.ip_network(spec, strict=False)


@lru_cache(maxsize=4096)
def _parsed_address(text: str):
    """字串 -> ipaddress 物件（層級 5 熱路徑：同一個位址字串不重複解析）。"""
    return ipaddress.ip_address(text)


def ip_in_spec(ip: str, network) -> bool:
    if network is None:
        return True
    try:
        attrs = _parsed_address(ip.split("%")[0])
    except ValueError:
        return False
    return attrs.version == network.version and attrs in network


def normalize_domain(domain: str) -> str:
    return (domain or "").strip().lower().rstrip(".")


def domain_matches(qname: str, domain: str) -> bool:
    q = normalize_domain(qname)
    d = normalize_domain(domain)
    return bool(d) and (q == d or q.endswith("." + d))


@dataclass
class InterceptRule:
    """一條即時攔截規則（會存到 rules.json）。執行時統計欄位不持久化。"""

    id: str = field(default_factory=new_id)
    name: str = "未命名規則"
    enabled: bool = True
    action: str = "block"
    direction: str = "out"          # out / in / both
    protocol: str = "any"           # any / tcp / udp / icmp（小寫）
    remote_ip: str = ""             # 單一 IP 或 CIDR，空 = 不限
    remote_port: str = ""           # 埠規格，如 "443"、"80,443"、"8000-9000"
    local_port: str = ""
    process_name: str = ""          # 如 chrome.exe，空 = 不限（需連線表歸屬命中）
    domain: str = ""                # 只對明文 DNS 查詢比對，空 = 不限
    # 動作參數
    limit_bytes_per_sec: int = 0    # action=limit
    delay_ms: int = 0               # action=impair
    loss_percent: float = 0.0       # action=impair
    redirect_ip: str = ""           # action=redirect
    redirect_port: int = 0          # 0 = 不改埠
    note: str = ""
    created_at: float = field(default_factory=time.time)
    # 執行時統計（不寫入 JSON，由 RuleStore 過濾）
    hits: int = field(default=0, repr=False)
    dropped: int = field(default=0, repr=False)
    passed: int = field(default=0, repr=False)

    # ---- 快取的解析結果（第一次用時建立）----
    _net: object = field(default=None, repr=False, compare=False)
    _net_src: str = field(default="\x00", repr=False, compare=False)
    _rports: list | None = field(default=None, repr=False, compare=False)
    _lports: list | None = field(default=None, repr=False, compare=False)

    def network(self):
        if self._net_src != self.remote_ip:
            self._net_src = self.remote_ip
            try:
                self._net = parse_ip_spec(self.remote_ip)
            except ValueError:
                self._net = False  # 解析失敗標記，validate() 會先擋下
        return None if self._net is False else self._net

    def remote_ports(self) -> list[tuple[int, int]]:
        if self._rports is None:
            self._rports = parse_port_spec(self.remote_port)
        return self._rports

    def local_ports(self) -> list[tuple[int, int]]:
        if self._lports is None:
            self._lports = parse_port_spec(self.local_port)
        return self._lports

    def invalidate_cache(self) -> None:
        self._net = None
        self._net_src = "\x00"
        self._rports = None
        self._lports = None

    def validate(self) -> list[str]:
        """回傳錯誤訊息清單（空 = 合法）。GUI 新增/修改規則時先呼叫。"""
        errors: list[str] = []
        if not self.name.strip():
            errors.append("規則名稱不能空白")
        if self.action not in ACTIONS:
            errors.append(f"未知動作：{self.action}")
        if self.direction not in DIRECTIONS:
            errors.append(f"未知方向：{self.direction}")
        if self.protocol not in PROTOCOLS:
            errors.append(f"未知協定：{self.protocol}")
        try:
            parse_ip_spec(self.remote_ip)
        except ValueError:
            errors.append(f"遠端 IP/CIDR 不正確：{self.remote_ip!r}（範例：1.2.3.4 或 10.0.0.0/8）")
        for label, spec in (("遠端埠", self.remote_port), ("本機埠", self.local_port)):
            try:
                parse_port_spec(spec)
            except (ValueError, TypeError):
                errors.append(f"{label}規格不正確：{spec!r}（範例：443 或 80,443 或 8000-9000）")
        if self.action == "limit" and self.limit_bytes_per_sec <= 0:
            errors.append("限速規則必須設定大於 0 的速率")
        if self.action == "impair":
            if self.delay_ms < 0:
                errors.append("延遲毫秒不可為負數")
            if not (0 <= self.loss_percent <= 100):
                errors.append("丟包百分比必須在 0~100")
            if self.delay_ms == 0 and self.loss_percent == 0:
                errors.append("弱網路模擬請至少設定延遲或丟包其中一個")
        if self.action == "redirect":
            try:
                ipaddress.ip_address(self.redirect_ip)
            except ValueError:
                errors.append(f"轉址目標 IP 不正確：{self.redirect_ip!r}")
            if self.redirect_port and not (1 <= self.redirect_port <= 65535):
                errors.append("轉址目標埠必須在 1~65535")
            if self.direction == "in":
                errors.append("轉址只作用於出向流量，方向請選「出向」或「雙向」")
        return errors

    def matches(self, view: "PacketView") -> bool:
        """這個封包是否命中本規則的條件（不看動作）。"""
        if not self.enabled:
            return False
        if self.direction != "both" and self.direction != view.direction:
            return False
        if self.protocol != "any" and self.protocol != view.protocol.lower():
            if not (self.protocol == "icmp" and view.protocol.lower() in ("icmp", "icmpv6")):
                return False
        # 出向：遠端 = 目的；入向：遠端 = 來源
        remote_ip = view.dst_ip if view.direction == "out" else view.src_ip
        remote_port = view.dst_port if view.direction == "out" else view.src_port
        local_port = view.src_port if view.direction == "out" else view.dst_port
        if not ip_in_spec(remote_ip, self.network()):
            return False
        if not port_in_spec(remote_port, self.remote_ports()):
            return False
        if not port_in_spec(local_port, self.local_ports()):
            return False
        if self.process_name:
            if not view.process_name or view.process_name.lower() != self.process_name.strip().lower():
                return False
        if self.domain:
            if view.dns_qname is None:
                return False
            if not domain_matches(view.dns_qname, self.domain):
                return False
        return True

    def condition_summary(self) -> str:
        parts: list[str] = []
        dir_s = {"out": "出向 ↑", "in": "入向 ↓", "both": "雙向"}[self.direction]
        parts.append(dir_s)
        parts.append("全部協定" if self.protocol == "any" else self.protocol.upper())
        if self.domain:
            parts.append(f"網域 {self.domain}（DNS）")
        if self.remote_ip:
            parts.append(f"遠端 {self.remote_ip}")
        if self.remote_port:
            parts.append(f"遠端埠 {self.remote_port}")
        if self.local_port:
            parts.append(f"本機埠 {self.local_port}")
        if self.process_name:
            parts.append(f"程式 {self.process_name}")
        if len(parts) <= 2:
            parts.append("全部流量")
        return "、".join(parts)

    def params_summary(self) -> str:
        if self.action == "limit":
            return f"上限 {self.limit_bytes_per_sec / 1024:.0f} KB/s"
        if self.action == "impair":
            bits = []
            if self.delay_ms:
                bits.append(f"延遲 {self.delay_ms} ms")
            if self.loss_percent:
                bits.append(f"丟包 {self.loss_percent:g}%")
            return "、".join(bits) or "-"
        if self.action == "redirect":
            target = self.redirect_ip
            if self.redirect_port:
                target += f":{self.redirect_port}"
            return f"→ {target}"
        return "-"

    def to_dict(self) -> dict:
        data = asdict(self)
        for key in ("hits", "dropped", "passed", "_net", "_net_src", "_rports", "_lports"):
            data.pop(key, None)
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "InterceptRule":
        allowed = {f.name for f in cls.__dataclass_fields__.values()
                   if not f.name.startswith("_")}
        clean = {k: v for k, v in (data or {}).items() if k in allowed}
        rule = cls(**clean)
        rule.action = str(rule.action).lower()
        rule.protocol = str(rule.protocol).lower()
        rule.direction = str(rule.direction).lower()
        if rule.action not in ACTIONS:
            rule.action = "block"
        return rule


@dataclass
class PacketView:
    """給規則引擎判斷的封包抽象檢視。"""

    direction: str                  # out / in
    protocol: str                   # TCP / UDP / ICMP / ICMPv6 / OTHER
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    length: int = 0
    payload: bytes = b""
    process_name: str = ""
    pid: int = 0
    timestamp: float = field(default_factory=time.time)
    _dns_name: str | None = field(default=None, repr=False)
    _dns_done: bool = field(default=False, repr=False)

    @property
    def dns_qname(self) -> str | None:
        """若為明文 DNS 查詢，回傳所查詢的網域名稱（延遲解析、只算一次）。"""
        if self._dns_done:
            return self._dns_name
        self._dns_done = True
        self._dns_name = None
        if self.payload and 53 in (self.src_port, self.dst_port):
            data = self.payload
            if self.protocol == "TCP" and len(data) > 2:
                data = data[2:]  # TCP DNS 有 2-byte 長度前綴
            info = parse_dns(data)
            if info and not info["is_response"]:
                self._dns_name = info["qname"]
        return self._dns_name

    @property
    def flow_text(self) -> str:
        s = f"{self.src_ip}:{self.src_port}" if self.src_port is not None else self.src_ip
        d = f"{self.dst_ip}:{self.dst_port}" if self.dst_port is not None else self.dst_ip
        return f"{s} → {d}"


@dataclass
class Decision:
    verdict: str = VERDICT_PASS
    rule: InterceptRule | None = None
    reason: str = ""
    delay_ms: int = 0
    new_dst_ip: str = ""
    new_dst_port: int | None = None
    new_src_ip: str = ""
    new_src_port: int | None = None

    @property
    def modified(self) -> bool:
        return self.verdict in (VERDICT_REDIRECT, VERDICT_REDIRECT_REVERSE)


class _TokenBucket:
    """限速用令牌桶：tokens 隨時間補滿，封包長度不足以扣除就丟棄。"""

    def __init__(self, rate: int):
        self.rate = max(rate, 1)
        self.capacity = max(rate, 64 * 1024)
        self.tokens = float(self.capacity)
        self.updated = 0.0

    def allow(self, size: int, now: float) -> bool:
        if self.updated == 0.0:
            self.updated = now
        elapsed = max(now - self.updated, 0.0)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = now
        if size <= self.tokens:
            self.tokens -= size
            return True
        return False


class RuleEngine:
    """依序比對規則、做出決策，並維護限速桶/轉址反向表/命中統計（thread-safe）。"""

    def __init__(self, rules: list[InterceptRule] | None = None,
                 rng: random.Random | None = None):
        self._lock = threading.Lock()
        self._rules: list[InterceptRule] = list(rules or [])
        self._buckets: dict[str, _TokenBucket] = {}
        # 轉址反向表：(proto, 轉後IP, 轉後埠, 本機IP, 本機埠) -> (原IP, 原埠, 寫入時刻)
        self._reverse: dict[tuple, tuple[str, int | None, float]] = {}
        self._rng = rng or random.Random()
        self._last_prune = 0.0

    # ------------------------------------------------------------- 規則管理
    def set_rules(self, rules: list[InterceptRule]) -> None:
        with self._lock:
            self._rules = list(rules)
            live = {r.id for r in rules}
            self._buckets = {k: v for k, v in self._buckets.items() if k in live}

    def get_rules(self) -> list[InterceptRule]:
        with self._lock:
            return list(self._rules)

    def enabled_rules(self) -> list[InterceptRule]:
        return [r for r in self.get_rules() if r.enabled]

    # ------------------------------------------------------------- 決策
    def evaluate(self, view: PacketView, now: float | None = None) -> Decision:
        now_mono = time.monotonic() if now is None else now
        proto = view.protocol.upper()

        with self._lock:
            # 1) 轉址回程還原（優先於一般規則）
            if view.direction == "in" and view.src_port is not None:
                hit = self._reverse.get(
                    (proto, view.src_ip, view.src_port, view.dst_ip, view.dst_port))
                if hit is not None:
                    orig_ip, orig_port, _ts = hit
                    return Decision(verdict=VERDICT_REDIRECT_REVERSE,
                                    new_src_ip=orig_ip, new_src_port=orig_port,
                                    reason="轉址回程還原")
            # 偶爾清理過期轉址表（120 秒）
            if now_mono - self._last_prune > 30:
                self._last_prune = now_mono
                self._reverse = {k: v for k, v in self._reverse.items()
                                 if now_mono - v[2] < 120}

            # 2) 規則依序比對，第一條命中決定結果
            for rule in self._rules:
                if not rule.matches(view):
                    continue
                if rule.action == "redirect" and view.direction != "out":
                    continue  # 入向轉址靠反向表，不走一般比對
                rule.hits += 1
                if rule.action == "allow":
                    rule.passed += 1
                    return Decision(VERDICT_PASS, rule, "命中放行規則")
                if rule.action == "block":
                    rule.dropped += 1
                    reason = "封鎖"
                    if rule.domain and view.dns_qname:
                        reason = f"封鎖網域解析 {view.dns_qname}"
                    return Decision(VERDICT_DROP, rule, reason)
                if rule.action == "limit":
                    bucket = self._buckets.get(rule.id)
                    if bucket is None or bucket.rate != rule.limit_bytes_per_sec:
                        bucket = _TokenBucket(rule.limit_bytes_per_sec)
                        self._buckets[rule.id] = bucket
                    if bucket.allow(max(view.length, 1), now_mono):
                        rule.passed += 1
                        return Decision(VERDICT_PASS, rule, "限速範圍內放行")
                    rule.dropped += 1
                    return Decision(VERDICT_DROP, rule, "超過限速丟棄")
                if rule.action == "impair":
                    if rule.loss_percent > 0 and \
                            self._rng.random() * 100 < rule.loss_percent:
                        rule.dropped += 1
                        return Decision(VERDICT_DROP, rule, "模擬丟包")
                    rule.passed += 1
                    if rule.delay_ms > 0:
                        return Decision(VERDICT_DELAY, rule, f"延遲 {rule.delay_ms} ms",
                                        delay_ms=int(rule.delay_ms))
                    return Decision(VERDICT_PASS, rule, "未被丟包")
                if rule.action == "redirect":
                    rule.passed += 1
                    new_port = rule.redirect_port or view.dst_port
                    if view.dst_port is not None and view.src_port is not None:
                        self._reverse[(proto, rule.redirect_ip, new_port,
                                       view.src_ip, view.src_port)] = (
                            view.dst_ip, view.dst_port, now_mono)
                    return Decision(VERDICT_REDIRECT, rule,
                                    f"轉址到 {rule.redirect_ip}"
                                    + (f":{rule.redirect_port}" if rule.redirect_port else ""),
                                    new_dst_ip=rule.redirect_ip,
                                    new_dst_port=rule.redirect_port or None)
        return Decision(VERDICT_PASS, None, "未命中任何規則")


# ---------------------------------------------------------------------------
# WinDivert 過濾語法產生：只讓「可能命中規則」的封包進 Python，
# 其餘封包留在核心高速路徑（Python 端仍會做權威比對，過濾寬一點是安全的）。
# ---------------------------------------------------------------------------

def _v4_range_frag(field_name: str, network) -> str:
    if network.prefixlen == 32:
        return f"{field_name} == {network.network_address}"
    return (f"{field_name} >= {network.network_address} and "
            f"{field_name} <= {network.broadcast_address}")


def _ip_frag(rule: InterceptRule) -> str:
    net = rule.network()
    if net is None:
        return ""
    directions = ("out", "in") if rule.direction == "both" else (rule.direction,)
    frags = []
    for d in directions:
        if net.version == 4:
            field_name = "ip.DstAddr" if d == "out" else "ip.SrcAddr"
            frags.append(f"({_v4_range_frag(field_name, net)})")
        else:
            field_name = "ipv6.DstAddr" if d == "out" else "ipv6.SrcAddr"
            if net.prefixlen == 128:
                frags.append(f"({field_name} == {net.network_address})")
            else:
                frags.append("(ipv6)")  # IPv6 CIDR 在過濾層表達不了，交給 Python
    return "(" + " or ".join(frags) + ")" if frags else ""


def _port_frag_for(proto: str, ranges: list[tuple[int, int]], kind: str,
                   rule_direction: str, packet_dir: str) -> str:
    """kind: remote/local。用 packet_dir 決定對應 SrcPort 還是 DstPort。"""
    if not ranges:
        return ""
    if kind == "remote":
        side = "Dst" if packet_dir == "out" else "Src"
    else:
        side = "Src" if packet_dir == "out" else "Dst"
    field_name = f"{proto}.{side}Port"
    parts = []
    for lo, hi in ranges:
        if lo == hi:
            parts.append(f"{field_name} == {lo}")
        else:
            parts.append(f"({field_name} >= {lo} and {field_name} <= {hi})")
    return "(" + " or ".join(parts) + ")"


def _rule_filter_fragment(rule: InterceptRule) -> str:
    parts: list[str] = []
    directions = ("out", "in") if rule.direction == "both" else (rule.direction,)
    if rule.direction != "both":
        parts.append("outbound" if rule.direction == "out" else "inbound")
    if rule.protocol == "tcp":
        parts.append("tcp")
    elif rule.protocol == "udp":
        parts.append("udp")
    elif rule.protocol == "icmp":
        parts.append("(icmp or icmpv6)")

    ip_frag = _ip_frag(rule)
    if ip_frag:
        parts.append(ip_frag)

    # 埠只有在協定明確時才能安全寫進過濾語法；any 時放寬給 Python 比對
    if rule.protocol in ("tcp", "udp"):
        port_frags = []
        for d in directions:
            sub = []
            for kind, ranges in (("remote", rule.remote_ports()),
                                 ("local", rule.local_ports())):
                frag = _port_frag_for(rule.protocol, ranges, kind, rule.direction, d)
                if frag:
                    sub.append(frag)
            if sub:
                port_frags.append("(" + " and ".join(sub) + ")")
        if port_frags:
            parts.append("(" + " or ".join(port_frags) + ")")

    if rule.domain:
        parts.append("((udp and udp.DstPort == 53) or (tcp and tcp.DstPort == 53))")

    frag = " and ".join(parts) if parts else "true"

    # 轉址規則也要攔截回程封包才能還原來源
    if rule.action == "redirect" and rule.redirect_ip:
        try:
            target = ipaddress.ip_address(rule.redirect_ip)
            field_name = "ip.SrcAddr" if target.version == 4 else "ipv6.SrcAddr"
            frag = f"(({frag}) or (inbound and {field_name} == {target}))"
        except ValueError:
            pass
    return f"({frag})"


def build_divert_filter(rules: list[InterceptRule], exclude_loopback: bool = True) -> str:
    """把所有啟用規則編譯成 WinDivert 過濾字串（沒有可用規則時回傳 'false'）。"""
    enabled = [r for r in rules if r.enabled]
    if not enabled:
        return "false"
    body = " or ".join(_rule_filter_fragment(r) for r in enabled)
    if exclude_loopback:
        return f"not loopback and ({body})"
    return body
