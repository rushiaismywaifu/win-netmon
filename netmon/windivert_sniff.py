"""以 WinDivert SNIFF 模式取代 Npcap 做封包擷取（層級 3/4 的替代後端）。

動機：Npcap 免費版授權禁止隨程式再散布，無法合法打包進單一 exe；
WinDivert 採 LGPL/GPL 授權、驅動已隨 pydivert 打包（本專案層級 5
即時攔截也在使用）。把 WinDivert handle 以 SNIFF 旗標開啟時，封包是
「複製一份給程式」，原始封包照常通過、不需回注 — 功能等同 WinPcap
的被動擷取（官方文件亦如此描述）。

與 Npcap 的差異（誠實限制）：
  - 在 IP 層擷取：有 IPv4/IPv6/TCP/UDP/ICMP 與 payload（DNS/TLS SNI/
    HTTP 分類照常），但**沒有 Ethernet/MAC、沒有 ARP、不能監聽模式**
    抓別台主機的流量，也不能指定單一介面（看全部介面）。
  - 需要系統管理員；驅動在部分 Win11（記憶體完整性/封鎖清單）可能
    被擋（錯誤 577/1275），與層級 5 攔截同一限制。
  - Python 3.10+ 會裝到新版 pydivert（4.x，WinDivert 2.2 驅動）；
    Python 3.9 會裝 pydivert 2.1（WinDivert 1.4）。本模組的開啟方式
    對兩代 API 都做了防禦（flags 關鍵字/位置參數、缺 RECV_ONLY 時
    只用 SNIFF、萬一 SNIFF 開不了就退回「攔下後原樣回注」保底模式，
    保證不會把流量卡住）。

pydivert 文件：https://ffalcinelli.github.io/pydivert/ ；
SNIFF 旗標：https://reqrypt.org/windivert-doc.html#divert_open
"""
from __future__ import annotations

import ipaddress
import re
from typing import Callable

# ---------------------------------------------------------------------------
# BPF（子集）-> WinDivert 過濾語法轉譯
#
# Win-NetMon 的 GUI 用 BPF 欄位（Wireshark/Sniffer 習慣），常見寫法在切到
# WinDivert 後端時自動轉譯：tcp/udp/icmp、[src|dst] port N、port N、
# [src|dst] host IP、[src|dst] net CIDR、portrange A-B，並可用 and/or/not
# 連接。轉不了的（arp、ether、greater/less、主機名、括號表達式…）回傳
# None，由呼叫方提示改用 WinDivert 語法或清空。
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|[^\s]+")


def _check_port(value: str) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _port_expr(proto_ctx: str | None, side: str, lo: int, hi: int) -> str:
    """side: 'src' / 'dst' / 'both'。"""
    sides = ("Dst", "Src") if side == "both" else ("Dst" if side == "dst" else "Src",)
    protos = (proto_ctx,) if proto_ctx else ("tcp", "udp")
    groups = []
    for proto in protos:
        terms = []
        for s in sides:
            field_name = f"{proto}.{s}Port"
            terms.append(f"{field_name} == {lo}" if lo == hi
                         else f"({field_name} >= {lo} and {field_name} <= {hi})")
        groups.append(f"({proto} and ({' or '.join(terms)}))")
    return "(" + " or ".join(groups) + ")"


def _host_expr(addr: str, side: str) -> str | None:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    prefix = "ip" if ip.version == 4 else "ipv6"
    sides = ("Dst", "Src") if side == "both" else ("Dst" if side == "dst" else "Src",)
    terms = [f"{prefix}.{s}Addr == {ip}" for s in sides]
    return "(" + " or ".join(terms) + ")"


def _net_expr(cidr: str, side: str) -> str | None:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    sides = ("Dst", "Src") if side == "both" else ("Dst" if side == "dst" else "Src",)
    if net.version == 6 and net.prefixlen != 128:
        return None  # WinDivert 語法表達不了 IPv6 網段範圍，誠實回報不支援
    prefix = "ip" if net.version == 4 else "ipv6"
    terms = []
    for s in sides:
        field_name = f"{prefix}.{s}Addr"
        if net.num_addresses == 1:
            terms.append(f"{field_name} == {net.network_address}")
        else:
            terms.append(f"({field_name} >= {net.network_address} and "
                         f"{field_name} <= {net.broadcast_address})")
    return "(" + " or ".join(terms) + ")"


def translate_bpf_to_windivert(bpf: str) -> str | None:
    """把常見 BPF 子集轉成 WinDivert 過濾語法；不支援時回傳 None。"""
    text = (bpf or "").strip().lower()
    if not text:
        return "true"
    tokens = _TOKEN_RE.findall(text)
    if "(" in tokens or ")" in tokens:
        return None

    primitives: list[str] = []
    operators: list[str] = []
    i = 0
    n = len(tokens)

    def peek(k: int = 0) -> str:
        j = i + k
        return tokens[j] if j < n else ""

    while i < n:
        negated = False
        if peek() == "not":
            negated = True
            i += 1
            if i >= n:
                return None
        token = peek()
        proto_ctx: str | None = None
        expr: str | None = None

        if token in ("tcp", "udp") and peek(1) in ("port", "src", "dst", "portrange"):
            proto_ctx = token
            i += 1
            token = peek()
        if token in ("tcp", "udp", "icmp"):
            expr = token
            i += 1
        elif token in ("ip", "ip6"):
            expr = "ip" if token == "ip" else "ipv6"
            i += 1
        elif token in ("src", "dst", "port", "host", "net", "portrange"):
            side = "both"
            if token in ("src", "dst"):
                side = token
                i += 1
                token = peek()
            if token == "port":
                port = _check_port(peek(1))
                if port is None:
                    return None
                expr = _port_expr(proto_ctx, side, port, port)
                i += 2
            elif token == "portrange":
                m = re.fullmatch(r"(\d+)-(\d+)", peek(1) or "")
                if not m:
                    return None
                lo, hi = _check_port(m.group(1)), _check_port(m.group(2))
                if lo is None or hi is None or lo > hi:
                    return None
                expr = _port_expr(proto_ctx, side, lo, hi)
                i += 2
            elif token == "host":
                expr = _host_expr(peek(1), side)
                if expr is None:
                    return None
                i += 2
            elif token == "net":
                expr = _net_expr(peek(1), side)
                if expr is None:
                    return None
                i += 2
            else:
                return None
        else:
            return None

        primitives.append(f"not ({expr})" if negated else f"({expr})")
        if i < n:
            op = peek()
            if op not in ("and", "or"):
                return None
            operators.append(op)
            i += 1
            if i >= n:
                return None

    if len(operators) != len(primitives) - 1:
        return None
    out = primitives[0]
    for op, prim in zip(operators, primitives[1:]):
        out += f" {op} {prim}"
    return out


# ---------------------------------------------------------------------------
# Handle 開啟（跨 pydivert 2.x / 4.x 防禦）與封包屬性讀取
# ---------------------------------------------------------------------------

SniffFactory = Callable[[str], tuple[object, bool]]


def open_sniff_handle(filter_string: str) -> tuple[object, bool]:
    """以 SNIFF 模式開啟 WinDivert。回傳 (handle, 是否確為 SNIFF 模式)。

    若該版本 API 不接受旗標，只能退回一般攔截模式時回傳 False，
    呼叫方必須把每個封包原樣回注（send）以免卡住流量。
    """
    import pydivert

    flag_cls = getattr(pydivert, "Flag", None)
    sniff = getattr(flag_cls, "SNIFF", 1)
    recv_only = getattr(flag_cls, "RECV_ONLY", 0)  # 舊版沒有就不用
    flags = sniff | recv_only

    handle = None
    sniff_ok = True
    try:
        handle = pydivert.WinDivert(filter_string, flags=flags)
    except TypeError:
        try:
            layer = pydivert.Layer.NETWORK  # type: ignore[attr-defined]
            handle = pydivert.WinDivert(filter_string, layer, 0, flags)
        except Exception:
            handle = None
    if handle is None:
        handle = pydivert.WinDivert(filter_string)
        sniff_ok = False
    opener = getattr(handle, "open", None)
    if callable(opener):
        opener()
    return handle, sniff_ok


def packet_raw_bytes(pkt) -> bytes:
    raw = getattr(pkt, "raw", b"") or b""
    try:
        return bytes(raw)
    except Exception:
        return b""


def packet_direction(pkt) -> str | None:
    """回傳 'out' / 'in'，判不出來回傳 None（之後用位址推斷）。"""
    is_outbound = getattr(pkt, "is_outbound", None)
    if isinstance(is_outbound, bool):
        return "out" if is_outbound else "in"
    direction = getattr(pkt, "direction", None)
    name = str(getattr(direction, "name", direction) or "").upper()
    if "OUT" in name:
        return "out"
    if "IN" in name:
        return "in"
    return None


def sniff_availability() -> tuple[bool, str]:
    """WinDivert 擷取後端是否就緒（與層級 5 攔截同一就緒條件）。"""
    from .divert_engine import divert_availability

    ok, msg = divert_availability()
    if ok:
        return True, "WinDivert SNIFF 就緒（免 Npcap，IP 層擷取）"
    return False, msg
