"""層級 4：擷取並解析封包內容（雙後端：Npcap/Scapy 或 WinDivert SNIFF）。

- 後端 A（Npcap + Scapy）：AsyncSniffer 在背景擷取完整 Ethernet 框。
- 後端 B（WinDivert SNIFF）：免安裝 Npcap，驅動隨 pydivert 打包；
  IP 層被動複本擷取（無 Ethernet/ARP），見 netmon.windivert_sniff。
- backend="auto"（預設）：優先 Npcap，缺 Npcap 時自動退回 WinDivert。
- 每個封包會分類協定（DNS / TLS(SNI) / HTTP / QUIC …）、判斷方向、
  並透過層級 3 的連線表索引歸屬到程式。
- 支援 BPF 過濾語法（同 Wireshark capture filter）、存/讀 .pcap 檔。
- Scapy 採延遲載入：未安裝時層級 1、2 仍可正常使用，GUI 會顯示安裝提示。

注意：HTTPS/TLS 內容是加密的，只能看到 IP、埠、網域（SNI）與流量大小。
"""
from __future__ import annotations

import importlib.util
import threading
import time
from dataclasses import dataclass, field
from types import ModuleType
from typing import Callable

from .ip_packet import parse_ip_packet
from .packet_info import classify_payload
from .traffic import UNKNOWN_NAME, UNKNOWN_PID, ConnectionIndex
from .utils import check_npcap, get_local_ips, is_windows
from .windivert_sniff import (
    open_sniff_handle, packet_direction, packet_raw_bytes, sniff_availability,
    translate_bpf_to_windivert,
)


def _scapy_spec_exists() -> bool:
    """用 find_spec 探測 Scapy 是否可載入（不會真的 import）。"""
    try:
        return importlib.util.find_spec("scapy") is not None
    except (ImportError, ValueError):
        return False


# Scapy 採延遲載入：import 本模組（GUI 啟動、WinDivert 路徑、層級 1~2）不會
# 付下 scapy 的大型 import（實測約 0.4~0.5 秒）；第一次真的需要 Npcap 擷取、
# 介面清單、pcap 存讀或逐層解析時才載入。SCAPY_AVAILABLE 先用 find_spec
# 判斷；屆時 import 若失敗（安裝損壞），旗標會被修正成真正原因。
SCAPY_AVAILABLE = _scapy_spec_exists()
SCAPY_ERROR = "" if SCAPY_AVAILABLE else "找不到 scapy 套件"

_scapy_mod: ModuleType | None = None


def _get_scapy() -> ModuleType:
    """延遲載入 Scapy，回傳 scapy.all 模組；失敗時更新旗標後抛原例外。"""
    global _scapy_mod, SCAPY_AVAILABLE, SCAPY_ERROR
    if _scapy_mod is None:
        try:
            import scapy.all as _mod
        except Exception as exc:
            SCAPY_AVAILABLE = False
            SCAPY_ERROR = f"{type(exc).__name__}: {exc}"
            raise
        SCAPY_AVAILABLE = True
        SCAPY_ERROR = ""
        try:
            import scapy.layers.inet6  # noqa: F401 （確保 inet6 層註冊）
        except Exception:
            pass
        _scapy_mod = _mod
    return _scapy_mod


def capture_availability() -> tuple[bool, str]:
    """封包擷取是否可用，回傳 (可用, 說明文字)。"""
    if not SCAPY_AVAILABLE:
        return False, f"Scapy 載入失敗（{SCAPY_ERROR}）。請執行：pip install scapy"
    ok, msg = check_npcap()
    if is_windows() and not ok:
        return False, msg
    return True, "Scapy + Npcap 就緒" if is_windows() else "Scapy 就緒"


BACKEND_NPCAP = "npcap"
BACKEND_WINDIVERT = "windivert"
BACKEND_AUTO = "auto"


def backend_availability() -> dict[str, tuple[bool, str]]:
    """各擷取後端的就緒狀態：{"npcap": (ok, 說明), "windivert": (ok, 說明)}。"""
    return {
        BACKEND_NPCAP: capture_availability(),
        BACKEND_WINDIVERT: sniff_availability(),
    }


def any_capture_availability() -> tuple[bool, str]:
    """任一擷取後端可用就回傳 True（說明會註明用的是哪一條路）。"""
    backs = backend_availability()
    npc_ok, npc_msg = backs[BACKEND_NPCAP]
    wd_ok, wd_msg = backs[BACKEND_WINDIVERT]
    if npc_ok:
        return True, npc_msg
    if wd_ok:
        return True, f"Npcap 未就緒，改用 WinDivert：{wd_msg}"
    return False, f"Scapy/Npcap：{npc_msg}；WinDivert：{wd_msg}"


@dataclass
class PacketRecord:
    """一個已解析封包（供 GUI 表格與詳細檢視使用）。"""

    index: int
    timestamp: float
    length: int
    src: str = ""
    dst: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    transport: str = ""              # TCP / UDP / ICMP / ARP ...
    protocol: str = ""               # 應用層協定：DNS / TLS / HTTP / TCP ...
    info: str = ""
    direction: str = "transit"       # out（↑）/ in（↓）/ transit（↔）
    pid: int = UNKNOWN_PID
    process_name: str = UNKNOWN_NAME
    raw: bytes = b""
    payload: bytes = b""
    link_type: str = "ethernet"      # ethernet（含 L2 標頭）/ ip（WinDivert，僅 IP 本體）
    _dissection: str = field(default="", repr=False)

    @property
    def direction_arrow(self) -> str:
        return {"out": "↑", "in": "↓"}.get(self.direction, "↔")

    @property
    def src_endpoint(self) -> str:
        return f"{self.src}:{self.src_port}" if self.src_port is not None else self.src

    @property
    def dst_endpoint(self) -> str:
        return f"{self.dst}:{self.dst_port}" if self.dst_port is not None else self.dst

    @property
    def remote_endpoint(self) -> str:
        return self.dst_endpoint if self.direction == "out" else self.src_endpoint

    def dissect(self) -> str:
        """逐層解析文字（類似 Wireshark 的封包詳細資料），第一次呼叫時才產生。"""
        if self._dissection:
            return self._dissection
        if self.raw:
            try:
                sc = _get_scapy()
                if self.link_type == "ip":
                    pkt = (sc.IP if (self.raw[0] >> 4) == 4 else sc.IPv6)(self.raw)
                else:
                    pkt = sc.Ether(self.raw)
                self._dissection = pkt.show(dump=True)
                return self._dissection
            except Exception:
                pass
        self._dissection = (
            f"協定：{self.protocol}（{self.transport}）\n"
            f"來源：{self.src_endpoint}\n目的：{self.dst_endpoint}\n"
            f"長度：{self.length} bytes\n資訊：{self.info}\n"
            "（完整逐層解析需要 Scapy）"
        )
        return self._dissection


# TCP 旗標位元 -> 名稱
_TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
              (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]


def _tcp_flag_str(flags: int) -> str:
    names = [name for bit, name in _TCP_FLAGS if flags & bit]
    return ", ".join(names) if names else "無"


def packet_to_record(pkt, index: int, local_ips: set[str],
                     conn_index: ConnectionIndex | None = None) -> PacketRecord:
    """把 Scapy 封包轉成 PacketRecord（含分類、方向、程式歸屬）。"""
    rec = PacketRecord(index=index, timestamp=float(pkt.time), length=len(pkt))
    try:
        rec.raw = bytes(pkt)
    except Exception:
        rec.raw = b""

    # 延遲載入後的 Scapy 存取（真的有執行緒需要時才會觸發第一次 import）
    sc = None
    if SCAPY_AVAILABLE:
        try:
            sc = _get_scapy()
        except Exception:
            sc = None
    IP = IPv6 = TCP = UDP = ICMP = ARP = Ether = ICMPv6EchoRequest = ICMPv6EchoReply = None
    if sc is not None:
        IP, IPv6, TCP, UDP, ICMP, ARP, Ether = (
            sc.IP, sc.IPv6, sc.TCP, sc.UDP, sc.ICMP, sc.ARP, sc.Ether)
        ICMPv6EchoRequest, ICMPv6EchoReply = (sc.ICMPv6EchoRequest, sc.ICMPv6EchoReply)

    # 讀 DLT_RAW 的 pcap（如 WinDivert 存的）時封包沒有 Ethernet 層
    rec.link_type = "ethernet" if (Ether is not None and Ether in pkt) else "ip"

    ip_layer = None
    if ip_layer is None and IP is not None and IP in pkt:
        ip_layer = pkt[IP]
    if ip_layer is None and IPv6 is not None and IPv6 in pkt:
        ip_layer = pkt[IPv6]

    if ip_layer is not None:
        rec.src = str(ip_layer.src).split("%")[0]
        rec.dst = str(ip_layer.dst).split("%")[0]
        payload = b""
        if TCP in pkt:
            layer = pkt[TCP]
            rec.transport = "TCP"
            rec.src_port = int(layer.sport)
            rec.dst_port = int(layer.dport)
            payload = bytes(layer.payload)
            flags = int(layer.flags)
            rec.info = (
                f"{layer.sport} → {layer.dport} [{_tcp_flag_str(flags)}] "
                f"Seq={layer.seq} Ack={layer.ack} Win={layer.window} Len={len(payload)}"
            )
        elif UDP in pkt:
            layer = pkt[UDP]
            rec.transport = "UDP"
            rec.src_port = int(layer.sport)
            rec.dst_port = int(layer.dport)
            payload = bytes(layer.payload)
            rec.info = f"{layer.sport} → {layer.dport}，長度 {len(payload)}"
        elif ICMP in pkt:
            rec.transport = rec.protocol = "ICMP"
            icmp_types = {0: "Echo 回覆（pong）", 3: "目的地無法到達",
                          8: "Echo 請求（ping）", 11: "TTL 超時"}
            rec.info = icmp_types.get(int(pkt[ICMP].type), f"type={pkt[ICMP].type}")
        elif ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt:
            rec.transport = rec.protocol = "ICMPv6"
            rec.info = "Echo 請求（ping6）" if ICMPv6EchoRequest in pkt else "Echo 回覆（pong6）"
        else:
            rec.transport = f"IP({getattr(ip_layer, 'proto', getattr(ip_layer, 'nh', '?'))})"
            rec.protocol = rec.transport
        rec.payload = payload

        if rec.transport in ("TCP", "UDP"):
            app_proto, app_info = classify_payload(
                rec.transport, rec.src_port, rec.dst_port, payload)
            rec.protocol = app_proto
            if app_proto != rec.transport and app_info:
                rec.info = app_info
            elif not payload and rec.transport == "UDP":
                rec.info = app_info or rec.info
    elif ARP is not None and ARP in pkt:
        arp = pkt[ARP]
        rec.transport = rec.protocol = "ARP"
        rec.src = str(arp.psrc)
        rec.dst = str(arp.pdst)
        if int(arp.op) == 1:
            rec.info = f"誰有 {arp.pdst}？ 告訴 {arp.psrc}"
        else:
            rec.info = f"{arp.psrc} 在 {arp.hwsrc}"
    else:
        if Ether is not None and Ether in pkt:
            rec.src = str(pkt[Ether].src)
            rec.dst = str(pkt[Ether].dst)
        rec.transport = rec.protocol = pkt.lastlayer().name if sc is not None else "?"
        rec.info = "非 IP 封包"

    _apply_direction_and_owner(rec, local_ips, conn_index)
    return rec


def _apply_direction_and_owner(rec: PacketRecord, local_ips: set[str],
                               conn_index: ConnectionIndex | None,
                               direction_hint: str | None = None) -> None:
    """判斷方向並把封包歸屬到程式（direction_hint 有值時以它為準）。"""
    if direction_hint in ("out", "in"):
        rec.direction = direction_hint
    elif rec.src in local_ips:
        rec.direction = "out"
    elif rec.dst in local_ips:
        rec.direction = "in"
    else:
        rec.direction = "transit"

    if conn_index is not None and rec.transport in ("TCP", "UDP"):
        if rec.direction == "out":
            pid, name = conn_index.lookup(rec.transport, rec.src, rec.src_port,
                                          rec.dst, rec.dst_port)
        else:
            pid, name = conn_index.lookup(rec.transport, rec.dst, rec.dst_port,
                                          rec.src, rec.src_port)
        rec.pid = pid or UNKNOWN_PID
        rec.process_name = name


_ICMP4_NAMES = {0: "Echo 回覆（pong）", 3: "目的地無法到達",
                8: "Echo 請求（ping）", 11: "TTL 超時"}
_ICMP6_NAMES = {1: "目的地無法到達", 3: "TTL 超時",
                128: "Echo 請求（ping6）", 129: "Echo 回覆（pong6）"}


def record_from_ip_bytes(data: bytes, index: int, local_ips: set[str],
                         conn_index: ConnectionIndex | None = None,
                         timestamp: float | None = None,
                         direction_hint: str | None = None) -> PacketRecord:
    """把一個 IP 本體位元組（WinDivert 擷取）轉成 PacketRecord。"""
    data = bytes(data)
    rec = PacketRecord(index=index, timestamp=timestamp or time.time(),
                       length=len(data), raw=data, link_type="ip")
    parsed = parse_ip_packet(data)
    if parsed is None:
        rec.transport = rec.protocol = "IP?"
        rec.info = f"無法解析的 IP 封包（{len(data)} bytes）"
        _apply_direction_and_owner(rec, local_ips, conn_index, direction_hint)
        return rec
    rec.src, rec.dst = parsed.src, parsed.dst
    rec.src_port, rec.dst_port = parsed.src_port, parsed.dst_port
    rec.transport = parsed.transport
    rec.payload = parsed.payload
    if parsed.transport == "TCP":
        rec.info = (
            f"{parsed.src_port} → {parsed.dst_port} [{_tcp_flag_str(parsed.tcp_flags)}] "
            f"Seq={parsed.tcp_seq} Ack={parsed.tcp_ack} Win={parsed.tcp_window} "
            f"Len={len(parsed.payload)}"
        )
    elif parsed.transport == "UDP":
        rec.info = f"{parsed.src_port} → {parsed.dst_port}，長度 {len(parsed.payload)}"
    elif parsed.transport in ("ICMP", "ICMPv6"):
        rec.protocol = parsed.transport
        names = _ICMP4_NAMES if parsed.transport == "ICMP" else _ICMP6_NAMES
        rec.info = names.get(parsed.icmp_type, f"type={parsed.icmp_type}")
    else:
        rec.protocol = parsed.transport
    if parsed.transport in ("TCP", "UDP"):
        app_proto, app_info = classify_payload(
            parsed.transport, parsed.src_port, parsed.dst_port, parsed.payload)
        rec.protocol = app_proto
        if app_proto != parsed.transport and app_info:
            rec.info = app_info
        elif not parsed.payload and parsed.transport == "UDP":
            rec.info = app_info or rec.info
    _apply_direction_and_owner(rec, local_ips, conn_index, direction_hint)
    return rec


def record_from_pydivert(pkt, index: int, local_ips: set[str],
                         conn_index: ConnectionIndex | None = None) -> PacketRecord:
    """把 pydivert 封包物件轉成 PacketRecord（由 raw IP 位元組重新解析）。"""
    timestamp = None
    raw_ts = getattr(pkt, "timestamp", None)
    if isinstance(raw_ts, (int, float)):
        timestamp = float(raw_ts)
    return record_from_ip_bytes(
        packet_raw_bytes(pkt), index, local_ips, conn_index,
        timestamp=timestamp, direction_hint=packet_direction(pkt))


def list_interfaces() -> list[dict]:
    """列出可擷取的介面：[{name: Scapy 介面名, label: 顯示文字, ip: IP}]。"""
    result: list[dict] = []
    if not SCAPY_AVAILABLE:
        return result
    try:
        if is_windows():
            from scapy.arch.windows import get_windows_if_list  # type: ignore

            for iface in get_windows_if_list():
                ips = iface.get("ips") or []
                ipv4 = next((ip for ip in ips if ":" not in ip), "")
                name = iface.get("name", "")
                label = name
                if iface.get("description"):
                    label = f"{name}（{iface['description']}）"
                if ipv4:
                    label += f" - {ipv4}"
                result.append({"name": iface.get("guid") and
                                      r"\Device\NPF_" + iface["guid"] or name,
                               "label": label, "ip": ipv4})
            if result:
                return result
        from scapy.all import get_if_list, get_if_addr  # type: ignore

        for name in get_if_list():
            try:
                ip = get_if_addr(name)
            except Exception:
                ip = ""
            label = f"{name} - {ip}" if ip and ip != "0.0.0.0" else name
            result.append({"name": name, "label": label, "ip": ip})
    except Exception:
        pass
    return result


PacketCallback = Callable[[PacketRecord], None]


class CaptureEngine:
    """封包擷取引擎（背景執行緒擷取、主緒程透過 callback 接收）。"""

    def __init__(self, conn_index: ConnectionIndex | None = None,
                 divert_factory=None):
        self.conn_index = conn_index
        # divert_factory：注入式 WinDivert 後端（測試用），簽名同 open_sniff_handle
        self._divert_factory = divert_factory
        self._sniffer = None
        self._counter = 0
        self._lock = threading.Lock()
        self._local_ips = get_local_ips()
        self.on_packet: PacketCallback | None = None
        self.running = False
        self.iface: str | None = None
        self.bpf_filter: str = ""
        self.started_at: float = 0.0
        self.total_packets = 0
        self.total_bytes = 0
        self.backend = ""              # 實際使用中的後端（npcap / windivert）
        self.active_filter = ""        # 實際套用的過濾條件（WinDivert 時是其語法）
        self.last_error = ""           # 背景擷取中斷原因（供 GUI 顯示）
        self._wd_handle = None
        self._wd_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def refresh_local_ips(self) -> None:
        self._local_ips = get_local_ips()

    # ---------------------------------------------------------- 即時擷取
    def start(self, iface: str | None = None, bpf_filter: str = "",
              backend: str = BACKEND_AUTO, divert_filter: str | None = None) -> None:
        """開始擷取。backend 可為 auto/npcap/windivert；iface=None 表示所有介面
        （僅 Npcap 後端可選介面）。divert_filter 有值時直接當 WinDivert 語法用；
        否則 bpf_filter 會在 WinDivert 後端嘗試自動轉譯（轉不了就拋錯）。
        失敗會拋出例外，訊息可直接顯示。"""
        if self.running:
            raise RuntimeError("擷取已在進行中")
        chosen = self._resolve_backend(backend)
        self.refresh_local_ips()
        self.last_error = ""
        if chosen == BACKEND_WINDIVERT:
            self._start_windivert(bpf_filter, divert_filter)  # 內部會先設 running=True
            self.iface = None
            if not self.running:  # 收包緒在交棒前就死了
                raise RuntimeError(self.last_error or "WinDivert 擷取啟動後立即停止")
        else:
            self._start_npcap(iface, bpf_filter)
            self.iface = iface
            self.running = True
        self.backend = chosen
        self.bpf_filter = bpf_filter
        self.started_at = time.time()

    def _resolve_backend(self, requested: str) -> str:
        req = (requested or BACKEND_AUTO).strip().lower()
        if req not in (BACKEND_AUTO, BACKEND_NPCAP, BACKEND_WINDIVERT):
            raise RuntimeError(f"不認識的擷取後端：{requested}")
        npc_ok, npc_msg = capture_availability()
        if req == BACKEND_NPCAP:
            if not npc_ok:
                raise RuntimeError(npc_msg)
            return BACKEND_NPCAP
        if self._divert_factory is not None:
            wd_ok, wd_msg = True, "（注入式測試後端）"
        else:
            wd_ok, wd_msg = sniff_availability()
        if req == BACKEND_WINDIVERT:
            if not wd_ok:
                raise RuntimeError(wd_msg)
            return BACKEND_WINDIVERT
        if npc_ok:
            return BACKEND_NPCAP
        if wd_ok:
            return BACKEND_WINDIVERT
        raise RuntimeError(f"沒有可用的擷取後端。{npc_msg}；WinDivert：{wd_msg}")

    def _start_npcap(self, iface: str | None, bpf_filter: str) -> None:
        self.active_filter = bpf_filter.strip()
        kwargs: dict = {"prn": self._handle, "store": False}
        if iface:
            kwargs["iface"] = iface
        if bpf_filter.strip():
            kwargs["filter"] = bpf_filter.strip()
        try:
            sniffer = _get_scapy().AsyncSniffer(**kwargs)
        except Exception as exc:
            raise RuntimeError(f"Npcap 後端需要 Scapy：{exc}"
                               "（請執行 pip install scapy）") from exc
        sniffer.start()
        # AsyncSniffer 在背景緒程開啟介面/編譯 BPF，失敗時不會在這裡拋錯，
        # 要短暫等待後檢查它的 exception / 是否還活著，錯誤才能即時呈現給使用者。
        time.sleep(0.35)
        exc = getattr(sniffer, "exception", None)
        alive = sniffer.is_alive() if hasattr(sniffer, "is_alive") else True
        if exc is not None or not alive:
            detail = f"（{type(exc).__name__}: {exc}）" if exc else ""
            raise RuntimeError(
                "擷取啟動失敗" + detail + "：請檢查介面與 BPF 過濾語法，"
                "或確認已以系統管理員身分執行、Npcap 已安裝。")
        self._sniffer = sniffer

    def _start_windivert(self, bpf_filter: str, divert_filter: str | None) -> None:
        if divert_filter is not None:
            wd_filter = divert_filter.strip() or "true"
        elif (bpf_filter or "").strip():
            wd_filter = translate_bpf_to_windivert(bpf_filter)
            if wd_filter is None:
                raise RuntimeError(
                    "目前的過濾條件無法自動轉成 WinDivert 語法（WinDivert 只有 IP "
                    "層、看不到 Ethernet/ARP）。請改寫成 WinDivert 語法"
                    "（例：tcp and tcp.DstPort == 443），或清空過濾後再開始。")
        else:
            wd_filter = "true"
        factory = self._divert_factory or open_sniff_handle
        try:
            opened = factory(wd_filter)
        except Exception as exc:
            raise RuntimeError(
                f"無法開啟 WinDivert 擷取：{exc}"
                "（常見原因：未以系統管理員身分執行，或 Windows 11 核心隔離／"
                "驅動程式封鎖清單擋下驅動）") from exc
        if isinstance(opened, tuple):
            handle, sniff_ok = opened
        else:
            handle, sniff_ok = opened, False  # 不確定就保底原樣回注，絕不卡流量
        self._wd_handle = handle
        self.active_filter = wd_filter
        self._stop_event.clear()
        thread = threading.Thread(target=self._divert_loop, args=(handle, sniff_ok),
                                  daemon=True, name="netmon-windivert-sniff")
        self._wd_thread = thread
        self.running = True  # 先設旗標，收包緒出錯時改成 False 才不會被覆寫
        thread.start()
        time.sleep(0.25)  # 讓開局錯誤（語法/權限）立刻浮現
        if not thread.is_alive() and self.last_error:
            error = self.last_error
            self._close_wd_handle()
            self._wd_thread = None
            self.running = False
            raise RuntimeError(error)

    def _close_wd_handle(self) -> None:
        handle, self._wd_handle = self._wd_handle, None
        closer = getattr(handle, "close", None)
        if callable(closer):
            try:
                closer()
            except Exception:
                pass

    def _divert_loop(self, handle, sniff_ok: bool) -> None:
        sender = getattr(handle, "send", None)
        try:
            for pkt in handle:
                if self._stop_event.is_set():
                    break
                if not sniff_ok and callable(sender):
                    # 非 SNIFF 保底：封包是真的被攔下來的，原封不動立即回注
                    try:
                        sender(pkt, recalculate_checksum=False)
                    except TypeError:
                        try:
                            sender(pkt)
                        except Exception:
                            pass
                    except Exception:
                        pass
                with self._lock:
                    self._counter += 1
                    index = self._counter
                try:
                    rec = record_from_pydivert(pkt, index, self._local_ips,
                                               self.conn_index)
                except Exception:
                    continue  # 單一封包解析失敗不應讓擷取中斷
                self._emit(rec)
        except Exception as exc:  # 關閉造成的中斷屬正常，其他要讓使用者知道
            if not self._stop_event.is_set():
                self.last_error = f"WinDivert 擷取中斷：{exc}"
                self.running = False

    def _handle(self, pkt) -> None:
        try:
            with self._lock:
                self._counter += 1
                index = self._counter
            rec = packet_to_record(pkt, index, self._local_ips, self.conn_index)
            self._emit(rec)
        except Exception:
            # 單一封包解析失敗不應讓擷取中斷
            pass

    def _emit(self, rec: PacketRecord) -> None:
        with self._lock:
            self.total_packets += 1
            self.total_bytes += rec.length
        if self.on_packet:
            self.on_packet(rec)

    def stop(self) -> None:
        self.running = False
        self._stop_event.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        thread, self._wd_thread = self._wd_thread, None
        self._close_wd_handle()
        if thread is not None and thread.is_alive():
            thread.join(timeout=3.0)
        self.backend = ""
        self.active_filter = ""

    def reset_counters(self) -> None:
        with self._lock:
            self._counter = 0
            self.total_packets = 0
            self.total_bytes = 0

    # ---------------------------------------------------------- pcap 存讀
    def save_pcap(self, path: str, records: list[PacketRecord]) -> int:
        """把已擷取的封包存成 .pcap（可用 Wireshark 開啟），回傳寫入筆數。

        全是 WinDivert 的 IP 封包時存成 DLT_RAW（LINKTYPE 101，純 IP）；
        若清單混有 Ethernet 封包，IP 封包會補上合成的 Ethernet 外框
        （位址為 0）統一鏈路層，才不會產生混鏈路層的壞檔。
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("需要 Scapy 才能儲存 pcap")
        sc = _get_scapy()
        IP, IPv6, Ether, wrpcap = sc.IP, sc.IPv6, sc.Ether, sc.wrpcap
        usable = [r for r in records if r.raw]
        all_ip = bool(usable) and all(r.link_type == "ip" for r in usable)
        pkts = []
        for rec in usable:
            try:
                if rec.link_type == "ip":
                    is_v4 = (rec.raw[0] >> 4) == 4
                    if all_ip:
                        pkt = (IP if is_v4 else IPv6)(rec.raw)
                    else:
                        eth_type = b"\x08\x00" if is_v4 else b"\x86\xdd"
                        pkt = Ether(b"\x00" * 12 + eth_type + rec.raw)
                else:
                    pkt = Ether(rec.raw)
                pkt.time = rec.timestamp
                pkts.append(pkt)
            except Exception:
                continue
        if all_ip:
            wrpcap(path, pkts, linktype=101)  # LINKTYPE_RAW（純 IP）
        else:
            wrpcap(path, pkts)
        return len(pkts)

    def load_pcap(self, path: str) -> list[PacketRecord]:
        """讀取 .pcap/.pcapng 檔並解析成 PacketRecord 清單（離線分析）。"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("需要 Scapy 才能讀取 pcap")
        self.refresh_local_ips()
        raw_pkts = _get_scapy().rdpcap(path)
        records = []
        with self._lock:
            base = self._counter
        for i, pkt in enumerate(raw_pkts, 1):
            records.append(packet_to_record(pkt, base + i, self._local_ips, None))
        with self._lock:
            self._counter = base + len(records)
        return records
