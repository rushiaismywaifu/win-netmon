"""層級 4：擷取並解析封包內容（Npcap + Scapy）。

- 以 Scapy 的 AsyncSniffer 在背景擷取，即時轉成 PacketRecord。
- 每個封包會分類協定（DNS / TLS(SNI) / HTTP / QUIC …）、判斷方向、
  並透過層級 3 的連線表索引歸屬到程式。
- 支援 BPF 過濾語法（同 Wireshark capture filter）、存/讀 .pcap 檔。
- Scapy 採延遲載入：未安裝時層級 1、2 仍可正常使用，GUI 會顯示安裝提示。

注意：HTTPS/TLS 內容是加密的，只能看到 IP、埠、網域（SNI）與流量大小。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from .packet_info import classify_payload
from .traffic import UNKNOWN_NAME, UNKNOWN_PID, ConnectionIndex
from .utils import check_npcap, get_local_ips, is_windows

try:
    from scapy.all import (  # type: ignore
        ARP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, IP, IPv6, TCP, UDP,
        AsyncSniffer, Ether, wrpcap, rdpcap,
    )
    from scapy.layers.inet6 import ICMPv6DestUnreach  # noqa: F401  （確保 inet6 層註冊）
    SCAPY_AVAILABLE = True
    SCAPY_ERROR = ""
except Exception as exc:  # ImportError 或 Npcap 未裝時的初始化錯誤
    SCAPY_AVAILABLE = False
    SCAPY_ERROR = f"{type(exc).__name__}: {exc}"


def capture_availability() -> tuple[bool, str]:
    """封包擷取是否可用，回傳 (可用, 說明文字)。"""
    if not SCAPY_AVAILABLE:
        return False, f"Scapy 載入失敗（{SCAPY_ERROR}）。請執行：pip install scapy"
    ok, msg = check_npcap()
    if is_windows() and not ok:
        return False, msg
    return True, "Scapy + Npcap 就緒" if is_windows() else "Scapy 就緒"


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
        if SCAPY_AVAILABLE and self.raw:
            try:
                pkt = Ether(self.raw)
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

    ip_layer = None
    if SCAPY_AVAILABLE and IP in pkt:
        ip_layer = pkt[IP]
    elif SCAPY_AVAILABLE and IPv6 in pkt:
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
    elif SCAPY_AVAILABLE and ARP in pkt:
        arp = pkt[ARP]
        rec.transport = rec.protocol = "ARP"
        rec.src = str(arp.psrc)
        rec.dst = str(arp.pdst)
        if int(arp.op) == 1:
            rec.info = f"誰有 {arp.pdst}？ 告訴 {arp.psrc}"
        else:
            rec.info = f"{arp.psrc} 在 {arp.hwsrc}"
    else:
        if SCAPY_AVAILABLE and Ether in pkt:
            rec.src = str(pkt[Ether].src)
            rec.dst = str(pkt[Ether].dst)
        rec.transport = rec.protocol = pkt.lastlayer().name if SCAPY_AVAILABLE else "?"
        rec.info = "非 IP 封包"

    # ---- 方向與程式歸屬 ----
    if rec.src in local_ips:
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
    return rec


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

    def __init__(self, conn_index: ConnectionIndex | None = None):
        self.conn_index = conn_index
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

    def refresh_local_ips(self) -> None:
        self._local_ips = get_local_ips()

    # ---------------------------------------------------------- 即時擷取
    def start(self, iface: str | None = None, bpf_filter: str = "") -> None:
        """開始擷取。iface=None 表示所有介面。失敗會拋出例外，訊息可直接顯示。"""
        ok, msg = capture_availability()
        if not ok:
            raise RuntimeError(msg)
        if self.running:
            raise RuntimeError("擷取已在進行中")
        self.refresh_local_ips()
        kwargs: dict = {"prn": self._handle, "store": False}
        if iface:
            kwargs["iface"] = iface
        if bpf_filter.strip():
            kwargs["filter"] = bpf_filter.strip()
        sniffer = AsyncSniffer(**kwargs)
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
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.running = True
        self.started_at = time.time()

    def _handle(self, pkt) -> None:
        try:
            with self._lock:
                self._counter += 1
                index = self._counter
            rec = packet_to_record(pkt, index, self._local_ips, self.conn_index)
            with self._lock:
                self.total_packets += 1
                self.total_bytes += rec.length
            if self.on_packet:
                self.on_packet(rec)
        except Exception:
            # 單一封包解析失敗不應讓擷取中斷
            pass

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        self.running = False

    def reset_counters(self) -> None:
        with self._lock:
            self._counter = 0
            self.total_packets = 0
            self.total_bytes = 0

    # ---------------------------------------------------------- pcap 存讀
    def save_pcap(self, path: str, records: list[PacketRecord]) -> int:
        """把已擷取的封包存成 .pcap（可用 Wireshark 開啟），回傳寫入筆數。"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("需要 Scapy 才能儲存 pcap")
        pkts = []
        for rec in records:
            if rec.raw:
                try:
                    pkt = Ether(rec.raw)
                    pkt.time = rec.timestamp
                    pkts.append(pkt)
                except Exception:
                    continue
        wrpcap(path, pkts)
        return len(pkts)

    def load_pcap(self, path: str) -> list[PacketRecord]:
        """讀取 .pcap/.pcapng 檔並解析成 PacketRecord 清單（離線分析）。"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("需要 Scapy 才能讀取 pcap")
        self.refresh_local_ips()
        raw_pkts = rdpcap(path)
        records = []
        with self._lock:
            base = self._counter
        for i, pkt in enumerate(raw_pkts, 1):
            records.append(packet_to_record(pkt, base + i, self._local_ips, None))
        with self._lock:
            self._counter = base + len(records)
        return records
