"""純 Python 的 IP 層封包解析（IPv4/IPv6 + TCP/UDP/ICMP 基本欄位）。

用途：WinDivert SNIFF 擷取拿到的是 IP 封包本體（沒有 Ethernet 標頭），
不需要 Scapy 就能解析出方向判斷、流量歸屬與應用層分類所需的欄位。
設計原則：只解析需要的欄位、容忍截斷（欄位缺失就留空），不驗 checksum。
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

_PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


@dataclass
class ParsedIPPacket:
    version: int                      # 4 / 6
    src: str = ""
    dst: str = ""
    protocol_num: int = 0
    transport: str = ""               # TCP / UDP / ICMP / ICMPv6 / IP(n)
    src_port: int | None = None
    dst_port: int | None = None
    payload: bytes = b""
    total_length: int = 0              # IP 標頭宣告的長度（可能與實際擷取長度不同）
    tcp_flags: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_window: int = 0
    icmp_type: int | None = None
    icmp_code: int | None = None


def _parse_transport(parsed: ParsedIPPacket, data: bytes, offset: int) -> None:
    proto = parsed.protocol_num
    parsed.transport = _PROTOCOL_NAMES.get(proto, f"IP({proto})")
    body = data[offset:]
    if proto == 6:  # TCP
        if len(body) >= 20:
            parsed.src_port, parsed.dst_port, parsed.tcp_seq, parsed.tcp_ack = \
                struct.unpack(">HHII", body[:12])
            data_offset = (body[12] >> 4) * 4
            parsed.tcp_flags = body[13]
            parsed.tcp_window = struct.unpack(">H", body[14:16])[0]
            if 20 <= data_offset <= len(body):
                parsed.payload = body[data_offset:]
            elif data_offset > len(body):
                parsed.payload = b""
            else:
                parsed.payload = body[20:]
    elif proto == 17:  # UDP
        if len(body) >= 8:
            parsed.src_port, parsed.dst_port, udp_len = struct.unpack(">HHH", body[:6])
            end = udp_len if 8 <= udp_len <= len(body) else len(body)
            parsed.payload = body[8:end]
    elif proto in (1, 58):  # ICMP / ICMPv6
        if len(body) >= 2:
            parsed.icmp_type, parsed.icmp_code = body[0], body[1]
        parsed.payload = body[4:] if len(body) > 4 else b""
    else:
        parsed.payload = body


def parse_ip_packet(data: bytes) -> ParsedIPPacket | None:
    """解析一個 IPv4/IPv6 封包。資料太短或版本不符回傳 None。"""
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            return None
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or ihl > len(data):
            return None
        total_length = struct.unpack(">H", data[2:4])[0]
        parsed = ParsedIPPacket(
            version=4,
            src=str(ipaddress.IPv4Address(data[12:16])),
            dst=str(ipaddress.IPv4Address(data[16:20])),
            protocol_num=data[9],
            total_length=total_length,
        )
        # 有宣告總長時以它截斷（Ethernet 可能有 padding；IP 本體通常沒有）
        view = data[:total_length] if ihl <= total_length <= len(data) else data
        frag_offset = struct.unpack(">H", data[6:8])[0] & 0x1FFF
        if frag_offset:
            # 非首片的 IP 分片沒有 L4 標頭，不要把內容誤讀成埠號
            parsed.transport = _PROTOCOL_NAMES.get(parsed.protocol_num,
                                                   f"IP({parsed.protocol_num})")
            parsed.payload = view[ihl:]
            return parsed
        _parse_transport(parsed, view, ihl)
        return parsed

    if version == 6:
        if len(data) < 40:
            return None
        payload_length = struct.unpack(">H", data[4:6])[0]
        next_header = data[6]
        parsed = ParsedIPPacket(
            version=6,
            src=str(ipaddress.IPv6Address(data[8:24])),
            dst=str(ipaddress.IPv6Address(data[24:40])),
            total_length=40 + payload_length,
        )
        offset = 40
        # 跳過常見延伸標頭，直到上層協定或跑完資料
        for _ in range(8):
            if next_header in (0, 43, 60) and offset + 2 <= len(data):  # Hop/Routing/Dest
                following = data[offset]
                offset += (data[offset + 1] + 1) * 8
                next_header = following
            elif next_header == 44 and offset + 8 <= len(data):  # Fragment 固定 8 bytes
                following = data[offset]
                offset += 8
                next_header = following
            elif next_header == 51 and offset + 2 <= len(data):  # AH 長度單位是 4 bytes
                following = data[offset]
                offset += (data[offset + 1] + 2) * 4
                next_header = following
            else:
                break
            if offset > len(data):
                offset = len(data)
                break
        parsed.protocol_num = next_header
        _parse_transport(parsed, data, offset)
        return parsed

    return None
