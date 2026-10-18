"""封包應用層解析（純 Python，不依賴 Scapy，方便測試與離線使用）。

功能：
  - DNS：解析查詢網域名稱與類型、回應筆數
  - TLS：從 ClientHello 取出 SNI（HTTPS 加密下仍看得到要連的網域）
  - HTTP：解析請求方法、Host、路徑與回應狀態碼
  - 依連接埠/payload 把封包分類成應用層協定並產生 Info 摘要
"""
from __future__ import annotations

import struct

# 常見連接埠對應服務（兜底顯示用）
WELL_KNOWN_PORTS: dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 137: "NBNS", 138: "NBDS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS/TLS",
    445: "SMB", 465: "SMTPS", 587: "SMTP", 853: "DoT", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1723: "PPTP",
    1883: "MQTT", 3306: "MySQL", 3389: "RDP", 5060: "SIP",
    5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

DNS_QTYPES: dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 257: "CAA",
}

HTTP_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
                "PATCH ", "CONNECT ", "TRACE ")

# HTTP 請求/回應第一行的可能開頭字元（9 種方法 + "HTTP/" 回應）。
# 第一 byte 不在其中時 parse_http 必定回 None，可因此省一次 decode+判斷。
_HTTP_START_CHARS = frozenset(b"GPDHOCT")


# ---------------------------------------------------------------- DNS
def _read_dns_name(data: bytes, offset: int) -> tuple[str, int] | None:
    """讀取 DNS 標籤式名稱，回傳 (名稱, 讀完後的 offset)。"""
    labels: list[str] = []
    jumped = False
    end_offset = offset
    hops = 0
    while True:
        if offset >= len(data) or hops > 32:
            return None
        length = data[offset]
        if length == 0:
            if not jumped:
                end_offset = offset + 1
            break
        if length & 0xC0 == 0xC0:  # 壓縮指標
            if offset + 1 >= len(data):
                return None
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
                jumped = True
            offset = pointer
            hops += 1
            continue
        if length & 0xC0:
            return None
        start = offset + 1
        end = start + length
        if end > len(data):
            return None
        try:
            labels.append(data[start:end].decode("ascii", errors="strict"))
        except UnicodeDecodeError:
            labels.append(data[start:end].decode("utf-8", errors="replace"))
        offset = end
    return (".".join(labels) if labels else "."), end_offset


def parse_dns(data: bytes) -> dict | None:
    """解析 DNS 訊息。成功回傳 dict：{is_response, qname, qtype, answers}。"""
    if len(data) < 12:
        return None
    try:
        _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        return None
    # opcode 必須是 0（標準查詢），避免把任意 UDP 資料誤判成 DNS
    if (flags >> 11) & 0xF != 0 or qd == 0:
        return None
    result = _read_dns_name(data, 12)
    if result is None:
        return None
    qname, off = result
    if off + 4 > len(data):
        return None
    qtype, _qclass = struct.unpack(">HH", data[off : off + 4])
    if qtype not in DNS_QTYPES and qtype > 512:
        return None
    return {
        "is_response": bool(flags & 0x8000),
        "qname": qname,
        "qtype": DNS_QTYPES.get(qtype, f"TYPE{qtype}"),
        "answers": an,
    }


# ---------------------------------------------------------------- TLS / SNI
def extract_tls_sni(data: bytes) -> str | None:
    """從 TLS ClientHello 取出 SNI 網域名稱（server_name 擴充欄位）。"""
    try:
        # TLS Record：type(1)=22 handshake, version(2), length(2)
        if len(data) < 5 or data[0] != 22:
            return None
        record_len = struct.unpack(">H", data[3:5])[0]
        body = data[5 : 5 + record_len]
        # Handshake：type(1)=1 ClientHello, length(3), version(2), random(32)
        if len(body) < 38 or body[0] != 1:
            return None
        pos = 4 + 2 + 32
        # session id
        if pos >= len(body):
            return None
        pos += 1 + body[pos]
        # cipher suites
        if pos + 2 > len(body):
            return None
        pos += 2 + struct.unpack(">H", body[pos : pos + 2])[0]
        # compression methods
        if pos >= len(body):
            return None
        pos += 1 + body[pos]
        # extensions
        if pos + 2 > len(body):
            return None
        ext_total = struct.unpack(">H", body[pos : pos + 2])[0]
        pos += 2
        ext_end = min(pos + ext_total, len(body))
        while pos + 4 <= ext_end:
            ext_type, ext_len = struct.unpack(">HH", body[pos : pos + 4])
            ext_data = body[pos + 4 : pos + 4 + ext_len]
            if ext_type == 0 and len(ext_data) >= 5:  # server_name
                # ServerNameList 長度(2), NameType(1)=0, HostName 長度(2)
                name_len = struct.unpack(">H", ext_data[3:5])[0]
                host = ext_data[5 : 5 + name_len]
                return host.decode("ascii", errors="replace")
            pos += 4 + ext_len
        return None
    except (struct.error, IndexError):
        return None


def is_tls_record(data: bytes) -> str | None:
    """是否為 TLS 記錄？回傳簡述（ClientHello / ServerHello / Application Data…）。"""
    if len(data) < 5:
        return None
    content_type = data[0]
    major = data[1]
    if major != 3 or content_type not in (20, 21, 22, 23):
        return None
    if content_type == 23:
        return "Application Data（已加密）"
    if content_type == 21:
        return "Alert"
    if content_type == 20:
        return "ChangeCipherSpec"
    # handshake
    if len(data) >= 6:
        hs_type = data[5]
        names = {1: "ClientHello", 2: "ServerHello", 11: "Certificate",
                 12: "ServerKeyExchange", 14: "ServerHelloDone",
                 16: "ClientKeyExchange", 20: "Finished"}
        return names.get(hs_type, f"Handshake({hs_type})")
    return "Handshake"


# ---------------------------------------------------------------- HTTP
def parse_http(data: bytes) -> dict | None:
    """解析明文 HTTP 請求/回應第一行與 Host 標頭。"""
    try:
        text_head = data[:2048].decode("iso-8859-1")
    except Exception:
        return None
    first_line, _, rest = text_head.partition("\r\n")
    if first_line.startswith(HTTP_METHODS):
        parts = first_line.split(" ")
        host = ""
        for line in rest.split("\r\n")[:20]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return {"kind": "request", "method": parts[0],
                "path": parts[1] if len(parts) > 1 else "", "host": host,
                "version": parts[2] if len(parts) > 2 else ""}
    if first_line.startswith("HTTP/"):
        parts = first_line.split(" ", 2)
        return {"kind": "response",
                "status": parts[1] if len(parts) > 1 else "",
                "reason": parts[2] if len(parts) > 2 else "",
                "version": parts[0]}
    return None


# ---------------------------------------------------------------- 分類
def classify_payload(transport: str, sport: int | None, dport: int | None,
                     payload: bytes) -> tuple[str, str]:
    """把封包分類為應用層協定並產生 Info 摘要。

    回傳 (協定名稱, Info 文字)。先看 payload 特徵（DNS/TLS/HTTP），
    再用連接埠對照表兜底，最後退回傳輸層協定名稱。
    """
    if payload:
        # DNS（UDP/TCP 53，或 mDNS 5353）
        if sport in (53, 5353) or dport in (53, 5353):
            dns_data = payload
            if transport == "TCP" and len(payload) > 2:  # TCP DNS 前有 2-byte 長度
                dns_data = payload[2:]
            dns = parse_dns(dns_data)
            if dns:
                if dns["is_response"]:
                    info = f"回應 {dns['qname']} {dns['qtype']}（{dns['answers']} 筆答案）"
                else:
                    info = f"查詢 {dns['qname']} {dns['qtype']}"
                proto = "mDNS" if 5353 in (sport, dport) else "DNS"
                return proto, info
        # HTTP（明文）：先看第一 byte，TLS/QUIC/隨機二進位大多直接跳過，
        # 不必花一次 2048-byte decode 與字串切割（行為等價的早退）。
        if payload[0] in _HTTP_START_CHARS:
            http = parse_http(payload)
        else:
            http = None
        if http:
            if http["kind"] == "request":
                host = http["host"] or ""
                info = f"{http['method']} {host}{http['path']}".strip()
                return "HTTP", info
            return "HTTP", f"{http['version']} {http['status']} {http['reason']}".strip()
        # TLS
        tls_desc = is_tls_record(payload)
        if tls_desc:
            sni = extract_tls_sni(payload) if tls_desc == "ClientHello" else None
            if sni:
                return "TLS", f"ClientHello，SNI = {sni}"
            return "TLS", tls_desc
        # QUIC（UDP 443，第一個 byte 高兩位為 11 的長標頭）
        if transport == "UDP" and 443 in (sport, dport) and payload[0] & 0x80:
            return "QUIC", "QUIC（HTTP/3，已加密）"

    for port in (dport, sport):
        if port in WELL_KNOWN_PORTS:
            name = WELL_KNOWN_PORTS[port]  # type: ignore[index]
            return name, f"{name} 資料（{len(payload)} bytes）" if payload else name
    info = f"{len(payload)} bytes 資料" if payload else ""
    return transport, info
