"""WinDivert SNIFF 替代擷取後端離線測試（不需要 Windows/驅動）。

覆蓋：純 Python IP 封包解析、BPF 子集轉 WinDivert 語法、IP 封包轉
PacketRecord（分類/方向/程式歸屬）、CaptureEngine 以假 handle 跑
WinDivert 後端（SNIFF 不回注、非 SNIFF 逐包原樣回注保底、開局錯誤
浮現、背景中斷寫入 last_error）、DLT_RAW pcap 存讀往返。
"""
import ipaddress
import socket
import struct
import time
import unittest
from pathlib import Path

from netmon.capture import (
    SCAPY_AVAILABLE, CaptureEngine, any_capture_availability,
    backend_availability, record_from_ip_bytes,
)
from netmon.connections import ConnectionRecord
from netmon.ip_packet import parse_ip_packet
from netmon.traffic import ConnectionIndex
from netmon.windivert_sniff import translate_bpf_to_windivert


def mk_ipv4(proto, src, dst, body):
    total = 20 + len(body)
    return (struct.pack(">BBHHHBBH", 0x45, 0, total, 0x1234, 0x4000, 64, proto, 0)
            + socket.inet_aton(src) + socket.inet_aton(dst) + body)


# DNS 查詢 example.com A
QNAME = b"\x07example\x03com\x00"
DNS_QUERY = (struct.pack(">HHHHHH", 0x1A2B, 0x0100, 1, 0, 0, 0)
             + QNAME + struct.pack(">HH", 1, 1))
DNS_UDP = struct.pack(">HHHH", 53123, 53, 8 + len(DNS_QUERY), 0) + DNS_QUERY
DNS_PKT = mk_ipv4(17, "192.168.1.50", "8.8.8.8", DNS_UDP)

TCP_SYN = (struct.pack(">HHII", 50000, 65000, 1000, 0)
           + bytes([5 << 4, 0x02]) + struct.pack(">HHH", 64240, 0, 0))
SYN_PKT = mk_ipv4(6, "10.0.0.5", "93.184.216.34", TCP_SYN)


def dns_connection_index() -> ConnectionIndex:
    idx = ConnectionIndex()
    idx.refresh([ConnectionRecord(pid=4242, process_name="browser.exe", protocol="UDP",
                                  local_ip="192.168.1.50", local_port=53123,
                                  remote_ip="8.8.8.8", remote_port=53, status="")])
    return idx


class TestParseIPPacket(unittest.TestCase):
    def test_ipv4_udp_dns(self):
        p = parse_ip_packet(DNS_PKT)
        self.assertIsNotNone(p)
        self.assertEqual((p.src, p.dst), ("192.168.1.50", "8.8.8.8"))
        self.assertEqual(p.transport, "UDP")
        self.assertEqual((p.src_port, p.dst_port), (53123, 53))
        self.assertEqual(p.payload, DNS_QUERY)

    def test_ipv4_tcp_fields(self):
        p = parse_ip_packet(SYN_PKT)
        self.assertEqual(p.transport, "TCP")
        self.assertEqual(p.tcp_flags, 0x02)
        self.assertEqual(p.tcp_seq, 1000)
        self.assertEqual(p.tcp_window, 64240)
        self.assertEqual(p.payload, b"")

    def test_ipv4_icmp(self):
        icmp = bytes([8, 0]) + struct.pack(">HHH", 0, 7, 1) + b"abcdefgh"
        p = parse_ip_packet(mk_ipv4(1, "10.0.0.5", "8.8.8.8", icmp))
        self.assertEqual(p.transport, "ICMP")
        self.assertEqual((p.icmp_type, p.icmp_code), (8, 0))

    def test_ipv6_and_extension_header(self):
        udp = struct.pack(">HHHH", 1111, 53, 8 + len(DNS_QUERY), 0) + DNS_QUERY
        src = socket.inet_pton(socket.AF_INET6, "fe80::1")
        dst = socket.inet_pton(socket.AF_INET6, "2001:4860:4860::8888")
        plain = struct.pack(">IHBB", 0x60000000, len(udp), 17, 64) + src + dst + udp
        p = parse_ip_packet(plain)
        self.assertEqual(p.version, 6)
        self.assertEqual((p.src, p.transport, p.dst_port), ("fe80::1", "UDP", 53))
        # Hop-by-Hop 延伸標頭（8 bytes）後才是 UDP
        hop = bytes([17, 0]) + b"\x00" * 6
        body = hop + udp
        with_ext = struct.pack(">IHBB", 0x60000000, len(body), 0, 64) + src + dst + body
        p2 = parse_ip_packet(with_ext)
        self.assertEqual((p2.transport, p2.src_port, p2.payload), ("UDP", 1111, DNS_QUERY))

    def test_ipv6_address_text_is_rfc5952_and_parsable(self):
        """位址文字化用 socket.inet_ntop：零壓縮正確、且可被 ipaddress 解回同位址。"""
        for src_text, dst_text in (
            ("2001:db8::1", "::ffff:192.168.1.5"),
            ("fe80::1", "2001:4860:4860::8888"),
            ("::1", "2001:0:0:2:0:0:0:3"),
            ("::", "2001:db8:0:0:1:0:0:1"),
        ):
            with self.subTest(src=src_text, dst=dst_text):
                src = socket.inet_pton(socket.AF_INET6, src_text)
                dst = socket.inet_pton(socket.AF_INET6, dst_text)
                p = parse_ip_packet(
                    struct.pack(">IHBB", 0x60000000, 0, 59, 64) + src + dst)
                self.assertEqual(p.src, socket.inet_ntop(socket.AF_INET6, src))
                self.assertEqual(p.dst, socket.inet_ntop(socket.AF_INET6, dst))
                self.assertEqual(ipaddress.IPv6Address(p.src).packed, src)
                self.assertEqual(ipaddress.IPv6Address(p.dst).packed, dst)

    def test_truncated_and_garbage(self):
        self.assertIsNone(parse_ip_packet(b""))
        self.assertIsNone(parse_ip_packet(b"\x45\x00"))
        self.assertIsNone(parse_ip_packet(b"\x99" * 40))
        # 截斷的 TCP（少於 20 bytes 標頭）：埠號留空但不丟例外
        p = parse_ip_packet(mk_ipv4(6, "10.0.0.5", "8.8.8.8", b"\x00\x01"))
        self.assertEqual(p.transport, "TCP")
        self.assertIsNone(p.src_port)


class TestBpfToWindivert(unittest.TestCase):
    def test_exact_translations(self):
        cases = {
            "": "true",
            "tcp": "(tcp)",
            "icmp": "(icmp)",
            "ip6": "(ipv6)",
            "not tcp": "not (tcp)",
            "tcp or udp": "(tcp) or (udp)",
            "tcp port 443": "(((tcp and (tcp.DstPort == 443 or tcp.SrcPort == 443))))",
            "udp port 53": "(((udp and (udp.DstPort == 53 or udp.SrcPort == 53))))",
            "port 53": "(((tcp and (tcp.DstPort == 53 or tcp.SrcPort == 53)) or "
                       "(udp and (udp.DstPort == 53 or udp.SrcPort == 53))))",
            "src port 80": "(((tcp and (tcp.SrcPort == 80)) or (udp and (udp.SrcPort == 80))))",
            "host 8.8.8.8": "((ip.DstAddr == 8.8.8.8 or ip.SrcAddr == 8.8.8.8))",
            "dst host 1.1.1.1": "((ip.DstAddr == 1.1.1.1))",
            "host 2001:db8::1": "((ipv6.DstAddr == 2001:db8::1 or ipv6.SrcAddr == 2001:db8::1))",
            "tcp portrange 8000-9000":
                "(((tcp and ((tcp.DstPort >= 8000 and tcp.DstPort <= 9000) or "
                "(tcp.SrcPort >= 8000 and tcp.SrcPort <= 9000)))))",
            "net 192.168.0.0/24":
                "(((ip.DstAddr >= 192.168.0.0 and ip.DstAddr <= 192.168.0.255) or "
                "(ip.SrcAddr >= 192.168.0.0 and ip.SrcAddr <= 192.168.0.255)))",
            "net 10.0.0.1/32": "((ip.DstAddr == 10.0.0.1 or ip.SrcAddr == 10.0.0.1))",
            "tcp and not port 22":
                "(tcp) and not (((tcp and (tcp.DstPort == 22 or tcp.SrcPort == 22)) or "
                "(udp and (udp.DstPort == 22 or udp.SrcPort == 22))))",
        }
        for src, expect in cases.items():
            with self.subTest(src=src):
                self.assertEqual(translate_bpf_to_windivert(src), expect)

    def test_unsupported_returns_none(self):
        for bad in ("arp", "ether host aa:bb:cc:dd:ee:ff", "host example.com",
                    "(tcp)", "tcp and", "port 70000", "port abc", "greater 100",
                    "src host 999.1.1.1", "net 2001:db8::/32"):
            with self.subTest(bad=bad):
                self.assertIsNone(translate_bpf_to_windivert(bad))


class TestRecordFromIPBytes(unittest.TestCase):
    def test_dns_classify_and_owner(self):
        rec = record_from_ip_bytes(DNS_PKT, 1, {"192.168.1.50"}, dns_connection_index(),
                                   direction_hint="out")
        self.assertEqual(rec.protocol, "DNS")
        self.assertIn("example.com", rec.info)
        self.assertEqual(rec.direction, "out")
        self.assertEqual(rec.pid, 4242)
        self.assertEqual(rec.process_name, "browser.exe")
        self.assertEqual(rec.link_type, "ip")
        self.assertEqual(rec.length, len(DNS_PKT))

    def test_tcp_flag_info_and_local_ip_direction(self):
        rec = record_from_ip_bytes(SYN_PKT, 2, {"10.0.0.5"}, None)
        self.assertEqual(rec.transport, "TCP")
        self.assertIn("SYN", rec.info)
        self.assertIn("Seq=1000", rec.info)
        self.assertEqual(rec.direction, "out")
        # 反向（目的為本機）
        incoming = mk_ipv4(6, "93.184.216.34", "10.0.0.5", TCP_SYN)
        self.assertEqual(record_from_ip_bytes(incoming, 3, {"10.0.0.5"}, None).direction, "in")
        # hint 優先於位址推斷
        hinted = record_from_ip_bytes(SYN_PKT, 4, set(), None, direction_hint="in")
        self.assertEqual(hinted.direction, "in")

    def test_icmp_and_unparseable(self):
        icmp = bytes([8, 0]) + struct.pack(">HHH", 0, 7, 1)
        rec = record_from_ip_bytes(mk_ipv4(1, "10.0.0.5", "8.8.8.8", icmp),
                                   5, {"10.0.0.5"}, None)
        self.assertEqual(rec.protocol, "ICMP")
        self.assertIn("ping", rec.info)
        bad = record_from_ip_bytes(b"\x45", 6, set(), None, direction_hint="out")
        self.assertEqual(bad.transport, "IP?")
        self.assertEqual(bad.direction, "out")


class FakePkt:
    def __init__(self, raw, is_outbound=True):
        self.raw = raw
        self.is_outbound = is_outbound


class FakeHandle:
    def __init__(self, pkts):
        self.pkts = list(pkts)
        self.sent = []
        self.closed = False

    def __iter__(self):
        while self.pkts and not self.closed:
            yield self.pkts.pop(0)
            time.sleep(0.01)
        while not self.closed:
            time.sleep(0.02)

    def send(self, pkt, recalculate_checksum=True):
        self.sent.append((pkt, recalculate_checksum))

    def close(self):
        self.closed = True


class TestWindivertBackendEngine(unittest.TestCase):
    def _run_engine(self, sniff, bpf="udp port 53", divert_filter=None):
        seen = {}
        handle = FakeHandle([FakePkt(DNS_PKT), FakePkt(SYN_PKT)])

        def factory(filter_string):
            seen["filter"] = filter_string
            return handle, sniff

        records = []
        eng = CaptureEngine(dns_connection_index(), divert_factory=factory)
        eng.on_packet = records.append
        eng.start(bpf_filter=bpf, backend="windivert", divert_filter=divert_filter)
        self.assertEqual(eng.backend, "windivert")
        for _ in range(100):
            if len(records) >= 2:
                break
            time.sleep(0.05)
        eng.stop()
        return eng, handle, records, seen.get("filter")

    def test_sniff_mode_never_reinjects(self):
        eng, handle, records, used_filter = self._run_engine(sniff=True)
        self.assertIn("udp.DstPort == 53", used_filter)  # BPF 已自動轉譯
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].protocol, "DNS")
        self.assertEqual(records[0].pid, 4242)
        self.assertEqual(records[0].direction, "out")
        self.assertEqual(handle.sent, [])       # SNIFF：絕對不用回注
        self.assertTrue(handle.closed)
        self.assertFalse(eng.running)
        self.assertEqual(eng.total_packets, 2)

    def test_non_sniff_fallback_reinjects_everything_unchanged(self):
        _, handle, records, _ = self._run_engine(sniff=False)
        self.assertEqual(len(records), 2)
        self.assertEqual(len(handle.sent), 2)   # 保底：每包原樣回注、不算封包 checksum
        self.assertTrue(all(flag is False for _pkt, flag in handle.sent))

    def test_explicit_windivert_filter_used_as_is(self):
        _, _, _, used_filter = self._run_engine(sniff=True, bpf="",
                                                divert_filter="outbound and tcp")
        self.assertEqual(used_filter, "outbound and tcp")

    def test_untranslatable_bpf_fails_before_opening(self):
        called = []
        eng = CaptureEngine(None, divert_factory=lambda f: called.append(f))
        with self.assertRaises(RuntimeError) as ctx:
            eng.start(bpf_filter="arp", backend="windivert")
        self.assertIn("WinDivert", str(ctx.exception))
        self.assertEqual(called, [])  # 轉不了就不要默默擴大擷取範圍

    def test_factory_failure_is_friendly(self):
        def factory(_f):
            raise OSError("找不到驅動")
        eng = CaptureEngine(None, divert_factory=factory)
        with self.assertRaises(RuntimeError) as ctx:
            eng.start(backend="windivert")
        self.assertIn("WinDivert", str(ctx.exception))
        self.assertFalse(eng.running)

    def test_unknown_backend_rejected(self):
        eng = CaptureEngine(None)
        with self.assertRaises(RuntimeError):
            eng.start(backend="wireshark")

    def test_early_stream_error_surfaces_at_start(self):
        class Exploding(FakeHandle):
            def __iter__(self):
                yield FakePkt(DNS_PKT)
                raise OSError("driver gone")
        eng = CaptureEngine(None, divert_factory=lambda f: (Exploding([]), True))
        with self.assertRaises(RuntimeError):
            eng.start(backend="windivert")
        self.assertFalse(eng.running)

    def test_mid_stream_error_sets_last_error(self):
        class LateBoom(FakeHandle):
            def __iter__(self):
                yield FakePkt(DNS_PKT)
                time.sleep(0.6)
                raise OSError("裝置中斷")
        eng = CaptureEngine(None, divert_factory=lambda f: (LateBoom([]), True))
        eng.start(backend="windivert")
        try:
            for _ in range(60):
                if not eng.running:
                    break
                time.sleep(0.05)
            self.assertFalse(eng.running)
            self.assertIn("中斷", eng.last_error)
        finally:
            eng.stop()


class TestPcapRoundTripIPOnly(unittest.TestCase):
    @unittest.skipUnless(SCAPY_AVAILABLE, "需要 Scapy")
    def test_dlt_raw_round_trip(self):
        import os
        import tempfile
        eng = CaptureEngine(None)
        recs = [
            record_from_ip_bytes(DNS_PKT, 1, {"192.168.1.50"}, None,
                                 timestamp=1_700_000_000.0),
            record_from_ip_bytes(SYN_PKT, 2, {"10.0.0.5"}, None,
                                 timestamp=1_700_000_001.0),
        ]
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "wd.pcap")
            self.assertEqual(eng.save_pcap(path, recs), 2)
            loaded = eng.load_pcap(path)
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0].link_type, "ip")
        self.assertEqual((loaded[0].src, loaded[0].dst_port), ("192.168.1.50", 53))
        self.assertEqual(loaded[1].transport, "TCP")
        self.assertIn("IP", loaded[0].dissect())  # IP 根層逐層解析


class TestBackendAvailability(unittest.TestCase):
    def test_shape(self):
        backs = backend_availability()
        self.assertEqual(sorted(backs), ["npcap", "windivert"])
        for ok, msg in backs.values():
            self.assertIsInstance(ok, bool)
            self.assertIsInstance(msg, str)
        any_ok, _ = any_capture_availability()
        self.assertEqual(any_ok, backs["npcap"][0] or backs["windivert"][0])


class TestLazyScapy(unittest.TestCase):
    """Scapy 延遲載入：import capture（GUI 啟動、WinDivert 路徑）不該拉 Scapy。"""

    def test_import_capture_and_windivert_path_do_not_load_scapy(self):
        from netmon import capture as capture_mod

        if not capture_mod.SCAPY_AVAILABLE:
            self.skipTest("本環境沒有安裝 Scapy")
        code = (
            "import sys\n"
            "import netmon.capture as c\n"
            "assert 'scapy' not in sys.modules, 'import netmon.capture 就載了 Scapy'\n"
            "import socket, struct\n"
            "ip4 = (struct.pack('>BBHHHBBH4s4s', 0x45, 0, 40, 0x1234, 0, 64, 6, 0,\n"
            "                  socket.inet_aton('192.168.1.5'), socket.inet_aton('1.2.3.4'))\n"
            "       + struct.pack('>HHIIBBHHH', 51000, 8123, 1, 2, (5 << 4) | 0, 0x02, 65535, 0, 0))\n"
            "rec = c.record_from_ip_bytes(ip4, 1, {'192.168.1.5'})\n"
            "assert rec.protocol == 'TCP', rec.protocol\n"
            "assert rec.src_port == 51000 and rec.dst_port == 8123\n"
            "assert 'scapy' not in sys.modules, 'WinDivert 路徑不應載入 Scapy'\n"
            "m = c._get_scapy()          # 第一次真的需要時才載\n"
            "assert c.SCAPY_AVAILABLE and 'scapy' in sys.modules\n"
            "assert m.IP is not None\n"
            "print('LAZY-OK')\n"
        )
        import subprocess
        import sys as _sys

        repo = Path(__file__).resolve().parents[1]
        out = subprocess.run([_sys.executable, "-c", code], capture_output=True,
                             text=True, cwd=repo)
        self.assertIn("LAZY-OK", out.stdout, out.stderr[-600:])

    def test_get_scapy_identity(self):
        from netmon import capture as capture_mod

        if not capture_mod.SCAPY_AVAILABLE:
            self.skipTest("本環境沒有安裝 Scapy")
        self.assertIs(capture_mod._get_scapy(), capture_mod._get_scapy())


if __name__ == "__main__":
    unittest.main()
