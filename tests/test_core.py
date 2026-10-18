"""核心模組單元測試（不含 GUI）：python -m unittest discover -s tests -v"""
import struct
import time
import unittest

from netmon.connections import ConnectionRecord, connections_to_csv
from netmon.packet_info import (classify_payload, extract_tls_sni, is_tls_record,
                                parse_dns, parse_http)
from netmon.traffic import (UNKNOWN_NAME, ConnectionIndex, TrafficAggregator)
from netmon.utils import fmt_bytes, fmt_rate, hexdump


def make_dns_query(name="example.com", qtype=1):
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)


def make_client_hello(host=b"www.google.com"):
    sni_data = struct.pack(">H", len(host) + 3) + b"\x00" + struct.pack(">H", len(host)) + host
    sni_ext = struct.pack(">HH", 0, len(sni_data)) + sni_data
    exts = struct.pack(">H", len(sni_ext)) + sni_ext
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00" + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


class TestUtils(unittest.TestCase):
    def test_fmt_bytes(self):
        self.assertEqual(fmt_bytes(0), "0 B")
        self.assertEqual(fmt_bytes(512), "512 B")
        self.assertEqual(fmt_bytes(1536), "1.50 KB")
        self.assertEqual(fmt_bytes(5 * 1024**3), "5.00 GB")

    def test_fmt_rate(self):
        self.assertTrue(fmt_rate(2048).endswith("/s"))

    def test_hexdump(self):
        out = hexdump(b"AB\x00")
        self.assertIn("41 42 00", out)
        self.assertIn("|AB.|", out)


class TestPacketInfo(unittest.TestCase):
    def test_dns_query(self):
        dns = parse_dns(make_dns_query("dns.google", 28))
        self.assertIsNotNone(dns)
        self.assertEqual(dns["qname"], "dns.google")
        self.assertEqual(dns["qtype"], "AAAA")
        self.assertFalse(dns["is_response"])

    def test_dns_rejects_garbage(self):
        self.assertIsNone(parse_dns(b"\x00" * 20))
        self.assertIsNone(parse_dns(b"short"))

    def test_tls_sni(self):
        hello = make_client_hello()
        self.assertEqual(extract_tls_sni(hello), "www.google.com")
        self.assertEqual(is_tls_record(hello), "ClientHello")

    def test_http(self):
        info = parse_http(b"GET /a?b=1 HTTP/1.1\r\nHost: example.org\r\n\r\n")
        self.assertEqual(info["method"], "GET")
        self.assertEqual(info["host"], "example.org")
        resp = parse_http(b"HTTP/1.1 404 Not Found\r\n\r\n")
        self.assertEqual(resp["status"], "404")

    def test_classify(self):
        proto, info = classify_payload("UDP", 53000, 53, make_dns_query())
        self.assertEqual(proto, "DNS")
        self.assertIn("example.com", info)
        proto, info = classify_payload("TCP", 50000, 443, make_client_hello())
        self.assertEqual(proto, "TLS")
        self.assertIn("www.google.com", info)
        proto, _ = classify_payload("TCP", 50000, 22, b"SSH-2.0-x")
        self.assertEqual(proto, "SSH")


class TestTraffic(unittest.TestCase):
    def _index(self):
        idx = ConnectionIndex()
        idx.refresh([ConnectionRecord(
            pid=4242, process_name="chrome.exe", protocol="TCP",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="142.250.1.1", remote_port=443, status="ESTABLISHED")])
        return idx

    def test_lookup_exact_and_port(self):
        idx = self._index()
        self.assertEqual(idx.lookup("TCP", "192.168.1.10", 50000, "142.250.1.1", 443),
                         (4242, "chrome.exe"))
        self.assertEqual(idx.lookup("TCP", "192.168.1.10", 50000, "1.2.3.4", 443),
                         (4242, "chrome.exe"))  # 埠號後備比對
        pid, name = idx.lookup("TCP", "192.168.1.10", 9, "1.2.3.4", 443)
        self.assertEqual(name, UNKNOWN_NAME)

    def test_aggregator(self):
        agg = TrafficAggregator()
        agg.add_packet(1, "a.exe", 100, sent=True, remote_endpoint="1.1.1.1:443")
        agg.add_packet(1, "a.exe", 900, sent=False, remote_endpoint="1.1.1.1:443")
        agg.add_packet(2, "b.exe", 50, sent=True)
        ranking = agg.ranking()
        self.assertEqual(ranking[0].name, "a.exe")
        self.assertEqual(ranking[0].total_bytes, 1000)
        agg.update_rates()
        time.sleep(0.02)
        agg.add_packet(1, "a.exe", 2000, sent=False)
        agg.update_rates()
        self.assertGreater(ranking[0].down_rate, 0)
        agg.reset()
        self.assertEqual(agg.ranking(), [])

    def test_add_batch_equals_add_packet(self):
        """批次 API（GUI 排空佇列用）與逐包 API 結果必須完全一致。"""
        entries = [
            (1, "a.exe", 100, True, "1.1.1.1:443"),
            (1, "a.exe", 900, False, "1.1.1.1:443"),
            (2, "b.exe", 50, True, ""),
            (1, "a.exe", 300, True, "1.1.1.1:443"),
            (2, "b.exe", 700, False, "8.8.8.8:53"),
        ]
        one = TrafficAggregator()
        many = TrafficAggregator()
        for pid, name, length, sent, endpoint in entries:
            one.add_packet(pid, name, length, sent=sent, remote_endpoint=endpoint)
        many.add_batch(entries)
        many.add_batch(())  # 空批次也不能出事
        def snapshot(agg):
            return [
                (p.pid, p.name, p.bytes_sent, p.bytes_recv, p.packets_sent,
                 p.packets_recv, sorted(p.endpoints))
                for p in agg.ranking()
            ]

        self.assertEqual(snapshot(one), snapshot(many))
        self.assertEqual(one.totals(), many.totals())


class TestScapyConversion(unittest.TestCase):
    def test_packet_to_record(self):
        try:
            from scapy.all import IP, UDP, Ether, Raw
        except ImportError:
            self.skipTest("未安裝 scapy")
        from netmon.capture import packet_to_record

        pkt = Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=53000, dport=53) / Raw(make_dns_query())
        pkt.time = 1700000000.0
        rec = packet_to_record(pkt, 1, {"10.0.0.2"}, None)
        self.assertEqual(rec.protocol, "DNS")
        self.assertEqual(rec.direction, "out")
        self.assertIn("example.com", rec.info)
        self.assertIn("UDP", rec.dissect())

    def test_csv_export(self):
        rec = ConnectionRecord(1, "a.exe", "TCP", "10.0.0.2", 80, "1.1.1.1", 443, "ESTABLISHED")
        csv_text = connections_to_csv([rec])
        self.assertIn("a.exe", csv_text)
        self.assertIn("1.1.1.1:443", csv_text)


if __name__ == "__main__":
    unittest.main()
