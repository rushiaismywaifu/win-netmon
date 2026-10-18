"""層級 5 單元測試（規則引擎、防火牆管理器、規則儲存、假 WinDivert 引擎）。

在非 Windows 環境用假 pydivert handle / 假 netsh runner 執行，不需要真驅動。
執行：python -m unittest discover -s tests -v
"""
import json
import random
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from netmon.divert_engine import DivertEngine, view_from_pydivert
from netmon.rule_engine import (
    VERDICT_DELAY, VERDICT_DROP, VERDICT_PASS, VERDICT_REDIRECT,
    VERDICT_REDIRECT_REVERSE, InterceptRule, PacketView, RuleEngine,
    build_divert_filter, domain_matches, ip_in_spec, normalize_domain,
    parse_ip_spec, parse_port_spec, port_in_spec,
)
from netmon.rule_store import RuleStore
from netmon.win_firewall import (
    FirewallManager, SystemFirewallRule, sanitize_label,
)


def view(direction="out", protocol="TCP", src="10.0.0.2", dst="2.2.2.2",
         sport=50000, dport=443, length=100, payload=b"", process=""):
    return PacketView(direction=direction, protocol=protocol, src_ip=src,
                      dst_ip=dst, src_port=sport, dst_port=dport,
                      length=length, payload=payload, process_name=process)


def dns_query(name="ads.doubleclick.net"):
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)


class TestPortIpDomainSpecs(unittest.TestCase):
    def test_parse_port_spec(self):
        self.assertEqual(parse_port_spec("443"), [(443, 443)])
        self.assertEqual(parse_port_spec("80,443"), [(80, 80), (443, 443)])
        self.assertEqual(parse_port_spec("8000-9000"), [(8000, 9000)])
        self.assertEqual(parse_port_spec(" 80 , 443 "), [(80, 80), (443, 443)])
        self.assertEqual(parse_port_spec(""), [])
        for bad in ("abc", "-1", "99999", "443-x", "80-"):
            with self.assertRaises((ValueError, TypeError), msg=bad):
                parse_port_spec(bad)

    def test_port_in_spec(self):
        rs = parse_port_spec("80,443,8000-9000")
        self.assertTrue(port_in_spec(443, rs))
        self.assertTrue(port_in_spec(8500, rs))
        self.assertFalse(port_in_spec(53, rs))
        self.assertFalse(port_in_spec(None, rs))
        self.assertTrue(port_in_spec(12345, []))  # 空 = 不限

    def test_parse_ip_spec(self):
        self.assertEqual(str(parse_ip_spec("1.2.3.4")), "1.2.3.4/32")
        self.assertEqual(str(parse_ip_spec("10.0.0.0/8")), "10.0.0.0/8")
        self.assertEqual(str(parse_ip_spec("10.0.0.1/8")), "10.0.0.0/8")  # strict=False
        self.assertIsNone(parse_ip_spec(""))
        self.assertEqual(str(parse_ip_spec("::1")), "::1/128")
        with self.assertRaises(ValueError):
            parse_ip_spec("not-an-ip")

    def test_ip_in_spec(self):
        net = parse_ip_spec("10.0.0.0/8")
        self.assertTrue(ip_in_spec("10.9.9.9", net))
        self.assertFalse(ip_in_spec("192.168.1.1", net))
        self.assertTrue(ip_in_spec("1.1.1.1", None))

    def test_domain_matches(self):
        self.assertTrue(domain_matches("doubleclick.net", "doubleclick.net"))
        self.assertTrue(domain_matches("ads.doubleclick.net", "doubleclick.net"))
        self.assertTrue(domain_matches("Ads.DoubleClick.Net", "DOUBLECLICK.NET"))
        self.assertTrue(domain_matches("ads.doubleclick.net.", "doubleclick.net"))
        self.assertFalse(domain_matches("fakedoubleclick.net", "doubleclick.net"))
        self.assertFalse(domain_matches("google.com", "doubleclick.net"))
        self.assertEqual(normalize_domain("  Example.COM. "), "example.com")


class TestRuleMatching(unittest.TestCase):
    def test_block_by_port(self):
        eng = RuleEngine([InterceptRule(action="block", protocol="tcp", remote_port="443")])
        self.assertEqual(eng.evaluate(view(dport=443)).verdict, VERDICT_DROP)
        self.assertEqual(eng.evaluate(view(dport=80)).verdict, VERDICT_PASS)
        # UDP 443 不命中（協定為 tcp）
        self.assertEqual(eng.evaluate(view(protocol="UDP", dport=443)).verdict, VERDICT_PASS)

    def test_allow_first_ordering(self):
        eng = RuleEngine([
            InterceptRule(name="放行", action="allow", remote_ip="1.1.1.1"),
            InterceptRule(name="封443", action="block", protocol="tcp", remote_port="443"),
        ])
        self.assertEqual(eng.evaluate(view(dst="1.1.1.1", dport=443)).verdict, VERDICT_PASS)
        self.assertEqual(eng.evaluate(view(dst="2.2.2.2", dport=443)).verdict, VERDICT_DROP)
        # 順序對調後 1.1.1.1:443 被擋
        eng2 = RuleEngine(list(reversed(eng.get_rules())))
        self.assertEqual(eng2.evaluate(view(dst="1.1.1.1", dport=443)).verdict, VERDICT_DROP)

    def test_cidr_plus_process(self):
        rule = InterceptRule(action="block", remote_ip="10.0.0.0/8", process_name="chrome.exe")
        eng = RuleEngine([rule])
        self.assertEqual(eng.evaluate(view(dst="10.1.2.3", process="Chrome.EXE")).verdict, VERDICT_DROP)
        self.assertEqual(eng.evaluate(view(dst="10.1.2.3", process="firefox.exe")).verdict, VERDICT_PASS)
        self.assertEqual(eng.evaluate(view(dst="172.16.0.1", process="chrome.exe")).verdict, VERDICT_PASS)
        # 無法歸屬程式時（process 空）不命中需程式條件的規則
        self.assertEqual(eng.evaluate(view(dst="10.1.2.3", process="")).verdict, VERDICT_PASS)

    def test_disabled_rule_and_direction(self):
        eng = RuleEngine([InterceptRule(action="block", enabled=False, protocol="tcp", remote_port="443")])
        self.assertEqual(eng.evaluate(view()).verdict, VERDICT_PASS)
        rule = InterceptRule(action="block", direction="in", protocol="tcp", remote_port="443")
        eng2 = RuleEngine([rule])
        inbound = view(direction="in", src="8.8.8.8", dst="10.0.0.2", sport=443, dport=50000)
        self.assertEqual(eng2.evaluate(inbound).verdict, VERDICT_DROP)
        self.assertEqual(eng2.evaluate(view(direction="out")).verdict, VERDICT_PASS)

    def test_hit_counters(self):
        rule = InterceptRule(action="block", protocol="tcp", remote_port="443")
        eng = RuleEngine([rule])
        eng.evaluate(view())
        eng.evaluate(view(dport=80))
        self.assertEqual(rule.hits, 1)
        self.assertEqual(rule.dropped, 1)
        self.assertEqual(rule.passed, 0)


class TestActions(unittest.TestCase):
    def test_limit_token_bucket(self):
        eng = RuleEngine([InterceptRule(action="limit", limit_bytes_per_sec=1000)])
        big = view(length=40000)
        # 初始 burst 容量 64KB：第 1 顆過（剩 25536），之後立刻同型封包被丟
        self.assertEqual(eng.evaluate(big, now=1000.0).verdict, VERDICT_PASS)
        self.assertEqual(eng.evaluate(big, now=1000.0).verdict, VERDICT_DROP)
        # 50 秒後以 1000 B/s 回補到容量上限，再次放行
        self.assertEqual(eng.evaluate(big, now=1050.0).verdict, VERDICT_PASS)

    def test_impair_delay_and_loss(self):
        rule = InterceptRule(action="impair", delay_ms=120, loss_percent=50)
        eng = RuleEngine([rule], rng=random.Random(42))
        verdicts = [eng.evaluate(view()).verdict for _ in range(8)]
        self.assertIn(VERDICT_DELAY, verdicts)
        self.assertIn(VERDICT_DROP, verdicts)
        d = eng.evaluate(view())
        while d.verdict == VERDICT_DROP:  # 找到一個沒被丟的確認 delay 值
            d = eng.evaluate(view())
        self.assertEqual(d.verdict, VERDICT_DELAY)
        self.assertEqual(d.delay_ms, 120)

    def test_impair_zero_loss(self):
        eng = RuleEngine([InterceptRule(action="impair", delay_ms=50, loss_percent=0)])
        for _ in range(5):
            self.assertEqual(eng.evaluate(view()).verdict, VERDICT_DELAY)

    def test_dns_domain_block(self):
        eng = RuleEngine([InterceptRule(action="block", domain="doubleclick.net")])
        bad = view(protocol="UDP", dst="8.8.8.8", sport=53000, dport=53,
                   length=len(dns_query()), payload=dns_query())
        d = eng.evaluate(bad)
        self.assertEqual(d.verdict, VERDICT_DROP)
        self.assertIn("ads.doubleclick.net", d.reason)
        good = view(protocol="UDP", dst="8.8.8.8", sport=53000, dport=53,
                    payload=dns_query("www.google.com"))
        self.assertEqual(eng.evaluate(good).verdict, VERDICT_PASS)

    def test_redirect_and_reverse(self):
        eng = RuleEngine([InterceptRule(action="redirect", protocol="tcp", remote_port="80",
                                        redirect_ip="127.0.0.1", redirect_port=8080)])
        out = view(src="192.168.1.5", dst="93.184.216.34", sport=50001, dport=80)
        d = eng.evaluate(out)
        self.assertEqual(d.verdict, VERDICT_REDIRECT)
        self.assertEqual(d.new_dst_ip, "127.0.0.1")
        self.assertEqual(d.new_dst_port, 8080)
        back = view(direction="in", src="127.0.0.1", dst="192.168.1.5", sport=8080, dport=50001)
        d2 = eng.evaluate(back)
        self.assertEqual(d2.verdict, VERDICT_REDIRECT_REVERSE)
        self.assertEqual(d2.new_src_ip, "93.184.216.34")
        self.assertEqual(d2.new_src_port, 80)

    def test_validation_errors(self):
        self.assertEqual(InterceptRule(name="ok").validate(), [])
        errs = InterceptRule(name="  ").validate()
        self.assertTrue(any("名稱" in e for e in errs))
        errs = InterceptRule(action="limit", limit_bytes_per_sec=0).validate()
        self.assertTrue(errs)
        errs = InterceptRule(action="impair", delay_ms=0, loss_percent=0).validate()
        self.assertTrue(errs)
        errs = InterceptRule(action="impair", loss_percent=150, delay_ms=10).validate()
        self.assertTrue(errs)
        errs = InterceptRule(action="redirect", redirect_ip="999.1.1.1").validate()
        self.assertTrue(errs)
        errs = InterceptRule(remote_ip="網段亂打", remote_port="一定不是埠").validate()
        self.assertGreaterEqual(len(errs), 2)


class TestDivertFilterBuild(unittest.TestCase):
    def test_empty_rules_false(self):
        self.assertEqual(build_divert_filter([]), "false")
        self.assertEqual(build_divert_filter([InterceptRule(enabled=False)]), "false")

    def test_tcp_port_and_loopback(self):
        f = build_divert_filter([InterceptRule(action="block", protocol="tcp", remote_port="443")])
        self.assertTrue(f.startswith("not loopback"))
        self.assertIn("tcp.DstPort == 443", f)
        self.assertIn("outbound", f)

    def test_no_loopback_exclusion(self):
        f = build_divert_filter([InterceptRule(action="block", protocol="tcp", remote_port="443")],
                                exclude_loopback=False)
        self.assertNotIn("loopback", f)

    def test_cidr_range_and_icmp(self):
        f = build_divert_filter([InterceptRule(action="block", remote_ip="10.0.0.0/8")])
        self.assertIn("ip.DstAddr >= 10.0.0.0", f)
        self.assertIn("ip.DstAddr <= 10.255.255.255", f)
        f2 = build_divert_filter([InterceptRule(action="block", protocol="icmp")])
        self.assertIn("(icmp or icmpv6)", f2)

    def test_domain_frag_and_redirect_inbound(self):
        f = build_divert_filter([InterceptRule(action="block", domain="x.com")])
        self.assertIn("udp.DstPort == 53", f)
        self.assertIn("tcp.DstPort == 53", f)
        f2 = build_divert_filter([InterceptRule(action="redirect", protocol="tcp", remote_port="80",
                                                redirect_ip="127.0.0.1", redirect_port=8080)])
        self.assertIn("inbound and ip.SrcAddr == 127.0.0.1", f2)

    def test_unconditional_rule_contains_true(self):
        f = build_divert_filter([InterceptRule(action="block", direction="both")])
        self.assertIn("(true)", f)


class TestSystemFirewall(unittest.TestCase):
    def test_add_command_program(self):
        r = SystemFirewallRule(label="測試", kind="program",
                               program_path=r"C:\Program Files\App\app.exe")
        cmd = " ".join(r.add_command())
        self.assertIn('name="Win-NetMon-', cmd)
        self.assertIn("dir=out", cmd)
        self.assertIn("action=block", cmd)
        self.assertIn('program="C:\\Program Files\\App\\app.exe"', cmd)

    def test_add_command_ip_with_port(self):
        r = SystemFirewallRule(kind="ip", remote_ip="203.0.113.0/24",
                               protocol="tcp", remote_port="443")
        cmd = " ".join(r.add_command())
        self.assertIn("remoteip=203.0.113.0/24", cmd)
        self.assertIn("protocol=TCP", cmd)
        self.assertIn("remoteport=443", cmd)

    def test_validation(self):
        self.assertEqual(SystemFirewallRule(kind="ip", remote_ip="1.2.3.4").validate(), [])
        self.assertTrue(SystemFirewallRule(kind="program", program_path="").validate())
        self.assertTrue(SystemFirewallRule(kind="program", program_path="app.dll").validate())
        self.assertTrue(SystemFirewallRule(kind="ip", remote_ip="abc").validate())
        # 埠 + 任意協定 → 不合法（netsh 限制）
        self.assertTrue(SystemFirewallRule(kind="port", protocol="any", remote_port="443").validate())
        self.assertTrue(SystemFirewallRule(kind="port", protocol="tcp", remote_port="").validate())

    def test_manager_with_fake_runner(self):
        rule = SystemFirewallRule(kind="ip", remote_ip="203.0.113.7", label="單元測試")
        calls = []

        def fake(cmd):
            calls.append(cmd)
            if "show" in cmd:
                return 0, f"規則名稱： {rule.system_name}\n已啟用： 是"
            return 0, "確定。"

        mgr = FirewallManager(runner=fake, check_platform=False)
        ok, _ = mgr.add(rule)
        self.assertTrue(ok)
        self.assertTrue(mgr.exists(rule))
        ok, _ = mgr.remove(rule)
        self.assertTrue(ok)
        removed, errors = mgr.remove_all([rule])
        self.assertEqual(removed, 1)
        self.assertEqual(errors, [])
        self.assertTrue(any("add" in c for c in calls))
        self.assertTrue(any("delete" in c for c in calls))

    def test_manager_failure_output(self):
        mgr = FirewallManager(runner=lambda cmd: (1, "錯誤：存取被拒。"),
                              check_platform=False)
        ok, msg = mgr.add(SystemFirewallRule(kind="ip", remote_ip="1.2.3.4"))
        self.assertFalse(ok)
        self.assertIn("netsh", msg)

    def test_sanitize_label(self):
        self.assertEqual(sanitize_label('  封鎖 "惡意\n" 程式  '), "封鎖  惡意   程式")
        self.assertEqual(sanitize_label(""), "未命名封鎖")


class TestRuleStore(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "sub" / "rules.json")
            store = RuleStore(path)
            r1 = InterceptRule(name="擋廣告", action="block", domain="doubleclick.net")
            r1.hits = 99  # 執行時統計不得寫入
            store.set_intercept_rules([r1])
            store.upsert_firewall(SystemFirewallRule(kind="ip", remote_ip="1.2.3.4", label="IP封鎖"))
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertNotIn("hits", raw["intercept"][0])
            s2 = RuleStore(path)
            s2.load()
            self.assertEqual(len(s2.intercept_rules), 1)
            self.assertEqual(s2.intercept_rules[0].domain, "doubleclick.net")
            self.assertEqual(s2.intercept_rules[0].hits, 0)
            self.assertEqual(s2.firewall_rules[0].system_name,
                             "Win-NetMon-" + s2.firewall_rules[0].id)
            s2.remove_firewall(s2.firewall_rules[0].id)
            s3 = RuleStore(path)
            s3.load()
            self.assertEqual(s3.firewall_rules, [])

    def test_corrupt_file_falls_back_empty(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rules.json"
            path.write_text("{這不是JSON", encoding="utf-8")
            store = RuleStore(str(path))
            store.load()
            self.assertEqual(store.intercept_rules, [])
            self.assertTrue(store.load_error)


class _FakePacket:
    def __init__(self, dport=443, protocol="tcp", payload=b"x" * 40):
        self.src_addr = "10.0.0.2"
        self.dst_addr = "2.2.2.2"
        self.src_port = 50000
        self.dst_port = dport
        self.is_outbound = True
        self.payload = payload
        self.raw = b"\x00" * (40 + len(payload))
        self.tcp = object() if protocol == "tcp" else None
        self.udp = object() if protocol == "udp" else None
        self.icmpv4 = None
        self.icmpv6 = None


class _FakeHandle:
    def __init__(self, packets):
        self._packets = packets
        self.sent = []
        self.closed = False
        self.filter_string = ""

    def __iter__(self):
        for pkt in self._packets:
            if self.closed:
                break
            yield pkt
        while not self.closed:
            time.sleep(0.02)

    def send(self, pkt, recalculate_checksum=True):
        self.sent.append((pkt.dst_addr, pkt.dst_port, recalculate_checksum))

    def close(self):
        self.closed = True


class TestDivertEngineFake(unittest.TestCase):
    def test_view_from_pydivert(self):
        pkt = _FakePacket(dport=53, protocol="udp", payload=dns_query())
        pkt.src_port = 53000
        v = view_from_pydivert(pkt, local_ips={"10.0.0.2"}, conn_index=None)
        self.assertEqual(v.direction, "out")
        self.assertEqual(v.protocol, "UDP")
        self.assertEqual(v.dst_ip, "2.2.2.2")
        self.assertEqual(v.dst_port, 53)
        self.assertEqual(v.dns_qname, "ads.doubleclick.net")

    def test_engine_end_to_end(self):
        rules = [
            InterceptRule(name="封443", action="block", protocol="tcp", remote_port="443"),
            InterceptRule(name="擋廣告", action="block", domain="doubleclick.net"),
            InterceptRule(name="轉址80", action="redirect", protocol="tcp", remote_port="80",
                          redirect_ip="127.0.0.1", redirect_port=8080),
        ]
        pkts = [_FakePacket(443), _FakePacket(80),
                _FakePacket(53, protocol="udp", payload=dns_query()),
                _FakePacket(25)]
        pkts[2].src_port = 53000
        holder = {}

        def factory(filt):
            handle = _FakeHandle(pkts)
            handle.filter_string = filt
            holder["h"] = handle
            return handle

        engine = DivertEngine(RuleEngine(rules), conn_index=None, handle_factory=factory)
        used_filter = engine.start(auto_stop_seconds=0)
        self.assertIn("tcp.DstPort == 443", used_filter)
        # 等統計與「實際送出」都到位才 stop（stop 會丟棄佇列中未送出的封包）
        deadline = time.time() + 5
        while time.time() < deadline:
            if engine.snapshot_stats().intercepted >= 4 and len(holder["h"].sent) >= 2:
                break
            time.sleep(0.05)
        engine.stop()
        stats = engine.snapshot_stats()
        self.assertEqual(stats.intercepted, 4)
        self.assertEqual(stats.dropped, 2)        # 443 + DNS
        self.assertEqual(stats.redirected, 1)     # 80
        sent = holder["h"].sent
        self.assertEqual(len(sent), 2)            # 轉址後的 80 與直通的 25
        self.assertIn(("127.0.0.1", 8080, True), sent)
        self.assertIn(("2.2.2.2", 25, False), sent)
        logs = engine.recent_logs()
        self.assertTrue(any(e.rule_name == "擋廣告" for e in logs))

    def test_start_without_rules_raises(self):
        engine = DivertEngine(RuleEngine([]), handle_factory=lambda f: _FakeHandle([]))
        with self.assertRaises(RuntimeError):
            engine.start()

    def test_deadline_helper(self):
        engine = DivertEngine(RuleEngine([InterceptRule(action="block", remote_port="443",
                                                        protocol="tcp")]),
                              handle_factory=lambda f: _FakeHandle([]))
        engine.start(auto_stop_seconds=0.1)
        self.assertIsNotNone(engine.seconds_remaining())
        time.sleep(0.15)
        self.assertTrue(engine.deadline_exceeded())
        engine.stop()
        self.assertIsNone(engine.seconds_remaining())


if __name__ == "__main__":
    unittest.main()
