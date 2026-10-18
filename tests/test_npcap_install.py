"""Npcap 一鍵安裝輔助測試（全部離線進行：假的網路 opener / 假的 PowerShell）。

重點：只允許 https://npcap.com/dist/npcap-X.YY.exe、官網首頁解析出最新版、
下載的完整性下限檢查、簽章狀態的判斷（有效/拒絕/未知）、一站式流程在簽章
明確失效時絕不執行。
執行：python -m unittest tests.test_npcap_install -v
"""
import tempfile
import unittest
from pathlib import Path

from netmon.npcap_install import (
    FALLBACK_INSTALLER_URL, discover_installer_url, download_installer,
    install_npcap, launch_installer, parse_latest_installer_url,
    validate_installer_url, verify_authenticode,
)

FAKE_EXE = b"MZ" + b"\x00" * 400_000  # 超過最小完整性下限（300KB）的假安裝檔


class _FakeResponse:
    def __init__(self, data: bytes, headers=None):
        self._data = data
        self._pos = 0
        self.headers = headers or {"Content-Length": str(len(data))}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        if size is None or size < 0:
            chunk = self._data[self._pos:]
            self._pos = len(self._data)
            return chunk
        chunk = self._data[self._pos:self._pos + size]
        self._pos += len(chunk)
        return chunk


def make_opener(mapping: dict[str, bytes]):
    def opener(url):
        if url in mapping:
            return _FakeResponse(mapping[url])
        raise OSError(f"offline fake: no {url}")
    return opener


HOMEPAGE_HTML = """
<html><body>
<a href="https://npcap.com/dist/npcap-1.79.exe">old</a>
<a href="https://npcap.com/dist/npcap-1.89.exe">latest</a>
<a href="https://npcap.com/dist/npcap-sdk-1.16.zip">sdk</a>
<a href="https://npcap.com/dist/npcap-1.89.zip">src</a>
</body></html>
"""


class TestUrlLogic(unittest.TestCase):
    def test_parse_latest_from_homepage(self):
        self.assertEqual(parse_latest_installer_url(HOMEPAGE_HTML),
                         "https://npcap.com/dist/npcap-1.89.exe")

    def test_parse_latest_version_ordering_numeric(self):
        html = "dist/npcap-1.9.exe dist/npcap-1.89.exe dist/npcap-1.10.exe"
        # 數值比較：1.89 > 1.10 > 1.9（不是字串字典序）
        self.assertEqual(parse_latest_installer_url(html),
                         "https://npcap.com/dist/npcap-1.89.exe")

    def test_parse_latest_none(self):
        self.assertIsNone(parse_latest_installer_url("<html>nothing</html>"))
        self.assertIsNone(parse_latest_installer_url(""))

    def test_validate_installer_url(self):
        self.assertTrue(validate_installer_url("https://npcap.com/dist/npcap-1.89.exe"))
        self.assertFalse(validate_installer_url("http://npcap.com/dist/npcap-1.89.exe"))
        self.assertFalse(validate_installer_url("https://evil.com/dist/npcap-1.89.exe"))
        self.assertFalse(validate_installer_url("https://npcap.com.evil.com/dist/npcap-1.89.exe"))
        self.assertFalse(validate_installer_url("https://npcap.com/dist/npcap-1.89.zip"))
        self.assertFalse(validate_installer_url("https://npcap.com/other/npcap-1.89.exe"))
        self.assertFalse(validate_installer_url(""))

    def test_discover_uses_homepage(self):
        opener = make_opener({"https://npcap.com": HOMEPAGE_HTML.encode()})
        self.assertEqual(discover_installer_url(opener=opener),
                         "https://npcap.com/dist/npcap-1.89.exe")

    def test_discover_falls_back_when_offline(self):
        def boom(url):
            raise OSError("no network")
        self.assertEqual(discover_installer_url(opener=boom), FALLBACK_INSTALLER_URL)

    def test_discover_falls_back_when_page_unparseable(self):
        opener = make_opener({"https://npcap.com": b"<html>changed layout</html>"})
        self.assertEqual(discover_installer_url(opener=opener), FALLBACK_INSTALLER_URL)


class TestDownload(unittest.TestCase):
    URL = "https://npcap.com/dist/npcap-1.89.exe"

    def test_download_ok_with_progress(self):
        opener = make_opener({self.URL: FAKE_EXE})
        seen = []
        with tempfile.TemporaryDirectory() as td:
            path = download_installer(url=self.URL, dest_dir=td, opener=opener,
                                      progress=lambda d, t: seen.append((d, t)))
            self.assertEqual(path.name, "npcap-1.89.exe")
            self.assertEqual(path.read_bytes(), FAKE_EXE)
            self.assertFalse((Path(td) / "npcap-1.89.exe.part").exists())
        self.assertTrue(seen)
        self.assertEqual(seen[-1], (len(FAKE_EXE), len(FAKE_EXE)))

    def test_download_rejects_unofficial_url(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                download_installer(url="https://evil.com/dist/npcap-1.89.exe",
                                   dest_dir=td, opener=make_opener({}))

    def test_download_rejects_tiny_file(self):
        opener = make_opener({self.URL: b"small"})
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                download_installer(url=self.URL, dest_dir=td, opener=opener)
            self.assertEqual(list(Path(td).iterdir()), [])  # 連 .part 都清掉

    def test_download_rejects_incomplete(self):
        def opener(url):
            return _FakeResponse(FAKE_EXE[:1000],
                                 headers={"Content-Length": str(len(FAKE_EXE))})
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                download_installer(url=self.URL, dest_dir=td, opener=opener)


class TestAuthenticode(unittest.TestCase):
    def _runner(self, output, code=0):
        return lambda cmd: (code, output)

    def test_valid_nmap_signer(self):
        out = "Valid|CN=Nmap Software LLC, O=Nmap Software LLC"
        ok, detail = verify_authenticode("x.exe", runner=self._runner(out),
                                         check_platform=False)
        self.assertIs(ok, True)
        self.assertIn("Nmap", detail)

    def test_valid_wrong_signer_rejected(self):
        out = "Valid|CN=Some Random Company"
        ok, _ = verify_authenticode("x.exe", runner=self._runner(out),
                                    check_platform=False)
        self.assertIs(ok, False)

    def test_not_signed_rejected(self):
        ok, _ = verify_authenticode("x.exe", runner=self._runner("NotSigned|"),
                                    check_platform=False)
        self.assertIs(ok, False)

    def test_check_failure_is_unknown(self):
        ok, _ = verify_authenticode("x.exe", runner=self._runner("", code=1),
                                    check_platform=False)
        self.assertIsNone(ok)

    def test_path_with_quote_is_escaped(self):
        captured = {}

        def runner(cmd):
            captured["cmd"] = cmd
            return 0, "Valid|CN=Nmap Software LLC"

        verify_authenticode(r"C:\a'b\npcap.exe", runner=runner, check_platform=False)
        script = captured["cmd"][-1]
        self.assertIn(r"C:\a''b\npcap.exe", script)


def _installer_opener():
    return make_opener({
        "https://npcap.com": HOMEPAGE_HTML.encode(),
        "https://npcap.com/dist/npcap-1.89.exe": FAKE_EXE,
    })


class TestInstallFlow(unittest.TestCase):
    def test_happy_path_launches(self):
        launched = {}

        def popen(cmd, close_fds=True):
            launched["cmd"] = cmd

        success, msg, path = install_npcap(
            opener=_installer_opener(),
            runner=lambda cmd: (0, "Valid|CN=Nmap Software LLC"),
            popen=popen, check_platform=False)
        self.assertTrue(success, msg)
        self.assertEqual(Path(launched["cmd"][0]).name, "npcap-1.89.exe")
        self.assertIsNotNone(path)

    def test_invalid_signature_never_launches(self):
        launched = []
        success, msg, _ = install_npcap(
            opener=_installer_opener(),
            runner=lambda cmd: (0, "HashMismatch|CN=Nmap Software LLC"),
            popen=lambda cmd, close_fds=True: launched.append(cmd),
            check_platform=False)
        self.assertFalse(success)
        self.assertIn("拒絕執行", msg)
        self.assertEqual(launched, [])

    def test_unknown_signature_blocked_by_default(self):
        success, msg, _ = install_npcap(
            opener=_installer_opener(),
            runner=lambda cmd: (1, ""),
            popen=lambda cmd, close_fds=True: None,
            check_platform=False)
        self.assertFalse(success)
        self.assertIn("手動下載", msg)

    def test_unknown_signature_allowed_with_override(self):
        launched = []
        success, _, _ = install_npcap(
            opener=_installer_opener(),
            runner=lambda cmd: (1, ""),
            popen=lambda cmd, close_fds=True: launched.append(cmd),
            allow_unverified=True, check_platform=False)
        self.assertTrue(success)
        self.assertEqual(len(launched), 1)

    def test_launch_installer_missing_file(self):
        ok, _ = launch_installer("/nonexistent/npcap.exe", check_platform=False)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
