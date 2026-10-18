"""版本工具測試：python -m unittest discover -s tests -v"""
import tempfile
import unittest
from pathlib import Path

from tools.version import (bump_version, parse_version, read_version, render_pyinstaller_version_file,
                           write_version)


class TestVersionHelpers(unittest.TestCase):
    def test_repo_version_is_readable(self):
        # 真實檔案必須是 major.minor.patch（auto-tag / release workflow 依賴這個格式）
        parse_version(read_version())

    def test_bump_levels(self):
        self.assertEqual(bump_version("1.2.3", "patch"), "1.2.4")
        self.assertEqual(bump_version("1.2.3", "minor"), "1.3.0")
        self.assertEqual(bump_version("1.2.3", "major"), "2.0.0")

    def test_bump_strips_prefix(self):
        self.assertEqual(bump_version("v1.2.3", "patch"), "1.2.4")

    def test_parse_rejects_garbage(self):
        for bad in ("1.2", "1.2.3.4", "x.y.z", "1.2.3a", ""):
            with self.assertRaises(SystemExit, msg=bad):
                parse_version(bad)

    def test_write_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "__init__.py"
            path.write_text('"""doc"""\n\n__version__ = "1.2.3"\n__app_name__ = "Win-NetMon"\n',
                            encoding="utf-8")
            self.assertEqual(read_version(path), "1.2.3")
            write_version("9.9.9", path)
            self.assertEqual(read_version(path), "9.9.9")
            text = path.read_text(encoding="utf-8")
            self.assertIn('__app_name__ = "Win-NetMon"', text)
            self.assertEqual(text.count("__version__"), 1)

    def test_write_missing_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.py"
            path.write_text("x = 1\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                write_version("1.0.0", path)

    def test_pyinstaller_version_file(self):
        content = render_pyinstaller_version_file("1.2.3")
        self.assertIn("filevers=(1, 2, 3, 0)", content)
        self.assertIn("prodvers=(1, 2, 3, 0)", content)
        self.assertIn("StringStruct('ProductVersion', '1.2.3')", content)
        self.assertIn("VSVersionInfo(", content)


if __name__ == "__main__":
    unittest.main()
