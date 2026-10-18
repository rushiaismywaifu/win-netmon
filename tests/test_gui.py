"""GUI 元件與視窗啟動測試（含無 tkinter 環境下的 ttk 參數檢查與有顯示環境下的整合測試）。"""
from __future__ import annotations

import importlib
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch


class FakeTclError(Exception):
    pass


def _check_ttk_opts(kw: dict) -> None:
    """模擬 tkinter.ttk._val_or_dict / _format_optdict 的行為：
    設定多個選項時，若任一選項值為 None，Tcl 會收到無值的 -option 並拋出
    `TclError: value for "-<opt>" missing`。
    """
    for opt, val in kw.items():
        if val is None:
            raise FakeTclError(f'value for "-{opt}" missing')


class _FakeVar:
    def __init__(self, value=None, **_kw):
        self._value = value

    def get(self):
        return self._value

    def set(self, value) -> None:
        self._value = value

    def trace_add(self, *_args, **_kw) -> None:
        pass


class _FakeWidget:
    def __init__(self, parent=None, **kw):
        _check_ttk_opts(kw)
        self.parent = parent
        self.kw = dict(kw)

    def pack(self, **kw):
        _check_ttk_opts(kw)
        return self

    def grid(self, **kw):
        _check_ttk_opts(kw)
        return self

    def rowconfigure(self, _idx, **kw):
        _check_ttk_opts(kw)

    def columnconfigure(self, _idx, **kw):
        _check_ttk_opts(kw)

    def configure(self, **kw):
        _check_ttk_opts(kw)
        self.kw.update(kw)

    config = configure

    def cget(self, key: str):
        return self.kw.get(key, "")

    def bind(self, _seq: str, _func=None, **_kw):
        pass

    def after(self, _ms: int, _func=None, *_args):
        return "after#1"


class _FakeTk(_FakeWidget):
    def title(self, _text: str = "") -> None:
        pass

    def geometry(self, _spec: str = "") -> None:
        pass

    def minsize(self, _w: int = 0, _h: int = 0) -> None:
        pass

    def protocol(self, _name: str = "", _func=None) -> None:
        pass

    def option_add(self, _pattern: str, _value) -> None:
        pass

    def update_idletasks(self) -> None:
        pass

    def withdraw(self) -> None:
        pass

    def destroy(self) -> None:
        pass

    def clipboard_clear(self) -> None:
        pass

    def clipboard_append(self, _text: str) -> None:
        pass

    def iconphoto(self, default: bool, img) -> None:
        self._iconphoto_args = (default, img)

    def iconbitmap(self, bitmap: str | None = None, default: str | None = None) -> None:
        if bitmap is not None:
            self._iconbitmap_arg = bitmap
        if default is not None:
            self._iconbitmap_default = default


class _FakeCanvas(_FakeWidget):
    def delete(self, *_args) -> None:
        pass

    def winfo_width(self) -> int:
        return 640

    def winfo_height(self) -> int:
        return 240

    def create_line(self, *_args, **kw) -> int:
        _check_ttk_opts(kw)
        return 1

    def create_text(self, *_args, **kw) -> int:
        _check_ttk_opts(kw)
        return 2

    def create_polygon(self, *_args, **kw) -> int:
        _check_ttk_opts(kw)
        return 3

    def create_rectangle(self, *_args, **kw) -> int:
        _check_ttk_opts(kw)
        return 4


class _FakeMenu(_FakeWidget):
    def add_command(self, **kw) -> None:
        _check_ttk_opts(kw)

    def add_separator(self) -> None:
        pass

    def tk_popup(self, *_args) -> None:
        pass


class _FakeNotebook(_FakeWidget):
    def __init__(self, parent=None, **kw):
        super().__init__(parent, **kw)
        self._tabs: list = []

    def add(self, child, **kw) -> None:
        _check_ttk_opts(kw)
        self._tabs.append(child)

    def select(self, tab_id=None):
        if tab_id is not None:
            return str(tab_id)
        return str(self._tabs[0]) if self._tabs else ""


class _FakePanedwindow(_FakeWidget):
    def add(self, _child, **kw) -> None:
        _check_ttk_opts(kw)


class _FakeScrolledText(_FakeWidget):
    def delete(self, *_args) -> None:
        pass

    def insert(self, *_args) -> None:
        pass

    def see(self, *_args) -> None:
        pass


class _FakeStyle(_FakeWidget):
    def theme_use(self, _name: str | None = None):
        return "clam"

    def configure(self, _style: str, **kw) -> None:
        _check_ttk_opts(kw)

    def map(self, _style: str, **kw) -> None:
        _check_ttk_opts(kw)


class _FakeScrollbar(_FakeWidget):
    def set(self, *_args) -> None:
        pass


class _FakeTreeview(_FakeWidget):
    def __init__(self, parent=None, **kw):
        super().__init__(parent, **kw)
        self.headings: dict[str, dict] = {}
        self.columns_cfg: dict[str, dict] = {}
        self._items: dict[str, dict] = {}
        self._selection: tuple[str, ...] = ()
        self._counter = 0
        self.yview = lambda *_a: None
        self.xview = lambda *_a: None

    def heading(self, col_id: str, option=None, **kw):
        if option is not None:
            kw[option] = None
        _check_ttk_opts(kw)
        self.headings[col_id] = dict(kw)

    def column(self, col_id: str, option=None, **kw):
        if option is not None:
            kw[option] = None
        _check_ttk_opts(kw)
        self.columns_cfg[col_id] = dict(kw)

    def tag_configure(self, _tagname: str, **kw) -> None:
        _check_ttk_opts(kw)

    def get_children(self, _item: str = "") -> tuple[str, ...]:
        return tuple(self._items.keys())

    def delete(self, *items: str) -> None:
        for iid in items:
            self._items.pop(iid, None)

    def insert(self, _parent: str, _index, iid: str | None = None, **kw) -> str:
        _check_ttk_opts(kw)
        self._counter += 1
        real_iid = iid or f"I{self._counter:03d}"
        self._items[real_iid] = {"values": tuple(kw.get("values", ())), "tags": kw.get("tags", ())}
        return real_iid

    def item(self, iid: str, option: str | None = None, **kw):
        if option == "values":
            return self._items.get(iid, {}).get("values", ())
        _check_ttk_opts(kw)
        return self._items.get(iid, {})

    def set(self, iid: str, column: str | None = None, value=None):
        if iid in self._items and column is not None and value is not None:
            self._items[iid][column] = value

    def selection(self) -> tuple[str, ...]:
        return self._selection

    def selection_set(self, *items: str) -> None:
        self._selection = tuple(items)

    def see(self, _iid: str) -> None:
        pass

    def identify_row(self, _y: int) -> str:
        return ""

    def identify_column(self, _x: int) -> str:
        return "#1"


def _build_fake_tk_modules() -> dict[str, types.ModuleType]:
    fake_tk = types.ModuleType("tkinter")
    fake_tk.TclError = FakeTclError
    fake_tk.Tk = _FakeTk
    fake_tk.Frame = _FakeWidget
    fake_tk.Label = _FakeWidget
    fake_tk.Canvas = _FakeCanvas
    fake_tk.Menu = _FakeMenu
    fake_tk.Misc = _FakeWidget
    fake_tk.Widget = _FakeWidget
    fake_tk.StringVar = lambda value="", **kw: _FakeVar(value, **kw)
    fake_tk.BooleanVar = lambda value=False, **kw: _FakeVar(value, **kw)
    fake_tk.PhotoImage = lambda **kw: _FakeWidget(**kw)

    fake_ttk = types.ModuleType("tkinter.ttk")
    fake_ttk.Frame = _FakeWidget
    fake_ttk.Label = _FakeWidget
    fake_ttk.Labelframe = _FakeWidget
    fake_ttk.Button = _FakeWidget
    fake_ttk.Entry = _FakeWidget
    fake_ttk.Combobox = _FakeWidget
    fake_ttk.Checkbutton = _FakeWidget
    fake_ttk.Notebook = _FakeNotebook
    fake_ttk.Panedwindow = _FakePanedwindow
    fake_ttk.Treeview = _FakeTreeview
    fake_ttk.Scrollbar = _FakeScrollbar
    fake_ttk.Style = _FakeStyle

    fake_font = types.ModuleType("tkinter.font")
    fake_font.families = lambda _root=None: ("Segoe UI", "Consolas")

    fake_st = types.ModuleType("tkinter.scrolledtext")
    fake_st.ScrolledText = _FakeScrolledText

    fake_fd = types.ModuleType("tkinter.filedialog")
    fake_mb = types.ModuleType("tkinter.messagebox")

    fake_tk.ttk = fake_ttk
    fake_tk.font = fake_font
    fake_tk.scrolledtext = fake_st
    fake_tk.filedialog = fake_fd
    fake_tk.messagebox = fake_mb

    return {
        "tkinter": fake_tk,
        "tkinter.ttk": fake_ttk,
        "tkinter.font": fake_font,
        "tkinter.scrolledtext": fake_st,
        "tkinter.filedialog": fake_fd,
        "tkinter.messagebox": fake_mb,
    }


class _FakeTkContext:
    """暫時以 fake tkinter 取代 sys.modules 並重新載入 netmon.gui.*。"""

    GUI_MODULES = (
        "netmon.gui",
        "netmon.gui.theme",
        "netmon.gui.widgets",
        "netmon.gui.dashboard_tab",
        "netmon.gui.connections_tab",
        "netmon.gui.processes_tab",
        "netmon.gui.packets_tab",
        "netmon.gui.firewall_tab",
        "netmon.gui.help_tab",
        "netmon.gui.app",
    )

    def __enter__(self):
        self._fake_mods = _build_fake_tk_modules()
        self._saved = {
            name: sys.modules.get(name)
            for name in (*self._fake_mods.keys(), *self.GUI_MODULES)
        }
        for name in self.GUI_MODULES:
            sys.modules.pop(name, None)
        sys.modules.update(self._fake_mods)
        return self

    def __exit__(self, *_exc):
        for name, mod in self._saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod


class TestMakeTreeOptions(unittest.TestCase):
    """回歸測試：確認 make_tree 在 on_sort=None 時不會把 command=None 傳進 tree.heading()。"""

    def test_make_tree_without_on_sort_does_not_pass_none_command(self):
        with _FakeTkContext():
            widgets = importlib.import_module("netmon.gui.widgets")
            cols = [
                ("name", "介面", 200, "w"),
                ("status", "狀態", 64, "center"),
            ]
            tree = widgets.make_tree(_FakeWidget(), cols, on_sort=None, height=7)
            self.assertEqual(tree.headings["name"], {"text": "介面"})
            self.assertNotIn("command", tree.headings["name"])
            self.assertEqual(tree.headings["status"], {"text": "狀態"})
            self.assertNotIn("command", tree.headings["status"])

    def test_make_tree_with_on_sort_registers_clickable_callback(self):
        with _FakeTkContext():
            widgets = importlib.import_module("netmon.gui.widgets")
            sorted_cols: list[str] = []
            cols = [
                ("name", "程式", 190, "w"),
                ("pid", "PID", 70, "e"),
            ]
            tree = widgets.make_tree(_FakeWidget(), cols, on_sort=sorted_cols.append)
            self.assertIn("command", tree.headings["name"])
            self.assertTrue(callable(tree.headings["name"]["command"]))
            tree.headings["name"]["command"]()
            tree.headings["pid"]["command"]()
            self.assertEqual(sorted_cols, ["name", "pid"])

    def test_main_app_all_tabs_init_with_strict_ttk_check(self):
        """在無頭環境下完整初始化 MainApp 與層級 1~5 所有分頁，確認無任何 None 選項傳入 ttk。"""
        with tempfile.TemporaryDirectory() as td, _FakeTkContext():
            store_path = str(Path(td) / "rules.json")
            with patch("netmon.rule_store.default_store_path", return_value=store_path):
                app_mod = importlib.import_module("netmon.gui.app")
                app = app_mod.MainApp()
                try:
                    app._tick_loop()
                    app._drain_loop()
                    self.assertIn("name", app.dashboard_tab.tree.headings)
                    self.assertNotIn("command", app.dashboard_tab.tree.headings["name"])
                    self.assertIn("command", app.connections_tab.tree.headings["name"])
                    self.assertIn("command", app.processes_tab.tree.headings["name"])
                    self.assertNotIn("command", app.packets_tab.tree.headings["no"])
                    self.assertNotIn("command", app.firewall_tab.rules_tree.headings["name"])
                    self.assertNotIn("command", app.firewall_tab.fw_tree.headings["label"])
                    self.assertNotIn("command", app.firewall_tab.log_tree.headings["time"])
                    self.assertTrue(getattr(app, "_iconbitmap_arg", "").endswith("icon.ico"))
                finally:
                    app._on_close()


class TestPacketsTabTrim(unittest.TestCase):
    """回歸測試：封包列表滿了之後只做增量裁剪（不整表重建），選取查找 O(1)。"""

    @staticmethod
    def _record(i: int):
        from netmon.capture import PacketRecord

        return PacketRecord(index=i, timestamp=1700000000.0 + i, length=100,
                            src="10.0.0.2", dst="1.2.3.4", src_port=50000, dst_port=443,
                            transport="TCP", protocol="TCP", info="x", direction="out",
                            pid=1, process_name="a.exe", raw=b"")

    def _with_app(self, callback) -> None:
        with tempfile.TemporaryDirectory() as td, _FakeTkContext():
            store_path = str(Path(td) / "rules.json")
            with patch("netmon.rule_store.default_store_path", return_value=store_path):
                app = importlib.import_module("netmon.gui.app").MainApp()
                try:
                    callback(app)
                finally:
                    app._on_close()

    def test_full_buffer_trim_is_incremental(self):
        def check(app):
            packets_mod = importlib.import_module("netmon.gui.packets_tab")
            limit = packets_mod.MAX_RECORDS
            tab = app.packets_tab
            total = limit + 3000
            records = [self._record(i) for i in range(total)]
            for start in range(0, total, 3000):
                tab.add_records(records[start:start + 3000])
            # 只保留最新 limit 筆，且表格列數一致
            self.assertEqual(len(tab._records), limit)
            self.assertEqual(tab._records[0].index, total - limit)
            self.assertEqual(len(tab._by_iid), limit)
            # 最舊的紀錄已從表格移除
            self.assertNotIn(records[0]._iid, tab._by_iid)
            # 選取查找用 iid 直接命中同一物件
            first = tab._records[0]
            self.assertIs(tab._record_from_iid(first._iid), first)

        self._with_app(check)

    def test_batch_larger_than_limit_skips_trimmed_rows(self):
        def check(app):
            packets_mod = importlib.import_module("netmon.gui.packets_tab")
            limit = packets_mod.MAX_RECORDS
            tab = app.packets_tab
            records = [self._record(i) for i in range(limit + 500)]
            tab.add_records(records)  # 單批就超過上限
            self.assertEqual(len(tab._records), limit)
            self.assertEqual(len(tab._by_iid), limit)
            # 這批中被裁掉的紀錄從未插入表格（沒有 _iid）
            self.assertFalse(hasattr(records[0], "_iid"))
            self.assertIs(tab._record_from_iid(tab._records[-1]._iid), tab._records[-1])

        self._with_app(check)

    def test_display_filter_is_cached_and_rebuild_applies_it(self):
        def check(app):
            tab = app.packets_tab
            tab.display_filter_var.set("udp")
            tab.add_records([self._record(1), self._record(2)])
            self.assertEqual(len(tab._records), 2)
            self.assertEqual(len(tab._by_iid), 0)  # 都不符顯示篩選，不插列
            tab.display_filter_var.set("")
            tab._rebuild()
            self.assertEqual(len(tab._by_iid), 2)

        self._with_app(check)


class TestCaptureStartAsync(unittest.TestCase):
    """回歸測試：開始擷取在背景緒程開啟後端，GUI 主緒程不凍結。"""

    def _with_app(self, callback) -> None:
        with tempfile.TemporaryDirectory() as td, _FakeTkContext():
            store_path = str(Path(td) / "rules.json")
            with patch("netmon.rule_store.default_store_path", return_value=store_path):
                app = importlib.import_module("netmon.gui.app").MainApp()
                try:
                    callback(app)
                finally:
                    app._on_close()

    def _wait_start(self, app) -> None:
        """反覆執行 GUI 排程迴圈，直到背景啟動回呼被處理完。"""
        deadline = time.time() + 5.0
        while app._capture_starting and time.time() < deadline:
            time.sleep(0.02)
            app._drain_loop()
        self.assertFalse(app._capture_starting, "背景啟動回呼未被處理（逾時）")

    def test_toggle_capture_does_not_block_and_updates_ui(self):
        import netmon.capture as capture_mod

        def slow_start(engine, **_kw):
            time.sleep(0.4)  # 模擬開驅動/等後端就緒
            engine.running = True
            engine.backend = "npcap"
            engine.started_at = time.time()

        def check(app):
            with patch.object(capture_mod.CaptureEngine, "start", slow_start):
                t0 = time.monotonic()
                app.toggle_capture()
                elapsed = time.monotonic() - t0
                self.assertLess(elapsed, 0.25, "toggle_capture 仍在同步等待後端啟動")
                self.assertTrue(app._capture_starting)
                self.assertEqual(app.packets_tab.capture_btn.cget("state"), "disabled")
                self.assertIn("啟動", app.packets_tab.capture_btn.cget("text"))
                # 啟動中再按一次不應再開一條緒程
                app.toggle_capture()
                self._wait_start(app)
            self.assertTrue(app.capture_engine.running)
            self.assertTrue(app._capture_was_running)
            self.assertEqual(app.packets_tab.capture_btn.cget("text"), "⏹ 停止擷取")
            self.assertIn("擷取中", app.status_var.get())

        self._with_app(check)

    def test_start_failure_restores_ui_and_reports_reason(self):
        import netmon.capture as capture_mod

        def failing_start(_engine, **_kw):
            time.sleep(0.05)
            raise RuntimeError("驅動打不開（測試）")

        def check(app):
            app_mod = importlib.import_module("netmon.gui.app")
            shown: list[str] = []

            class _StubMessagebox:
                @staticmethod
                def showerror(_title, message, **_kw):
                    shown.append(message)

            with patch.object(capture_mod.CaptureEngine, "start", failing_start), \
                    patch.object(app_mod, "messagebox", _StubMessagebox()):
                app.toggle_capture()
                self._wait_start(app)
            self.assertFalse(app.capture_engine.running)
            self.assertFalse(app._capture_was_running)
            self.assertEqual(app.packets_tab.capture_btn.cget("text"), "▶ 開始擷取")
            self.assertEqual(app.packets_tab.capture_btn.cget("state"), "normal")
            self.assertTrue(shown, "啟動失敗應該跳對話框")
            self.assertIn("驅動打不開", shown[0])

        self._with_app(check)

    def test_unexpected_stop_is_still_reported_by_tick_loop(self):
        import netmon.capture as capture_mod

        def quick_start(engine, **_kw):
            engine.running = True
            engine.backend = "npcap"
            engine.started_at = time.time()

        def check(app):
            with patch.object(capture_mod.CaptureEngine, "start", quick_start):
                app.toggle_capture()
                self._wait_start(app)
            engine = app.capture_engine
            engine.running = False  # 模擬後端意外中斷
            engine.last_error = "WinDivert 擷取中斷：boom"
            app._tick_loop()
            self.assertFalse(app._capture_was_running)
            self.assertEqual(app.packets_tab.capture_btn.cget("text"), "▶ 開始擷取")
            self.assertIn("已中斷", app.capture_badge.cget("text"))
            self.assertIn("已中斷", app.status_var.get())

        self._with_app(check)


class TestHostnameResolver(unittest.TestCase):
    """反向 DNS 快取：TTL 過期重新查詢、pending 時先維持舊值（注入式 lookup）。"""

    def _resolver(self, lookup):
        with _FakeTkContext():
            module = importlib.import_module("netmon.gui.connections_tab")
        resolver = module.HostnameResolver()
        resolver._lookup = lookup
        return resolver

    @staticmethod
    def _wait(resolver, ip, timeout=2.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with resolver._lock:
                if ip not in resolver._pending:
                    return
            time.sleep(0.01)

    def test_expired_positive_requeries_keeps_display(self):
        calls: list[str] = []

        def lookup(ip):
            calls.append(ip)
            return ("host.example", [], None)

        resolver = self._resolver(lookup)
        resolver._cache["9.9.9.9"] = ("old-host.example",
                                      time.time() - (resolver.TTL_POSITIVE + 1))
        # 過期：先回舊值（畫面不閃爍），同時在背景重新查詢
        self.assertEqual(resolver.get("9.9.9.9"), "old-host.example")
        self._wait(resolver, "9.9.9.9")
        self.assertEqual(resolver._cache["9.9.9.9"][0], "host.example")
        self.assertEqual(calls, ["9.9.9.9"])

    def test_fresh_cache_hit_does_not_lookup(self):
        def no_lookup(ip):
            raise AssertionError("快取有效時不該發起查詢")

        resolver = self._resolver(no_lookup)
        resolver._cache["1.1.1.1"] = ("fresh.example", time.time())
        self.assertEqual(resolver.get("1.1.1.1"), "fresh.example")

    def test_expired_negative_requeries(self):
        def lookup(ip):
            raise OSError("模擬查不到")

        resolver = self._resolver(lookup)
        resolver._cache["8.8.8.8"] = ("-", time.time() - (resolver.TTL_NEGATIVE + 1))
        # 負向過期：先回舊值（查無 = "-"），同時在背景重新查詢
        self.assertEqual(resolver.get("8.8.8.8"), "-")
        self._wait(resolver, "8.8.8.8")
        self.assertEqual(resolver._cache["8.8.8.8"][0], "-")  # 重新查仍是查不到
        self.assertGreaterEqual(resolver._cache["8.8.8.8"][1],
                                time.time() - resolver.TTL_NEGATIVE)

    def test_loopback_and_empty_skipped(self):
        def no_lookup(ip):
            raise AssertionError("保留位址不該查詢")

        resolver = self._resolver(no_lookup)
        self.assertEqual(resolver.get("127.0.0.1"), "-")
        self.assertEqual(resolver.get("0.0.0.0"), "-")
        self.assertEqual(resolver.get(""), "-")
        self.assertEqual(resolver._pending, set())


class TestMainStdStreams(unittest.TestCase):
    def test_ensure_std_streams_replaces_none(self):
        import main

        with patch.object(sys, "stdout", None), patch.object(sys, "stderr", None):
            main._ensure_std_streams()
            self.assertIsNotNone(sys.stdout)
            self.assertIsNotNone(sys.stderr)
            sys.stdout.write("ok")
            sys.stderr.write("ok")


class TestRealTkGuiSmoke(unittest.TestCase):
    """在有真實 tkinter 與顯示環境（如 Windows CI）時，實際建立 MainApp 驗證所有分頁能初始化。"""

    def test_main_app_startup_and_close(self):
        try:
            import tkinter as tk
        except ImportError:
            self.skipTest("此環境未安裝 tkinter")

        try:
            probe = tk.Tk()
            probe.withdraw()
            probe.destroy()
        except tk.TclError as exc:
            self.skipTest(f"此環境無可用顯示器（{exc}）")

        from netmon.gui.app import MainApp

        with tempfile.TemporaryDirectory() as td:
            store_path = str(Path(td) / "rules.json")
            with patch("netmon.rule_store.default_store_path", return_value=store_path):
                app = MainApp()
                try:
                    app.withdraw()
                    app.update_idletasks()
                    self.assertIsNotNone(app.dashboard_tab.tree)
                    self.assertIsNotNone(app.connections_tab.tree)
                    self.assertIsNotNone(app.processes_tab.tree)
                    self.assertIsNotNone(app.packets_tab.tree)
                    self.assertIsNotNone(app.firewall_tab.rules_tree)
                    self.assertIsNotNone(app.firewall_tab.fw_tree)
                    self.assertIsNotNone(app.firewall_tab.log_tree)
                finally:
                    app._on_close()


if __name__ == "__main__":
    unittest.main()
