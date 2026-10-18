"""GUI 元件與視窗啟動測試（含無 tkinter 環境下的 ttk 參數檢查與有顯示環境下的整合測試）。"""
from __future__ import annotations

import importlib
import sys
import tempfile
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
                finally:
                    app._on_close()


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
