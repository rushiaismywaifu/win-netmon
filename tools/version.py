"""版本號工具（給 GitHub Actions 與人工使用）。

用法：
    python tools/version.py bump patch            # 印出下一個版本號（不修改檔案）
    python tools/version.py bump minor --write    # 直接改寫 netmon/__init__.py
    python tools/version.py set 2.0.0 --write     # 指定版本號
    python tools/version.py pyinstaller-version --out version_info.txt

版本號唯一來源是 netmon/__init__.py 的 __version__（GUI 狀態列與 exe 檔案內容都用它）。
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = REPO_ROOT / "netmon" / "__init__.py"
VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.MULTILINE)


def read_version(path: Path | str = VERSION_FILE) -> str:
    """讀出 __version__ 的值。"""
    match = VERSION_RE.search(Path(path).read_text(encoding="utf-8"))
    if not match:
        raise SystemExit(f"在 {path} 找不到 __version__")
    return match.group(1)


def write_version(version: str, path: Path | str = VERSION_FILE) -> None:
    """把 __version__ 改寫成指定版本（保留原本的格式與其他內容）。"""
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if not VERSION_RE.search(text):
        raise SystemExit(f"在 {target} 找不到 __version__")
    target.write_text(VERSION_RE.sub(f'__version__ = "{version}"', text, count=1),
                      encoding="utf-8")


def parse_version(version: str) -> tuple[int, int, int]:
    parts = version.strip().lstrip("vV").split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise SystemExit(f"版本號格式錯誤（需要 major.minor.patch）：{version}")
    return tuple(int(p) for p in parts)  # type: ignore[return-value]


def bump_version(version: str, level: str = "patch") -> str:
    """把版本號往上加一階：patch / minor / major。"""
    major, minor, patch = parse_version(version)
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    if level == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise SystemExit(f"未知的升級層級：{level}")


def render_pyinstaller_version_file(version: str) -> str:
    """產生 PyInstaller --version-file 需要的檔案內容（Windows 檔案內容）。"""
    major, minor, patch = parse_version(version)
    tup = f"({major}, {minor}, {patch}, 0)"
    return f"""# 由 tools/version.py 產生，請勿手動修改。
# PyInstaller 用它寫入 WinNetMon.exe 的「內容 → 詳細資料」。
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={tup},
    prodvers={tup},
    mask=0x3F,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0),
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904b0',
        [StringStruct('CompanyName', 'Win-NetMon'),
         StringStruct('FileDescription', 'Win-NetMon - Windows network monitor and traffic control'),
         StringStruct('FileVersion', '{version}'),
         StringStruct('InternalName', 'WinNetMon'),
         StringStruct('OriginalFilename', 'WinNetMon.exe'),
         StringStruct('ProductName', 'Win-NetMon'),
         StringStruct('ProductVersion', '{version}')])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])]),
  ]
)
"""


def main(argv: list[str] | None = None) -> int:
    # Windows runner 的預設 stdout 編碼是 cp1252，中文訊息會直接炸掉
    # （UnicodeEncodeError），所以在這裡統一改成 UTF-8。
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Win-NetMon 版本號工具")
    sub = parser.add_subparsers(dest="command", required=True)

    p_bump = sub.add_parser("bump", help="遞增版本號（預設只印出結果）")
    p_bump.add_argument("level", nargs="?", default="patch", choices=["patch", "minor", "major"])
    p_bump.add_argument("--write", action="store_true", help="把新版本號寫回 netmon/__init__.py")

    p_set = sub.add_parser("set", help="直接指定版本號")
    p_set.add_argument("version")
    p_set.add_argument("--write", action="store_true")

    p_pyi = sub.add_parser("pyinstaller-version", help="產生 PyInstaller version file")
    p_pyi.add_argument("--out", default="-", help="輸出檔（- 表示標準輸出）")

    args = parser.parse_args(argv)
    current = read_version()

    if args.command == "bump":
        target = bump_version(current, args.level)
    elif args.command == "set":
        target = args.version.lstrip("vV")
    else:
        content = render_pyinstaller_version_file(current)
        if args.out == "-":
            sys.stdout.write(content)
        else:
            Path(args.out).write_text(content, encoding="utf-8")
            print(f"已寫出 {args.out}（version {current}）")
        return 0

    if args.write:
        write_version(target)
        print(target)
    else:
        print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
