"""層級 5（即時攔截部分）：WinDivert 執行層。

把通過「WinDivert 過濾語法」的封包從核心撈到 Python，交給
rule_engine 判斷，再決定放行（send 回去）、丟棄（不送）、延遲
（排隊晚點送）或轉址（改寫後送出）。

安全重點：
  - 預設過濾只攔「可能命中規則」的封包，其餘走核心高速路徑。
  - 本引擎停止/程式結束/閃退 -> handle 關閉 -> 流量自動恢復正常，
    延遲佇列中未送出的封包被丟棄（TCP 會自己重傳）。
  - 支援自動停止期限（deadline），避免開了忘記關。
  - pydivert 採延遲載入且所有屬性存取都有防禦；驅動不可用時
    會拋出友善訊息，層級 1~4 與 WFP 防火牆部分不受影響。

pydivert（封裝 WinDivert 驅動）安裝：pip install pydivert（僅 Windows）。
需系統管理員身分；首次啟動會載入 WinDivert 簽章驅動。
若遇錯誤 577/1275（驅動被封鎖），多為「記憶體完整性/易受攻擊驅動
封鎖清單」擋下簽名較舊的驅動，請改用同一分頁的 WFP 防火牆功能。
"""
from __future__ import annotations

import heapq
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

from .rule_engine import (
    VERDICT_DELAY, VERDICT_DROP, VERDICT_PASS, VERDICT_REDIRECT,
    VERDICT_REDIRECT_REVERSE, PacketView, RuleEngine, build_divert_filter,
)
from .traffic import UNKNOWN_NAME, UNKNOWN_PID, ConnectionIndex
from .utils import get_local_ips, is_admin, is_windows

MAX_LOG_ENTRIES = 300


def divert_availability() -> tuple[bool, str]:
    """WinDivert 即時攔截是否「可以嘗試啟動」。"""
    if not is_windows():
        return False, "僅支援 Windows（需要 WinDivert 驅動）"
    try:
        import pydivert  # noqa: F401
    except Exception as exc:  # ImportError / DLL 載入失敗
        return False, f"未正確載入 pydivert（{type(exc).__name__}: {exc}），請執行：pip install pydivert"
    if not is_admin():
        return False, "pydivert 已就緒，但啟動攔截需要系統管理員身分"
    return True, "WinDivert（pydivert）就緒"


def pydivert_installed() -> bool:
    try:
        import pydivert  # noqa: F401

        return True
    except Exception:
        return False


@dataclass
class InterceptLogEntry:
    timestamp: float
    rule_name: str
    verdict: str
    flow: str
    protocol: str
    process_name: str
    reason: str
    length: int


@dataclass
class DivertStats:
    intercepted: int = 0
    passed: int = 0
    dropped: int = 0
    delayed: int = 0
    redirected: int = 0
    dropped_bytes: int = 0


# ---------------------------------------------------------------------------
# pydivert 封包 -> PacketView（屬性存取全部防禦，方便用假封包測試）
# ---------------------------------------------------------------------------

def _get(obj, *names, default=None):
    for name in names:
        value = getattr(obj, name, None)
        if value is not None and not callable(value):
            return value
    return default


def view_from_pydivert(pkt, local_ips: set[str],
                       conn_index: ConnectionIndex | None = None) -> PacketView:
    src_ip = str(_get(pkt, "src_addr", default="") or "")
    dst_ip = str(_get(pkt, "dst_addr", default="") or "")
    is_outbound = _get(pkt, "is_outbound", default=None)
    if is_outbound is None:
        direction = "out" if src_ip in local_ips else "in"
    else:
        direction = "out" if bool(is_outbound) else "in"

    tcp = getattr(pkt, "tcp", None)
    udp = getattr(pkt, "udp", None)
    if tcp is not None:
        proto = "TCP"
    elif udp is not None:
        proto = "UDP"
    elif getattr(pkt, "icmpv4", None) is not None or getattr(pkt, "icmp", None) is not None:
        proto = "ICMP"
    elif getattr(pkt, "icmpv6", None) is not None:
        proto = "ICMPv6"
    else:
        proto = "OTHER"

    src_port = _get(pkt, "src_port")
    dst_port = _get(pkt, "dst_port")
    payload = _get(pkt, "payload", default=b"") or b""
    raw = _get(pkt, "raw", default=b"") or b""
    length = len(raw) if raw else len(payload)

    view = PacketView(
        direction=direction, protocol=proto, src_ip=src_ip, dst_ip=dst_ip,
        src_port=int(src_port) if src_port is not None else None,
        dst_port=int(dst_port) if dst_port is not None else None,
        length=length, payload=bytes(payload),
    )
    if conn_index is not None and proto in ("TCP", "UDP"):
        if direction == "out":
            pid, name = conn_index.lookup(proto, src_ip, view.src_port, dst_ip, view.dst_port)
        else:
            pid, name = conn_index.lookup(proto, dst_ip, view.dst_port, src_ip, view.src_port)
        view.pid = pid or UNKNOWN_PID
        view.process_name = name or UNKNOWN_NAME
    return view


def _apply_rewrite(pkt, decision) -> bool:
    """把轉址決策寫回 pydivert 封包。成功回傳 True（表示需要重算 checksum）。"""
    changed = False
    try:
        if decision.verdict == VERDICT_REDIRECT:
            if decision.new_dst_ip:
                pkt.dst_addr = decision.new_dst_ip
                changed = True
            if decision.new_dst_port:
                pkt.dst_port = int(decision.new_dst_port)
                changed = True
        elif decision.verdict == VERDICT_REDIRECT_REVERSE:
            if decision.new_src_ip:
                pkt.src_addr = decision.new_src_ip
                changed = True
            if decision.new_src_port:
                pkt.src_port = int(decision.new_src_port)
                changed = True
    except Exception:
        return False
    return changed


def _default_handle_factory(filter_string: str):
    import pydivert

    handle = pydivert.WinDivert(filter_string)
    handle.open()
    return handle


class DivertEngine:
    """WinDivert 攔截執行緒：recv 緒（判斷） + send 緒（即時/延遲送出）。"""

    def __init__(self, rule_engine: RuleEngine,
                 conn_index: ConnectionIndex | None = None,
                 handle_factory: Callable[[str], object] | None = None):
        self.rule_engine = rule_engine
        self.conn_index = conn_index
        self._handle_factory = handle_factory or _default_handle_factory
        self._check_real_platform = handle_factory is None

        self.running = False
        self.filter_string = ""
        self.started_at: float = 0.0
        self._deadline_mono: float | None = None
        self.last_error: str = ""

        self.stats = DivertStats()
        self._stats_lock = threading.Lock()
        self._log: deque[InterceptLogEntry] = deque(maxlen=MAX_LOG_ENTRIES)
        self._log_lock = threading.Lock()
        self._local_ips = get_local_ips()

        self._stop_event = threading.Event()
        self._handle = None
        self._recv_thread: threading.Thread | None = None
        self._send_thread: threading.Thread | None = None
        self._send_heap: list[tuple[float, int, object, bool]] = []
        self._send_cond = threading.Condition()
        self._send_seq = 0

    # ------------------------------------------------------------- 啟停
    def start(self, exclude_loopback: bool = True,
              auto_stop_seconds: float = 0) -> str:
        """開始攔截，回傳實際用的 WinDivert 過濾字串。失敗拋 RuntimeError。"""
        if self.running:
            raise RuntimeError("即時攔截已在進行中")
        if self._check_real_platform:
            ok, msg = divert_availability()
            if not ok:
                raise RuntimeError(msg)
        rules = self.rule_engine.get_rules()
        enabled = [r for r in rules if r.enabled]
        if not enabled:
            raise RuntimeError("沒有啟用的攔截規則：請先新增規則再開始攔截")
        filter_string = build_divert_filter(rules, exclude_loopback)
        if filter_string in ("", "false"):
            raise RuntimeError("沒有可攔截的規則（過濾條件為空）")

        self._local_ips = get_local_ips()
        self._stop_event.clear()
        with self._send_cond:
            self._send_heap.clear()
        try:
            self._handle = self._handle_factory(filter_string)
        except OSError as exc:
            hint = ""
            err_text = str(exc)
            if any(code in err_text for code in ("577", "1275", "signature", "簽章")):
                hint = ("\n\n（像是 WinDivert 驅動被 Windows 封鎖：常見於開啟"
                        "「記憶體完整性」或易受攻擊驅動封鎖清單時。"
                        "暫解：同分頁的 WFP 防火牆封鎖不受影響；或依你對風險的接受度"
                        "調整 Windows 安全性設定後再試。）")
            raise RuntimeError(f"WinDivert 啟動失敗：{exc}{hint}") from exc
        except Exception as exc:
            raise RuntimeError(f"WinDivert 啟動失敗：{type(exc).__name__}: {exc}") from exc

        self.filter_string = filter_string
        self.running = True
        self.last_error = ""
        self.started_at = time.time()
        self._deadline_mono = (
            time.monotonic() + auto_stop_seconds if auto_stop_seconds > 0 else None)
        self._send_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._recv_thread = threading.Thread(target=self._receiver_loop, daemon=True)
        self._send_thread.start()
        self._recv_thread.start()
        return filter_string

    def stop(self) -> None:
        if not self.running and self._handle is None:
            return
        self._stop_event.set()
        self.running = False
        with self._send_cond:
            self._send_heap.clear()  # 未送出的延遲封包丟棄（TCP 會重傳）
            self._send_cond.notify_all()
        handle = self._handle
        self._handle = None
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass
        for thread in (self._recv_thread, self._send_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=2.0)
        self._recv_thread = self._send_thread = None
        self._deadline_mono = None

    # ------------------------------------------------------------- 狀態
    def deadline_exceeded(self) -> bool:
        return (self.running and self._deadline_mono is not None
                and time.monotonic() >= self._deadline_mono)

    def seconds_remaining(self) -> float | None:
        if not self.running or self._deadline_mono is None:
            return None
        return max(self._deadline_mono - time.monotonic(), 0.0)

    def snapshot_stats(self) -> DivertStats:
        with self._stats_lock:
            return DivertStats(**vars(self.stats))

    def reset_stats(self) -> None:
        with self._stats_lock:
            self.stats = DivertStats()

    def recent_logs(self, limit: int = 200) -> list[InterceptLogEntry]:
        with self._log_lock:
            return list(self._log)[-limit:]

    def clear_logs(self) -> None:
        with self._log_lock:
            self._log.clear()

    # ------------------------------------------------------------- 內部工作緒
    def _queue_send(self, pkt, delay_ms: int, modified: bool) -> None:
        due = time.monotonic() + max(delay_ms, 0) / 1000.0
        with self._send_cond:
            self._send_seq += 1
            heapq.heappush(self._send_heap, (due, self._send_seq, pkt, modified))
            self._send_cond.notify()

    def _sender_loop(self) -> None:
        while not self._stop_event.is_set():
            with self._send_cond:
                if not self._send_heap:
                    self._send_cond.wait(timeout=0.5)
                    continue
                due, _seq, pkt, modified = self._send_heap[0]
                wait = due - time.monotonic()
                if wait > 0:
                    self._send_cond.wait(timeout=min(wait, 0.5))
                    continue
                heapq.heappop(self._send_heap)
            handle = self._handle
            if handle is None or self._stop_event.is_set():
                continue
            try:
                try:
                    handle.send(pkt, recalculate_checksum=modified)
                except TypeError:
                    handle.send(pkt)
            except Exception:
                # 送不出去就丟掉（介面重置等情況），不讓工作緒死掉
                pass

    def _receiver_loop(self) -> None:
        handle = self._handle
        if handle is None:
            return
        try:
            for pkt in handle:
                if self._stop_event.is_set():
                    break
                self._process(pkt)
        except Exception as exc:  # handle 關閉時迭代可能拋錯，停止中屬正常
            if not self._stop_event.is_set():
                self.last_error = f"攔截中斷：{type(exc).__name__}: {exc}"
                self.running = False

    def _process(self, pkt) -> None:
        try:
            view = view_from_pydivert(pkt, self._local_ips, self.conn_index)
        except Exception:
            # 解析不了的封包直接放行，不要卡死網路
            self._queue_send(pkt, 0, False)
            return
        decision = self.rule_engine.evaluate(view)
        with self._stats_lock:
            self.stats.intercepted += 1
            if decision.verdict == VERDICT_DROP:
                self.stats.dropped += 1
                self.stats.dropped_bytes += view.length
            elif decision.verdict == VERDICT_DELAY:
                self.stats.delayed += 1
                self.stats.passed += 1
            elif decision.verdict == VERDICT_REDIRECT:
                self.stats.redirected += 1
                self.stats.passed += 1
            else:
                self.stats.passed += 1

        if decision.verdict != VERDICT_PASS or (decision.rule and decision.rule.action != "allow"):
            with self._log_lock:
                self._log.append(InterceptLogEntry(
                    timestamp=view.timestamp,
                    rule_name=decision.rule.name if decision.rule else "(回程還原)",
                    verdict=decision.verdict,
                    flow=view.flow_text,
                    protocol=view.protocol,
                    process_name=view.process_name or UNKNOWN_NAME,
                    reason=decision.reason,
                    length=view.length,
                ))

        if decision.verdict == VERDICT_DROP:
            return  # 不送回 = 丟棄
        modified = False
        if decision.modified:
            modified = _apply_rewrite(pkt, decision)
        self._queue_send(pkt, decision.delay_ms if decision.verdict == VERDICT_DELAY else 0,
                         modified)
