"""層級 3：每個程式各用了多少流量。

做法（README 所述「封包 + 連線表比對」）：
  1. 定期（約每 2 秒）快照系統連線表，建立
     (協定, 本機埠, 遠端 IP:埠) -> (PID, 程式名稱) 索引。
  2. 層級 4 每抓到一個封包，依方向取出「本機端埠號」查索引，
     把封包長度累計到對應程式的上傳/下載。
查不到的封包（如連線剛建立/剛結束、系統核心流量）歸入「(未歸屬)」。

備註：Windows 上另一種做法是 ETW（Microsoft-Windows-Kernel-Network），
精確度更高但需 pywintrace 且架構複雜；本專案採可攜性佳的比對法，
啟動封包擷取後即可運作。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .connections import ConnectionRecord

UNKNOWN_PID = 0
UNKNOWN_NAME = "(未歸屬 / 系統)"


class ConnectionIndex:
    """連線表索引：封包 -> 程式 的查詢表（thread-safe）。"""

    def __init__(self):
        self._lock = threading.Lock()
        # 精確比對：(proto, local_ip, local_port, remote_ip, remote_port)
        self._exact: dict[tuple, tuple[int | None, str]] = {}
        # 埠號比對：(proto, local_port)（UDP/短暫連線的後備）
        self._by_port: dict[tuple[str, int], tuple[int | None, str]] = {}
        self.updated_at: float = 0.0

    def refresh(self, records: list[ConnectionRecord]) -> None:
        exact: dict[tuple, tuple[int | None, str]] = {}
        by_port: dict[tuple[str, int], tuple[int | None, str]] = {}
        for rec in records:
            owner = (rec.pid, rec.process_name)
            if rec.remote_ip and rec.remote_port is not None:
                exact[rec.tuple_key()] = owner
            # 同一個埠可能被多條連線共用（例如瀏覽器的多條 TCP），保留第一個即可，
            # 精確比對會優先命中。
            by_port.setdefault((rec.protocol, rec.local_port), owner)
        with self._lock:
            self._exact = exact
            self._by_port = by_port
            self.updated_at = time.time()

    def lookup(self, protocol: str, local_ip: str, local_port: int | None,
               remote_ip: str, remote_port: int | None) -> tuple[int, str]:
        """查封包屬於哪個程式，回傳 (pid, name)，查不到回傳未歸屬。"""
        if local_port is None:
            return UNKNOWN_PID, UNKNOWN_NAME
        with self._lock:
            owner = self._exact.get(
                (protocol, local_ip, local_port, remote_ip, remote_port))
            if owner is None:
                owner = self._by_port.get((protocol, local_port))
        if owner is None or owner[0] is None:
            if owner is not None and owner[1] not in ("", "(未知)"):
                return UNKNOWN_PID, owner[1]
            return UNKNOWN_PID, UNKNOWN_NAME
        return owner[0], owner[1]


@dataclass
class ProcessTraffic:
    pid: int
    name: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    up_rate: float = 0.0
    down_rate: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    endpoints: set[str] = field(default_factory=set)  # 遠端 IP:埠

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv

    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_recv


class TrafficAggregator:
    """把封包依程式累計流量、計算即時速率（thread-safe）。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._procs: dict[tuple[int, str], ProcessTraffic] = {}
        self._rate_snapshot: dict[tuple[int, str], tuple[float, int, int]] = {}
        self.started_at = time.time()

    def add_packet(self, pid: int, name: str, length: int,
                   sent: bool, remote_endpoint: str = "") -> None:
        now = time.time()
        key = (pid, name)
        with self._lock:
            proc = self._procs.get(key)
            if proc is None:
                proc = ProcessTraffic(pid=pid, name=name)
                proc.first_seen = now
                self._procs[key] = proc
            if sent:
                proc.bytes_sent += length
                proc.packets_sent += 1
            else:
                proc.bytes_recv += length
                proc.packets_recv += 1
            proc.last_seen = now
            if remote_endpoint and len(proc.endpoints) < 512:
                proc.endpoints.add(remote_endpoint)

    def update_rates(self) -> None:
        """與上一次快照比對，更新每個程式的上/下載速率（GUI 每秒呼叫）。"""
        now = time.time()
        with self._lock:
            for key, proc in self._procs.items():
                prev = self._rate_snapshot.get(key)
                if prev is not None:
                    elapsed = now - prev[0]
                    if elapsed > 0:
                        proc.up_rate = max((proc.bytes_sent - prev[1]) / elapsed, 0.0)
                        proc.down_rate = max((proc.bytes_recv - prev[2]) / elapsed, 0.0)
                self._rate_snapshot[key] = (now, proc.bytes_sent, proc.bytes_recv)

    def ranking(self) -> list[ProcessTraffic]:
        """所有程式依總流量由大到小排序（回傳複本快照欄位的參考）。"""
        with self._lock:
            items = list(self._procs.values())
        items.sort(key=lambda p: p.total_bytes, reverse=True)
        return items

    def totals(self) -> tuple[int, int, int]:
        """回傳 (已歸屬上傳, 已歸屬下載, 未歸屬總量)。"""
        with self._lock:
            sent = sum(p.bytes_sent for p in self._procs.values() if p.pid != UNKNOWN_PID)
            recv = sum(p.bytes_recv for p in self._procs.values() if p.pid != UNKNOWN_PID)
            unknown = sum(p.total_bytes for p in self._procs.values() if p.pid == UNKNOWN_PID)
        return sent, recv, unknown

    def connection_counts(self, records: list[ConnectionRecord]) -> dict[int, int]:
        """依目前連線表統計每個 PID 的活躍連線數。"""
        counts: dict[int, int] = {}
        for rec in records:
            if rec.pid:
                counts[rec.pid] = counts.get(rec.pid, 0) + 1
        return counts

    def reset(self) -> None:
        with self._lock:
            self._procs.clear()
            self._rate_snapshot.clear()
            self.started_at = time.time()


def process_traffic_to_csv(items: list[ProcessTraffic]) -> str:
    import csv
    import io

    from .utils import fmt_bytes, fmt_rate

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["排名", "程式", "PID", "下載速率", "上傳速率",
                     "下載總量", "上傳總量", "總流量", "總封包數", "遠端端點數"])
    for rank, proc in enumerate(items, 1):
        writer.writerow([rank, proc.name, proc.pid or "",
                         fmt_rate(proc.down_rate), fmt_rate(proc.up_rate),
                         fmt_bytes(proc.bytes_recv), fmt_bytes(proc.bytes_sent),
                         fmt_bytes(proc.total_bytes), proc.total_packets,
                         len(proc.endpoints)])
    return "﻿" + buf.getvalue()
