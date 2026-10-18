"""層級 2：哪些程式連到哪些 IP（psutil.net_connections）。

對應 Windows 的 GetExtendedTcpTable / GetExtendedUdpTable API。
以系統管理員身分執行才能看到所有程式（否則部分 PID 會是 None）。
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass

import psutil

_TYPE_MAP = {
    socket.SOCK_STREAM: "TCP",
    socket.SOCK_DGRAM: "UDP",
}


@dataclass
class ConnectionRecord:
    pid: int | None
    process_name: str
    protocol: str                 # TCP / UDP
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int | None
    status: str

    @property
    def local(self) -> str:
        return f"{self.local_ip}:{self.local_port}"

    @property
    def remote(self) -> str:
        if self.remote_ip and self.remote_port is not None:
            return f"{self.remote_ip}:{self.remote_port}"
        return "-"

    def tuple_key(self) -> tuple:
        return (self.protocol, self.local_ip, self.local_port,
                self.remote_ip, self.remote_port)


class ProcessNameCache:
    """PID -> 程式名稱快取，避免每次刷新都逐一查詢行程（很慢）。"""

    def __init__(self, ttl: float = 30.0):
        self._ttl = ttl
        self._cache: dict[int, tuple[str, float, float]] = {}  # pid -> (name, create_time, cached_at)

    def get(self, pid: int | None) -> str:
        if not pid:
            return "(系統)"
        now = time.time()
        cached = self._cache.get(pid)
        if cached and now - cached[2] < self._ttl:
            return cached[0]
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            create_time = proc.create_time()
        except (psutil.Error, ValueError):
            name, create_time = "(未知)", 0.0
        # PID 可能被新程式重用；用 create_time 判斷是否為同一個行程
        if cached and cached[1] != create_time:
            self._cache.pop(pid, None)
        self._cache[pid] = (name, create_time, now)
        return name


_default_cache = ProcessNameCache()


def get_connections(include_listening: bool = True,
                      cache: ProcessNameCache | None = None) -> list[ConnectionRecord]:
    """取得目前所有 TCP/UDP 連線（含對應程式名稱）。"""
    name_cache = cache or _default_cache
    records: list[ConnectionRecord] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        # 非管理員時退而求其次：只看得到自己程式群的連線也比沒有好
        conns = []
    for conn in conns:
        if not conn.laddr:
            continue
        if not include_listening and conn.status == psutil.CONN_LISTEN:
            continue
        records.append(ConnectionRecord(
            pid=conn.pid,
            process_name=name_cache.get(conn.pid),
            protocol=_TYPE_MAP.get(conn.type, "?"),  # type: ignore[arg-type]
            local_ip=conn.laddr.ip,
            local_port=conn.laddr.port,
            remote_ip=conn.raddr.ip if conn.raddr else "",
            remote_port=conn.raddr.port if conn.raddr else None,
            status=conn.status or "-",
        ))
    records.sort(key=lambda r: (r.process_name.lower(), r.local_port))
    return records


def connections_to_csv(records: list[ConnectionRecord]) -> str:
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["程式", "PID", "協定", "本機位址", "遠端位址", "狀態"])
    for r in records:
        writer.writerow([r.process_name, r.pid or "", r.protocol,
                         r.local, r.remote, r.status])
    return "﻿" + buf.getvalue()  # BOM 讓 Excel 正確顯示中文
