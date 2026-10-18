"""層級 1：整體網速監測（psutil.net_io_counters 差值計算）。

用法：
    mon = SpeedMonitor(history_seconds=120)
    sample = mon.sample()      # 每秒呼叫一次
    print(sample.up_rate, sample.down_rate)   # bytes/秒
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

import psutil


@dataclass
class NicSample:
    name: str
    up_rate: float = 0.0
    down_rate: float = 0.0
    total_sent: int = 0
    total_recv: int = 0


@dataclass
class SpeedSample:
    timestamp: float
    up_rate: float = 0.0          # 上傳 bytes/秒
    down_rate: float = 0.0        # 下載 bytes/秒
    total_sent: int = 0           # 累計上傳（開機以來）
    total_recv: int = 0           # 累計下載（開機以來）
    per_nic: dict[str, NicSample] = field(default_factory=dict)


def _diff(new: int, old: int, elapsed: float) -> float:
    """計數器差值轉每秒速率；計數器重置（負差值）時視為 0。"""
    if elapsed <= 0:
        return 0.0
    delta = new - old
    return (delta / elapsed) if delta >= 0 else 0.0


class SpeedMonitor:
    """每秒取樣一次，保留歷史資料供圖表繪製。"""

    def __init__(self, history_seconds: int = 120):
        self._prev_total = psutil.net_io_counters()
        self._prev_nic = psutil.net_io_counters(pernic=True)
        self._prev_time = time.time()
        # 歷史：(timestamp, up_rate, down_rate)
        self.history: deque[tuple[float, float, float]] = deque(maxlen=history_seconds)
        self.peak_up = 0.0
        self.peak_down = 0.0
        self.session_sent = 0     # 本程式開啟後累計上傳
        self.session_recv = 0
        self.last: SpeedSample | None = None

    def sample(self) -> SpeedSample:
        now = time.time()
        elapsed = now - self._prev_time
        total = psutil.net_io_counters()
        per_nic_raw = psutil.net_io_counters(pernic=True)

        up_rate = _diff(total.bytes_sent, self._prev_total.bytes_sent, elapsed)
        down_rate = _diff(total.bytes_recv, self._prev_total.bytes_recv, elapsed)

        per_nic: dict[str, NicSample] = {}
        for name, counters in per_nic_raw.items():
            old = self._prev_nic.get(name)
            nic = NicSample(
                name=name,
                total_sent=counters.bytes_sent,
                total_recv=counters.bytes_recv,
                up_rate=_diff(counters.bytes_sent, old.bytes_sent, elapsed) if old else 0.0,
                down_rate=_diff(counters.bytes_recv, old.bytes_recv, elapsed) if old else 0.0,
            )
            per_nic[name] = nic

        result = SpeedSample(
            timestamp=now, up_rate=up_rate, down_rate=down_rate,
            total_sent=total.bytes_sent, total_recv=total.bytes_recv,
            per_nic=per_nic,
        )
        self.peak_up = max(self.peak_up, up_rate)
        self.peak_down = max(self.peak_down, down_rate)
        sent_delta = total.bytes_sent - self._prev_total.bytes_sent
        recv_delta = total.bytes_recv - self._prev_total.bytes_recv
        self.session_sent += max(sent_delta, 0)
        self.session_recv += max(recv_delta, 0)
        self.history.append((now, up_rate, down_rate))

        self._prev_total = total
        self._prev_nic = per_nic_raw
        self._prev_time = now
        self.last = result
        return result


def nic_details() -> list[dict]:
    """所有介面卡的詳細資訊：名稱、IP、MAC、是否啟用、速度、MTU。"""
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    result: list[dict] = []
    for name, st in stats.items():
        ipv4 = ipv6 = mac = ""
        for addr in addrs.get(name, []):
            family_name = getattr(addr.family, "name", str(addr.family))
            if family_name == "AF_INET":
                ipv4 = addr.address
            elif family_name == "AF_INET6":
                ipv6 = addr.address.split("%")[0]
            elif family_name in ("AF_LINK", "AF_PACKET"):
                mac = addr.address
        result.append({
            "name": name, "isup": st.isup, "speed_mbps": st.speed,
            "mtu": st.mtu, "ipv4": ipv4, "ipv6": ipv6, "mac": mac,
        })
    return result
