# Windows 網路流量監測：現成軟體與自己寫程式的可行性

## 一、現成可用的軟體

### Windows 內建工具（不用安裝）
| 工具 | 開啟方式 | 用途 |
|---|---|---|
| **工作管理員** | `Ctrl+Shift+Esc` → 效能 | 看整體上傳和下載速度 |
| **資源監視器** | `Win+R` 輸入 `resmon` → 網路分頁 | 看**每個程式**的流量和連線，很實用 |
| **netstat** | 命令列 `netstat -ano` | 列出所有連線和對應的 PID |
| **pktmon** | 命令列 `pktmon start --capture` | Win10 1809 以後內建的封包擷取工具 |

### 第三方軟體
| 軟體 | 特點 | 費用 |
|---|---|---|
| **Wireshark** | 業界標準的封包分析工具，可以看到每個封包的內容 | 免費、開源 |
| **TCPView**（微軟 Sysinternals） | 即時顯示每個程式的 TCP/UDP 連線，輕量 | 免費 |
| **GlassWire** | 介面漂亮，有流量圖表、新程式連網警示 | 有免費版 |
| **NetLimiter** | 監控每個程式的流量，也能**限速或阻擋** | 付費（有試用） |
| **Portmaster** | 開源，可以監控和管理連線 | 有免費版 |
| **Fiddler** | 專門看 HTTP/HTTPS 請求 | 有免費版 |

**建議**：一般使用先開 `resmon` 或 TCPView；要深入分析封包內容就用 Wireshark。

---

## 二、自己寫程式的可行性

**答案是完全可行**，難度看你要做到哪一層：

| 層級 | 功能 | 難度 | 技術 |
|---|---|---|---|
| 1 | 整體網速（上傳和下載） | ⭐ | `psutil` / 效能計數器 |
| 2 | 哪些程式連到哪些 IP | ⭐ | `psutil.net_connections` / `GetExtendedTcpTable` API |
| 3 | **每個程式**各用了多少流量 | ⭐⭐⭐ | ETW（Event Tracing for Windows） |
| 4 | 擷取並解析封包內容 | ⭐⭐ | Npcap + Scapy / SharpPcap |
| 5 | 阻擋或修改流量（像防火牆） | ⭐⭐⭐⭐ | WFP、WinDivert |

### 範例 1：即時網速 + 連線清單（Python，最簡單）

```bash
pip install psutil
```

```python
import psutil, time

def fmt(b):
    for u in ['B', 'KB', 'MB', 'GB']:
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

def show_connections():
    print(f"{'程式':<25}{'PID':<8}{'本機位址':<25}{'遠端位址':<25}{'狀態'}")
    for c in psutil.net_connections(kind='inet'):
        if not c.raddr:
            continue
        try:
            name = psutil.Process(c.pid).name() if c.pid else '?'
        except psutil.NoSuchProcess:
            name = '?'
        l = f"{c.laddr.ip}:{c.laddr.port}"
        r = f"{c.raddr.ip}:{c.raddr.port}"
        print(f"{name:<25}{c.pid or '':<8}{l:<25}{r:<25}{c.status}")

def monitor_speed():
    old = psutil.net_io_counters()
    while True:
        time.sleep(1)
        new = psutil.net_io_counters()
        up = new.bytes_sent - old.bytes_sent
        down = new.bytes_recv - old.bytes_recv
        print(f"\r↑ {fmt(up)}/s   ↓ {fmt(down)}/s   "
              f"(累計 ↑{fmt(new.bytes_sent)} ↓{fmt(new.bytes_recv)})   ", end='')
        old = new

if __name__ == '__main__':
    show_connections()
    print("\n即時網速（Ctrl+C 結束）：")
    monitor_speed()
```
> 用**系統管理員身分**執行，才看得到所有程式的 PID。

### 範例 2：擷取封包（Python + Scapy）

先安裝 [Npcap](https://npcap.com)（Wireshark 也用它），然後執行：
```bash
pip install scapy
```

```python
from scapy.all import sniff, IP, TCP, UDP

def handle(pkt):
    if IP in pkt:
        proto = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'OTHER'
        sport = pkt.sport if proto in ('TCP', 'UDP') else ''
        dport = pkt.dport if proto in ('TCP', 'UDP') else ''
        print(f"{proto:<5} {pkt[IP].src}:{sport} -> {pkt[IP].dst}:{dport}  {len(pkt)} bytes")

sniff(prn=handle, store=False, count=50)   # 可加 filter="tcp port 443"
```

### 進階：統計每個程式的流量
這是自己寫程式最有價值、也最難的部分，有兩種做法：
- **ETW**：訂閱 `Microsoft-Windows-Kernel-Network` 事件，每筆收送都會附上 PID。C# 可以用微軟的 **TraceEvent** 套件，Python 可以用 `pywintrace`。
- **封包 + 連線表比對**：用 Npcap 抓封包，再用連接埠對照 `net_connections` 找出是哪個程式，算出每個程式的流量。

---

## 三、語言建議

| 語言 | 適合情境 |
|---|---|
| **Python** | 快速做原型、個人使用，套件很多 |
| **C#** | 想做有 GUI 的 Windows 工具，ETW 和 WinAPI 的支援最好 |
| **C/C++** | 要求效能，或要碰 WFP、驅動程式 |

## 四、注意事項
1. **權限**：抓封包和看所有程式的連線都需要**系統管理員權限**。
2. **HTTPS 加密**：封包抓得到，但內容是加密的，只看得到 IP、連接埠、網域（SNI）和流量大小。
3. **合法性**：只監控**你自己的電腦或網路**。監控別人的流量可能違法。
4. **防毒誤報**：自製的封包擷取程式有時會被防毒軟體標記，這是正常的。

如果你告訴我想做到哪種程度（例如：「做一個 GUI，顯示每個程式的即時流量排行」），我可以幫你寫更完整的程式。