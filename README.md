# Win-NetMon — Windows 網路流量監測器（層級 1～4 + GUI）

一個用 Python 寫的 Windows 網路流量監測工具，附圖形介面。從「整體網速」一路做到
「擷取並逐層解析封包」，共四個層級、四個分頁：

| 層級 | 分頁 | 功能 | 技術 |
|---|---|---|---|
| 1 | 📊 **總覽** | 即時上/下行速率圖（120 秒）、尖峰與本次總量、每一介面卡的速率與累計 | `psutil.net_io_counters` |
| 2 | 🔌 **連線清單** | 每個程式連到哪些 IP:埠 - 可搜尋、依協定篩選、排序、解析遠端主機名、匯出 CSV | `psutil.net_connections` |
| 3 | 🏆 **程式流量** | 每個程式的下/上行即時速率與總量排行、封包數、目前連線數 | 封包 + 連線表比對（依埠號把封包歸屬給程式） |
| 4 | 📦 **封包擷取** | 即時封包列表、逐層解析、Hex dump、DNS 查詢、TLS SNI 網域、HTTP 請求、BPF 過濾、存/讀 `.pcap` | Npcap + Scapy |

> **層級 5（阻擋/修改流量，WFP/WinDivert）不在範圍內** — 本專案只做監測與分析。

![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![Platform](https://img.shields.io/badge/Platform-Windows-0078D6) ![GUI](https://img.shields.io/badge/GUI-tkinter-green)

---

## 快速開始（Windows）

### 前置安裝
1. **Python 3.9+**：[python.org](https://www.python.org/downloads/windows/)，安裝時勾選
   「Add python.exe to PATH」與 Tcl/Tk（GUI 用，預設有勾）。
2. **Npcap**：[npcap.com](https://npcap.com)，一路下一步即可（建議勾選
   *"Install Npcap in WinPcap API-compatible Mode"*）。Wireshark 也是用它。
   > 只有層級 3、4 需要 Npcap；不裝的話層級 1、2 仍可正常使用。

### 啟動
點兩下 **`run_as_admin.bat`**（會自動以系統管理員身分啟動，並在第一次自動
`pip install` 所需套件）。或手動：

```bat
pip install -r requirements.txt
python main.py
```

> 💡 **為什麼要系統管理員？** 沒管理員權限會看不到全部程式的 PID，也無法擷取封包。
> 程式右上角會顯示目前權限，也可以按「以系統管理員身分重新啟動」。

### 先檢查環境（可選）

```bat
python main.py --check
```
會檢查 Python、psutil、tkinter、Scapy、Npcap、管理員權限與可擷取介面，並告訴你缺什麼。

---

## 使用指南

程式開啟後層級 1、2 就自動運作；頂欄會一直顯示目前的 ↓ 下載 / ↑ 上傳速率。

### 📊 層級 1：總覽
- 上方四張卡：即時下/上行速率（含本次開啟後的尖峰）、本次下/上傳總量（含開機以來累計）。
- 中間折線圖：最近 120 秒速率走勢（藍 = 下載、橘 = 上傳）。
- 下方表格：每張介面卡的 IPv4、連結速度、目前速率與累計流量。

### 🔌 層級 2：連線清單
- 每 2 秒自動刷新（可關閉），可關鍵字搜尋（程式名/IP/狀態）、只看 TCP 或 UDP、
  選擇是否顯示 LISTEN 連線；點欄位標題可排序。
- 勾「解析主機名」會對遠端 IP 做反向 DNS 查詢（背景進行，不卡 UI）。
- 點右鍵可複製 IP/整行；連按兩下會用該程式名篩選；「匯出 CSV」可存檔用 Excel 開。

### 🏆 層級 3：程式流量
按下「▶ 開始擷取」後開始統計（與層級 4 共用同一個擷取引擎）：
- Top 8 長條圖 + 完整排行表：即時速率、總流量、封包數、目前活躍連線數、最後活動時間。
- 連按兩下某個程式，會跳到連線清單看它實際連去哪裡。
- **原理**：定期快照系統連線表，建立（協定, 本機埠, 遠端）→（PID, 程式）的索引，
  每個擷取到的封包查表歸屬並累計長度。查不到的（剛建立/剛結束的連線、核心流量）
  會列在「(未歸屬 / 系統)」，狀態列會顯示歸屬百分比。
  > Windows 另一條路是 ETW（`Microsoft-Windows-Kernel-Network`，C# TraceEvent / pywintrace），
  > 更精確但架構複雜；本專案採用可攜性高、不裝額外元件的比對法。

### 📦 層級 4：封包擷取
選好介面（預設已幫你選有 IP 的卡）按「▶ 開始擷取」：
- 封包列表即時捲動，依協定著色（DNS 綠、TLS 紫、HTTP 藍、ICMP 紅…），含方向（↑/↓）
  與歸屬程式。
- **BPF 過濾**（同 Wireshark 的 capture filter），有常用預設可選，也能自己寫，
  例如 `tcp port 443`、`udp port 53`、`host 8.8.8.8`、`icmp`。
- 點任何一個封包：下方左邊是**逐層解析**（Ethernet / IP / TCP / … 各欄位）、右邊是
  **Hex dump**；Info 欄會直接點出重點：DNS 在查什麼網域、TLS 的 SNI（要連去哪個網域）、
  HTTP 的方法與 Host。
- 「顯示篩選」是擷取後在畫面上篩選（不會漏抓）；「暫停顯示」只是暫停畫面、背景續抓。
- 「儲存 pcap」存成 `.pcap` 可直接用 Wireshark 開；「開啟 pcap」可離線分析別人抓好的檔。

> ⚠ **HTTPS 是加密的**：你能看到 IP、埠、網域（SNI）、流量大小與時序，
> 但看不到內容 — 這跟 Wireshark 未提供金鑰解密時完全一樣，是正常的。

---

## 命令列模式

```bat
python main.py --cli     :: 不開啟 GUI：先列連線清單，再即時顯示網速（Ctrl+C 結束）
python main.py --check   :: 環境診斷
```

## 打包成 exe（選用）

```bat
build_exe.bat    :: 用 PyInstaller 產出 dist\WinNetMon.exe（雙擊時會自動要求管理員權限）
```
Npcap 仍需另外安裝，無法打包進去。

---

## 專案結構

```
win-netmon/
├─ main.py                  # 入口：GUI / --check / --cli
├─ run_as_admin.bat         # ⭐ 建議啟動方式（自動提權 + 裝套件）
├─ run.bat                  # 一般身分啟動
├─ build_exe.bat            # （選用）PyInstaller 打包
├─ requirements.txt         # psutil、scapy（GUI 用內建 tkinter，不必裝）
├─ netmon/
│  ├─ speed_monitor.py      # 層級 1：整體與每介面網速
│  ├─ connections.py        # 層級 2：連線表 + 程式名快取
│  ├─ traffic.py            # 層級 3：連線索引 + 每程式流量彙總
│  ├─ capture.py            # 層級 4：Scapy 擷取引擎、封包轉換、pcap 存讀
│  ├─ packet_info.py        # DNS / TLS SNI / HTTP 解析 + 協定分類（純 Python）
│  ├─ utils.py              # 格式化、權限檢查、Npcap 偵測、hex dump
│  └─ gui/
│     ├─ app.py             # 主視窗與排程（200ms 收封包、1s 取樣、2s 刷連線）
│     ├─ dashboard_tab.py   # 層級 1 分頁        ├─ processes_tab.py  # 層級 3 分頁
│     ├─ connections_tab.py # 層級 2 分頁        ├─ packets_tab.py    # 層級 4 分頁
│     ├─ widgets.py         # 統計卡、速率圖、Top 長條圖、表格輔助
│     └─ theme.py           # 深色主題色票與字體
└─ tests/
   └─ test_core.py          # 核心單元測試：python -m unittest discover -s tests -v
```

設計上核心（`speed_monitor` / `connections` / `traffic` / `capture` / `packet_info`）
與 GUI 完全分離，可以單獨在自己的 script 裡 import 使用，也方便測試。

## 測試

```bat
python -m unittest discover -s tests -v
```
涵蓋：位元組格式化、DNS 查詢解析、TLS SNI 擷取、HTTP 解析、協定分類、
連線索引比對（精確 + 埠號後備）、流量彙總速率、Scapy 封包轉換與 CSV 匯出（共 12 項）。

---

## 疑難排解

| 症狀 | 解法 |
|---|---|
| 連線清單看不到別人/系統程式的 PID | 用 `run_as_admin.bat` 以系統管理員身分執行 |
| 封包擷取顯示「不可用」 | 還沒裝 Npcap 或 Scapy；先跑 `python main.py --check` 它會告訴你缺哪個 |
| 按開始擷取出現錯誤對話框 | 常見：非管理員、Npcap 沒裝好、BPF 語法打錯、介面選錯。先把 BPF 清空、介面選「所有介面」再試 |
| 抓不到封包但流量明明有在跑 | 換一張介面卡試試（選有 IPv4 的那張）；VPN 流量要選 VPN 的虛擬介面 |
| 層級 3 都在「(未歸屬 / 系統)」 | 確認有以管理員執行（否則連線表缺 PID 無法比對）；連線剛建立的短時間流量歸不到是正常現象 |
| HTTPS 封包只看得出網域、看不到內容 | 正常，內容有 TLS 加密（見上方說明） |
| 防毒軟體跳警告 | 封包擷取行為敏感、自製程式無簽章，被標記很常見；本程式原始碼完全公開在本 repo |

## 注意事項

1. **合法性**：只監控**你自己的電腦或網路**。側錄他人的流量未經同意可能違法。
2. **權限**：擷取封包、檢視所有程式連線需系統管理員權限。
3. **效能**：高速流量下封包列表最多保留 10,000 筆（舊的會自動汰換）；長時間擷取建議加 BPF 過濾縮小範圍，並適時存 pcap 後清除。

---

## 附錄：背景研究筆記（本專案的出發點）

### Windows 內建工具（不用安裝）
| 工具 | 開啟方式 | 用途 |
|---|---|---|
| **工作管理員** | `Ctrl+Shift+Esc` → 效能 | 看整體上傳和下載速度 |
| **資源監視器** | `Win+R` 輸入 `resmon` → 網路分頁 | 看每個程式的流量和連線 |
| **netstat** | `netstat -ano` | 列出所有連線和 PID |
| **pktmon** | `pktmon start --capture` | Win10 1809+ 內建封包擷取 |

### 第三方軟體
| 軟體 | 特點 | 費用 |
|---|---|---|
| **Wireshark** | 業界標準封包分析（本專案存的 pcap 可直接用它開） | 免費、開源 |
| **TCPView**（Sysinternals） | 即時顯示各程式 TCP/UDP 連線，輕量 | 免費 |
| **GlassWire** | 流量圖表、新程式連網警示 | 有免費版 |
| **NetLimiter** | 每程式流量監控，還能限速/阻擋（層級 5） | 付費 |
| **Portmaster** | 開源，監控兼管理連線 | 有免費版 |
| **Fiddler** | 專門看 HTTP/HTTPS 請求 | 有免費版 |

### 語言選型（為何選 Python）
| 語言 | 適合情境 |
|---|---|
| **Python**（本專案） | 快速做原型、個人工具，套件豐富；tkinter 讓 GUI 免裝框架即可發行 |
| **C#** | 要做完整 Windows 產品、需要 ETW/WinAPI 最佳支援 |
| **C/C++** | 要求效能，或要碰 WFP、驅動程式（層級 5） |

### 想繼續往上做（層級 5）的方向
阻擋/修改流量需要 **WFP（Windows Filtering Platform）** 或 **WinDivert** 這類核心層技術，
複雜度與風險（藍屏、相容性）都高一截，建議先熟悉 Wireshark/Npcap 與 WFP 的官方範例再動手。
