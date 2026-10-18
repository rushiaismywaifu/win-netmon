# Win-NetMon — Windows 網路流量監測/管制器（層級 1～5 + GUI）

一個用 Python 寫的 Windows 網路流量工具，附圖形介面。從「整體網速」一路做到
「阻擋或修改流量」，五個層級、五個分頁全實作：

| 層級 | 分頁 | 功能 | 技術 |
|---|---|---|---|
| 1 | 📊 **總覽** | 即時上/下行速率圖（120 秒）、尖峰與本次總量、每一介面卡的速率與累計 | `psutil.net_io_counters` |
| 2 | 🔌 **連線清單** | 每個程式連到哪些 IP:埠 - 可搜尋、依協定篩選、排序、解析遠端主機名、匯出 CSV | `psutil.net_connections` |
| 3 | 🏆 **程式流量** | 每個程式的下/上行即時速率與總量排行、封包數、目前連線數 | 封包 + 連線表比對（依埠號把封包歸屬給程式） |
| 4 | 📦 **封包擷取** | 即時封包列表、逐層解析、Hex dump、DNS 查詢、TLS SNI 網域、HTTP 請求、BPF 過濾、存/讀 `.pcap` | Npcap + Scapy |
| 5 | 🛡 **封鎖/管制** | (a) 即時封包攔截：封鎖/放行/限速/弱網路模擬（延遲+丟包）/轉址，可依 IP、埠、程式、DNS 網域比對；(b) 長效封鎖寫入 Windows 防火牆（依程式/IP/埠，核心強制） | WinDivert（pydivert）+ WFP（netsh advfirewall） |

> ⚠ **層級 5 會實際干預網路**（丟棄/延遲/改寫封包、改寫系統防火牆）。請先看
> 「層級 5 使用說明」與安全設計，只在**你自己的電腦**上、且理解自己在擋什麼的前提下使用。

![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![Platform](https://img.shields.io/badge/Platform-Windows-0078D6) ![GUI](https://img.shields.io/badge/GUI-tkinter-green)

---

## 快速開始（Windows）

### 前置安裝
1. **Python 3.9+**：[python.org](https://www.python.org/downloads/windows/)，安裝時勾選
   「Add python.exe to PATH」與 Tcl/Tk（GUI 用，預設有勾）。
2. **Npcap**：[npcap.com](https://npcap.com)，一路下一步即可（建議勾選
   *"Install Npcap in WinPcap API-compatible Mode"*）。Wireshark 也是用它。
   > 只有層級 3、4 需要 Npcap；不裝的話層級 1、2、5 仍可正常使用。
3. **（層級 5 即時攔截）** pydivert 套件（內含 WinDivert 驅動），隨 `requirements.txt`
   一起自動安裝，不用另外上網抓東西。

### 啟動
點兩下 **`run_as_admin.bat`**（會自動以系統管理員身分啟動，並在第一次自動
`pip install` 所需套件）。或手動：

```bat
pip install -r requirements.txt
python main.py
```

> 💡 **為什麼要系統管理員？** 沒管理員權限會看不到全部程式的 PID，也無法擷取封包、
> 跑 WinDivert 攔截或寫入系統防火牆。
> 程式右上角會顯示目前權限，也可以按「以系統管理員身分重新啟動」。

### 先檢查環境（可選）

```bat
python main.py --check
```
會檢查 Python、psutil、tkinter、Scapy、Npcap、pydivert/WinDivert、防火牆（netsh）可用性、管理員權限與可擷取介面，並告訴你缺什麼。

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
- 右鍵也能直接「封鎖此程式連外網／封鎖此遠端 IP」（層級 5）：會帶好參數跳到
  層級 5 分頁的表單讓你確認，**不會**未經確認就寫入。

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
- 封包上點右鍵可直接對該遠端 IP 建層級 5 封鎖/攔截規則（同樣只帶入表單待確認）。

> ⚠ **HTTPS 是加密的**：你能看到 IP、埠、網域（SNI）、流量大小與時序，
> 但看不到內容 — 這跟 Wireshark 未提供金鑰解密時完全一樣，是正常的。

### 🛡 層級 5：封鎖/管制（阻擋與修改流量）

這個分頁有兩個互補的子系統，對應 README 原始規劃的 WFP 與 WinDivert 兩條路線：

#### A. 即時攔截（WinDivert）— 彈性高、即開即停

先維護一張**規則清單**，再按「▶ 開始即時攔截」。每個封包依清單順序判斷，
**第一條命中者**決定處置（所以例外放行放上面）：

| 動作 | 行為 |
|---|---|
| ✅ 放行（allow） | 立即放行，不再比對後面規則（做白名單例外用） |
| 🚫 封鎖（block） | 直接丟棄封包（drop，不送回核心） |
| 🐌 限速（limit） | 令牌桶限速（KB/s，可短暫 burst 約 64KB），超額直接丟棄（TCP 會自然降速重傳適應） |
| 📶 弱網路模擬（impair） | 固定延遲 ms + 隨機丟包 % — 拿來測自家程式在爛網路下的表現（類似 clumsy） |
| ↪ 轉址（redirect） | 把封包的目標 IP:埠 改寫送出（自動重算 checksum），回程封包自動還原來源（conntrack 式還原）；例如把 80 明文導向本機代理 |

**比對條件**：方向、協定、遠端/本機 IP(CIDR)、遠端/本機埠（逗號清單或範圍，
如 `80,443`、`8000-9000`）、**程式名**（用層級 3 的連線比對歸屬，查不到歸屬時
不會命中需程式條件的規則）、**DNS 網域**（比對 UDP/TCP 53 的明文 DNS 查詢
qname 本身或子網域；封鎖等於讓它解析不到 — 但走 DoH/DoT 的加密解析擋不到）。
表單有範本按鈕（封鎖網域、弱網路模擬、全域限速、封鎖全部出向）一鍵帶好參數。

**運作原理**：規則被編譯成 WinDivert 過濾字串，只把*可能命中*的封包撈進
Python 做權威判斷（介面上會顯示實際用的過濾字串；若有無條件「抓全部」規則
會先警告效能）。其餘封包留在核心高速路徑，不經過 Python。放行封包不重算
checksum、只有被改寫的（轉址）才重算。延遲包由獨立送出執行緒按到時順序補送。

**安全設計**（這一級真的會影響網路，所以做了多重保險）：
- 預設**10 分鐘自動停止**（可改 5/30/60 分鐘或關閉），標題欄與狀態徽章會顯示「管制中」紅字。
- 停止、關閉程式、程式閃退 → WinDivert handle 關閉，**網路立即完全恢復**，
  不會在系統留下東西；佇列中未送出的延遲包直接丟棄（TCP 重傳即可恢復）。
- 預設排除 loopback；攔截中鎖定規則編輯（避免與已編譯的過濾字串不一致）；
  「封鎖全部出向」範本按下開始時會彈窗再次確認。
- 底部有攔截紀錄（被丟/延遲/轉址逐筆）與統計；驅動沒裝/被擋時這個子分頁會
  顯示原因，但其他層級與下列系統防火牆**不受影響**。

#### B. 系統防火牆（WFP / `netsh advfirewall`）— 長效可靠、依程式封鎖

把「封鎖規則」寫進 Windows 內建防火牆（它建構於 WFP 之上，核心直接強制，
**重開機/關閉本程式仍有效**）。三種形式：
- **封鎖程式（.exe 路徑）**：這種「擋這個程式上網」只能在這裡精確做到 —
  WinDivert 在 NETWORK/IP 層看到的是封包、沒有程序概念（程式層級需 WFP ALE 層）；
  可在層級 2 的連線清單右鍵「封鎖此程式連外網」一鍵帶好完整路徑。
- **封鎖遠端 IP / CIDR**、**封鎖遠端埠**（TCP/UDP）。
本程式只建立名稱 `Win-NetMon-xxxxxxxx` 的規則（避開本地化輸出地獄：GUI 用你的
標籤顯示、內部以該名精準增刪查，**絕不碰**既有系統規則）；有防手殘移除與
「全部移除」一鍵清除 + 從系統狀態重新整理（例如你手動在防火牆 UI 刪掉的話）。
啟動時若有遺留規則，狀態列會提醒。規則定義保存在
`%APPDATA%\Win-NetMon\rules.json`（與上面即時攔截規則同檔不同節）。

> 兩條路線怎麼選？**永久擋某程式/某 IP 上網 → 用系統防火牆**；要臨時的、
> 彈性的（測試、限速、假裝弱網路、觀察擋下後效果）→ 用即時攔截。
> **誠實限制**：DNS 網域封鎖對 DoH/DoT/QUIC 加密解析無效；QUIC 在 IP 層
> 照樣能封 IP/埠；加密內容本來就改不了（只能丟或延遲）。

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
Npcap 仍需另外安裝，無法打包進去；WinDivert 驅動則已隨 pydivert 一起收進 exe（`--collect-all pydivert`）。

---

## 專案結構

```
win-netmon/
├─ main.py                  # 入口：GUI / --check / --cli
├─ run_as_admin.bat         # ⭐ 建議啟動方式（自動提權 + 裝套件）
├─ run.bat                  # 一般身分啟動
├─ build_exe.bat            # （選用）PyInstaller 打包
├─ requirements.txt         # psutil、scapy、pydivert(僅 Win)（GUI 用內建 tkinter，不必裝）
├─ netmon/
│  ├─ speed_monitor.py      # 層級 1：整體與每介面網速
│  ├─ connections.py        # 層級 2：連線表 + 程式名快取
│  ├─ traffic.py            # 層級 3：連線索引 + 每程式流量彙總
│  ├─ capture.py            # 層級 4：Scapy 擷取引擎、封包轉換、pcap 存讀
│  ├─ rule_engine.py        # 層級 5：管制規則比對/決策 + WinDivert 過濾字串編譯（純邏輯）
│  ├─ divert_engine.py      # 層級 5：WinDivert 攔截執行層（recv 判斷緒 + sender 緒）
│  ├─ win_firewall.py       # 層級 5：WFP 防火牆（netsh 封裝，只認 Win-NetMon-* 規則）
│  ├─ rule_store.py         # 層級 5：rules.json 原子持久化（%APPDATA%/Win-NetMon）
│  ├─ packet_info.py        # DNS / TLS SNI / HTTP 解析 + 協定分類（純 Python）
│  ├─ utils.py              # 格式化、權限檢查、Npcap 偵測、hex dump
│  └─ gui/
│     ├─ app.py             # 主視窗與排程（200ms 收封包、1s 取樣、2s 刷連線）
│     ├─ dashboard_tab.py   # 層級 1 分頁        ├─ processes_tab.py  # 層級 3 分頁
│     ├─ connections_tab.py # 層級 2 分頁        ├─ packets_tab.py    # 層級 4 分頁
│     ├─ firewall_tab.py    # 層級 5 分頁（攔截規則 + 防火牆 + 紀錄）
│     ├─ widgets.py         # 統計卡、速率圖、Top 長條圖、表格輔助
│     └─ theme.py           # 深色主題色票與字體
└─ tests/
   ├─ test_core.py          # 層級 1~4 核心測試：python -m unittest discover -s tests -v
   └─ test_level5.py        # 層級 5：規則引擎/防火牆假 runner/假 WinDivert 端到端
```

設計上核心（`speed_monitor` / `connections` / `traffic` / `capture` / `rule_engine` / `divert_engine` / `win_firewall` / `packet_info`）
與 GUI 完全分離，可以單獨在自己的 script 裡 import 使用，也方便測試。

## 測試

```bat
python -m unittest discover -s tests -v
```
涵蓋：位元組格式化、DNS 查詢解析、TLS SNI 擷取、HTTP 解析、協定分類、
連線索引比對（精確 + 埠號後備）、流量彙總速率、Scapy 封包轉換與 CSV 匯出（層級 1~4 共 12 項）；
層級 5 另有 34 項：埠/IP/網域規格解析、規則比對與優先順序、令牌桶限速、延遲/丟包、DNS 網域封鎖、
轉址與回程還原、WinDivert 過濾字串編譯、防火牆指令（假 runner）、rules.json 往返、假 WinDivert 端到端（合計 46 項）。

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
| 即時攔截開啟失敗 / 驅動被擋（錯誤 577、1275） | pydivert 包的是較舊的 WinDivert 簽章驅動，可能被 Win11 的「記憶體完整性」或易受攻擊驅動封鎖清單擋下。解法：改用同分頁的**系統防火牆封鎖**（完全不受影響）；或評估風險後調整 Windows 安全性設定。其餘層級不受影響 |
| 不小心把網路擋死了怎麼辦 | 「即時攔截」：按停止或直接關閉程式即完全恢復；「系統防火牆」：到層級 5 的防火牆子分頁按「全部移除」（規則名皆為 `Win-NetMon-*`，也可在 Windows 防火牆進階設定按此字串搜尋手動刪） |
| 封鎖了網域還是連得上 | 屬 DoH/DoT（加密 DNS）在解析，明文 DNS 規則擋不到。可用系統防火牆直接封該服務的遠端 IP，或改擋查詢用的 53/853 等去向（副作用較大，慎用） |
| 「依程式」即時攔截有時沒擋到第一批封包 | WinDivert 本身無程式資訊，本專案靠連線表比對歸屬（每 2 秒快照）；連線建立最初的短暫封包歸屬不到屬正常。要**確保**封住某程式請用系統防火牆的「封鎖程式」 |
| 限速一開始衝很快 | 令牌桶初始可 burst 約 64KB，長時間速率才收斂到上限，屬正常 |

## 注意事項

1. **合法性**：只監控/管制**你自己的電腦或網路**。側錄或干擾他人的流量未經同意可能違法。
2. **權限**：擷取封包、檢視所有程式連線、WinDivert 攔截、寫入系統防火牆都需系統管理員權限。
3. **層級 5 會有斷線風險**：不要封鎖你不認識的系統服務（svchost、驅動、更新）；
   用了「系統防火牆」封鎖後記得它在關閉程式後**依然有效**，用完在層級 5 按「全部移除」。
4. **驅動與相容性**：層級 5 載入 WinDivert 第三方簽章驅動，老舊簽章可能被新版 Windows
   安全功能封鎖（見 FAQ），封鎖系統防火牆功能仍不受影響。
5. **效能**：高速流量下封包列表最多保留 10,000 筆；長時間擷取/攔截請縮小過濾範圍，避免讓全部流量都流經 Python。

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
| **Python**（本專案） | 快速做原型、個人工具，套件豐富；tkinter 讓 GUI 免裝框架即可發行；層級 5 又靠 pydivert 省下自己寫驅動 |
| **C#** | 要做完整 Windows 產品、需要 ETW/WinAPI 最佳支援 |
| **C/C++** | 要求效能，或要自寫 WFP callout 驅動（層級 5 的進階路線） |

### 層級 5 已實作（v1.1.0），未來還能加強的方向
- 自寫 WFP callout 驅動（ALE 層直接知道程式身分，免連線表比對）— 複雜度最高的路線，
  需 C 與驅動程式簽章；目前的「WinDivert + 連線歸屬」是免寫驅動的權宜版。
- 針對 DoH/DoT/QUIC 的解析封鎖策略、SNI 層級的 TLS 封鎖（在 ClientHello 丟棄）、
  以及匯入 adblock 規則清單批次產生封鎖規則。
