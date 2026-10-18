"""Win-NetMon：Windows 網路流量監測器（層級 1～4）。

層級對照（見 README）：
  1. 整體網速（上傳／下載）          -> netmon.speed_monitor
  2. 哪些程式連到哪些 IP              -> netmon.connections
  3. 每個程式各用了多少流量          -> netmon.traffic（封包＋連線表比對）
  4. 擷取並解析封包內容              -> netmon.capture（Npcap + Scapy）
GUI 在 netmon.gui（tkinter，Windows/Python 內建，不需另外安裝）。
"""

__version__ = "1.0.0"
__app_name__ = "Win-NetMon"
