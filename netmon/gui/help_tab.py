"""說明 / 幫助分頁：把各頁面的使用說明集中到這裡，避免主介面過於擁擠。"""
from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext, ttk

from . import theme


_HELP_TEXT = """Win-NetMon 使用說明

一、整體概念
本程式把網路流量分成 5 個層級，依序為：
  1. 總覽：整體上/下行速率、尖峰、每張介面卡的速率與累計。
  2. 連線清單：目前所有 TCP/UDP 連線與對應程式、PID、遠端 IP/埠。
  3. 程式流量：各程式用了多少流量（需先開始「封包擷取」）。
  4. 封包擷取：即時封包列表、逐層解析、Hex dump、pcap 存取。
  5. 封鎖/管制：即時攔截（WinDivert）與系統防火牆封鎖。

二、基本操作
  - 層級 1、2 開啟程式就會自動運作，不需額外設定。
  - 要看「程式流量」與「封包擷取」，請到「📦 封包擷取」分頁按「▶ 開始擷取」。
  - 預設會自動選一張有 IPv4 的介面卡；也可手動選擇。
  - 擷取後可使用 BPF（Npcap）或 WinDivert 過濾語法縮小範圍。
  - 「顯示篩選」可只在列表中搜尋關鍵字，不影響擷取。

三、擷取後端
  - Npcap：完整後端，含 Ethernet/ARP 與介面選擇（需安裝 Npcap）。
  - WinDivert：免 Npcap，抓 IP 層封包，所有介面一次看（無 ARP/Ethernet）。
  - 自動選擇：優先 Npcap，沒有時自動改用 WinDivert。
  - 沒裝 Npcap 也可用「⬇ 一鍵下載並安裝 Npcap」按鈕從官方下載安裝。

四、層級 5 封鎖/管制
  A. 即時攔截（WinDivert）：規則在記憶體中，停止或關閉程式即恢復。
     - 規則依由上而下順序比對，第一條命中為準。
     - 條件全空 = 全部流量（慎用，有效能影響）。
     - 預設 10 分鐘自動停止，可調整。
  B. 系統防火牆（WFP/netsh）：寫入 Windows 防火牆，重開機仍在。
     - 建議用「程式（.exe）」封鎖，最可靠。
     - 用「全部移除」可一次清除本程式寫入的規則。

五、權限
  - 以系統管理員身分執行才能看到全部程式的 PID、擷取封包、使用層級 5。
  - 非管理員時右上角會出現「以系統管理員身分重新啟動」按鈕。

六、常見問題
  - 看不到封包：確認有管理員權限、Npcap/WinDivert 可用、介面選對。
  - 流量歸屬率低：先開始擷取並刷新連線表；部分系統流量無法歸屬。
  - 封鎖後斷網：停止即時攔截或移除系統防火牆規則即可恢復。
  - HTTPS 內容為加密，只能看到 IP、埠、網域（SNI）與大小。

七、注意
  本程式僅供監控自己的電腦/網路，請勿用於未授權的環境。
"""


class HelpTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        fonts = app.fonts

        header = ttk.Frame(self)
        header.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(header, text="使用說明與常見問題", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="把各分頁的詳細說明集中於此，主介面只保留操作元件。",
                  style="Muted.TLabel").pack(anchor="w")

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=10, pady=(2, 10))
        self.text = scrolledtext.ScrolledText(
            body, font=fonts["ui"], bg=theme.PANEL, fg=theme.TEXT,
            insertbackground=theme.TEXT, wrap="word", height=24,
            selectbackground=theme.SELECT, relief="flat", borderwidth=0)
        self.text.pack(fill="both", expand=True)
        self.text.insert("1.0", _HELP_TEXT)
        self.text.config(state="disabled")
