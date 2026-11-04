# NIKKE PC Launcher 供應鏈投毒事件報告

**文件：** K2F PURGE 事件說明（繁體中文，可獨立閱讀）  
**對應工具：** K2F PURGE 0.1.0  
**主要來源：** [MotherSphere gist](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5)（**2026-11-04 02:00 GMT** 版）與同 gist 的 `target-paths.md`  
**本文件不包含惡意 payload、不提供重現攻擊的步驟。**

> **警告：** 自 2026-09-27 起，Level Infinite CDN 上四個官方 JavaScript 檔被植入 loader。NIKKE PC launcher 會載入這些檔。最晚自 10 月 23 日起，開啟 launcher 就可能安裝遠端控制 agent：launcher 開著時，攻擊者可以在你的帳號權限下執行任意命令、讀取任意檔案、擷取螢幕。  
> 2026-11-03 之後官方檔已陸續替換、攻擊者伺服器已關閉，**這不能清除已經中招的機器，也不能清掉 launcher 快取裡的舊檔。** 在官方確認修復並清掉 `tbs_cache` 之前，不要開啟 NIKKE PC launcher。

---

## 摘要

| 項目 | 內容 |
|---|---|
| 入侵點 | Level Infinite CDN（`playerinfinite.com`，Tencent COS）上四個官方 JS 檔，於 2026-09-27 被改 |
| 影響對象 | 2026-10-23（最晚）至修復前曾開啟 NIKKE PC launcher 的 Windows 使用者，以及透過 Proton／Wine 遊玩的 Linux／Steam Deck 使用者；快取或過期 CDN 節點仍可能提供舊檔 |
| 惡意程式 | 遠端控制 agent（內部名稱 `K2F_LUA_BUILD`）：命令執行、檔案存取、截圖、竊取密碼／cookie／token／SSH 金鑰／錢包 |
| 持久化（僅 Windows） | Chrome 載入的 DLL + `HKCU` CLSID。安裝 DLL **不需要** 本機已裝 Chrome。HKLM 同名 CLSID 是正常的 `wpc.dll`，**不可刪** |
| Payload 活躍 | 留言區最早的 agent 啟動為 2026-10-23 16:40 GMT；分析機於 2026-11-03 00:47 GMT 被執行。Loader 自 09-27 就在 |
| 修復狀態 | `aegis-fix.min.js`、`vue-bucket.min.js`、`images.7fec4c32.js` 於 11-03 17:04／17:13／17:21 GMT 替換。`FeedList.feb647c9.js` origin 自 10-28 已乾淨，但部分 CDN 節點到 11-03 22:26 仍送舊檔 |
| 攻擊者主機 | `89.127.233.127` 於 11-03 18:31 GMT 起無回應；託管商 1984 ehf 回覆已關閉。先前約至 10-21 使用 `89.126.250.172` |
| 仍未釐清 | 攻擊者如何取得 CDN 寫入權；仍送舊檔的 CDN 節點；官方尚未公開說明 |

K2F PURGE **不是防毒軟體**。它只核對本事件已公開的 IOC。沒找到 ≠ 安全。

---

## 攻擊鏈

### Stage 1 — 官方檔被植入 loader

四個官方檔被加入隱藏 URL 的程式碼，動態插入 `<script>` 載入 `https://insightjs.com/l.js?f=<aegis|images|feedlist|vue>`。若 `insightjs.com` 失敗或 30 秒無回應，改用 `insightjs.org`。

| 官方檔 | 載入 |
|---|---|
| `https://sg-gpts.playerinfinite.com/comm/assets/lib/aegis-fix.min.js` | `l.js?f=aegis` |
| `https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/images.7fec4c32.js` | `l.js?f=images` |
| `https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/FeedList.feb647c9.js` | `l.js?f=feedlist` |
| `https://na-webassets.playerinfinite.com/comm/assets/lib/vue-bucket.min.js` | `l.js?f=vue` |

惡意版（解壓後大小；Last-Modified 皆為 2026-09-27 06:41–06:42 GMT）：

| 檔案 | 大小 | ETag |
|---|---|---|
| `aegis-fix.min.js` | 69,731 | `50d1861152ea7f6875ffceb7d08445b5` |
| `images.7fec4c32.js` | 4,358 | `481e9b5ab8fb93406bf31980b53e0578` |
| `FeedList.feb647c9.js` | 5,808 | `b7d842200372ad0d9a84ef4cc8511311` |
| `vue-bucket.min.js` | 135,273 | `dd06875637a29cddd3bae2ba84142c78` |

已替換的乾淨版（不含 loader、不含 `insightjs`）：

| 檔案 | 大小 | ETag | Last-Modified |
|---|---|---|---|
| `aegis-fix.min.js` | 69,032 | `44c576454a5b0b4ed60e1a983aa4e782` | 2026-11-03 17:04:28 GMT |
| `images.7fec4c32.js` | 3,659 | `6e5f79cf9b7c364249f9de83ba7fa59e` | 2026-11-03 17:21:31 GMT |
| `FeedList.feb647c9.js` | 5,099 | `04ee9800128396ba26f10ca70f170967` | 2026-10-28 15:46:09 GMT |
| `vue-bucket.min.js` | 134,592 | `63bc3a47b35b80a5d200dc5624d7126e` | 2026-11-03 17:13:36 GMT |

`FeedList.feb647c9.js` 多出來的約 708 bytes 插在檔尾 `export{...}` **之前**，只比對檔尾會漏掉。各 CDN 節點快取不一致：11-03 18:57–22:26，`43.152.43.115` 已是乾淨版，`43.175.144.148` 與 `43.175.145.181` 仍送 09-27 的惡意版（含 cache-busting 查詢字串）。

Loader 本身不寫 launcher 日誌。`debug.log` 裡的 `startup already in progress`、`k2f_chan registered`、`adopted` 來自 `l.js`。`startup already in progress` **不可靠**（有些感染場次沒有）。

V8 code cache（`tbs_cache\Code Cache\js\`）在每台機器上使用相同檔名：

| 檔名 | 對應 |
|---|---|
| `dd65fa4d61079e7e_0` | aegis |
| `ce2fd3f1007a9fe9_0` | images |
| `1416c638b3830103_0` | feedlist |
| `fd520c7c0f65c2d7_0` | vue |

HTTP cache（`tbs_cache\Cache\data_*`）也可能還留著被改過的官方檔。

### Stage 2 — 下載 payload

`l.js` 透過 launcher 自己的 JS bridge `Srv_DownloadFile` 下載：

| 項目 | 值 |
|---|---|
| URL | `https://analytics.insightjs.com/comm/assets/insight.bundle` |
| 大小 | 205,135 bytes |
| 已知樣本 SHA-256 | `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`（2026-11-03 16:22 GMT 取得） |
| 標頭 | `content-type: application/octet-stream`，`cache-control: no-store` |

受害者跑過**多個同大小、不同雜湊**的 build。`tinyget.mem.log` 保存回應標頭；nginx ETag 由 mtime 與 size 的十六進位組成。已知五次上傳：

| ETag | 約略時間 |
|---|---|
| `6ae78037-3214f` | 2026-11-01 18:08:55 |
| `6ae8ccff-3214f` | 2026-11-02 17:48:47 |
| `6ae90538-3214f` | 2026-11-02 21:48:40（分析機這份） |
| `6ae9d408-3214f` | 2026-11-03 12:31:04 |
| `6ae9f628-3214f` | 2026-11-03 14:56:40（已公開樣本） |

Agent 自 10-23 就有啟動紀錄，因此還有更早、沒人貼標頭的 build。同一組 build 同時打到 Windows 與 Proton，**不是依作業系統分開**。單一 SHA-256 不能涵蓋所有感染。

Launcher 把 payload 存成 `Launcher\log\tinyget\` 底下看起來像 `.log` 的檔，執行後刪除。早期（約 10-24）曾存成 `k2f.lua`。

`onominan.tmp` **不是 IOC**（Tencent 其他軟體、甚至投毒前就會產生）。

### Stage 3 — Agent

- 格式：LuaJIT 2.0 bytecode（32-bit、stripped），Prometheus 混淆。
- 在 launcher 行程內向 `comm_center` 註冊 `k2f_chan`，只回答 `open`／`read`／`write`／`ping`／`close`。**所有命令來自伺服器**，agent 不會自己排程偷竊。
- 狀態寫在 `%APPDATA%\nikke_launcher\tbs_cache\Local Storage\leveldb\` 的 `k2f.agent.state`（origin `https://www.nikkelauncher.com`）。刪掉 NIKKE 安裝資料夾**不會**清掉這份狀態。
- Lua agent **沒有網路程式碼**。對外流量全部走 launcher 內嵌瀏覽器（Windows 上是 `tbs_browser.exe`），不走遊戲行程。防火牆、proxy、SRUM 看到的都是這個行程。
- 實務上，agent 一啟動數秒內就會有第一波收集（有機器 3 秒內寫入 Chrome DLL；SRUM 顯示啟動當下約 0.9 MB 至數十 MB 上傳）。沒找到暫存檔、或設定裡 `collect_cookies: false`，**都不代表什麼都沒被拿走**。
- 只有 `exec` 會啟動新行程。其餘命令在 launcher 行程內用 LuaJIT FFI 完成，Prefetch／行程建立日誌看不到。
- **launcher 日誌不會記錄執行過哪些命令。** 必須假設最壞情況。

---

## 時間線（GMT）

| 時間 | 事件 |
|---|---|
| 2026-09-27 01:59 | `insightjs.com` 註冊（PDR Ltd.／PublicDomainRegistry，所有人隱藏；NS 為 1984.is） |
| 2026-09-27 03:00 | `insightjs.com`／`www` 第一張憑證 |
| 2026-09-27 06:41–06:42 | 四個官方 CDN 檔被改 |
| 2026-10-05 07:09 | 目前最早的 `insightjs.com` 查詢紀錄（Pi-hole，留言回報） |
| 2026-10-05–10-21 | 有受害者解析到 `89.126.250.172` |
| 2026-10-06 00:55 | `analytics.insightjs.com` 第一張憑證 |
| 2026-10-12 | `insightjs.com` 註冊資料更新 |
| 2026-10-21–10-23 | 改指向 `89.127.233.127`；10-23 15:37 新憑證涵蓋 apex／analytics／portal／www |
| 2026-10-23 16:40 | 留言區最早的 agent 啟動（約在 15:37 憑證之後一小時） |
| 2026-10-24 01:16 | Linux Proton 上有 agent 啟動（payload 存成 `k2f.lua`） |
| 2026-10-28 15:46 | `FeedList.feb647c9.js` 在 origin 換成乾淨版；部分 CDN 仍快取 09-30 的惡意版 |
| 2026-10-30–11-03 | 多起 agent 啟動回報（10-30、11-01、11-02、11-03 上午） |
| 2026-11-01 11:14、11-02 17:34 | 分析機啟動：有 loader、沒有 payload |
| 2026-11-01 18:08 起 | 多個 `insight.bundle` build 上傳（見 ETag 表） |
| 2026-11-03 00:47 | 分析機下載並執行 payload |
| 2026-11-03 16:11 | NIKKE 社群 Discord 出現公開警告 |
| 2026-11-03 17:04／17:13／17:21 | 三個官方檔被替換 |
| 2026-11-03 17:30 | 攻擊者的 `l.js` 改回看起來像測速腳本；`insight.bundle` 當時仍在線 |
| 2026-11-03 17:55 | 第三方註冊 `insightjs.org` 並改成警告頁 |
| 2026-11-03 18:31 | `89.127.233.127` 連線逾時 |
| 2026-11-03 18:59、20:23、22:26 | 兩個 CDN 節點仍提供惡意 `FeedList.feb647c9.js` |
| 2026-11-03 23:26 | 1984 ehf 回覆該 IP「has been shut down」（DNS 22:26 仍指向該址） |
| 2026-11-04 02:00 | 本報告所依據的 gist 版本 |

---

## 指標（IOC）

### 網域

| 網域 | 角色 |
|---|---|
| `insightjs.com` | Loader 主域 |
| `analytics.insightjs.com` | Payload（`insight.bundle`） |
| `insightjs.org` | Loader 後援；11-03 17:55 後被第三方做成警告頁 |

### IP

| IP | 說明 |
|---|---|
| `89.127.233.127` | 約 10-21 後的主 C2（1984 ehf，冰島） |
| `89.126.250.172` | 約用到 10-21（同一家、同一個 ASN） |

### 雜湊（SHA-256）

| SHA-256 | 檔案 |
|---|---|
| `2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203` | 被改的 `FeedList.feb647c9.js` |
| `3aaafbd612f04501a6fdb0bb8b2f8a87796223e5584ac18ea5eb180feeafb193` | 被改的 `vue-bucket.min.js` |
| `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec` | `insight.bundle` 樣本（其他 build 同大小不同雜湊） |

### 日誌字串（`Launcher/intl_service/debug.log`）

| 字串 | 意義 |
|---|---|
| `k2f_chan registered` | **強訊號**：agent 已在 launcher 內註冊 |
| `agent started as` | **強訊號**：agent 已啟動 |
| `lua downloaded to log\tinyget\` | payload 落地（亦可能是 `tinyget.<ts>.log` 或早期的 `k2f.lua`） |
| `adopted` | l.js 在伺服器回應後寫入 |
| `resuming` | 弱訊號 |
| `startup already in progress` | **不可靠**，有些感染場次沒有 |
| `FETCH_LIST suc success` | **正常日誌**，乾淨啟動也有 |

`debug.log` 是附加寫入，不是每次啟動覆寫。刪除／重裝 NIKKE 資料夾後這份日誌會消失，但 Local Storage 裡的 agent 狀態還在。

### Code cache key

`dd65fa4d61079e7e_0`、`ce2fd3f1007a9fe9_0`、`1416c638b3830103_0`、`fd520c7c0f65c2d7_0`（見 Stage 1）。

### 登錄與 DLL（僅 Windows）

| 位置 | 說明 |
|---|---|
| `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<64 字元 hex>\platform_experience_helper.dll` | 惡意 DLL。每台機器雜湊不同。父資料夾是 Chrome **正常**建立的，只刪 64-hex 子資料夾 |
| `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32` | 使用者登錄持久化。空 default 值是 agent 自己的 `chrome_uninstall` 殘留，仍應刪 |
| `HKLM\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` | **正常** Windows Parental Controls（`wpc.dll`）。**絕不可刪** |

其他可能殘留：`platform_experience_helper.dll.old`、`old-clsid.txt`、`service_util.dll`（僅限已知 Chrome 根目錄）。

### 暫存與 payload 殘留

- `%TEMP%` 下的 agent dump 前綴（與 `k2f_screen_*.jpg`）
- `Launcher\log\tinyget\*`、`k2f*.lua`
- `tinyget.mem.log` 內的已知 ETag

DNS 快取裡的 `insightjs` 僅供參考（可能已被 flush）。一台同時使用路由器 IPv6 DNS 的感染機，Pi-hole 完全沒有 `analytics.insightjs.com` 紀錄，所以 DNS 日誌沒打到 **不能** 排除 agent。

---

## 攻擊者能做什麼

Agent 是由操作者下指令的遠端工具，不是固定的偷竊腳本。Launcher 開著時可下：

| 命令 | 作用 |
|---|---|
| `exec` | 執行任意程式或 shell，回傳輸出 |
| `ls`／`cd`／`cat`／`download`／`file_chunk` | 瀏覽目錄、下載任意檔 |
| `screens` | 每個螢幕截圖 |
| `creds` | 解密 launcher 存在 `psd.dat`／`last_user.dat` 的 **NIKKE 帳密**（不是 Windows 認證管理員；讀認證管理員的是 `keyscan`） |
| `browserscan` | Chrome／Edge／Brave／Vivaldi／Opera／Firefox 的已存密碼；`collect_cookies` 為 false 時跳過 cookie store，但密碼仍讀。`cat`／`download`／`exec` 仍可複製 Cookies 檔 |
| `chrome_scan` | 列出 Chrome 安裝、profile、擴充 ID |
| `keyscan` | 讀 264 條已知憑證／設定路徑，並讀開發工具在 Windows 認證管理員的項目（`git:`、`gh:`、`npm:`、`docker:`、`aws:`、`azure:`、`vscode:` 等） |
| `wallet_files` | 讀 Chrome profile 裡 28 種錢包擴充（其他瀏覽器的錢包仍可用 `download` 複製） |
| `whoami`／`sysinfo`／`host_facts` | 電腦名、使用者、完整性層級、Windows 組建、CPU／RAM／磁碟／網卡 |
| `chrome_install` | 安裝 Chrome DLL 持久化 |
| `chrome_cleanup`／`chrome_uninstall`／`payload_cleanup` | 清痕跡 |

`exec` 就等於操作者能做你這個使用者能做的一切。有受害者回報 launcher 預設會要系統管理員權限；提權後的 launcher 讓 `browserscan` 能用 SYSTEM token 解 Chrome／Edge 的 app-bound encryption。

要估算 Windows 上流出多少資料：以系統管理員開啟 SRUM（`C:\Windows\System32\sru\SRUDB.dat`），對 `tbs_browser.exe` 比對 agent 啟動那個小時的流量。

---

## 影響範圍

### Windows

完整攻擊鏈都適用。DLL 持久化讓 agent 在 launcher 關閉後仍可能透過 Chrome 存活。DLL 載入中會被鎖住，即使關掉所有 Chrome 視窗（有回報）；需要重開機才能刪。Microsoft Defender Offline 在某一台機器上未偵測到該 DLL（特徵 1.463.110.0），掃毒乾淨 **不代表** 已清除。

最穩的做法是重裝 Windows，因為 agent 活躍期間攻擊者可以執行任意命令。

### Linux／Steam Deck（Proton）與 macOS 上的 Wine

**Proton 不能保護你。**

自動掃描找的是 Windows 路徑，在 prefix 裡通常只看得到 NIKKE launcher 資料。Chrome DLL 持久化在 Linux 上不適用。

但遠端命令是另一回事。Wine 把 Linux 家目錄與 `/` 映射成磁碟機（至少 `Z:`），也把環境變數傳進遊戲。`exec`／`ls`／`cat`／`download` 能讀你這個 Linux 使用者能讀的一切：`~/.ssh`、瀏覽器 profile、帶 API 金鑰的 shell 設定、密碼庫、文件。把家目錄與環境裡的秘密都當成已曝險。

SteamOS 的 `/etc` 預設唯讀，改 hosts 可能失敗；nftables 由 root 直接操作核心，不受 `/etc` overlay 影響。

---

## 如何自行檢查

1. 打開 NIKKE 安裝目錄，用文字編輯器開啟 `Launcher/intl_service/debug.log`，搜尋 `k2f_chan`。找到就表示 agent 跑過，即使後面沒有 `adopted`／`resuming`。
2. 看 `Launcher/log/tinyget/tinyget.*.log` 是否下載過 `analytics.insightjs.com/comm/assets/insight.bundle`。
3. 在 `%APPDATA%\nikke_launcher\tbs_cache\Code Cache\js\` 找上列四個 cache key；在 `tbs_cache\Cache\data_*` 找 `insightjs`。
4. 在 `%APPDATA%\nikke_launcher\tbs_cache\Local Storage\leveldb\` 搜 `k2f.agent`。
5. Windows：檢查 `PlatformExperienceHelper\<64-hex>\platform_experience_helper.dll` 與 HKCU CLSID（不要動 HKLM）。
6. DNS／路由器日誌：查到 `insightjs.com` 代表 loader 跑過；`analytics.insightjs.com` 多半已到 agent 階段。沒查到不能排除。

K2F PURGE 把以上檢查編成規則，判定四級：

| 判定 | 意義 |
|---|---|
| `CONFIRMED` | agent 確實執行過（`k2f_chan registered`、`k2f.agent.state`、惡意 DLL、HKCU CLSID） |
| `LIKELY` | loader 執行過，未見 agent 落地 |
| `INCONCLUSIVE` | 找不到 launcher，或日誌已輪替／資料夾已刪 |
| `CLEAR_OF_LISTED_IOCS` | 已完整掃描且未命中內建規則。**不是「安全」** |

---

## 如何處置

### 所有人

1. 官方確認修復前不要開啟 launcher。
2. 再開之前刪掉 `%APPDATA%\nikke_launcher\tbs_cache`（Proton 則在 prefix 內）。
3. 封鎖：
   - 網域：`insightjs.com`、`www.insightjs.com`、`analytics.insightjs.com`、`insightjs.org`、`www.insightjs.org`
   - IP：`89.127.233.127`、`89.126.250.172`  
   這只能擋住**目前**這組基礎設施。CDN 寫入權來源不明，攻擊者以後可能換網域再來。

### 已確認感染

1. 關掉 launcher，或斷網，讓攻擊者失去通道。
2. Windows 持久化：
   - 刪 `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}`（先匯出 `.reg`）。**不要動 HKLM。**
   - 重開機（DLL 載入中會鎖檔）。
   - 空 default 的 HKCU 鍵也要刪。
   - 只刪 `PlatformExperienceHelper\` 下「64-hex 子資料夾且內含 DLL」。**不要刪整個父資料夾。**
3. 用**乾淨裝置**改密碼：遊戲帳號（Level Infinite）→ 電子郵件 → Discord → 銀行 → 瀏覽器已存密碼。開 2FA。
4. 登出所有工作階段（Discord、Google、Steam、GitHub…）。Cookie 不需要密碼就能用。
5. 撤銷並重新產生 API token、SSH 金鑰、雲端與開發者憑證。
6. 加密錢包資金轉到**新種子**的新錢包。
7. 最穩是重裝作業系統。

---

## 本工具會自動做什麼、不能做什麼

K2F PURGE 在本機、離線完成：

| 會做 | 不會做 |
|---|---|
| 掃描已知 launcher／Wine prefix／Chrome helper 路徑 | 不連網、無遙測、無崩潰回報、無自動更新 |
| 依內建 IOC 判定四級並附證據（路徑、規則、遮罩片段 ≤160 字、雜湊、時間） | 不讀取憑證或錢包內容 |
| hosts + 防火牆封鎖 3 個網域與 2 個 IP，可解除、可驗證 | 不改 HKLM、不刪 `PlatformExperienceHelper` 父資料夾 |
| 先 dry-run 再隔離到可還原的 quarantine；永久刪除需確認 | 不代為改密碼、撤銷 token、動加密錢包 |
| 對 `target-paths.md` 的 250+16+17+7 條路徑做 **Lstat 存在檢查** | 不做 SRUM／流量鑑識（報告裡只提示你可以自己做） |
| 匯出本機 Markdown／JSON 報告 | 不開啟外部連結、不執行 JS、無 WebView |

Windows 未提權時會以 `runas` 重啟；拒絕 UAC 則進入受限模式（掃描、曝險、報告仍可用）。Linux／macOS 採按需提權（`pkexec`／`osascript`），不把整個 GUI 用 root 重開。

---

## 限制與已知陷阱

1. 只確認「本報告列出的 IOC」。IOC 變種、未公開的 build、已被 `payload_cleanup` 清掉的檔，都可能漏報。
2. 找不到 launcher → `INCONCLUSIVE`，不是安全。
3. `PlatformExperienceHelper` 父資料夾是 Chrome 正常元件。
4. HKLM 同名 CLSID = `wpc.dll`，禁止觸碰。
5. `FETCH_LIST suc success` 不是感染跡象。
6. `collect_cookies: false` 不代表 cookie 安全。
7. `startup already in progress` 不可靠。
8. `onominan.tmp` 不是 IOC。
9. `FeedList.feb647c9.js` 的惡意碼在 `export{...}` 之前。
10. 日誌只回答「有沒有跑過」；不能回答「攻擊者做了什麼」。
11. Linux／macOS 以交叉編譯與單元測試覆蓋，本文件撰寫時未在那些平台做實機 GUI 驗證。
12. SteamOS `/etc` 唯讀時，hosts 可能無法寫入；應改用 nftables（本次開機有效）或自行處理。

---

## 給 Level Infinite 的重點（轉述來源）

- 四個被改檔的 `last-modified` 是 2026-09-27 06:41–06:42 GMT。三個已於 11-03 替換；`FeedList.feb647c9.js` 必須在**每一台** CDN 伺服器 purge，不能只查解析器回傳的那一台。
- 09-27 之後開過 launcher 的玩家，`tbs_cache` 裡可能還有舊檔，下次更新應強制清快取。
- 攻擊者擁有 CDN bucket 或發布管線的寫入權。這條路不堵上，換一個網域就能再投一次。
- 同一 bucket 的其他檔也應與 build 產物核對。

來源分析是靜態完成的，payload 未曾在分析環境執行。留言區無法在此核對的發現已標為「回報」。
