# 標籤核對網頁第一版

手機拍照或相簿上傳 → 中文 OCR 全文掃描 → 對應既有系統標籤、逐行與日期規則核對。
本專案位於 `C:\build\barcode53_phase1\label_web`，與原有 PyQt 桌面程式分開啟動。

## 已實作

- 標準照片上傳、辨識原文、人工修正與核准。
- 「掃描標籤」以 HTTPS 網頁開啟後鏡頭，按下拍攝後辨識；不支援時可改用手機拍照或選照片。
- 不需要正確照片即可直接掃描。依完全對應的品名、貨號等找出 `db_0801` 的同一款標籤；多款或無法對應時可自行選擇，近似品名僅供建議，不會自動選用。每次核對唯讀取得最新內容，並保留來源版本快照。
- 結果逐行顯示「✓ 相符／✕ 有差異／？待確認／· 僅辨識」，異常置前，同一 OCR 行不重複列出。公司、地址等有錯字、多字或漏字會標示差異；沒有比對依據不判相符。
- 每行 OCR 文字都有對應的檢查或辨識列；日期檢查仍涵蓋合法性、先後及指定本批日期。
- 系統標籤比對容許繁簡、台／臺、全半形、空白及 kg／KG 等格式差異，電話標題可辨識為同一欄位；數字、溫度正負號與字元增刪不會自動修正。保留 OCR 原文、正規化說明與差異證據。
- 可搜尋既有系統標籤，帶入品名、規格、保存條件、產地、公司名稱、地址及電話，人工核准後成為無照片的文字標準。
- 首頁及直接掃描不再使用寫死的四項公司文字；比對文字來自該款系統標籤。既有人工核准照片標準仍保留原有嚴格核對方式，歷史紀錄不改寫。
- 支援右下角未加「公司／地址／電話」前綴的廠商資訊，以文字內容及版面位置定位；候選不確定時要求複核。
- 製造日／有效日格式、先後順序、選填的保存天數與本批製造日。
- 到店日可獨立啟用，檢查日期合法性並與選填的「本批到店日」核對；標準照片的到店日只供建立標準確認，不固定沿用到日後批次。未指定本批到店日不能確認日期是否符合該批作業。
- 系統比對只在辨識分數至少 0.65、候選唯一且內容正規化後相符時顯示勾選；分數並非正確率。極低信心、漏讀或候選不唯一需複核，保留完整照片證據。
- 本批基準日預設台灣當天，可調整檢查歷史標籤。依系統日期格式、位移及有效保存天數核對日期；Barcode.SaveDays 有設定時優先，否則用 BcMst.KeepDays（0 也是有效值）。日期違反日曆、日期先後、來源期望日期或基準年份時會標示，短格式不補出照片未印的年份。
- 「重新核對」使用原 OCR 文字與最新來源／日期設定產生新紀錄，不重新上傳照片、不覆寫原判定；原 OCR 讀錯時仍需重新拍照。
- 原圖框選證據、逐字差異、歷史查詢與獨立人工複核紀錄。
- 標準版本不可覆寫；建立新版時保留舊版和當時檢查快照。
- 照片格式 JPG / PNG / WebP / HEIC，EXIF 方向修正、最大 15 MB / 3,200 萬像素。
- 單一辨識工作執行、最多 12 個待處理工作、重啟時將未完成工作標為失敗。
- 每張照片使用獨立 OCR 程序，完成或逾時後釋放模型記憶體；文字辨識批次為 1，使用 PP-OCRv6 small 偵測＋medium 文字模型。繁忙時上傳會立即提示稍後重試，避免占滿網頁連線。
- Linux 辨識程序會提早釋放大型配置，並監測程序及服務的記憶體預算；超量會停止該張辨識、保留照片並提示重試，不接受部分辨識結果。監測是提早停止機制，並非核心層的獨立記憶體隔離，仍須以實際掃描驗證。
- 每張辨識前及工作結束後回收網頁程序的閒置 heap。只有服務總記憶體超限時，才在回收後用同張照片與同模型自動重試一次，總逾時不延長；程序自身超限或監測不可用仍停止。失敗照片可由「未完成的辨識」直接重新辨識，沿用原日期與比對設定，保留原失敗紀錄並產生新工作。
- 無版面的清單另存 `labelcheck_catalog`，對外代碼使用 `list:`，只核對清單已知品名、原條碼與照片印出的保存天數。沒有版面與日期位移時，不推造排程或其他印字。
- 同名來源以條碼、規格、產地及其他完整文字消歧；未知欄位不當成不相符。清單的品名、條碼、保存天數與類型完全一致時可共用等價依據，仍保留來源編號。
- 即時相機支援時使用原生靜態照片，備援保留完整影片畫面尺寸；小圖採受限放大以改善細字。v6 字典支援 `※`，但實測仍容易在整句漏讀；遇到單獨此符號差異時提示人工確認，不自動補字。

OCR 並非零錯誤保證。模型信心分數不是經校準的正確率，清楚、完整且無反光的標籤仍需現場樣本驗收。
本版會列出辨識到的全部文字；成分、營養標示等沒有標準的內容僅供閱讀，不能確認無錯字。尚未實作條碼圖形解碼。

## 本機啟動

```powershell
cd C:\build\barcode53_phase1\label_web
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.\Start-LabelWeb.ps1
```

開啟 http://127.0.0.1:5083/ 。第一次辨識會下載 PP-OCRv6 模型到 `models/`；後續辨識不傳送照片給外部 OCR 服務。
選用標準庫可保持空白，直接掃描會對應原系統標籤；未連接資料庫時仍提供文字及日期檢查。也可上傳正確照片建立特定標準；不會把 QA 樣本當作正式標準。

預設資料庫為 `data/labelcheck.sqlite3`，照片在 `data/images/`。原圖另保留於每張圖片的 `original` 檔案，介面展示去除 EXIF 的標準化 JPEG。
不要刪除 `data/`。備份時需同時保存資料庫與照片。

## 共用既有 PostgreSQL

已核對目標為 Render **My Workspace → DB_0801 / db_0801 / Singapore**。

本機要開始將真實建檔資料存入既有資料庫，可先停止本機服務，再執行：

```powershell
.\Start-LabelWeb.ps1 -UseExistingDatabase
```

此參數從父目錄 `config.ini` 在記憶體讀取既有連線，不複製密碼到網頁原始碼。
首次啟動會新增以下獨立資料表，**不會搬移本機 SQLite 已有資料**：

- `labelcheck_images`
- `labelcheck_templates`
- `labelcheck_jobs`
- `labelcheck_inspections`
- `labelcheck_reviews`
- `labelcheck_catalog`

唯讀查詢原有 `barcode53.BcMst / BcDtl`，不修改原標籤資料。匯入時排除不顯示欄位，日期設定及位移只供參考；若來源已變更，核准會要求重新匯入。未連接或遷移正式 DB 的測試不能視為正式資料庫驗證。
只共用資料庫時，照片仍位於執行網頁的主機；搬到 Render 前須一起遷移圖片，不能只切換連線。

## 手機同網路試用

先透過環境變數設定至少 8 字元的 `LABELCHECK_PASSWORD`，再執行：

```powershell
.\Start-LabelWeb.ps1 -AllowLan
```

手機與電腦需在同一個區域網路，使用 `http://電腦區域網路IP:5083/`；Windows 防火牆是否允許連入需由現場確認。
本機 `127.0.0.1` 網址無法供另一支手機存取。即時相機需要 HTTPS 或 localhost；一般區網 HTTP 會使用手機檔案拍攝功能，相簿上傳作為相容方式。
外網使用應以 Render 的 HTTPS 網址提供；不能把開發服務直接公開。

## Render 部署

正式網址：https://fuhe-label-check-tgv3.onrender.com/

- 服務：`srv-dbq1mi49v7es73c98v5g`（My Workspace，Singapore）。
- Blueprint：`exs-dbq1luon74is739euef0`；已依使用者確認建立網頁服務與 5 GB 持久磁碟。
- 程式庫：`maxxam1220/flask-license-auth`，獨立分支 `label-check-v1`，設定檔 `label_web/render.yaml`。
- 登入密碼：到 https://dashboard.render.com/web/srv-dbq1mi49v7es73c98v5g/env 複製 `LABELCHECK_PASSWORD` 的值。
- 不要將登入密碼、資料庫連線字串或 session secret 寫入本文件。

新建獨立 Python Web Service，區域選 Singapore，共用 DB_0801，**不新建第二個資料庫**。
部署設定見 `render.yaml`。獨立分支 `label-check-v1`、來源子目錄 `label_web`，不修改其他應用程式的正式分支。

- Root Directory：若整個標籤專案入庫則為 `label_web`；若只入庫網頁子目錄則留空。
- Build：`pip install -r requirements.txt && python prepare_models.py`（建置時下載並驗證模型）
- Start：`python run.py`
- Health：`/healthz`
- 用 `.env.example` 的鍵設定環境變數；`LABELCHECK_DATABASE_URL` 使用 DB_0801 的 Internal URL。
- 照片需要持久儲存。第一版檔案介面可使用掛載 `/var/data` 的 Render Persistent Disk；一般服務目錄重啟會遺失資料。
- 第一版只執行 **一個** 程式實例。多實例或大量照片階段應遷移到 R2/S3 物件儲存和外部工作佇列。
- 建議起始配置：0.5 CPU / 512 MB Web Service 與 5 GB Persistent Disk，依 2026-11-11 官方價格每月新增約 US$8.25，未含額外流量及既有資料庫費用；須以 Render 實際計價為準。
- Render 產生登入密碼及 session secret；登入密碼在服務的 Environment 頁面 `LABELCHECK_PASSWORD` 查看，勿放入原始碼或照片。
- 照片（含原始檔）放 `/var/data/labelcheck/images/`；DB_0801 只保存照片索引、標準、OCR 原文與核對紀錄。需同時備份 DB 與持久磁碟。
- OCR 模型以實際記憶體及延遲測量選擇方案；目前採單實例逐張辨識，不能假設高併發時仍有相同效能。
- 尚未提供照片保留期、自動清理、外部備份與大量上傳功能。

## 驗證

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
node --check static\app.js
.venv\Scripts\python.exe tests\real_ocr_check.py
```

單元/API 測試使用注入的辨識結果，涵蓋錯字、門牌數字、日期、低信心、版本快照、覆核及存取保護。
`real_ocr_check.py` 使用實際模型辨識合成測試標籤與使用者提供的錯誤照片，產物僅在 `qa/`，不接正式資料庫。
合成標籤標有「網頁測試用・不是正式商品標籤」。QA 的假地址不得作為正式標準。

模型與相依套件依各自授權使用：
- RapidOCR：https://github.com/RapidAI/RapidOCR
- PP-OCRv6：https://github.com/PaddlePaddle/PaddleOCR
- 繁體閱讀顯示（OpenCC）：https://github.com/yichen0831/opencc-python

