# Render monorepo 部署欄位

此配置新增獨立巡檢服務，使用既有儲存庫中的 `patrol/` 子目錄。現有授權服務的程式、Render 設定及 `main` 分支保持原有用途。

| Dashboard 欄位 | 值 |
| --- | --- |
| Service Type | Web Service |
| Repository | `https://github.com/maxxam1220/flask-license-auth` |
| Branch | `patrol-v1` |
| Name | `patrol-checkin-v1`（若名稱被占用，確認新名稱與實際網址後同步設定） |
| Language / Runtime | Python 3 |
| Region | Singapore |
| Root Directory | `patrol` |
| Compute Plan | Free（試用；會休眠） |
| Build Command | `pip install -r requirements.txt` |
| Health Check Path | `/healthz` |
| Auto-Deploy | Off |
| Blueprint Path（若使用 Blueprint） | `patrol/render.yaml` |

Start Command：

```sh
python -m flask --app app init-db && python -m flask --app app bootstrap-admin && exec waitress-serve --host=0.0.0.0 --port=$PORT --trusted-proxy='*' --trusted-proxy-count=1 --trusted-proxy-headers='x-forwarded-for x-forwarded-proto' app:application
```

Root Directory 會影響命令的工作目錄；不要把命令改成 `pip install -r patrol/requirements.txt` 或 `patrol.app:application`。Python 版本檔 `.python-version` 也須隨本站放進 `patrol/`，內容為 `3.12`，讓 Render 使用該系列的修補版本。

## 環境變數

| 名稱 | 值／來源 |
| --- | --- |
| `APP_ENV` | `production` |
| `DEMO_MODE` | `false` |
| `SECRET_KEY` | 此服務專用的至少 32 字元隨機密鑰；Blueprint 使用 `generateValue: true`，直接建立服務時需另行安全產生 |
| `DATABASE_URL` | 既有 `DB_0801`，ID `dpg-d9mnbfp42hec73e3hd6g-a` 的實際 Internal Database URL |
| `INITIAL_ADMIN_USERNAME` | `admin` |
| `INITIAL_ADMIN_PASSWORD_HASH` | 首次管理員密碼的 scrypt 雜湊；從受控記憶體安全填入，不是明文密碼 |
| `PUBLIC_BASE_URL` | 選填；預設使用平台的 `RENDER_EXTERNAL_URL`。自訂網域時才設定 HTTPS 根網址，無 `/login`、`/patrol`、查詢參數或片段 |
| `IMPORT_SAFETY_POINTS` | 此次升級設為 `1`，一次性匯入 42 個職安點位；完成標記存於資料庫，後續重啟不覆寫 |
| `PHOTO_STORAGE_LIMIT_BYTES` | 選填，預設 `209715200`（200 MiB），原始巡檢及結案照片共用此總量限制 |

不要把憑證值寫進此文件、Git、工單或指令列。使用 Render Environment 設定保存。不要自行設定或猜測 `RENDER_EXTERNAL_URL`，平台會注入此值。網站建立後，核對 QR Code 目的網址與 Dashboard 顯示的實際網址完全一致；正式列印 QR Code 前完成此檢查。

巡檢服務與資料庫須在同一工作區、同一地區，且沒有禁止兩者通訊的環境隔離。Free Web Service 可以主動連線到私有資料庫，但不能接收私有網路入站連線。

## 初始化與驗證

啟動命令以 `migrations.py` 對 `patrol_` 資料表執行交易式版本升級，不會新增示範帳號或示範紀錄。版本 2 加入分類、早晚時段、備註、異常標記與照片表；版本 3 只新增異常案件與處理歷程兩表，將舊異常紀錄補為未結案，不修改原始回報、既有 ID、QR 與密碼。資料庫帳號需具備建立及調整這些表與索引的必要權限。升級前先建立 Render 邏輯匯出備份，確認完成後部署；若需回復單一應用，只還原巡檢相關資料表，不能覆蓋同庫授權應用。`IMPORT_SAFETY_POINTS=1` 時升級後匯入使用者提供的清單，遇到衝突整批中止。

接著 `bootstrap-admin` 僅在 `patrol_users` 尚無任何管理員時，使用環境中的初始帳號及 scrypt 雜湊建立正式管理員，並要求首次登入變更密碼。只要已有管理員，即使停用或密碼已變更，也不能藉此命令重設帳號。重部署不會覆寫既有管理員。

版本 4 在 `patrol_point_schedules` 增加可空的樓層、點位編號與名稱快照，舊排程以目前已知點位設定回填，不修改已完成巡檢、異常處理、照片與 QR。舊工作程序在部署交接期間插入的空值仍可讀取，新版在編輯前會凍結空值為編輯前設定，避免後續搬移改寫已知歷史。確認頁新增頻率檢查；部署前已開啟的舊表單可能要求重新確認並重選照片。

版本 5 增加巡檢員分類及點位刪除時間，既有紀錄與 QR 不變。升級後在人員管理逐一核對並指定巡檢員所屬分類；未指派者不能巡檢，管理員仍可查看全部。不要依姓名猜測分類或變更既有管理員權限。

版本 6 只新增巡檢工作階段撤銷表及索引。部署前已登入的人員可繼續操作；登出會撤銷該次登入，其他瀏覽器的獨立登入仍有效。舊版啟動程式會拒絕較新的資料版本。若需修正此版，應部署保留版本 6 及撤銷檢查的修正版，不要刪除撤銷表或調低版本號。

首次明文密碼由部署者在本機安全產生與保存，再交付使用者；Render 只接收雜湊，不接收明文。資料庫連線字串留在 Render，本流程不需要把外部 DB URL 帶到本機。成功初始化並確認管理員可用後，可移除 `INITIAL_ADMIN_PASSWORD_HASH`，因既有管理員會讓後續初始化直接跳過。

部署後驗證 `/healthz` 回應成功、登入頁能開啟、管理員登入、真實員工帳號建立、手機綁定核准、掃描一個真實點位的 QR Code、提交一次及重複提交不新增紀錄。`/healthz` 會對資料庫執行 `SELECT 1`，但成功不表示已有管理員或現場點位設定完成。

## 執行環境注意事項

- Waitress 接收 Render 負載平衡器轉送的 HTTP；正式用戶端仍使用 HTTPS，認證 Cookie 為 Secure。啟動命令只信任最後一層代理的來源 IP／協定資訊。
- `--trusted-proxy='*'` 僅適用於此處由 Render 代理保護的配置，不應複製到直接對外公開 Waitress 連接埠的主機。
- SQLAlchemy 使用連線池與 `pool_pre_ping`；此服務會與既有應用共享資料庫容量及連線額度，正式運作後需觀察使用量。
- `/healthz` 或登入失敗時先查新服務日誌、環境變數是否完整、Root Directory／Branch、資料庫權限與網路；不要更改既有授權服務來修復新服務。
- 後續 push 仍保持在 `patrol-v1`。此新服務設定關閉自動部署，完成驗證後手動部署指定提交；不要為了更新巡檢服務直接合併至 `main`。

參考：[Render monorepo](https://render.com/docs/monorepo-support)、[Web Service](https://render.com/docs/web-services)、[Private Network](https://render.com/docs/private-network)、[Waitress 反向代理](https://docs.pylonsproject.org/projects/waitress/en/stable/reverse-proxy.html)。

版本 7 新增總務點位打卡方式、執行紀錄與巡檢配對，舊總務排程留歷史快照，生效後預設抽查。部署前確認資料庫匯出已完成，盡量選總務無人送單時段；部署後再設定兩段式設備與執行人員。若需修正，部署支援版本 7 的修正版，不降版或覆蓋共用授權資料庫。

版本 8 支援每月與不定期排程、總務同一時段多人巡檢與個人日上限。正式總務清冊由服務私有的 GENERAL_PATROL_CATALOG_JSON 提供，各筆與授權清冊摘要核對後才匯入。啟動紀錄可核對新增、既有與是否已匯入的數量。資料表升級前應完成資料庫備份，修正部署請使用支援版本 8 的程式。

版本 9 在巡檢紀錄新增執行人員直接簽到標記。既有紀錄保留原類型。授權範圍取自已驗證的私有清冊，只有指定的 7 個總務不定期點開放直接簽到。

版本 10 只在巡檢人員表新增總務管理員職稱標記，預設關閉；舊帳號、綁定與歷史打卡保留。部署前確認可還原的資料庫備份。部署後由系統管理員到「人員管理 → 帳號設定」指派職稱；如需修正版，請使用可讀取版本 10 的程式。

版本 11 新增巡檢成功登入事件表及時間、帳號索引，從啟用後開始記錄，不變更其他應用的資料。部署前確認資料庫匯出完成；啟動後以系統管理員檢查「人員管理」下方的「登入紀錄」。後續修正請使用支援版本 11 的程式。

版本 14 在 `patrol_users` 新增 `ui_language`（預設 `zh-Hant`）與 `simple_executor_ui`（預設關閉）。只新增欄位，不重寫巡檢、綁定、密碼或離線紀錄；切換語言及簡易介面不撤銷既有登入或暫存授權。升級前確認備份完成。部署後由管理員替指定帳號選擇語言及「僅今日待簽到」，不要依姓名自動指派；只有執行人員會啟用簡易導覽。後續修正須使用支援 schema 14 的程式，不能用舊程式降版啟動。

版本 15 在 `patrol_points` 增加 `inspection_team`（預設 general）、`pending_frequency` 與 `frequency_effective_date`；資料表升級不改派任何點位。備份完成並確認新版上線後，由系統管理員至 `/admin/points/revision-20261109` 核對 15 點方案，再套用：11 點工務分流立即生效，10 點頻率於 2026/11/10 台北時間零時起啟用。新排程與一次性標記同一交易提交，原 QR、Inspection、PatrolExecution 不改寫。到期啟用在工作請求前完成；若設定不一致，打卡停止但管理及診斷頁保留。後續修正版必須支援 schema 15，不得降版本或還原整個共用資料庫。頻率變更前未同步的舊設定暫存會被拒絕而保留，現場需先同步並重新準備。

版本 16 只新增 `patrol_issue_event_photos`，每張處理後照片歸屬不可覆寫的結案事件，既有巡檢、結案歷程與 QR 不變。升級前完成 Render 邏輯匯出；總務管理員獲得總務及工務案件結案權，職安與重新開案權限維持原規則。所有照片寫入共用原照片配額及 PostgreSQL advisory lock。XLSX 含照片匯出新增 openpyxl 依賴，單次限 100 件／500 張／原圖 50 MiB，並在載入照片前序列化匯出工作。部署後以唯讀方式驗證總覽提醒、異常匯出、照片存取與 schema 16；不要建立測試結案或覆寫共用資料庫。後續修正版須支援 schema 16，不可直接降版啟動。
