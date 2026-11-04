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
| `PHOTO_STORAGE_LIMIT_BYTES` | 選填，預設 `209715200`（200 MiB），限制巡檢壓縮照片總量 |

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
