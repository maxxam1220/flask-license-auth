# 授權服務緊急修正與上線順序

這個分支尚未部署。Render 追蹤 main，合併 main 會自動部署。必須先完成下列設定與管理客戶端更新；不可先合併再處理金鑰。

## 新的權限分工

API 接受 `Authorization: Bearer <key>` 或 `X-API-KEY: <key>`。金鑰應由安全管道配置到受信任的管理／備份電腦，不得寫進 Git、打包給一般使用者或放進 URL。

| 環境變數 | 可用功能 |
| --- | --- |
| `ADMIN_API_KEY` | 帳號清單與管理、角色／模組寫入、授權清單／修改／刪除／解除綁定、踢除連線及修改線上限制 |
| `BACKUP_READ_API_KEY` | `/export_licenses`、`/export_auth_backup`、`/export_barcode53_backup` |
| `BACKUP_RESTORE_API_KEY` | 所有授權／條碼備份匯入、條碼紀錄清空與逐批還原 |

三組金鑰必須不同、各至少 32 字元，且不得與一般客戶端 `SESSIONS_API_KEY` 相同。請使用密碼管理器產生至少 32 隨機位元組的新金鑰。已公開的舊 token 不再接受，沒有相容舊 token 的過渡開關。

未設定某組管理金鑰時，該組 API 回 503；錯誤或缺少請求憑證回 401。不得將管理金鑰直接替换進一般客戶端使用的共用 session／audit key。

## 保留的正常流程

- `/check_account`、`/check_license` 的 URL、要求欄位與回傳格式不變。
- RBAC GET 繼續提供客戶端讀取角色／模組 tab mapping；寫入需要管理金鑰。
- 一般 heartbeat/start/end/online/config GET 仍使用原本 `SESSIONS_API_KEY`。未設定時改為拒絕，不再匿名放行。
- **已知未修範圍：** 一般 `/api/sessions/end` 仍依共用 session key 與 session_id 結束連線，而 online 會列出 session_id。持有一般 key 的客戶端仍可能結束別人的連線。因此 `/kick` 需要管理金鑰不等於已完成連線所有權驗證；後續應讓 start/heartbeat/end 使用與帳號綁定的專屬憑證，配合全部客戶端升級。這次保留生命周期協定，避免一般登入端突然失聯。
- Google Sheets 上傳仍使用原本 `GSHEET_UPLOAD_API_KEY`。未設定時改為拒絕。
- 瀏覽器 session 登入仍用 `ADMIN_USER`、`ADMIN_PASS`，但沒有程式內預設密碼。管理 JSON API 不因瀏覽器 cookie 而放行。
- `FLASK_SECRET_KEY` 必須是至少 32 字元的私密隨機值，未設定／太短則拒絕啟動。更新後舊瀏覽器登入 cookie 會失效，需重新登入。
- 登入表單與登入紀錄清除加入 CSRF；cookie 設定 Secure、HttpOnly、SameSite=Lax。正式網站使用 HTTPS；本地測試可用 Flask test_client。

## 還原防呆

- 先驗證 JSON、完整資料集、欄位、型別、日期、重複主鍵及 bindings 參照，再進行還原交易。
- 完整授權還原需要 licenses、bindings、accounts、rbac_tabs、rbac_modules 全部存在；bindings 可空，其他表必須有資料。若確實要清空某表，需另行設計明確操作，不能用空備份兼作刪除。
- 接受現有匯出格式及舊 role/module 欄位別名，不強迫先重新備份；資料有負數剩餘次數或不完整列時會拒絕，應先調查來源。
- 條碼完整還原需包含 BcMst、BcDtl、BcLog、Barcode 四組，不能只有 BcLog 或全部為空。沒有相容欄位的列會讓交易回滾，不能略過後回報成功。
- `/import_barcode53_bclog_reset` 額外需要 JSON `{"confirm":"reset_bclog"}`，不接受空白要求。
- 條碼紀錄仍依原設計分批還原；本次沒有將它改成跨批次原子還原，這項後續風險仍存在。

## 上線順序與中斷保護

1. 保留目前 live 部署 commit ID 與一份已驗證可用的完整資料庫／授權備份。不要將備份加進公開儲存庫。
2. 在受信任管理電腦準備客戶端修補版，將新增三組金鑰分別安全配置；一般登入電腦不應取得它們。舊 EXE 不會自動套用 Python 原始碼補丁，需要重新打包／分發。
3. 確認現有 `FLASK_SECRET_KEY`、`ADMIN_PASS`、`SESSIONS_API_KEY`、`GSHEET_UPLOAD_API_KEY` 有效。使用缺少依賴的功能之前補齊設定。變更 Render 環境變數可能觸發部署，應在切換窗口統一執行。
4. 同步準備 Render 的三組新金鑰及更新的管理客戶端，再合併此分支並等待 live。不要把舊公開 token 填回新變數。
5. 驗收一般帳號登入、授權檢查、心跳、管理頁讀取、新金鑰匯出，以及「錯金鑰／空備份被拒絕」。破壞性還原僅在獨立測試資料庫演練。
6. 若部署／驗收失败，優先修正配置或隔離管理入口；回退舊版本會重新暴露已知漏洞，不應當作長期方案。這次無 schema migration，程式碼回退本身不需要還原資料表。

每一階段都有獨立檔案與 Git commit；用量中斷時，未合併分支不影響正式主機。程式修改完成不代表公開金鑰已在正式環境撤銷：只有新版本部署與客戶端切換完成才算完成線上輪替。

## 離線驗證

在儲存庫根目錄，安裝現有 requirements 後執行：

```powershell
python -B -m unittest discover -s tests -v
```

測試封鎖網路、替換啟動 migration 與資料庫。涵蓋匿名拒絕、權限分離、別名路由、正確管理寫入、完整還原、空白還原拒絕、失敗回滾與 CSRF。這不是正式 PostgreSQL／Render 整合驗收。
