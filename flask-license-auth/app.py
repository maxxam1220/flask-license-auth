from flask import Flask, request, jsonify, render_template, redirect, session, render_template_string
import psycopg2, os, json, base64, hmac, hashlib
from psycopg2.extras import RealDictCursor, Json
from datetime import datetime, timezone, date
from urllib.parse import urlencode
from zoneinfo import ZoneInfo
from migrations import ensure_audit_login_table

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")  # ✅ 改用環境變數

# ✅ 登入帳密
USERNAME = os.getenv("ADMIN_USER", "admin")
PASSWORD = os.getenv("ADMIN_PASS", "Aa721220")

# ✅ 給外部 ping 的 health token（可選，沒設就不檢查）
PING_TOKEN = os.getenv("invimb-health-721220-9Dx2fP0")  # 不設的話 = None

# ✅ PostgreSQL 連線字串（補上 sslmode=require）
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL 未設定")
if "sslmode=" not in DATABASE_URL:
    DATABASE_URL += ("&" if "?" in DATABASE_URL else "?") + "sslmode=require"

def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
# === 密碼雜湊 / 驗證 & 到期日解碼（跟 auth_accounts.py 保持一致） ===
# ⚠️ 這個 KEY 一定要跟 auth_accounts.py 一樣
SIGN_KEY = b"invimb-accounts-signature-key-v1"

def _row_to_jsonable(row: dict) -> dict:
    """把 DB 回來的 dict 中的 date/datetime 轉成 ISO 字串，其他原樣丟回。"""
    out = {}
    for k, v in row.items():
        if isinstance(v, (datetime, date)):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out
# -----------------------------
# ① 讀取所有帳號（給 PermissionAdminTab 顯示用）
# -----------------------------
@app.get("/accounts")
def api_list_accounts():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT
                    username,
                    role,
                    module,
                    active,
                    expires_enc
                FROM accounts
                ORDER BY username
            """)
            rows = cur.fetchall()

        accounts = []
        for row in rows:
            accounts.append({
                "username": row["username"],
                "role": row["role"],
                "module": row["module"],
                "active": row["active"],
                # 前端只看到「解碼後」的 YYYY-MM-DD
                "expires_at": _decode_expiry(row.get("expires_enc")) or None,
            })

        return jsonify({"ok": True, "accounts": accounts})
    except Exception as e:
        return jsonify({"ok": False, "message": f"讀取帳號失敗：{e}"}), 500
# -----------------------------
# ② 新增帳號（PermissionAdminTab.on_add_account）
# -----------------------------
@app.post("/accounts")
def api_add_account():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role     = (data.get("role") or "").strip() or "admin"
    module   = (data.get("module") or "").strip() or "admin"
    active   = bool(data.get("active", True))
    expires_at = data.get("expires_at")  # 前端送來的是 YYYY-MM-DD 或 None

    if not username or not password:
        return jsonify({"ok": False, "message": "username / password 不可空白"}), 400

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM accounts WHERE username = %s", (username,))
            if cur.fetchone():
                return jsonify({"ok": False, "message": "帳號已存在"}), 400

            # ✅ 用本檔案裡的 hash_password（你已經在下面定義）
            pwd_hash = hash_password(password)
            expires_enc = _encode_expiry(expires_at)

            cur.execute("""
                INSERT INTO accounts (username, password_hash, role, module, active, expires_enc)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (username, pwd_hash, role, module, active, expires_enc))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "message": f"新增帳號失敗：{e}"}), 500
# -----------------------------
# ③ 刪除帳號（PermissionAdminTab.on_delete_account）
# -----------------------------
@app.post("/accounts/delete")
def api_delete_account():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()

    if not username:
        return jsonify({"ok": False, "message": "缺少 username"}), 400
    if username == "admin":
        return jsonify({"ok": False, "message": "admin 不允許刪除"}), 400

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM accounts WHERE username = %s", (username,))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "message": f"刪除帳號失敗：{e}"}), 500
# -----------------------------
# ④ 重設密碼（PermissionAdminTab.on_reset_password）
# -----------------------------
@app.post("/accounts/reset_password")
def api_reset_password():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    new_password = data.get("new_password") or ""

    if not username or not new_password:
        return jsonify({"ok": False, "message": "缺少 username 或 new_password"}), 400

    try:
        pwd_hash = hash_password(new_password)

        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                UPDATE accounts
                SET password_hash = %s
                WHERE username = %s
            """, (pwd_hash, username))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "message": f"重設密碼失敗：{e}"}), 500
# -----------------------------
# ⑤ 批次更新帳號 meta（role/module/expires_at/active）
#     PermissionAdminTab.on_save_accounts()
# -----------------------------
@app.post("/accounts/update_meta")
def api_update_accounts_meta():
    data = request.get_json(silent=True) or {}
    accounts = data.get("accounts") or []
    if not isinstance(accounts, list):
        return jsonify({"ok": False, "message": "accounts 必須是 list"}), 400

    try:
        with get_conn() as conn, conn.cursor() as cur:
            for row in accounts:
                username = (row.get("username") or "").strip()
                if not username:
                    continue
                role     = (row.get("role") or "").strip()
                module   = (row.get("module") or "").strip()
                active   = bool(row.get("active", True))
                expires_at = row.get("expires_at")  # 前端傳來的
                expires_enc = _encode_expiry(expires_at)

                cur.execute("""
                    UPDATE accounts
                    SET role = %s, module = %s, active = %s, expires_enc = %s
                    WHERE username = %s
                """, (role, module, active, expires_enc, username))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "message": f"更新帳號設定失敗：{e}"}), 500

SIGN_KEY = b"invimb-accounts-signature-key-v1"

def _decode_expiry(token: str | None) -> str | None:
    if not token:
        return None
    try:
        ob = base64.b64decode(token.encode("ascii"))
        key = SIGN_KEY
        raw = bytes(b ^ key[i % len(key)] for i, b in enumerate(ob))
        s = raw.decode("utf-8")
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            return s
    except Exception:
        pass
    return None

import os, base64, hashlib, hmac
def hash_password(password: str) -> str:
    """
    產生密碼雜湊：16 bytes salt + PBKDF2-HMAC-SHA256(120_000 次)，
    然後整串用 base64 編碼成字串存進 DB。
    """
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        120_000,
    )
    return base64.b64encode(salt + dk).decode("ascii")

def verify_password(password: str, stored_hash: str) -> bool:
    """
    驗證密碼是否符合 stored_hash。
    必須跟 INVIMB 以前那套演算法完全相同。
    """
    try:
        raw = base64.b64decode(stored_hash.encode("ascii"))
    except Exception:
        return False

    if len(raw) < 16:
        return False

    salt, dk = raw[:16], raw[16:]
    new_dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        120_000,
    )
    return hmac.compare_digest(dk, new_dk)

def _encode_expiry(date_str: str | None) -> str | None:
    """把 'YYYY-MM-DD' 編碼成 expires_enc（跟 _decode_expiry 互為反函式）"""
    if not date_str:
        return None
    try:
        # 先確認一下格式
        d = date.fromisoformat(date_str)
    except Exception:
        return None

    raw = date_str.encode("utf-8")
    key = SIGN_KEY
    ob = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return base64.b64encode(ob).decode("ascii")
    
def decode_license_expiry_utc(expires_enc: str | None) -> str | None:
    """
    提供給 / 回傳的 license_expiry_utc：

    1. 用 _decode_expiry() 還原 'YYYY-MM-DD'
    2. 視為【台北時間當天 23:59:59】到期
    3. 轉成 UTC ISO8601 字串，例如 '2099-12-31T15:59:59Z'
    """
    expiry_str = _decode_expiry(expires_enc)
    if not expiry_str:
        return None
    try:
        d = date.fromisoformat(expiry_str)
    except Exception:
        return None

    tz = ZoneInfo("Asia/Taipei")
    dt_local = datetime(d.year, d.month, d.day, 23, 59, 59, tzinfo=tz)
    dt_utc = dt_local.astimezone(timezone.utc)
    return dt_utc.isoformat().replace("+00:00", "Z")

# ✅ 啟動即確保 audit_login 已建立（函式內部自己讀 DATABASE_URL）
ensure_audit_login_table()

# 初始化資料表（首次啟動）
def init_db():
    # 授權/帳號/RBAC 表已由 migrations.ensure_all_tables() 處理
    pass

# ✅ 給 Cron-Job.org / 監控用的健康檢查
@app.route("/health", methods=["GET"])
def health():
    """
    簡單健康檢查：
    - 若有設定 PING_TOKEN，必須帶 ?token=xxx 才回 200
    - 沒設定 PING_TOKEN，任何人 GET /health 都會回 200
    """
    if PING_TOKEN:
        token = request.args.get("token", "")
        if token != PING_TOKEN:
            return jsonify({"status": "forbidden"}), 403

    # 這裡你也可以順便測 DB（可選）：
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
        db_ok = True
    except Exception as e:
        print("🔥 [health] DB check failed:", e)
        db_ok = False

    return jsonify({
        "status": "ok" if db_ok else "degraded",
        "db": db_ok,
    }), 200 if db_ok else 500

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == USERNAME and request.form["password"] == PASSWORD:
            session["logged_in"] = True
            return redirect("/admin")
        return "❌ 帳號或密碼錯誤", 401
    return render_template_string("""
        <form method="post" style="margin: 80px auto; width: 300px;">
            <h2>授權後台登入</h2>
            <input name="username" placeholder="帳號"><br><br>
            <input name="password" type="password" placeholder="密碼"><br><br>
            <button type="submit">登入</button>
        </form>
    """)

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect("/login")

@app.route("/admin")
def admin():
    if not session.get("logged_in"):
        return redirect("/login")
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM licenses ORDER BY auth_code")
        licenses = cur.fetchall()
    return render_template("admin.html", licenses=licenses)

@app.route("/get_licenses", methods=["GET"])
def get_licenses():
    token = request.headers.get("Authorization", "")
    if token != "Bearer max-lic-8899-secret":
        return jsonify({"error": "無效 API 金鑰"}), 403

    with get_conn() as conn:
        cur = conn.cursor()

        # 取出所有授權資料
        cur.execute("SELECT * FROM licenses")
        license_rows = cur.fetchall()

        # 建立 auth_code → 資訊 dict
        data = {}
        for row in license_rows:
            data[row['auth_code']] = {
                "expiry": row["expiry"],
                "remaining": row["remaining"],
                "mac": ""  # 預設先留空，等等補上 bindings
            }

        # 撈出綁定的裝置資訊
        cur.execute("SELECT auth_code, mac FROM bindings")
        bindings = cur.fetchall()

        # 整理：把綁定資訊加到上面的 license 資料中
        for row in bindings:
            auth_code = row["auth_code"]
            mac = row["mac"]
            if auth_code in data:
                existing = data[auth_code]["mac"]
                if existing:
                    data[auth_code]["mac"] += f"\n{mac}"  # 多台裝置用換行隔開
                else:
                    data[auth_code]["mac"] = mac

    return jsonify(data)

@app.route("/check_account", methods=["POST"])
def check_account():
    """
    給 INVIMB main_gui 用的「線上帳號登入」API。

    Request JSON:
      {
        "username": "admin",
        "password": "xxx"
      }

    Response JSON (成功範例):
      {
        "ok": true,
        "username": "admin",
        "role": "admin",
        "module": "admin",
        "allowed_tabs": ["sale_hist", "pur_hist", ...],
        "license_expiry_utc": "2099-12-31T15:59:59Z"  # 或 null (無到期日)
      }
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({
            "ok": False,
            "error": "MISSING_CREDENTIALS",
            "message": "請提供 username / password"
        }), 400

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()

        # 1) 撈出帳號（多撈 expires_at）
        cur.execute(
            """
            SELECT
              username,
              password_hash,
              role,
              module,
              active,
              expires_enc,
              expires_at
            FROM accounts
            WHERE username = %s
            """,
            (username,)
        )
        row = cur.fetchone()
        if not row:
            return jsonify({
                "ok": False,
                "error": "NO_SUCH_USER",
                "message": "帳號不存在"
            }), 400

        if not row["active"]:
            return jsonify({
                "ok": False,
                "error": "ACCOUNT_DISABLED",
                "message": "帳號已停用"
            }), 403

        # 2) 密碼驗證
        if not verify_password(password, row["password_hash"]):
            return jsonify({
                "ok": False,
                "error": "BAD_PASSWORD",
                "message": "密碼錯誤"
            }), 401

        role_name   = row["role"]
        module_name = row["module"]

        # 3) 模組 → tabs（module 限制）
        cur.execute(
            "SELECT tabs FROM rbac_modules WHERE module_name = %s",
            (module_name,)
        )
        m = cur.fetchone()
        module_tabs = m["tabs"] if m else []

        # 4) 角色 → tabs（role 限制）
        cur.execute(
            "SELECT tabs FROM rbac_tabs WHERE role_name = %s",
            (role_name,)
        )
        r = cur.fetchone()
        role_tabs = r["tabs"] if r else []

        # jsonb 可能會以文字回傳，保險轉一下
        if isinstance(module_tabs, str):
            module_tabs = json.loads(module_tabs)
        if isinstance(role_tabs, str):
            role_tabs = json.loads(role_tabs)

        # 5) allowed_tabs = 模組 tabs ∩ 角色 tabs
        allowed_tabs = sorted(set(module_tabs) & set(role_tabs))

        # 6) 到期日：優先使用 accounts.expires_at，沒有再退回 expires_enc
        expires_at = row.get("expires_at")   # 可能是 date / datetime / str / None
        expiry_utc_dt = None

        if expires_at:
            # 允許三種型別：date / datetime / "YYYY-MM-DD"
            if isinstance(expires_at, str):
                try:
                    d = date.fromisoformat(expires_at)
                except Exception:
                    d = None
            elif isinstance(expires_at, datetime):
                d = expires_at.date()
            else:
                # 預設當成 date 對待（psycopg2 RealDictCursor 通常就是 date 型別）
                d = expires_at

            if d:
                # 視為【台北時間該日 23:59:59 到期】，再轉成 UTC
                tz = ZoneInfo("Asia/Taipei")
                dt_local = datetime(d.year, d.month, d.day, 23, 59, 59, tzinfo=tz)
                expiry_utc_dt = dt_local.astimezone(timezone.utc)

        else:
            # 舊資料：仍支援 expires_enc
            enc = row.get("expires_enc")
            s = decode_license_expiry_utc(enc)  # 回傳 "YYYY-...Z" 或 None
            if s:
                try:
                    expiry_utc_dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                except Exception:
                    expiry_utc_dt = None

        # 6-1) 若已過期 → 直接拒絕登入
        if expiry_utc_dt and datetime.now(timezone.utc) > expiry_utc_dt:
            return jsonify({
                "ok": False,
                "error": "ACCOUNT_EXPIRED",
                "message": "帳號已到期，請聯絡管理員。",
            }), 403

        # 6-2) 給 client 的 ISO 字串（讓 INVIMB 端也可以再做一次檢查）
        license_expiry_utc = (
            expiry_utc_dt.isoformat().replace("+00:00", "Z")
            if expiry_utc_dt else None
        )

        return jsonify({
            "ok": True,
            "username": row["username"],
            "role": role_name,
            "module": module_name,
            "allowed_tabs": allowed_tabs,
            "license_expiry_utc": license_expiry_utc,
        })

    except Exception as e:
        print("🔥 [check_account] error:", e)
        return jsonify({
            "ok": False,
            "error": "SERVER_ERROR",
            "message": str(e),
        }), 500
    finally:
        if conn is not None:
            conn.close()

# === RBAC 設定：角色 / 模組 → tabs ====
@app.get("/rbac/role_tabs")
def api_get_role_tabs():
    """回傳 role → tabs mapping，給客戶端載入 RBAC 用。"""
    try:
        with get_conn() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT role_name, tabs FROM rbac_tabs ORDER BY role_name")
            rows = cur.fetchall()
        mapping = {r["role_name"]: r["tabs"] for r in rows}
        return jsonify({"ok": True, "role_tabs": mapping})
    except Exception as e:
        print("[rbac] api_get_role_tabs error:", e)
        return jsonify({"ok": False, "message": str(e)}), 500

@app.post("/rbac/role_tabs")
def api_save_role_tabs():
    """
    覆蓋整份 role → tabs 設定。
    Request JSON:
      { "role_tabs": { "admin": ["conn", "perm_admin", ...], "pur": [...], ... } }
    """
    data = request.get_json(silent=True) or {}
    mapping = data.get("role_tabs") or {}
    if not isinstance(mapping, dict):
        return jsonify({"ok": False, "message": "role_tabs 必須是 dict"}), 400

    try:
        with get_conn() as conn, conn.cursor() as cur:
            # 先清掉，再整批重建
            cur.execute("DELETE FROM rbac_tabs")
            for role, tabs in mapping.items():
                if not isinstance(tabs, list):
                    tabs = []
                cur.execute(
                    "INSERT INTO rbac_tabs (role_name, tabs) VALUES (%s, %s)",
                    (role, Json(tabs)),
                )
        return jsonify({"ok": True})
    except Exception as e:
        print("[rbac] api_save_role_tabs error:", e)
        return jsonify({"ok": False, "message": str(e)}), 500
        
@app.get("/rbac/module_tabs")
def api_get_module_tabs():
    """回傳 module → tabs mapping。"""
    try:
        with get_conn() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT module_name, tabs FROM rbac_modules ORDER BY module_name")
            rows = cur.fetchall()
        mapping = {r["module_name"]: r["tabs"] for r in rows}
        return jsonify({"ok": True, "module_tabs": mapping})
    except Exception as e:
        print("[rbac] api_get_module_tabs error:", e)
        return jsonify({"ok": False, "message": str(e)}), 500

@app.post("/rbac/module_tabs")
def api_save_module_tabs():
    """覆蓋整份 module → tabs 設定。"""
    data = request.get_json(silent=True) or {}
    mapping = data.get("module_tabs") or {}
    if not isinstance(mapping, dict):
        return jsonify({"ok": False, "message": "module_tabs 必須是 dict"}), 400

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM rbac_modules")
            for module, tabs in mapping.items():
                if not isinstance(tabs, list):
                    tabs = []
                cur.execute(
                    "INSERT INTO rbac_modules (module_name, tabs) VALUES (%s, %s)",
                    (module, Json(tabs)),
                )
        return jsonify({"ok": True})
    except Exception as e:
        print("[rbac] api_save_module_tabs error:", e)
        return jsonify({"ok": False, "message": str(e)}), 500

@app.route("/check_license", methods=["POST"])
def check_license():
    try:
        data = request.get_json()
        code = data.get("auth_code")
        mac = data.get("mac")

        if not code or not mac:
            return jsonify({"error": "缺少授權碼或 MAC"}), 400

        with get_conn() as conn:
            cur = conn.cursor()

            cur.execute("SELECT auth_code FROM bindings WHERE mac = %s", (mac,))
            existing = cur.fetchone()

            cur.execute("SELECT * FROM licenses WHERE auth_code = %s", (code,))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "無效授權碼"}), 403

            if existing and existing["auth_code"] != code:
                return jsonify({"error": "此裝置已綁定其他授權碼"}), 403

            remaining = row["remaining"]
            if not isinstance(remaining, int):
                return jsonify({"error": "授權碼剩餘次數格式錯誤"}), 500

            if not existing:
                if remaining > 0:
                    cur.execute("INSERT INTO bindings (mac, auth_code) VALUES (%s, %s)", (mac, code))
                    cur.execute(
                        "UPDATE licenses SET remaining = remaining - 1, mac = %s WHERE auth_code = %s",
                        (mac, code)
                    )
                else:
                    return jsonify({"error": "此授權碼已無剩餘使用次數"}), 403
            else:
                cur.execute("UPDATE licenses SET mac = %s WHERE auth_code = %s", (mac, code))

            expiry = row["expiry"]
            if isinstance(expiry, str):
                expiry = datetime.strptime(expiry, "%Y-%m-%d").date()
            elif isinstance(expiry, datetime):
                expiry = expiry.date()

            if expiry < datetime.today().date():
                return jsonify({"error": "授權已過期"}), 403

            conn.commit()

            return jsonify({
                "success": True,
                "expiry": str(expiry),
                "remaining": remaining
            })
    except Exception as e:
        print("🔥 [check_license] 例外：", e)
        return jsonify({"error": "伺服器錯誤", "message": str(e)}), 500

@app.route("/update_license", methods=["POST"])
def update_license():
    data = request.get_json()
    code = data.get("auth_code")
    expiry = data.get("expiry")
    remaining = data.get("remaining")

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT mac FROM licenses WHERE auth_code = %s", (code,))
        row = cur.fetchone()
        mac = row["mac"] if row else None
        cur.execute("""
            INSERT INTO licenses (auth_code, expiry, remaining, mac)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (auth_code) DO UPDATE
            SET expiry = EXCLUDED.expiry,
                remaining = EXCLUDED.remaining,
                mac = COALESCE(licenses.mac, '')
        """, (code, expiry, remaining, mac))
        conn.commit()
    return jsonify({"success": True})

@app.route("/delete_license", methods=["POST"])
def delete_license():
    code = request.get_json().get("auth_code")
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM licenses WHERE auth_code = %s", (code,))
        conn.commit()
    return jsonify({"success": True})

@app.route("/reset_mac", methods=["POST"])
def reset_mac():
    token = request.headers.get("Authorization", "")
    if token != "Bearer max-lic-8899-secret":
        return jsonify({"error": "無效 API 金鑰"}), 403

    code = request.get_json().get("auth_code")

    if not code:
        return jsonify({"error": "缺少授權碼"}), 400

    with get_conn() as conn:
        cur = conn.cursor()

        # 先查出該授權碼對應的 mac（可能為空）
        cur.execute("SELECT mac FROM licenses WHERE auth_code = %s", (code,))
        row = cur.fetchone()

        if not row:
            return jsonify({"error": "授權碼不存在"}), 404

        mac = row.get("mac")
        if mac:
            # ❗ 同步刪除 bindings 表中這個 mac 綁定的資料
            cur.execute("DELETE FROM bindings WHERE mac = %s", (mac,))

        # ✅ 清空 licenses 表中這筆授權的 mac 欄位
        cur.execute("UPDATE licenses SET mac = '' WHERE auth_code = %s", (code,))
        conn.commit()

    return jsonify({"success": True})

@app.route("/export_licenses", methods=["GET"])
def export_licenses():
    if request.headers.get("Authorization", "") != "Bearer max-lic-8899-secret":
        return jsonify({"error": "無效 API 金鑰"}), 403

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM licenses")
        licenses = cur.fetchall()
        cur.execute("SELECT * FROM bindings")
        bindings = cur.fetchall()
    return jsonify({
        "licenses": licenses,
        "bindings": bindings
    })

@app.route("/export_auth_backup", methods=["GET"])
def export_auth_backup():
    """一次匯出：licenses + bindings + accounts + rbac_tabs + rbac_modules"""
    token = request.headers.get("Authorization", "")
    if token != "Bearer max-lic-8899-secret":
        return jsonify({"ok": False, "error": "無效 API 金鑰"}), 403

    with get_conn() as conn:
        cur = conn.cursor()

        # licenses
        cur.execute("SELECT * FROM licenses ORDER BY auth_code")
        licenses_rows = cur.fetchall()
        licenses = [_row_to_jsonable(r) for r in licenses_rows]

        # bindings
        cur.execute("SELECT * FROM bindings ORDER BY mac")
        bindings_rows = cur.fetchall()
        bindings = [_row_to_jsonable(r) for r in bindings_rows]

        # accounts
        cur.execute("SELECT * FROM accounts ORDER BY username")
        accounts_rows = cur.fetchall()
        accounts = [_row_to_jsonable(r) for r in accounts_rows]

        # rbac_tabs
        cur.execute("SELECT * FROM rbac_tabs ORDER BY role_name")
        rbac_tabs_rows = cur.fetchall()
        rbac_tabs = [_row_to_jsonable(r) for r in rbac_tabs_rows]

        # rbac_modules
        cur.execute("SELECT * FROM rbac_modules ORDER BY module_name")
        rbac_modules_rows = cur.fetchall()
        rbac_modules = [_row_to_jsonable(r) for r in rbac_modules_rows]

    return jsonify({
        "ok": True,
        "schema_version": 1,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "licenses": licenses,
        "bindings": bindings,
        "accounts": accounts,
        "rbac_tabs": rbac_tabs,
        "rbac_modules": rbac_modules,
    })

@app.route("/import_auth_backup", methods=["POST"])
def import_auth_backup():
    """
    還原整套授權系統：
    - licenses
    - bindings
    - accounts
    - rbac_tabs
    - rbac_modules

    ⚠ 會 TRUNCATE 這幾張表再重灌，建議只給 MIS 用。
    """
    token = request.headers.get("Authorization", "")
    if token != "Bearer max-lic-8899-secret":
        return jsonify({"ok": False, "error": "無效 API 金鑰"}), 403

    data = request.get_json(silent=True) or {}

    licenses     = data.get("licenses")     or []
    bindings     = data.get("bindings")     or []
    accounts     = data.get("accounts")     or []
    rbac_tabs    = data.get("rbac_tabs")    or []
    rbac_modules = data.get("rbac_modules") or []

    # 簡單型別檢查，避免傳錯格式
    if not all(isinstance(x, list) for x in [licenses, bindings, accounts, rbac_tabs, rbac_modules]):
        return jsonify({"ok": False, "error": "payload 格式錯誤，欄位必須是 list"}), 400

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            # 1) 先清空（注意順序：有 FK 的先 TRUNCATE 子表）
            #    bindings -> licenses，有外鍵；用 CASCADE 比較保險
            cur.execute("TRUNCATE TABLE bindings RESTART IDENTITY CASCADE;")
            cur.execute("TRUNCATE TABLE licenses RESTART IDENTITY CASCADE;")
            cur.execute("TRUNCATE TABLE accounts RESTART IDENTITY CASCADE;")
            cur.execute("TRUNCATE TABLE rbac_tabs RESTART IDENTITY CASCADE;")
            cur.execute("TRUNCATE TABLE rbac_modules RESTART IDENTITY CASCADE;")

            # 2) licenses
            for row in licenses:
                code = row.get("auth_code")
                if not code:
                    # 沒授權碼就略過，避免塞進 NULL primary key
                    continue

                expiry = row.get("expiry") or None
                remaining = row.get("remaining")
                # 殘次數轉成 int（遇到 None / 空字串就當 0）
                try:
                    remaining = int(remaining) if remaining is not None else 0
                except (TypeError, ValueError):
                    remaining = 0

                cur.execute(
                    """
                    INSERT INTO licenses (auth_code, expiry, remaining, mac)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        code,
                        expiry,              # ISO 字串或 date 讓 Postgres 自己處理
                        remaining,
                        row.get("mac"),
                    ),
                )

            # 3) accounts
            for row in accounts:
                username = (row.get("username") or "").strip()
                if not username:
                    # 沒帳號就略過
                    continue

                # role / module 多給一層 fallback（相容舊欄位）
                role   = (row.get("role") or row.get("role_name") or "admin").strip()
                module = (row.get("module") or row.get("module_name") or "admin").strip()

                active = bool(row.get("active", True))
                expires_at = row.get("expires_at")  # str / date / None 都交給 Postgres

                cur.execute(
                    """
                    INSERT INTO accounts
                        (username, password_hash, role, module, active, expires_at, expires_enc)
                    VALUES
                        (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        username,
                        row.get("password_hash"),
                        role,
                        module,
                        active,
                        expires_at,          # ISO 字串讓 Postgres 自己 parse
                        row.get("expires_enc"),
                    ),
                )

            # 4) rbac_tabs
            for row in rbac_tabs:
                role_name = (
                    row.get("role_name")
                    or row.get("role")
                    or row.get("name")
                )
                if not role_name:
                    continue

                tabs = row.get("tabs") or []
                if isinstance(tabs, str):
                    # 若不小心存成 JSON 字串，嘗試 parse 一下
                    try:
                        import json as _json
                        tabs = _json.loads(tabs)
                    except Exception:
                        tabs = []

                if not isinstance(tabs, list):
                    tabs = []

                cur.execute(
                    """
                    INSERT INTO rbac_tabs (role_name, tabs)
                    VALUES (%s, %s)
                    """,
                    (
                        role_name,
                        Json(tabs),
                    ),
                )

            # 5) rbac_modules
            for row in rbac_modules:
                module_name = (
                    row.get("module_name")
                    or row.get("module")
                    or row.get("name")
                )
                if not module_name:
                    continue

                tabs = row.get("tabs") or []
                if isinstance(tabs, str):
                    try:
                        import json as _json
                        tabs = _json.loads(tabs)
                    except Exception:
                        tabs = []

                if not isinstance(tabs, list):
                    tabs = []

                cur.execute(
                    """
                    INSERT INTO rbac_modules (module_name, tabs)
                    VALUES (%s, %s)
                    """,
                    (
                        module_name,
                        Json(tabs),
                    ),
                )

            # 6) 最後插回 bindings（依賴 licenses）
            for row in bindings:
                mac = row.get("mac")
                code = row.get("auth_code")
                if not mac or not code:
                    # 缺欄位就略過
                    continue

                cur.execute(
                    """
                    INSERT INTO bindings (mac, auth_code)
                    VALUES (%s, %s)
                    """,
                    (
                        mac,
                        code,
                    ),
                )

            conn.commit()

    except Exception as e:
        # 若中途出錯，讓呼叫端知道
        return jsonify({
            "ok": False,
            "error": "IMPORT_FAILED",
            "message": str(e),
        }), 500

    return jsonify({
        "ok": True,
        "import_counts": {
            "licenses": len(licenses),
            "bindings": len(bindings),
            "accounts": len(accounts),
            "rbac_tabs": len(rbac_tabs),
            "rbac_modules": len(rbac_modules),
        },
    })

@app.route("/import_licenses", methods=["POST"])
def import_licenses():
    if request.headers.get("Authorization", "") != "Bearer max-lic-8899-secret":
        return jsonify({"error": "無效 API 金鑰"}), 403

    data = request.get_json()
    licenses = data.get("licenses", [])
    bindings = data.get("bindings", [])

    with get_conn() as conn:
        cur = conn.cursor()
        for row in licenses:
            cur.execute("""
                INSERT INTO licenses (auth_code, expiry, remaining, mac)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (auth_code) DO UPDATE
                SET expiry = EXCLUDED.expiry,
                    remaining = EXCLUDED.remaining,
                    mac = EXCLUDED.mac
            """, (row["auth_code"], row["expiry"], row["remaining"], row["mac"]))

        for row in bindings:
            cur.execute("""
                INSERT INTO bindings (mac, auth_code)
                VALUES (%s, %s)
                ON CONFLICT (mac) DO UPDATE
                SET auth_code = EXCLUDED.auth_code
            """, (row["mac"], row["auth_code"]))

        conn.commit()

    return jsonify({"success": True})

AUDIT_API_KEY = os.getenv("AUDIT_API_KEY")  # 在 Render 設環境變數

@app.get("/invimb/latest")
def invimb_latest():
    return jsonify({
        "ok": True,
        "version": "1.4.3",
        # 內網共享路徑，只是當成字串給客戶端用，不是給 Flask 自己用
        "exe_path": r"\\192.168.10.183\公共資料夾\Reports\INVIMB-setup-1.4.3.exe",
        "changelog": "1. 系統優化 2. 更新線上授權 3. Bug等問題修正"
    })

@app.route("/api/audit_log", methods=["POST"])
def api_audit_log():
    # 用 API key 簡單保護（也可換成你既有的授權驗證）
    api_key = request.headers.get("X-API-KEY", "")
    if not AUDIT_API_KEY or api_key != AUDIT_API_KEY:
        return jsonify({"ok": False, "msg": "unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    action   = payload.get("action")
    if not username or not action:
        return jsonify({"ok": False, "msg": "missing username/action"}), 400

    # 以伺服器看到的來源 IP 為準（比 client 傳的準確）
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        remote_ip = xff.split(",")[0].strip()
    else:
        remote_ip = request.remote_addr

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO audit_login
              (event_time, username, role, allowed_tabs, machine_name, local_ip, public_ip,
               app_version, client_os, action, note, source, extra)
            VALUES (
               COALESCE(%s, now()), %s, %s, %s, %s, %s, %s,
               %s, %s, %s, %s, %s, %s
            )
        """, (
            payload.get("event_time"),
            username,
            payload.get("role"),
            Json(payload.get("allowed_tabs")) if payload.get("allowed_tabs") is not None else None,
            payload.get("machine_name"),
            payload.get("local_ip"),
            payload.get("public_ip") or remote_ip,
            payload.get("app_version"),
            payload.get("client_os"),
            action,
            payload.get("note"),
            payload.get("source") or "gui",
            Json(payload.get("extra") or {})
        ))
        conn.commit()
    return jsonify({"ok": True})

# 簡易查詢頁（沿用你現有的 login session 保護）
@app.route("/audit", methods=["GET"])
def audit_list():
    if not session.get("logged_in"):
        return redirect("/login")

    username = request.args.get("username") or None
    action   = request.args.get("action") or None
    from_ts  = request.args.get("from") or None
    to_ts    = request.args.get("to") or None
    limit    = int(request.args.get("limit") or 50)
    page     = int(request.args.get("page") or 1)
    offset   = (page - 1) * limit

    where, params = ["1=1"], []
    if username:
        where.append("username = %s"); params.append(username)
    if action:
        where.append("action = %s"); params.append(action)
    if from_ts:
        where.append("event_time >= %s"); params.append(from_ts)
    if to_ts:
        where.append("event_time <= %s"); params.append(to_ts)

    sql = f"""
      SELECT
        to_char(event_time AT TIME ZONE 'Asia/Taipei','YYYY-MM-DD HH24:MI:SS') AS event_time,
        username, action, machine_name, local_ip, public_ip, app_version, client_os, COALESCE(note,'') AS note
      FROM audit_login
      WHERE {' AND '.join(where)}
      ORDER BY event_time DESC
      LIMIT %s OFFSET %s
    """

    params2 = params + [limit, offset]

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(sql, params2)
        rows = cur.fetchall()

    def mk_link(delta):
        q = request.args.to_dict(flat=True)
        q["page"] = str(page + delta)
        return f"{request.path}?{urlencode(q)}"

    prev_link = mk_link(-1) if page > 1 else None
    next_link = mk_link(+1) if len(rows) >= limit else None

    current_qs = urlencode(request.args.to_dict(flat=False), doseq=True)
    # 用 render_template_string，省一個檔案
    return render_template_string("""
    <!doctype html>
    <html lang="zh-Hant">
    <head>
      <meta charset="utf-8">
      <title>Audit Login ｜ 授權後台</title>
      <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}?v=2" type="image/x-icon">
      <link rel="shortcut icon" href="{{ url_for('static', filename='favicon.ico') }}?v=2" type="image/x-icon">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        :root{
          --bg:#0f1115; --panel:#151821; --panel2:#1b1f2a; --line:#2b2f3a;
          --text:#eaeaea; --muted:#9aa0a6; --accent:#2d7dff;
        }
        *{box-sizing:border-box}
        body{margin:0;padding:18px 18px 28px;background:var(--bg);color:var(--text);font:14px/1.6 system-ui,Segoe UI,Roboto,Apple Color Emoji}
        h1{margin:0 0 12px;font-size:28px}
        form{display:flex;gap:10px;flex-wrap:wrap;align-items:center;background:var(--panel);padding:12px;border:1px solid var(--line);border-radius:10px}
        input,select{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:8px 10px}
        input[type="number"]{width:90px}
        .btn{background:var(--accent);border:none;color:#fff;padding:8px 12px;border-radius:8px;cursor:pointer}
        .pill{display:inline-block;padding:6px 10px;border-radius:999px;background:#1b1d23;border:1px solid var(--line);color:var(--text);text-decoration:none}
        table{width:100%;border-collapse:collapse;margin-top:12px;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
        th,td{border-bottom:1px solid var(--line);padding:8px 10px;font-size:13px;text-align:left}
        th{color:var(--muted);background:#121521}
        tr:hover{background:#171b25}
        .msg{margin:10px 0;padding:10px 12px;border:1px solid #335c33;background:#132313;color:#b7e1b7;border-radius:8px}
        @media (max-width:760px){
          th:nth-child(6),td:nth-child(6){display:none}
        }
      </style>
    </head>
    <body>
      <h1>Audit Login</h1>
    
      {% if request.args.get('msg') %}
        <div class="msg">{{ request.args.get('msg') }}</div>
      {% endif %}
    
      <form method="GET">
        <label>使用者 <input type="text" name="username" value="{{ request.args.get('username','') }}"></label>
        <label>事件
          {% set act = request.args.get('action','') %}
          <select name="action">
            <option value="">(全部)</option>
            {% for a in ["login_success","login_fail"] %}
              <option value="{{a}}" {% if a==act %}selected{% endif %}>{{a}}</option>
            {% endfor %}
          </select>
        </label>
        <label>起 <input type="datetime-local" name="from" value="{{ request.args.get('from','') }}"></label>
        <label>迄 <input type="datetime-local" name="to"   value="{{ request.args.get('to','') }}"></label>
        <label>每頁 <input type="number" name="limit" min="10" max="500" value="{{ request.args.get('limit','50') }}"></label>
    
        <button class="btn" type="submit">查詢</button>
    
        <a class="pill" href="/audit/export.csv{% if current_qs %}?{{ current_qs }}{% endif %}">下載 CSV</a>
        <input type="number" name="days" min="1" max="3650" value="{{ request.args.get('days','180') }}">
        <button class="pill" type="submit"
                formmethod="post"
                formaction="/audit/prune{% if current_qs %}?{{ current_qs }}{% endif %}"
                onclick="return confirm('確定要清除舊紀錄嗎？此動作無法復原。');">
          清除(天)
        </button>
    
        {% if prev_link %}<a class="pill" href="{{ prev_link }}">上一頁</a>{% endif %}
        {% if next_link %}<a class="pill" href="{{ next_link }}">下一頁</a>{% endif %}
      </form>
    
      <table>
        <thead><tr>
          <th>時間</th><th>使用者</th><th>事件</th><th>機器</th><th>local ip</th><th>public ip</th><th>版本</th><th>OS</th><th>備註</th>
        </tr></thead>
        <tbody>
          {% for r in rows %}
          <tr>
            <td>{{ r["event_time"] }}</td>
            <td>{{ r["username"] }}</td>
            <td>{{ r["action"] }}</td>
            <td>{{ r["machine_name"] }}</td>
            <td>{{ r["local_ip"] }}</td>
            <td>{{ r["public_ip"] }}</td>
            <td>{{ r["app_version"] }}</td>
            <td>{{ r["client_os"] }}</td>
            <td>{{ r["note"] }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </body>
    </html>
    """, rows=rows, prev_link=prev_link, next_link=next_link, current_qs=current_qs)

@app.route("/audit/export.csv", methods=["GET"])
def audit_export_csv():
    if not session.get("logged_in"):
        return redirect("/login")

    import csv, io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["time_tw","username","action","machine","local_ip","public_ip","version","os","note"])

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
          SELECT
            to_char(event_time AT TIME ZONE 'Asia/Taipei','YYYY-MM-DD HH24:MI:SS') AS time_tw,
            username, action, machine_name, local_ip, public_ip, app_version, client_os, COALESCE(note,'') AS note
          FROM audit_login
          ORDER BY event_time DESC
          LIMIT 5000
        """)
        for row in cur.fetchall():
            writer.writerow([
                row["time_tw"], row["username"], row["action"], row["machine_name"],
                row["local_ip"], row["public_ip"], row["app_version"], row["client_os"], row["note"]
            ])

    resp = app.response_class(output.getvalue(), mimetype="text/csv; charset=utf-8")
    resp.headers["Content-Disposition"] = "attachment; filename=audit_login.csv"
    return resp

@app.route("/audit/prune", methods=["POST"])
def audit_prune():
    if not session.get("logged_in"):
        return redirect("/login")

    # 限制 days 範圍，避免誤刪或注入
    try:
        days = int(request.form.get("days", "180"))
    except ValueError:
        days = 180
    days = max(1, min(days, 3650))  # 1~3650 天

    # 刪除並回傳筆數
    with get_conn() as conn:
        cur = conn.cursor()
        # 用 make_interval 比較安全（param 是純整數）
        cur.execute("DELETE FROM audit_login WHERE event_time < now() - make_interval(days => %s)", (days,))
        deleted = cur.rowcount
        conn.commit()

    # （可選）輕量更新統計，幫查詢計劃更準
    try:
        with get_conn() as conn2:
            cur2 = conn2.cursor()
            cur2.execute("ANALYZE audit_login")
            conn2.commit()
    except Exception:
        pass
        
    # 帶訊息回到 /audit（保留原查詢參數）
    q = request.args.to_dict(flat=True)
    q["msg"] = f"已清除 {days} 天前的舊紀錄，共 {deleted} 筆。"
    from urllib.parse import urlencode
    return redirect(f"/audit?{urlencode(q)}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
