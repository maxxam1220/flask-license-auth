from flask import Flask, request, jsonify, render_template, redirect, session, render_template_string
import psycopg2, os
from psycopg2.extras import RealDictCursor, Json
from datetime import datetime
from urllib.parse import urlencode
from migrations import ensure_audit_login_table

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")  # ✅ 改用環境變數

# ✅ 登入帳密
USERNAME = os.getenv("ADMIN_USER", "admin")
PASSWORD = os.getenv("ADMIN_PASS", "Aa721220")

# ✅ PostgreSQL 連線字串（補上 sslmode=require）
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL 未設定")
if "sslmode=" not in DATABASE_URL:
    DATABASE_URL += ("&" if "?" in DATABASE_URL else "?") + "sslmode=require"

def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

# ✅ 啟動即確保 audit_login 已建立（函式內部自己讀 DATABASE_URL）
ensure_audit_login_table()

# 初始化資料表（首次啟動）
def init_db():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                auth_code TEXT PRIMARY KEY,
                expiry DATE NOT NULL,
                remaining INTEGER NOT NULL,
                mac TEXT
            )
        """)
 # 新增 bindings 表，用來限制每台裝置只能綁定一組授權
        cur.execute("""
            CREATE TABLE IF NOT EXISTS bindings (
                mac TEXT PRIMARY KEY,
                auth_code TEXT NOT NULL,
                FOREIGN KEY (auth_code) REFERENCES licenses(auth_code)
            )
        """)
        conn.commit()

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
    remote_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

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
      SELECT event_time, username, action, machine_name, local_ip, public_ip, app_version, client_os, COALESCE(note,'') AS note
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

    # 用 render_template_string，省一個檔案
    return render_template_string("""
<!doctype html><meta charset="utf-8">
<style>
body{background:#0f1115;color:#eaeaea;font-family:system-ui,sans-serif}
form{margin:12px 0} input,select{background:#1b1d23;color:#eaeaea;border:1px solid #2b2f3a;border-radius:6px;padding:6px 8px}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{border-bottom:1px solid #2b2f3a;padding:6px 8px;font-size:13px} th{color:#9aa0a6;text-align:left}
.btn{background:#2d7dff;border:none;color:#fff;padding:6px 10px;border-radius:6px;cursor:pointer}
.pill{padding:2px 6px;border-radius:999px;background:#222;border:1px solid #333;font-size:12px}
.flex{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
</style>
<h1>Audit Login</h1>
<form method="GET" class="flex">
  <label>使用者 <input type="text" name="username" value="{{ request.args.get('username','') }}"></label>
  <label>事件 <select name="action">
    {% set act = request.args.get('action','') %}
    <option value="">(全部)</option>
    {% for a in ["login_success","login_fail"] %}
      <option value="{{a}}" {% if a==act %}selected{% endif %}>{{a}}</option>
    {% endfor %}
  </select></label>
  <label>起 <input type="datetime-local" name="from" value="{{ request.args.get('from','') }}"></label>
  <label>迄 <input type="datetime-local" name="to"   value="{{ request.args.get('to','') }}"></label>
  <label>每頁 <input style="width:80px" type="number" name="limit" min="10" max="500" value="{{ request.args.get('limit','50') }}"></label>
  <button class="btn">查詢</button>
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
    """, rows=rows, prev_link=prev_link, next_link=next_link)

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL 未設定")
if "sslmode=" not in DATABASE_URL:
    DATABASE_URL += ("&" if "?" in DATABASE_URL else "?") + "sslmode=require"

def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
