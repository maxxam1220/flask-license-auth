from flask import Flask, request, jsonify, render_template, redirect, session, render_template_string
import psycopg2, os
from psycopg2.extras import RealDictCursor
from datetime import datetime

app = Flask(__name__)
app.secret_key = "super_secret_key_123"  # 請改成更安全的亂數

# ✅ 登入帳密
USERNAME = os.getenv("ADMIN_USER", "admin")
PASSWORD = os.getenv("ADMIN_PASS", "Aa721220")

# ✅ PostgreSQL 資料庫連線資訊（Render 會自動提供 DATABASE_URL 環境變數）
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

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

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
