from flask import Flask, request, jsonify, render_template, redirect, session, render_template_string
import psycopg2, os
from psycopg2.extras import RealDictCursor
from datetime import datetime

app = Flask(__name__)
app.secret_key = "super_secret_key_123"  # 請改成更安全的亂數

# ✅ 登入帳密
USERNAME = "admin"
PASSWORD = "Aa721220"

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
        cur.execute("SELECT * FROM licenses")
        data = {row['auth_code']: row for row in cur.fetchall()}
    return jsonify(data)

@app.route("/check_license", methods=["POST"])
def check_license():
    data = request.get_json()
    code = data.get("auth_code")
    mac = data.get("mac")

    if not code or not mac:
        return jsonify({"error": "缺少授權碼或 MAC"}), 400

    with get_conn() as conn:
        cur = conn.cursor()

        # 先查這個 MAC 是否已綁定別的授權碼
        cur.execute("SELECT auth_code FROM bindings WHERE mac = %s", (mac,))
        existing = cur.fetchone()
        if existing and existing["auth_code"] != code:
            return jsonify({"error": "此裝置已綁定其他授權碼"}), 403

        # 查詢授權碼是否存在
        cur.execute("SELECT * FROM licenses WHERE auth_code = %s", (code,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "無效授權碼"}), 403

        # 如果 MAC 尚未綁定，建立綁定紀錄
        if not existing:
            cur.execute("INSERT INTO bindings (mac, auth_code) VALUES (%s, %s)", (mac, code))
            # 同步寫回 licenses 表（僅供前端查看用途）
            cur.execute("UPDATE licenses SET mac = %s WHERE auth_code = %s", (mac, code))

        # 到期檢查
        expiry = row["expiry"]
        if isinstance(expiry, datetime):
            expiry = expiry.date()
        if expiry < datetime.today().date():
            return jsonify({"error": "授權已過期"}), 403

        # 減少剩餘次數（如果你想在驗證時遞減）
        # cur.execute("UPDATE licenses SET remaining = remaining - 1 WHERE auth_code = %s AND remaining > 0", (code,))

        conn.commit()

        return jsonify({
            "success": True,
            "expiry": str(expiry),
            "remaining": row["remaining"]
        })

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
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE licenses SET mac = '' WHERE auth_code = %s", (code,))
        conn.commit()
    return jsonify({"success": True})

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
