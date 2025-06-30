from flask import Flask, request, jsonify, render_template, redirect, session, url_for, render_template_string
import sqlite3, os

app = Flask(__name__)
app.secret_key = "super_secret_key_123"

# 登入帳密設定
USERNAME = "admin"
PASSWORD = "Aa721220"

DB_PATH = "licenses.db"

# 初始化資料庫
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            auth_code TEXT PRIMARY KEY,
            expiry TEXT,
            remaining INTEGER,
            mac TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT auth_code, expiry, remaining, COALESCE(mac, '') FROM licenses")
    licenses = c.fetchall()
    conn.close()
    return render_template("admin.html", licenses=licenses)

@app.route("/get_licenses", methods=["GET"])
def get_licenses():
    token = request.headers.get("Authorization", "")
    if token != "Bearer max-lic-8899-secret":
        return jsonify({"error": "無效 API 金鑰"}), 403

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM licenses")
    rows = c.fetchall()
    conn.close()

    result = {row[0]: {"expiry": row[1], "remaining": row[2], "mac": row[3]} for row in rows}
    return jsonify(result)

@app.route("/check_license", methods=["POST"])
def check_license():
    data = request.get_json()
    code = data.get("auth_code")
    mac = data.get("mac")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT expiry, remaining, mac FROM licenses WHERE auth_code = ?", (code,))
    row = c.fetchone()

    if not row:
        return jsonify({"error": "無效授權碼"}), 403

    expiry, remaining, saved_mac = row
    if saved_mac and saved_mac != mac:
        return jsonify({"error": "裝置不符"}), 403
    if not saved_mac:
        c.execute("UPDATE licenses SET mac = ? WHERE auth_code = ?", (mac, code))
        conn.commit()

    conn.close()
    return jsonify({"success": True, "expiry": expiry, "remaining": remaining})

@app.route("/update_license", methods=["POST"])
def update_license():
    data = request.get_json()
    code = data.get("auth_code")
    expiry = data.get("expiry")
    remaining = data.get("remaining")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT mac FROM licenses WHERE auth_code = ?", (code,))
    row = c.fetchone()
    mac = row[0] if row else ""

    c.execute("REPLACE INTO licenses (auth_code, expiry, remaining, mac) VALUES (?, ?, ?, ?)",
              (code, expiry, remaining, mac))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/delete_license", methods=["POST"])
def delete_license():
    data = request.get_json()
    code = data.get("auth_code")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE auth_code = ?", (code,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/reset_mac", methods=["POST"])
def reset_mac():
    token = request.headers.get("Authorization", "")
    if token != "Bearer max-lic-8899-secret":
        return jsonify({"error": "無效 API 金鑰"}), 403

    data = request.get_json()
    code = data.get("auth_code")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE licenses SET mac = '' WHERE auth_code = ?", (code,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port)
