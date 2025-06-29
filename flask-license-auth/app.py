from flask import Flask, request, jsonify, render_template, redirect, session, url_for, render_template_string
import json, os

app = Flask(__name__)
app.secret_key = "super_secret_key_123"  # ← 請改成更安全的亂數字串

# ✅ 登入帳密設定
USERNAME = "admin"
PASSWORD = "Aa721220"

# ✅ 登入頁面
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

# ✅ 登出
@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect("/login")

# ✅ 管理頁面，加上登入保護
@app.route("/admin")
def admin():
    if not session.get("logged_in"):
        return redirect("/login")
    try:
        with open("license_db.json", "r", encoding="utf-8") as f:
            licenses = json.load(f)
    except:
        licenses = {}
    return render_template("admin.html", licenses=licenses)
@app.route("/get_licenses", methods=["GET"])
def get_licenses():
    token = request.headers.get("Authorization", "")
    if token != "Bearer max-lic-8899-secret":
        return jsonify({"error": "無效 API 金鑰"}), 403

    try:
        with open("license_db.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port)
