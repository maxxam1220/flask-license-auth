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

@app.route("/check_license", methods=["POST"])
def check_license():
    data = request.get_json()
    code = data.get("auth_code")
    mac = data.get("mac")

    try:
        with open("license_db.json", "r", encoding="utf-8") as f:
            db = json.load(f)
    except:
        return jsonify({"error": "找不到授權資料"}), 500

    if code not in db:
        return jsonify({"error": "無效授權碼"}), 403

    lic = db[code]
    if "mac" not in lic:
        lic["mac"] = mac
    elif lic["mac"] != mac:
        return jsonify({"error": "裝置不符"}), 403

    with open("license_db.json", "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)

    return jsonify({"success": True, "expiry": lic["expiry"], "remaining": lic["remaining"]})

@app.route("/update_license", methods=["POST"])
def update_license():
    data = request.get_json()
    code = data.get("auth_code")
    expiry = data.get("expiry")
    remaining = data.get("remaining")

    try:
        with open("license_db.json", "r", encoding="utf-8") as f:
            db = json.load(f)
    except:
        db = {}

    db[code] = {
    "expiry": expiry,
    "remaining": remaining,
    "mac": db[code].get("mac", "")  # 保留原 mac，如果有的話
}

    with open("license_db.json", "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)

    return jsonify({"success": True})

@app.route("/delete_license", methods=["POST"])
def delete_license():
    data = request.get_json()
    code = data.get("auth_code")

    try:
        with open("license_db.json", "r", encoding="utf-8") as f:
            db = json.load(f)
    except:
        return jsonify({"error": "讀取資料失敗"}), 500

    if code in db:
        del db[code]
        with open("license_db.json", "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2)
        return jsonify({"success": True})
    else:
        return jsonify({"error": "找不到該授權碼"}), 404

@app.route("/reset_mac", methods=["POST"])
def reset_mac():
    token = request.headers.get("Authorization", "")
    if token != "Bearer max-lic-8899-secret":
        return jsonify({"error": "無效 API 金鑰"}), 403

    data = request.get_json()
    code = data.get("auth_code")

    try:
        with open("license_db.json", "r", encoding="utf-8") as f:
            db = json.load(f)
        if code in db and "mac" in db[code]:
            db[code]["mac"] = ""
            with open("license_db.json", "w", encoding="utf-8") as f:
                json.dump(db, f, ensure_ascii=False, indent=2)
            return jsonify({"success": True})
        else:
            return jsonify({"error": "找不到綁定資訊"}), 404
    except:
        return jsonify({"error": "處理失敗"}), 500

port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port)
