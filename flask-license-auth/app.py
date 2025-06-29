
from flask import Flask, request, jsonify, render_template
from datetime import datetime
import json
import os

app = Flask(__name__, template_folder="templates")

DB_FILE = "license_db.json"

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_db(db):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)

@app.route("/check_license", methods=["POST"])
def check_license():
    data = request.json
    auth_code = data.get("auth_code")
    mac = data.get("mac")

    db = load_db()
    lic = db.get(auth_code)

    if not lic:
        return jsonify({"status": "fail", "msg": "授權碼錯誤"})

    if datetime.today() > datetime.strptime(lic["expiry"], "%Y-%m-%d"):
        return jsonify({"status": "fail", "msg": "授權已過期"})

    if mac in lic["used_macs"]:
        return jsonify({"status": "success", "msg": "已註冊裝置", "expiry": lic["expiry"]})

    if lic["remaining"] <= 0:
        return jsonify({"status": "fail", "msg": "授權次數已用完"})

    lic["used_macs"].append(mac)
    lic["remaining"] -= 1
    save_db(db)

    return jsonify({"status": "success", "msg": "新裝置已註冊", "expiry": lic["expiry"]})

@app.route("/update_license", methods=["POST"])
def update_license():
    data = request.json
    auth_code = data.get("auth_code")
    expiry = data.get("expiry")
    remaining = data.get("remaining")

    db = load_db()
    if auth_code not in db:
        return jsonify({"status": "fail", "msg": "授權碼不存在"})

    if expiry:
        db[auth_code]["expiry"] = expiry
    if remaining is not None:
        db[auth_code]["remaining"] = int(remaining)

    save_db(db)
    return jsonify({"status": "success", "msg": "授權更新成功"})

@app.route("/admin")
def admin_page():
    db = load_db()
    return render_template("admin.html", db=db)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
