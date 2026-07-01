"""Application Flask web + API pour le TP MFA/RBAC/ABAC hospitalier."""
import csv
import os
from datetime import datetime, timezone
from functools import wraps

import bcrypt
import pandas as pd
import pyotp
from flask import (Flask, Response, flash, redirect, render_template, request,
                   session, url_for)

from access.engine import authorize
from access.routes import access_bp
from auth.routes import auth_bp
from auth.security import create_jwt, get_current_totp, verify_password, verify_totp
from db.connection import get_collection

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
app.register_blueprint(auth_bp)
app.register_blueprint(access_bp)

DATASETS = "datasets"


def _safe_find(collection_name, query=None, projection=None):
    try:
        return list(get_collection(collection_name).find(query or {}, projection or {"_id": 0}))
    except Exception:
        filename = {"users": "users.csv", "resources": "resources.csv", "access_logs": "access_logs.csv"}[collection_name]
        with open(os.path.join(DATASETS, filename), newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))


def _safe_find_one(collection_name, query):
    for item in _safe_find(collection_name):
        if all(str(item.get(k)) == str(v) for k, v in query.items()):
            return item
    return None


def _init_users():
    col = get_collection("users")
    if col.count_documents({}) > 0:
        print("[INIT] Collection 'users' déjà remplie — import ignoré.")
        return
    df = pd.read_csv(os.path.join(DATASETS, "users.csv"))
    docs = []
    for _, row in df.iterrows():
        docs.append({
            "user_id": row["user_id"], "name": row["name"], "role": row["role"],
            "department": row["department"],
            "mfa_enabled": str(row["mfa_enabled"]).lower() == "true",
            "clearance": row.get("clearance", "medical"),
            "password_hash": bcrypt.hashpw(str(row["user_id"]).encode(), bcrypt.gensalt()).decode(),
            "totp_secret": pyotp.random_base32(),
        })
    col.insert_many(docs)
    print(f"[INIT] {len(docs)} utilisateurs importés dans 'users'.")


def _init_resources():
    col = get_collection("resources")
    if col.count_documents({}) > 0:
        print("[INIT] Collection 'resources' déjà remplie — import ignoré.")
        return
    docs = pd.read_csv(os.path.join(DATASETS, "resources.csv")).to_dict(orient="records")
    col.insert_many(docs)
    print(f"[INIT] {len(docs)} ressources importées dans 'resources'.")


def _init_logs():
    col = get_collection("access_logs")
    if col.count_documents({}) > 0:
        print("[INIT] Collection 'access_logs' déjà remplie — import ignoré.")
        return
    docs = pd.read_csv(os.path.join(DATASETS, "access_logs.csv")).to_dict(orient="records")
    col.insert_many(docs)
    print(f"[INIT] {len(docs)} entrées de log importées dans 'access_logs'.")


def current_user():
    uid = session.get("user_id")
    return _safe_find_one("users", {"user_id": uid}) if uid else None


@app.context_processor
def inject_user():
    user = current_user()
    return {"current_user": user, "session_started": session.get("login_time")}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Veuillez vous connecter pour continuer.", "warning")
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login_page"))


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        user_id = request.form.get("user_id", "").strip()
        password = request.form.get("password", "")
        user = _safe_find_one("users", {"user_id": user_id})
        password_ok = bool(user and ((user.get("password_hash") and verify_password(password, user["password_hash"])) or password == user_id))
        if not password_ok:
            flash("Identifiants invalides.", "danger")
            return render_template("login.html")
        session.clear(); session["pending_user_id"] = user_id
        if str(user.get("mfa_enabled")).lower() == "true":
            flash("Authentification MFA requise.", "info")
            return redirect(url_for("verify_otp_page"))
        _open_session(user, mfa_ok=False)
        return redirect(url_for("dashboard"))
    return render_template("login.html")


def _open_session(user, mfa_ok):
    session["user_id"] = user["user_id"]
    session["mfa_ok"] = mfa_ok
    session["login_time"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    session["token"] = create_jwt(user["user_id"], user["role"], user["department"], mfa_ok=mfa_ok)
    session.pop("pending_user_id", None)


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp_page():
    user = _safe_find_one("users", {"user_id": session.get("pending_user_id")})
    if not user:
        return redirect(url_for("login_page"))
    debug_code = get_current_totp(user["totp_secret"]) if user.get("totp_secret") else None
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if user.get("totp_secret") and not verify_totp(user["totp_secret"], otp):
            flash("Code OTP invalide ou expiré.", "danger")
            return render_template("verify_otp.html", debug_code=debug_code)
        _open_session(user, mfa_ok=True)
        return redirect(url_for("dashboard"))
    return render_template("verify_otp.html", debug_code=debug_code)


@app.route("/logout")
def logout():
    session.clear(); flash("Session fermée avec succès.", "success")
    return redirect(url_for("login_page"))


@app.route("/dashboard")
@login_required
def dashboard():
    logs = sorted(_safe_find("access_logs"), key=lambda x: x.get("timestamp", ""), reverse=True)
    uid = session["user_id"]
    user_logs = [l for l in logs if l.get("user_id") == uid]
    denied = [l for l in user_logs if str(l.get("success")).lower() == "false"]
    by_type = {}
    for l in user_logs: by_type[l.get("resource_type", "inconnu")] = by_type.get(l.get("resource_type", "inconnu"), 0) + 1
    return render_template("dashboard.html", stats={"total": len(user_logs), "denied": len(denied), "recent": user_logs[:5], "by_type": by_type})


@app.route("/resources")
@login_required
def resources_page():
    return render_template("resources.html", resources=_safe_find("resources"))


@app.route("/resources/<resource_id>", methods=["GET", "POST"])
@login_required
def resource_detail(resource_id):
    resource = _safe_find_one("resources", {"resource_id": resource_id})
    if not resource:
        flash("Ressource introuvable.", "danger"); return redirect(url_for("resources_page"))
    decision = None
    if request.method == "POST":
        user = current_user(); user = dict(user)
        ok, reason = authorize(user, resource, "read", {"mfa_ok": session.get("mfa_ok", False), "hour": datetime.now(timezone.utc).hour}, request.remote_addr or "0.0.0.0")
        decision = {"ok": ok, "reason": reason}
        flash(reason, "success" if ok else "danger")
    history = [l for l in _safe_find("access_logs") if l.get("resource_id") == resource_id][-10:]
    return render_template("resource_detail.html", resource=resource, history=history, decision=decision)


@app.route("/audit-logs")
@login_required
def audit_logs_page():
    logs = sorted(_safe_find("access_logs"), key=lambda x: x.get("timestamp", ""), reverse=True)
    denies_by_user = {}
    for l in logs:
        if str(l.get("success")).lower() == "false": denies_by_user[l.get("user_id", "?")] = denies_by_user.get(l.get("user_id", "?"), 0) + 1
    return render_template("audit_logs.html", logs=logs[:250], denies_by_user=denies_by_user)


@app.route("/audit-logs/export.csv")
@login_required
def export_audit_csv():
    logs = _safe_find("access_logs")
    fields = ["timestamp", "user_id", "role", "department", "resource_id", "resource_type", "sensitivity", "action", "ip", "success", "mfa_passed", "reason"]
    output = ",".join(fields) + "\n" + "\n".join(",".join(str(log.get(f, "")).replace(",", " ") for f in fields) for log in logs)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=audit_logs.csv"})


if __name__ == "__main__":
    print("=== Initialisation de la base MongoDB ===")
    try:
        _init_users(); _init_resources(); _init_logs()
    except Exception as exc:
        print(f"[INIT WARNING] MongoDB indisponible, mode CSV en lecture seule: {exc}")
    print("=== Démarrage du serveur Flask ===")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG", "true").lower() == "true")
