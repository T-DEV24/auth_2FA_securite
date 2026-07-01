"""
main.py
Point d'entrée de l'application Flask.
Initialise le serveur, enregistre les blueprints et importe
les données CSV dans MongoDB au premier démarrage.
"""
import os
import pandas as pd
import bcrypt
import pyotp
from flask import Flask
from db.connection import get_collection
from auth.routes import auth_bp
from access.routes import access_bp

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ─── Blueprints ───────────────────────────────────────────────────────────────
app.register_blueprint(auth_bp)
app.register_blueprint(access_bp)

# ─── Initialisation de la base au démarrage ───────────────────────────────────

def _init_users():
    """
    Importe datasets/users.csv dans la collection 'users'.
    Les mots de passe sont hachés avec bcrypt.
    Chaque utilisateur reçoit un secret TOTP individuel.
    """
    col = get_collection("users")
    if col.count_documents({}) > 0:
        print("[INIT] Collection 'users' déjà remplie — import ignoré.")
        return

    df = pd.read_csv(os.path.join("datasets", "users.csv"))
    docs = []
    for _, row in df.iterrows():
        # Mot de passe par défaut = user_id (à changer en prod)
        plain_pw     = row["user_id"]
        password_hash = bcrypt.hashpw(
            plain_pw.encode(), bcrypt.gensalt()
        ).decode()
        totp_secret  = pyotp.random_base32()

        docs.append({
            "user_id":       row["user_id"],
            "name":          row["name"],
            "role":          row["role"],
            "department":    row["department"],
            "mfa_enabled":   str(row["mfa_enabled"]).lower() == "true",
            "clearance":     row.get("clearance", "medical"),
            "password_hash": password_hash,
            "totp_secret":   totp_secret,
        })
    col.insert_many(docs)
    print(f"[INIT] {len(docs)} utilisateurs importés dans 'users'.")


def _init_resources():
    """Importe datasets/resources.csv dans la collection 'resources'."""
    col = get_collection("resources")
    if col.count_documents({}) > 0:
        print("[INIT] Collection 'resources' déjà remplie — import ignoré.")
        return

    df = pd.read_csv(os.path.join("datasets", "resources.csv"))
    docs = df.rename(columns={"type": "type"}).to_dict(orient="records")
    col.insert_many(docs)
    print(f"[INIT] {len(docs)} ressources importées dans 'resources'.")


def _init_logs():
    """
    Importe datasets/access_logs.csv dans 'access_logs'
    pour amorcer l'analyse dans le notebook.
    """
    col = get_collection("access_logs")
    if col.count_documents({}) > 0:
        print("[INIT] Collection 'access_logs' déjà remplie — import ignoré.")
        return

    df = pd.read_csv(os.path.join("datasets", "access_logs.csv"))
    docs = df.to_dict(orient="records")
    col.insert_many(docs)
    print(f"[INIT] {len(docs)} entrées de log importées dans 'access_logs'.")


# ─── Route de santé ───────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def home():
    return {
        "service": "BIG DATA Security API",
        "status": "running",
        "endpoints": [
            "/health",
            "/auth/*",
            "/access/*"
        ]
    }


# ─── Lancement ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Initialisation de la base MongoDB ===")
    _init_users()
    _init_resources()
    _init_logs()
    print("=== Démarrage du serveur Flask ===")
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000)),
        debug=os.getenv("FLASK_DEBUG", "true").lower() == "true",
    )