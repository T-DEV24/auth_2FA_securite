"""
auth/security.py
Hachage de mot de passe (bcrypt) et gestion TOTP (pyotp).
Isolé pour être testable indépendamment.
"""
import bcrypt
import pyotp
import jwt
import os
from datetime import datetime, timedelta, timezone

JWT_SECRET  = os.getenv("JWT_SECRET", "change_me_in_production")
JWT_ALGO    = "HS256"
JWT_EXPIRY  = int(os.getenv("JWT_EXPIRY_MINUTES", 60))
TOTP_INTERVAL_SECONDS = int(os.getenv("TOTP_INTERVAL_SECONDS", 180))

# ─── Hachage de mot de passe ──────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Hache le mot de passe avec bcrypt. Ne jamais stocker le mot de passe en clair."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plain.encode(), salt).decode()

def verify_password(plain: str, hashed: str) -> bool:
    """Vérifie qu'un mot de passe correspond au hash stocké."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())

# ─── TOTP (MFA) ───────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    """Génère un secret TOTP aléatoire unique à stocker par utilisateur."""
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str, issuer: str = "Hopital") -> str:
    """Retourne l'URI otpauth:// pour générer un QR code."""
    totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL_SECONDS)
    return totp.provisioning_uri(name=username, issuer_name=issuer)

def verify_totp(secret: str, code: str) -> bool:
    """
    Vérifie le code TOTP fourni par l'utilisateur.
    Le code expire après 3 minutes par défaut.
    """
    totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL_SECONDS)
    return totp.verify(code, valid_window=0)

def get_current_totp(secret: str) -> str:
    """Renvoie le code TOTP courant (utile pour les tests)."""
    return pyotp.TOTP(secret, interval=TOTP_INTERVAL_SECONDS).now()

# ─── JWT ──────────────────────────────────────────────────────────────────────

def create_jwt(user_id: str, role: str, department: str, mfa_ok: bool) -> str:
    """
    Émet un JWT signé contenant l'identité et le statut MFA.
    Le JWT prouve l'identité ; c'est le moteur RBAC/ABAC qui décide de l'accès.
    """
    payload = {
        "sub":        user_id,
        "role":       role,
        "department": department,
        "mfa_ok":     mfa_ok,
        "exp":        datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY),
        "iat":        datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_jwt(token: str) -> dict:
    """
    Décode et valide le JWT.
    Lève jwt.ExpiredSignatureError ou jwt.InvalidTokenError si invalide.
    """
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])