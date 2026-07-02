"""
auth/mailer.py
Envoi du code OTP par email (Gmail SMTP).
Tous les OTP sont envoyés vers OTP_RECIPIENT, quel que soit l'utilisateur.
"""
import os
import smtplib
from email.mime.text import MIMEText

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")
OTP_RECIPIENT = os.getenv("OTP_RECIPIENT")
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


def send_otp_email(user_id: str, code: str, minutes_validite: int = 3) -> bool:
    """Envoie le code OTP par email à OTP_RECIPIENT. Retourne True si l'envoi a réussi."""
    if not EMAIL_SENDER or not EMAIL_APP_PASSWORD or not OTP_RECIPIENT:
        print("[MFA] EMAIL_SENDER / EMAIL_APP_PASSWORD / OTP_RECIPIENT non configurés.")
        return False

    msg = MIMEText(
        f"Utilisateur : {user_id}\n"
        f"Code de vérification : {code}\n"
        f"Il expire dans {minutes_validite} minutes.\n\n"
        f"Si vous n'êtes pas à l'origine de cette demande, ignorez ce message."
    )
    msg["Subject"] = f"Code OTP - {user_id} - Hopital App"
    msg["From"] = EMAIL_SENDER
    msg["To"] = OTP_RECIPIENT

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_APP_PASSWORD)
            server.sendmail(EMAIL_SENDER, [OTP_RECIPIENT], msg.as_string())
        return True
    except Exception as e:
        print(f"[MFA] Echec envoi email : {e}")
        return False