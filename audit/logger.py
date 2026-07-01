"""
audit/logger.py
Fonction unique d'écriture dans access_logs.
Appelée systématiquement par le moteur de décision (autorisé OU refusé).
Un refus non journalisé = une tentative d'intrusion invisible.
"""
from db.connection import get_collection
from db.models import make_log

def log_access(user_id: str, role: str, department: str,
               resource_id: str, resource_type: str, sensitivity: str,
               action: str, ip: str, success: bool,
               mfa_passed: bool, reason: str) -> None:
    """
    Insère une entrée dans la collection access_logs.
    Champs garantis : timestamp, user_id, role, department,
                      resource_id, resource_type, sensitivity,
                      action, ip, success, mfa_passed, reason.
    """
    entry = make_log(
        user_id=user_id,
        role=role,
        department=department,
        resource_id=resource_id,
        resource_type=resource_type,
        sensitivity=sensitivity,
        action=action,
        ip=ip,
        success=success,
        mfa_passed=mfa_passed,
        reason=reason,
    )
    try:
        get_collection("access_logs").insert_one(entry)
    except Exception as exc:
        # En dernier recours : ne jamais laisser une erreur DB
        # bloquer l'application, mais le signaler clairement.
        print(f"[AUDIT ERROR] Impossible d'écrire dans access_logs : {exc}")