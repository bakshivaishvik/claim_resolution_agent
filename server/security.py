import os
import json
import base64
import hmac
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple, Optional

HMAC_SECRET_KEY = os.environ.get("HMAC_SECRET_KEY", "cra-governed-audit-hmac-sec-token-2026-key")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "cra-governed-audit-jwt-sec-token-2026-key")

def compute_claim_payload_hash(claim_id: str, customer_id: str, amount: float, reason: str, status: str) -> str:
    """
    Computes a canonical SHA-256 hash of the critical claim state.
    Used to detect stale approvals or mid-flight claim tampering.
    """
    canonical = {
        "claim_id": str(claim_id),
        "customer_id": str(customer_id),
        "amount": round(float(amount), 2),
        "reason": str(reason),
        "status": str(status)
    }
    serialized = json.dumps(canonical, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

def generate_approval_token(
    claim_id: str,
    amount: float,
    decision: str,
    payload_hash: str,
    approver_username: str,
    approver_role: str,
    step: int = 1,
    validity_minutes: int = 15,
    custom_secret: Optional[str] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Generates a cryptographically signed HMAC-SHA256 short-lived approval token.
    """
    secret = custom_secret or HMAC_SECRET_KEY
    approval_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=validity_minutes)

    payload = {
        "approval_id": approval_id,
        "claim_id": str(claim_id),
        "amount": round(float(amount), 2),
        "decision": decision,
        "payload_hash": payload_hash,
        "approver_username": approver_username,
        "approver_role": approver_role,
        "step": int(step),
        "issued_at": now.isoformat(),
        "expires_at": expires_at.isoformat()
    }

    payload_json = json.dumps(payload, sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8")

    signature = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    token_str = f"{payload_b64}.{signature}"
    return token_str, payload

def verify_approval_token(
    token_str: str,
    current_claim_payload_hash: Optional[str] = None,
    custom_secret: Optional[str] = None
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Validates cryptographic signature, expiry, and payload hash parity.
    Returns (is_valid, reason_code, payload_dict).
    """
    if not token_str or "." not in token_str:
        return False, "MALFORMED_TOKEN", None

    try:
        parts = token_str.strip().split(".")
        if len(parts) != 2:
            return False, "MALFORMED_TOKEN", None

        payload_b64, signature = parts[0], parts[1]
        secret = custom_secret or HMAC_SECRET_KEY

        expected_sig = hmac.new(
            secret.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        # 1. Cryptographic HMAC Signature Verification (Constant Time)
        if not hmac.compare_digest(expected_sig, signature):
            return False, "INVALID_SIGNATURE", None

        # 2. Decode Payload
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))

        # 3. Expiration Check
        expires_at_str = payload.get("expires_at")
        if expires_at_str:
            expires_at = datetime.fromisoformat(expires_at_str)
            now = datetime.now(timezone.utc)
            if now > expires_at:
                return False, "TOKEN_EXPIRED", payload

        # 4. Payload Hash Parity (Stale Approval / Claim Modification Check)
        if current_claim_payload_hash is not None:
            token_payload_hash = payload.get("payload_hash")
            if token_payload_hash != current_claim_payload_hash:
                return False, "PAYLOAD_HASH_MISMATCH", payload

        return True, "VALID", payload

    except Exception as e:
        return False, f"VERIFICATION_ERROR: {str(e)}", None

def naive_verify_approval_token(token_str: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Vulnerable naive verifier simulation demonstrating insecure architecture.
    Does not verify HMAC signature or check payload hash consistency.
    """
    if not token_str or "." not in token_str:
        return False, "NAIVE_FAILED_NO_TOKEN", None
    try:
        payload_b64 = token_str.split(".")[0]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
        # Blindly accepts any token that decodes as valid JSON
        return True, "NAIVE_ACCEPTED_INSECURE", payload
    except Exception:
        return False, "NAIVE_PARSE_ERROR", None
