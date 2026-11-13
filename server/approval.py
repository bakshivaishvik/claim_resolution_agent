from datetime import datetime, timezone
from server.database import get_db_connection, compute_claim_payload_hash
from server.security import generate_approval_token
from ledger.audit_ledger import audit_ledger

def submit_approval_decision(
    claim_id: str,
    approver_username: str,
    approver_role: str,
    decision: str, # "APPROVED" or "REJECTED"
    step: int = 1,
    notes: str = ""
) -> dict:
    """
    Processes an approval or rejection step for a claim.
    Generates HMAC-signed approval token and updates workflow state.
    """
    decision = decision.upper()
    if decision not in ["APPROVED", "REJECTED"]:
        raise ValueError("Decision must be either 'APPROVED' or 'REJECTED'.")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM claims WHERE id = ?", (claim_id,))
    claim_row = cursor.fetchone()
    if not claim_row:
        conn.close()
        raise ValueError(f"Claim '{claim_id}' not found.")

    claim = dict(claim_row)
    risk_cat = claim["risk_category"]
    current_status = claim["status"]

    # 1. Governance Pre-conditions
    if risk_cat == "TIER_DECLINE":
        conn.close()
        raise ValueError("Governed policy strictly prohibits approving claims classified under TIER_DECLINE.")

    if current_status in ["REFUNDED", "REJECTED"]:
        conn.close()
        raise ValueError(f"Cannot approve claim already in terminal state: {current_status}.")

    # Fetch existing approvals for this claim
    cursor.execute("SELECT * FROM approvals WHERE claim_id = ? ORDER BY step ASC", (claim_id,))
    existing_approvals = [dict(r) for r in cursor.fetchall()]

    # 2. Check Four-Eyes distinctness
    if risk_cat == "FOUR_EYES":
        if step == 1:
            if existing_approvals:
                conn.close()
                raise ValueError("Step 1 approval is already recorded for this claim.")
        elif step == 2:
            if not existing_approvals:
                conn.close()
                raise ValueError("Step 1 approval must be completed before Step 2.")
            first_approval = existing_approvals[0]
            if first_approval["approver_username"] == approver_username:
                conn.close()
                raise ValueError("Four-Eyes Principle Violation: Step 2 cannot be approved by the same individual who approved Step 1!")
            if approver_role not in ["SENIOR_APPROVER", "ADMIN"]:
                conn.close()
                raise ValueError("Step 2 authorization for Four-Eyes claims requires Senior Approver or Admin role.")
    elif risk_cat == "SINGLE_APPROVAL":
        if existing_approvals:
            conn.close()
            raise ValueError("Claim has already received required single approval.")
        if approver_role not in ["APPROVER", "SENIOR_APPROVER", "ADMIN"]:
            conn.close()
            raise ValueError("Single approval requires certified Approver, Senior Approver, or Admin.")

    now_iso = datetime.now(timezone.utc).isoformat()

    # If REJECTED
    if decision == "REJECTED":
        new_status = "REJECTED"
        new_payload_hash = compute_claim_payload_hash(
            claim_id=claim_id,
            customer_id=claim["customer_id"],
            amount=claim["amount"],
            reason=claim["reason"],
            status=new_status
        )
        cursor.execute("""
        UPDATE claims
        SET status = ?, payload_hash = ?, updated_at = ?
        WHERE id = ?
        """, (new_status, new_payload_hash, now_iso, claim_id))
        conn.commit()
        conn.close()

        audit_ledger.append_entry(
            claim_id=claim_id,
            action="CLAIM_REJECTED",
            amount=claim["amount"],
            actor=approver_username,
            actor_role=approver_role,
            metadata={"step": step, "reason": notes or "Rejected by reviewer"}
        )

        return {
            "success": True,
            "decision": "REJECTED",
            "claim_id": claim_id,
            "status": new_status,
            "message": "Claim has been formally rejected and closed."
        }

    # If APPROVED: Compute new state & Generate Cryptographic HMAC Token
    if risk_cat == "FOUR_EYES" and step == 1:
        new_status = "PENDING_APPROVAL_STEP2"
    else:
        new_status = "APPROVED_PENDING_EXECUTION"

    # Compute expected payload hash at approval moment
    approval_payload_hash = compute_claim_payload_hash(
        claim_id=claim_id,
        customer_id=claim["customer_id"],
        amount=claim["amount"],
        reason=claim["reason"],
        status=new_status
    )

    token_str, token_payload = generate_approval_token(
        claim_id=claim_id,
        amount=claim["amount"],
        decision="APPROVED",
        payload_hash=approval_payload_hash,
        approver_username=approver_username,
        approver_role=approver_role,
        step=step,
        validity_minutes=20
    )

    # Persist approval record
    cursor.execute("""
    INSERT INTO approvals (
        id, claim_id, approver_username, approver_role, decision, step,
        approval_token, payload_hash, expires_at, is_consumed, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
    """, (
        token_payload["approval_id"],
        claim_id,
        approver_username,
        approver_role,
        "APPROVED",
        step,
        token_str,
        approval_payload_hash,
        token_payload["expires_at"],
        now_iso
    ))

    # Update claim status and hash
    cursor.execute("""
    UPDATE claims
    SET status = ?, payload_hash = ?, updated_at = ?
    WHERE id = ?
    """, (new_status, approval_payload_hash, now_iso, claim_id))

    conn.commit()
    conn.close()

    # Log to audit ledger
    action_name = "APPROVAL_GRANTED_STEP1" if step == 1 else "APPROVAL_GRANTED_STEP2"
    audit_ledger.append_entry(
        claim_id=claim_id,
        action=action_name,
        amount=claim["amount"],
        actor=approver_username,
        actor_role=approver_role,
        metadata={
            "approval_id": token_payload["approval_id"],
            "step": step,
            "token_signature_preview": token_str.split(".")[1][:16] + "..."
        }
    )

    return {
        "success": True,
        "decision": "APPROVED",
        "claim_id": claim_id,
        "step": step,
        "new_status": new_status,
        "token": token_str,
        "token_payload": token_payload
    }
