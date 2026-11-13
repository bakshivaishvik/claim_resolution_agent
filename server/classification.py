import json
from datetime import datetime, timezone
from server.database import get_db_connection, compute_claim_payload_hash
from server.ai_service import ai_service
from server.policy_engine import policy_engine
from ledger.audit_ledger import audit_ledger

def classify_claim(claim_id: str, actor_username: str = "system") -> dict:
    """
    Coordinates AI recommendation and deterministic policy governance.
    Enforces that deterministic policy strictly overrides AI if they diverge.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch claim
    cursor.execute("SELECT * FROM claims WHERE id = ?", (claim_id,))
    claim_row = cursor.fetchone()
    if not claim_row:
        conn.close()
        raise ValueError(f"Claim with ID {claim_id} not found.")

    claim = dict(claim_row)

    # Fetch customer
    cursor.execute("SELECT * FROM customers WHERE id = ?", (claim["customer_id"],))
    customer_row = cursor.fetchone()
    customer = dict(customer_row) if customer_row else {}

    # Fetch transaction
    cursor.execute("SELECT * FROM transactions WHERE id = ?", (claim["transaction_id"],))
    transaction_row = cursor.fetchone()
    transaction = dict(transaction_row) if transaction_row else {}

    # 1. Advisory AI Analysis (Groq SDK)
    ai_result = ai_service.analyze_claim(claim, customer, transaction)

    # 2. Deterministic Policy Evaluation (Hard Governance Ground Truth)
    policy_result = policy_engine.evaluate(claim, customer, transaction)

    # Store AI Analysis in DB
    now_iso = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    INSERT INTO ai_analyses (claim_id, summary, risk_indicators, customer_history_evaluation, suggested_category, explanation, model_used, is_mock, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        claim_id,
        ai_result["summary"],
        json.dumps(ai_result["risk_indicators"]),
        ai_result["customer_history_evaluation"],
        ai_result["suggested_category"],
        ai_result["explanation"],
        ai_result["model_used"],
        1 if ai_result["is_mock"] else 0,
        now_iso
    ))
    ai_analysis_id = cursor.lastrowid

    # 3. Governance Resolution
    # The deterministic policy ALWAYS dictates the governed risk category.
    governed_category = policy_result["risk_category"]
    is_overridden = (ai_result["suggested_category"] != governed_category)

    # Determine status progression based on governed category
    if governed_category == "ROUTINE":
        new_status = "APPROVED_PENDING_EXECUTION"
    elif governed_category == "TIER_DECLINE":
        new_status = "REJECTED"
    else: # SINGLE_APPROVAL or FOUR_EYES
        new_status = "PENDING_APPROVAL_STEP1"

    new_payload_hash = compute_claim_payload_hash(
        claim_id=claim_id,
        customer_id=claim["customer_id"],
        amount=claim["amount"],
        reason=claim["reason"],
        status=new_status
    )

    # Update Claim record
    cursor.execute("""
    UPDATE claims
    SET risk_category = ?,
        policy_clause_id = ?,
        policy_clause_text = ?,
        status = ?,
        payload_hash = ?,
        ai_analysis_id = ?,
        updated_at = ?
    WHERE id = ?
    """, (
        governed_category,
        policy_result["clause_id"],
        f"{policy_result['clause_name']}: {policy_result['clause_text']}",
        new_status,
        new_payload_hash,
        ai_analysis_id,
        now_iso,
        claim_id
    ))
    conn.commit()
    conn.close()

    # Append to Hash-Chained Audit Ledger
    audit_ledger.append_entry(
        claim_id=claim_id,
        action="AI_ANALYZED",
        amount=claim["amount"],
        actor=actor_username,
        actor_role="SYSTEM_AI",
        metadata={
            "ai_suggested": ai_result["suggested_category"],
            "governed_category": governed_category,
            "policy_clause": policy_result["clause_id"],
            "is_overridden": is_overridden,
            "model_used": ai_result["model_used"]
        }
    )

    return {
        "claim_id": claim_id,
        "ai_result": ai_result,
        "policy_result": policy_result,
        "governed_category": governed_category,
        "is_overridden": is_overridden,
        "new_status": new_status,
        "new_payload_hash": new_payload_hash
    }
