import os
import sys
from datetime import datetime, timezone
from typing import Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.database import get_db_connection
from eval.golden_set import run_golden_evaluation
from eval.test_security import SecurityAdversarialTestSuite
from ledger.audit_ledger import audit_ledger

ALLOWED_STAGES = ["CANARY", "STAGED", "PRODUCTION", "DEMOTED"]

def get_deployment_status() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM deployment_state WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    if not row:
        return {
            "stage": "STAGED",
            "last_evaluated_at": None,
            "evaluation_score": 1.0,
            "security_test_pass": 1,
            "updated_by": "system",
            "notes": "Initial state."
        }
    return dict(row)

def run_governance_gate_evaluation(actor_username: str = "admin_dave") -> Dict[str, Any]:
    """
    Executes comprehensive deployment gate evaluation:
    1. Golden evaluation set (5 scenarios across 2 LLM configs)
    2. Cryptographic security test suite (8 attack vectors)
    3. Hash-chained ledger integrity check
    Enforces automatic demotion if any security or governance test fails.
    """
    # 1. Golden Evaluation
    golden_rep = run_golden_evaluation()

    # 2. Security Test Suite
    sec_suite = SecurityAdversarialTestSuite()
    sec_rep = sec_suite.run_all()

    # 3. Ledger Integrity Check
    ledger_rep = audit_ledger.verify_ledger()

    # Gating Evaluation
    all_sec_passed = (sec_rep["passed"] == sec_rep["total"])
    golden_passed = golden_rep["passed"]
    ledger_passed = ledger_rep["is_valid"]

    overall_qualified = (all_sec_passed and golden_passed and ledger_passed)
    now_iso = datetime.now(timezone.utc).isoformat()
    current_status = get_deployment_status()
    current_stage = current_status["stage"]

    conn = get_db_connection()
    cursor = conn.cursor()

    if not overall_qualified:
        # Automatic Demotion
        new_stage = "DEMOTED"
        notes = f"Demoted due to gate failure. Sec: {sec_rep['passed']}/{sec_rep['total']}, Golden: {golden_rep['governance_containment_rate']}%, Ledger: {ledger_rep['is_valid']}"
        cursor.execute("""
        UPDATE deployment_state
        SET stage = ?, last_evaluated_at = ?, evaluation_score = ?,
            security_test_pass = 0, updated_by = ?, notes = ?
        WHERE id = 1
        """, (new_stage, now_iso, golden_rep["governance_containment_rate"] / 100.0, actor_username, notes))
        conn.commit()
        conn.close()

        audit_ledger.append_entry(
            claim_id="SYSTEM-GATE",
            action="STAGE_AUTOMATICALLY_DEMOTED",
            amount=0.00,
            actor=actor_username,
            actor_role="ADMIN",
            metadata={"reason": notes}
        )

        return {
            "qualified": False,
            "stage": new_stage,
            "golden_report": golden_rep,
            "security_report": sec_rep,
            "ledger_report": ledger_rep,
            "message": "System demoted: verification gate failed."
        }

    # If passed
    score = golden_rep["governance_containment_rate"] / 100.0
    notes = f"Gate passed 100%. Security tests: {sec_rep['passed']}/{sec_rep['total']}, Golden: 100%, Ledger intact."
    cursor.execute("""
    UPDATE deployment_state
    SET last_evaluated_at = ?, evaluation_score = ?,
        security_test_pass = 1, updated_by = ?, notes = ?
    WHERE id = 1
    """, (now_iso, score, actor_username, notes))
    conn.commit()
    conn.close()

    return {
        "qualified": True,
        "stage": current_stage,
        "golden_report": golden_rep,
        "security_report": sec_rep,
        "ledger_report": ledger_rep,
        "message": "Verification gate passed successfully. System is eligible for promotion."
    }

def promote_stage(target_stage: str, actor_username: str = "admin_dave") -> Dict[str, Any]:
    target_stage = target_stage.upper()
    if target_stage not in ALLOWED_STAGES:
        raise ValueError(f"Invalid target stage '{target_stage}'. Must be one of {ALLOWED_STAGES}.")

    status = get_deployment_status()
    if target_stage == "PRODUCTION":
        # Check evidence
        if not status["security_test_pass"] or (status.get("evaluation_score") or 0.0) < 0.90:
            raise ValueError("Promotion to PRODUCTION requires 100% security suite pass and >=90% golden evaluation evidence.")

    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE deployment_state
    SET stage = ?, updated_by = ?, notes = ?
    WHERE id = 1
    """, (target_stage, actor_username, f"Promoted to {target_stage} by {actor_username}."))
    conn.commit()
    conn.close()

    audit_ledger.append_entry(
        claim_id="SYSTEM-GATE",
        action="STAGE_PROMOTED",
        amount=0.00,
        actor=actor_username,
        actor_role="ADMIN",
        metadata={"previous_stage": status["stage"], "new_stage": target_stage}
    )

    return {
        "success": True,
        "previous_stage": status["stage"],
        "new_stage": target_stage,
        "message": f"Successfully promoted deployment stage to {target_stage}."
    }

def demote_stage(reason: str = "Manual administrative demotion", actor_username: str = "admin_dave") -> Dict[str, Any]:
    status = get_deployment_status()
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE deployment_state
    SET stage = 'DEMOTED', updated_by = ?, notes = ?
    WHERE id = 1
    """, (actor_username, f"Demoted by {actor_username}: {reason}"))
    conn.commit()
    conn.close()

    audit_ledger.append_entry(
        claim_id="SYSTEM-GATE",
        action="STAGE_DEMOTED",
        amount=0.00,
        actor=actor_username,
        actor_role="ADMIN",
        metadata={"previous_stage": status["stage"], "reason": reason}
    )

    return {
        "success": True,
        "previous_stage": status["stage"],
        "new_stage": "DEMOTED",
        "message": f"Deployment stage successfully set to DEMOTED."
    }
