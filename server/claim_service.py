import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from server.database import get_db_connection, compute_claim_payload_hash
from server.security import verify_approval_token
from ledger.audit_ledger import audit_ledger

class ClaimService:
    def get_all_claims(self, status: Optional[str] = None, risk: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = """
        SELECT c.*, cust.name as customer_name, cust.email as customer_email,
               t.item_name, t.item_category
        FROM claims c
        JOIN customers cust ON c.customer_id = cust.id
        LEFT JOIN transactions t ON c.transaction_id = t.id
        WHERE 1=1
        """
        params = []
        if status and status != "ALL":
            query += " AND c.status = ?"
            params.append(status)
        if risk and risk != "ALL":
            query += " AND c.risk_category = ?"
            params.append(risk)

        query += " ORDER BY c.created_at DESC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        claims = [dict(r) for r in rows]
        conn.close()
        return claims

    def get_claim_by_id(self, claim_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT c.*, cust.name as customer_name, cust.email as customer_email,
               cust.account_age_days, cust.risk_score as customer_risk_score,
               cust.total_orders, cust.total_refunds_count, cust.total_refunds_amount,
               cust.is_flagged as customer_is_flagged,
               t.item_name, t.item_category, t.amount as transaction_amount,
               t.purchase_date, t.payment_method
        FROM claims c
        JOIN customers cust ON c.customer_id = cust.id
        LEFT JOIN transactions t ON c.transaction_id = t.id
        WHERE c.id = ?
        """, (claim_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        claim = dict(row)

        # Get approvals
        cursor.execute("SELECT * FROM approvals WHERE claim_id = ? ORDER BY step ASC", (claim_id,))
        claim["approvals"] = [dict(r) for r in cursor.fetchall()]

        # Get AI analysis
        cursor.execute("SELECT * FROM ai_analyses WHERE claim_id = ? ORDER BY created_at DESC LIMIT 1", (claim_id,))
        ai_row = cursor.fetchone()
        claim["ai_analysis"] = dict(ai_row) if ai_row else None

        conn.close()
        return claim

    def create_claim(
        self,
        customer_id: str,
        transaction_id: str,
        amount: float,
        reason: str,
        description: str,
        actor_username: str = "agent_alice"
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Generate unique claim ID
        claim_id = f"CLM-{uuid.uuid4().hex[:6].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        initial_status = "SUBMITTED"

        # Fetch customer and transaction for immediate policy classification
        cursor.execute("SELECT * FROM customers WHERE id = ?", (customer_id,))
        cust_row = cursor.fetchone()
        customer_data = dict(cust_row) if cust_row else {}

        cursor.execute("SELECT * FROM transactions WHERE id = ?", (transaction_id,))
        txn_row = cursor.fetchone()
        transaction_data = dict(txn_row) if txn_row else {}

        from server.policy_engine import policy_engine
        eval_result = policy_engine.evaluate(
            claim_data={"amount": amount, "reason": reason},
            customer_data=customer_data,
            transaction_data=transaction_data
        )

        initial_risk = eval_result["risk_category"]
        clause_id = eval_result["clause_id"]
        clause_text = f"{eval_result['clause_name']}: {eval_result['clause_text']}"

        if initial_risk == "ROUTINE":
            initial_status = "APPROVED_PENDING_EXECUTION"
        elif initial_risk == "TIER_DECLINE":
            initial_status = "REJECTED"
        else:
            initial_status = "PENDING_APPROVAL_STEP1"

        # Calculate initial payload hash
        payload_hash = compute_claim_payload_hash(
            claim_id=claim_id,
            customer_id=customer_id,
            amount=amount,
            reason=reason,
            status=initial_status
        )
        idempotency_key = f"IDEM-{uuid.uuid4().hex[:8].upper()}"

        cursor.execute("""
        INSERT INTO claims (
            id, customer_id, transaction_id, amount, reason, description,
            status, risk_category, policy_clause_id, policy_clause_text,
            payload_hash, idempotency_key, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            claim_id, customer_id, transaction_id, round(float(amount), 2),
            reason, description, initial_status, initial_risk, clause_id, clause_text,
            payload_hash, idempotency_key, now_iso, now_iso
        ))

        conn.commit()
        conn.close()

        # Log into audit ledger
        audit_ledger.append_entry(
            claim_id=claim_id,
            action="CLAIM_CREATED",
            amount=amount,
            actor=actor_username,
            actor_role="AGENT",
            metadata={"reason": reason, "description": description[:60], "risk_category": initial_risk}
        )

        return self.get_claim_by_id(claim_id)

    def execute_refund(
        self,
        claim_id: str,
        idempotency_key: str,
        actor_username: str = "system",
        actor_role: str = "EXECUTION_ENGINE"
    ) -> Dict[str, Any]:
        """
        Central secure refund execution function.
        Enforces token signature verification, payload hash parity,
        single-use token consumption, multi-approver requirements,
        and idempotency locks.
        """
        if not idempotency_key:
            raise ValueError("Idempotency key is required for refund execution.")

        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Check Idempotency Key across all claims
        cursor.execute("SELECT id, status, amount FROM claims WHERE idempotency_key = ? AND status = 'REFUNDED'", (idempotency_key,))
        existing_refunded = cursor.fetchone()
        if existing_refunded:
            conn.close()
            return {
                "success": True,
                "is_idempotent_replay": True,
                "claim_id": existing_refunded["id"],
                "status": "REFUNDED",
                "message": "Idempotent execution: Claim has already been executed under this idempotency key. No duplicate payout was triggered."
            }

        # 2. Retrieve Claim
        cursor.execute("SELECT * FROM claims WHERE id = ?", (claim_id,))
        claim_row = cursor.fetchone()
        if not claim_row:
            conn.close()
            raise ValueError(f"Claim '{claim_id}' not found.")

        claim = dict(claim_row)
        risk_cat = claim["risk_category"]
        current_status = claim["status"]

        if current_status == "REFUNDED":
            conn.close()
            raise ValueError("Claim has already been refunded. Duplicate payout blocked.")

        if risk_cat == "TIER_DECLINE" or current_status == "REJECTED":
            conn.close()
            raise ValueError("Governed policy strictly forbids refund execution for TIER_DECLINE or REJECTED claims.")

        # Recalculate current claim payload hash at the present state
        current_hash = compute_claim_payload_hash(
            claim_id=claim_id,
            customer_id=claim["customer_id"],
            amount=claim["amount"],
            reason=claim["reason"],
            status=current_status
        )

        # 3. Retrieve Approval Records
        cursor.execute("SELECT * FROM approvals WHERE claim_id = ? ORDER BY step ASC", (claim_id,))
        approvals = [dict(r) for r in cursor.fetchall()]

        # 4. Governance & Cryptographic Verification by Risk Category
        consumed_token_ids = []

        if risk_cat == "ROUTINE":
            # Routine claims require status to be APPROVED_PENDING_EXECUTION (or ANALYZED)
            if current_status not in ["APPROVED_PENDING_EXECUTION", "ANALYZED"]:
                conn.close()
                raise ValueError(f"Routine claim is in invalid status: {current_status}")

        elif risk_cat == "SINGLE_APPROVAL":
            if not approvals:
                conn.close()
                raise ValueError("SINGLE_APPROVAL requires one verified cryptographic approval token.")

            appr = approvals[0]
            token_str = appr["approval_token"]

            # Token Already Consumed Check (Replay Prevention)
            if appr["is_consumed"]:
                conn.close()
                raise ValueError("Security Violation: Approval token has already been consumed! Replay attack detected.")

            # Cryptographic HMAC & Expiry & Payload Hash Verification
            is_valid, reason, payload = verify_approval_token(token_str, current_claim_payload_hash=current_hash)
            if not is_valid:
                conn.close()
                raise ValueError(f"Cryptographic Verification Failed: {reason}. Execution denied.")

            consumed_token_ids.append(appr["id"])

        elif risk_cat == "FOUR_EYES":
            if len(approvals) < 2:
                conn.close()
                raise ValueError(f"Four-Eyes Governance requires two completed approvals. Found {len(approvals)}.")

            appr1, appr2 = approvals[0], approvals[1]

            # Replay / Already Consumed check
            if appr1["is_consumed"] or appr2["is_consumed"]:
                conn.close()
                raise ValueError("Security Violation: One or more Four-Eyes approval tokens have already been consumed! Replay attack detected.")

            # Distinct Approver Verification
            if appr1["approver_username"] == appr2["approver_username"]:
                conn.close()
                raise ValueError("Four-Eyes Collision: Dual approvals must originate from two distinct individuals.")

            # Verify Token 1
            is_valid1, reason1, _ = verify_approval_token(appr1["approval_token"], current_claim_payload_hash=appr1["payload_hash"])
            if not is_valid1:
                conn.close()
                raise ValueError(f"Step 1 Cryptographic Token Invalid: {reason1}")

            # Verify Token 2
            is_valid2, reason2, _ = verify_approval_token(appr2["approval_token"], current_claim_payload_hash=current_hash)
            if not is_valid2:
                conn.close()
                raise ValueError(f"Step 2 Cryptographic Token Invalid: {reason2}")

            consumed_token_ids.extend([appr1["id"], appr2["id"]])

        # 5. Execute Refund State Transition
        now_iso = datetime.now(timezone.utc).isoformat()
        final_status = "REFUNDED"

        final_payload_hash = compute_claim_payload_hash(
            claim_id=claim_id,
            customer_id=claim["customer_id"],
            amount=claim["amount"],
            reason=claim["reason"],
            status=final_status
        )

        # Mark tokens as consumed
        for t_id in consumed_token_ids:
            cursor.execute("""
            UPDATE approvals SET is_consumed = 1, consumed_at = ? WHERE id = ?
            """, (now_iso, t_id))

        # Update claim
        cursor.execute("""
        UPDATE claims
        SET status = ?, payload_hash = ?, idempotency_key = ?, updated_at = ?
        WHERE id = ?
        """, (final_status, final_payload_hash, idempotency_key, now_iso, claim_id))

        # Update customer statistics
        cursor.execute("""
        UPDATE customers
        SET total_refunds_count = total_refunds_count + 1,
            total_refunds_amount = total_refunds_amount + ?
        WHERE id = ?
        """, (claim["amount"], claim["customer_id"]))

        conn.commit()
        conn.close()

        # 6. Append to Hash-Chained Audit Ledger
        audit_ledger.append_entry(
            claim_id=claim_id,
            action="REFUND_EXECUTED",
            amount=claim["amount"],
            actor=actor_username,
            actor_role=actor_role,
            metadata={
                "idempotency_key": idempotency_key,
                "risk_category": risk_cat,
                "consumed_tokens": len(consumed_token_ids)
            }
        )

        return {
            "success": True,
            "claim_id": claim_id,
            "amount": claim["amount"],
            "status": "REFUNDED",
            "idempotency_key": idempotency_key,
            "consumed_tokens": consumed_token_ids,
            "executed_at": now_iso,
            "message": f"Refund of ${claim['amount']:.2f} securely executed and recorded into hash-chained ledger."
        }

claim_service = ClaimService()
