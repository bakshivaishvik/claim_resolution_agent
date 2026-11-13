import os
import json
from datetime import datetime, timezone

POLICY_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy", "refund_policies.json")

class PolicyEngine:
    def __init__(self, policy_path: str = None):
        self.policy_path = policy_path or POLICY_FILE_PATH
        self._load_policies()

    def _load_policies(self):
        if os.path.exists(self.policy_path):
            with open(self.policy_path, "r", encoding="utf-8") as f:
                self.policy_data = json.load(f)
        else:
            self.policy_data = {"policies": []}

    def get_clause(self, clause_id: str):
        for p in self.policy_data.get("policies", []):
            if p.get("clause_id") == clause_id:
                return p
        return None

    def evaluate(self, claim_data: dict, customer_data: dict, transaction_data: dict) -> dict:
        """
        Deterministic, non-LLM governance rule evaluation.
        Evaluates claim against codified policies and returns final authorized risk category.
        """
        amount = float(claim_data.get("amount", 0.0))
        reason = claim_data.get("reason", "")
        
        # Customer attributes
        account_age_days = int(customer_data.get("account_age_days", 0))
        risk_score = float(customer_data.get("risk_score", 0.0))
        is_flagged = bool(customer_data.get("is_flagged", False))
        refunds_count = int(customer_data.get("total_refunds_count", 0))
        
        # Transaction attributes
        category = transaction_data.get("item_category", "General") if transaction_data else "General"
        purchase_date_str = transaction_data.get("purchase_date") if transaction_data else None

        days_since_purchase = 0
        if purchase_date_str:
            try:
                # Handle ISO timestamps with or without Z
                clean_date = purchase_date_str.replace("Z", "+00:00")
                p_date = datetime.fromisoformat(clean_date)
                now = datetime.now(timezone.utc)
                days_since_purchase = (now - p_date).days
            except Exception:
                days_since_purchase = 10

        reasons = []

        # 1. Hard Decline: Statutory Time-Barred Check (>60 days)
        if days_since_purchase > 60:
            clause = self.get_clause("POL-501") or {}
            return {
                "risk_category": "TIER_DECLINE",
                "clause_id": "POL-501",
                "clause_name": clause.get("name", "Time-Barred Purchase Window Exclusion"),
                "clause_text": clause.get("description", "Claims initiated >60 days post-purchase are barred."),
                "approvers_needed": 0,
                "approval_requirement": "BLOCKED",
                "governance_override": True,
                "reasons": [f"Transaction was made {days_since_purchase} days ago, exceeding statutory 60-day limit."]
            }

        # 2. Hard Decline: Tier Decline Limits & High Fraud Checks
        if amount > 1500.00:
            reasons.append(f"Claim amount (${amount:.2f}) exceeds hard automated limit of $1,500.00.")
        if account_age_days < 7 and amount > 200.00:
            reasons.append(f"New account ({account_age_days} days old) requesting high amount (${amount:.2f}).")
        if is_flagged:
            reasons.append("Customer account has an active security/fraud flag.")
        if refunds_count >= 4 or risk_score >= 0.75:
            reasons.append(f"High customer risk profile (Risk: {risk_score:.2f}, Prior refunds: {refunds_count}).")

        if reasons:
            clause = self.get_clause("POL-401") or {}
            return {
                "risk_category": "TIER_DECLINE",
                "clause_id": "POL-401",
                "clause_name": clause.get("name", "Tier Decline Hard-Limit & Fraud Exclusion"),
                "clause_text": clause.get("description", "High-risk threshold breached; barred from automated approval."),
                "approvers_needed": 0,
                "approval_requirement": "BLOCKED",
                "governance_override": True,
                "reasons": reasons
            }

        # 3. Four-Eyes Dual Authorization Check
        four_eyes_reasons = []
        if amount > 250.00:
            four_eyes_reasons.append(f"High-value claim amount (${amount:.2f}) mandates Four-Eyes approval.")
        if category in ["Electronics", "Digital Goods"] and amount > 150.00:
            four_eyes_reasons.append(f"Sensitive merchandise category '{category}' above $150 threshold.")
        if risk_score > 0.30 and amount > 100.00:
            four_eyes_reasons.append(f"Elevated risk score ({risk_score:.2f}) requires senior dual oversight.")

        if four_eyes_reasons:
            clause = self.get_clause("POL-301") or {}
            return {
                "risk_category": "FOUR_EYES",
                "clause_id": "POL-301",
                "clause_name": clause.get("name", "High-Value Four-Eyes Dual-Authorization"),
                "clause_text": clause.get("description", "Mandates dual independent signoffs from distinct approvers."),
                "approvers_needed": 2,
                "approval_requirement": "FOUR_EYES",
                "governance_override": False,
                "reasons": four_eyes_reasons
            }

        # 4. Routine Low-Value Processing
        if amount <= 50.00 and account_age_days >= 30 and risk_score <= 0.25 and refunds_count <= 1:
            clause = self.get_clause("POL-101") or {}
            return {
                "risk_category": "ROUTINE",
                "clause_id": "POL-101",
                "clause_name": clause.get("name", "Routine Low-Value Auto-Resolution"),
                "clause_text": clause.get("description", "Under $50, established account, low risk, qualifies for routine execution."),
                "approvers_needed": 0,
                "approval_requirement": "NONE",
                "governance_override": False,
                "reasons": ["Amount <= $50.00 and customer satisfies all trusted baseline conditions."]
            }

        # 5. Standard Dispute Single-Signoff
        clause = self.get_clause("POL-201") or {}
        single_reasons = []
        if amount > 50.00:
            single_reasons.append(f"Claim amount (${amount:.2f}) exceeds routine auto-resolution threshold.")
        if account_age_days < 30:
            single_reasons.append(f"Account age ({account_age_days} days) requires review.")
        if risk_score > 0.25:
            single_reasons.append(f"Risk score ({risk_score:.2f}) requires single certified approver review.")
        if not single_reasons:
            single_reasons.append("Standard dispute resolution policy clause POL-201 applied.")

        return {
            "risk_category": "SINGLE_APPROVAL",
            "clause_id": "POL-201",
            "clause_name": clause.get("name", "Standard Dispute Single-Signoff"),
            "clause_text": clause.get("description", "Mandates single cryptographic approval from certified reviewer."),
            "approvers_needed": 1,
            "approval_requirement": "SINGLE_APPROVAL",
            "governance_override": False,
            "reasons": single_reasons
        }

policy_engine = PolicyEngine()
