import os
import sys
import unittest
import json
import uuid

# Set up path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.app import create_app
from server.database import init_db
from ledger.audit_ledger import audit_ledger

class TestClaimsWorkflow(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        init_db(seed_sample_data=True, force_recreate=True)
        audit_ledger.reset_to_genesis()

    def test_pages_load_successfully(self):
        """Verify all major UI pages return HTTP 200."""
        routes = ["/", "/claims", "/approvals", "/execution", "/audit", "/security", "/evaluation", "/login"]
        for r in routes:
            resp = self.client.get(r)
            self.assertEqual(resp.status_code, 200, f"Route {r} failed to load.")

    def test_complete_single_approval_workflow(self):
        """End-to-end test: Create claim -> Analyze -> Approve -> Execute -> Verify Ledger."""
        # 1. Create claim ($140 -> SINGLE_APPROVAL)
        create_resp = self.client.post("/api/claims", json={
            "customer_id": "CUST-1002",
            "transaction_id": "TXN-8802",
            "amount": 140.00,
            "reason": "DEFECTIVE",
            "description": "Coffee grinder motor died on first use."
        })
        self.assertEqual(create_resp.status_code, 201)
        claim_data = create_resp.get_json()["claim"]
        claim_id = claim_data["id"]
        self.assertEqual(claim_data["risk_category"], "SINGLE_APPROVAL")

        # 2. Trigger AI Analysis
        analyze_resp = self.client.post(f"/api/claims/{claim_id}/analyze")
        self.assertEqual(analyze_resp.status_code, 200)

        # 3. Approve via Approver Bob (Set cookies for auth)
        self.client.set_cookie("demo_active_user", "approver_bob")
        appr_resp = self.client.post(f"/api/claims/{claim_id}/approve", json={
            "decision": "APPROVED",
            "step": 1,
            "notes": "Verified manufacturer defect."
        })
        self.assertEqual(appr_resp.status_code, 200)
        appr_data = appr_resp.get_json()
        self.assertTrue(appr_data["success"])
        self.assertEqual(appr_data["new_status"], "APPROVED_PENDING_EXECUTION")
        self.assertIn("token", appr_data)

        # 4. Execute Refund
        idem_key = f"IDEM-TEST-{uuid.uuid4().hex[:6]}"
        exec_resp = self.client.post(f"/api/claims/{claim_id}/execute", json={
            "idempotency_key": idem_key
        })
        self.assertEqual(exec_resp.status_code, 200)
        exec_data = exec_resp.get_json()
        self.assertTrue(exec_data["success"])
        self.assertEqual(exec_data["status"], "REFUNDED")

        # 5. Verify Audit Ledger Integrity
        verify_resp = self.client.get("/api/ledger/verify")
        ledger_data = verify_resp.get_json()
        self.assertTrue(ledger_data["is_valid"])

    def test_four_eyes_approval_workflow(self):
        """End-to-end test: Four-Eyes Dual Approval ($750)."""
        create_resp = self.client.post("/api/claims", json={
            "customer_id": "CUST-1003",
            "transaction_id": "TXN-8803",
            "amount": 750.00,
            "reason": "DAMAGED_ITEM",
            "description": "UltraWide monitor display broken in transit."
        })
        claim_id = create_resp.get_json()["claim"]["id"]

        # Step 1 Approval by Bob
        self.client.set_cookie("demo_active_user", "approver_bob")
        r1 = self.client.post(f"/api/claims/{claim_id}/approve", json={"decision": "APPROVED", "step": 1})
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.get_json()["new_status"], "PENDING_APPROVAL_STEP2")

        # Step 2 Attempt by Bob (Must fail - collusion)
        r2_fail = self.client.post(f"/api/claims/{claim_id}/approve", json={"decision": "APPROVED", "step": 2})
        self.assertEqual(r2_fail.status_code, 400)

        # Step 2 Approval by Carol (Senior Approver - Must succeed)
        self.client.set_cookie("demo_active_user", "approver_carol")
        r2_pass = self.client.post(f"/api/claims/{claim_id}/approve", json={"decision": "APPROVED", "step": 2})
        self.assertEqual(r2_pass.status_code, 200)
        self.assertEqual(r2_pass.get_json()["new_status"], "APPROVED_PENDING_EXECUTION")

        # Execute
        exec_res = self.client.post(f"/api/claims/{claim_id}/execute", json={"idempotency_key": f"IDEM-4EYES-{uuid.uuid4().hex[:6]}"})
        self.assertEqual(exec_res.status_code, 200)
        self.assertEqual(exec_res.get_json()["status"], "REFUNDED")

    def test_tier_decline_blocked_from_execution(self):
        """Claims in TIER_DECLINE cannot be approved or refunded."""
        create_resp = self.client.post("/api/claims", json={
            "customer_id": "CUST-1004",
            "transaction_id": "TXN-8804",
            "amount": 1850.00,
            "reason": "ITEM_NOT_RECEIVED",
            "description": "Lost expensive smartphone."
        })
        claim_id = create_resp.get_json()["claim"]["id"]

        # Attempt to approve
        self.client.set_cookie("demo_active_user", "approver_bob")
        appr_resp = self.client.post(f"/api/claims/{claim_id}/approve", json={"decision": "APPROVED", "step": 1})
        self.assertEqual(appr_resp.status_code, 400)

        # Attempt to execute
        exec_resp = self.client.post(f"/api/claims/{claim_id}/execute", json={"idempotency_key": "IDEM-DECLINE"})
        self.assertEqual(exec_resp.status_code, 400)

if __name__ == "__main__":
    unittest.main()
