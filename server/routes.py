import os
import json
import uuid
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, make_response, g

from server.database import get_db_connection, compute_claim_payload_hash, hash_password
from server.claim_service import claim_service
from server.classification import classify_claim
from server.approval import submit_approval_decision
from server.security import verify_approval_token
from server.auth import (
    create_jwt_token, decode_jwt_token, get_current_user_from_request,
    login_required, roles_required
)
from server.policy_engine import policy_engine
from ledger.audit_ledger import audit_ledger
from eval.test_security import SecurityAdversarialTestSuite
from eval.golden_set import run_golden_evaluation
from eval.deployment import (
    get_deployment_status, run_governance_gate_evaluation,
    promote_stage, demote_stage
)

main_bp = Blueprint("main", __name__)
api_bp = Blueprint("api", __name__, url_prefix="/api")

# Context processor for templates: current user & deployment stage
@main_bp.context_processor
def inject_globals():
    user = get_current_user_from_request()
    if not user:
        # Default fallback to admin_dave for smooth presentation if not signed in
        user = {
            "id": 4,
            "username": "admin_dave",
            "role": "ADMIN",
            "full_name": "Dave Sterling (System Administrator)"
        }
    status = get_deployment_status()
    return {"current_user": user, "deployment_status": status}

# -------------------------------------------------------------
# Web UI Page Routes
# -------------------------------------------------------------

@main_bp.route("/")
def dashboard_page():
    claims = claim_service.get_all_claims()
    total_claims = len(claims)
    pending_approvals = sum(1 for c in claims if "PENDING" in c["status"])
    approved_count = sum(1 for c in claims if c["status"] in ["APPROVED_PENDING_EXECUTION", "REFUNDED"])
    rejected_count = sum(1 for c in claims if c["status"] == "REJECTED")
    refunded_count = sum(1 for c in claims if c["status"] == "REFUNDED")
    total_refund_amount = sum(c["amount"] for c in claims if c["status"] == "REFUNDED")

    risk_dist = {
        "ROUTINE": sum(1 for c in claims if c["risk_category"] == "ROUTINE"),
        "SINGLE_APPROVAL": sum(1 for c in claims if c["risk_category"] == "SINGLE_APPROVAL"),
        "FOUR_EYES": sum(1 for c in claims if c["risk_category"] == "FOUR_EYES"),
        "TIER_DECLINE": sum(1 for c in claims if c["risk_category"] == "TIER_DECLINE")
    }

    recent_activities = audit_ledger.read_all_entries()[-8:]
    recent_activities.reverse()

    return render_template(
        "dashboard.html",
        total_claims=total_claims,
        pending_approvals=pending_approvals,
        approved_count=approved_count,
        rejected_count=rejected_count,
        refunded_count=refunded_count,
        total_refund_amount=total_refund_amount,
        risk_dist=risk_dist,
        recent_activities=recent_activities,
        claims=claims[:5]
    )

@main_bp.route("/claims")
def claims_page():
    status_filter = request.args.get("status", "ALL")
    risk_filter = request.args.get("risk", "ALL")
    claims = claim_service.get_all_claims(status=status_filter, risk=risk_filter)

    # Fetch customers and transactions for new claim modal
    conn = get_db_connection()
    customers = [dict(r) for r in conn.execute("SELECT id, name, email FROM customers").fetchall()]
    transactions = [dict(r) for r in conn.execute("SELECT id, customer_id, item_name, amount FROM transactions").fetchall()]
    conn.close()

    return render_template(
        "claims.html",
        claims=claims,
        customers=customers,
        transactions=transactions,
        status_filter=status_filter,
        risk_filter=risk_filter
    )

@main_bp.route("/claims/<claim_id>")
def claim_details_page(claim_id):
    claim = claim_service.get_claim_by_id(claim_id)
    if not claim:
        return render_template("404.html", message=f"Claim {claim_id} not found"), 404

    # Parse AI risk indicators if available
    risk_indicators = []
    if claim.get("ai_analysis") and claim["ai_analysis"].get("risk_indicators"):
        try:
            risk_indicators = json.loads(claim["ai_analysis"]["risk_indicators"])
        except Exception:
            risk_indicators = [claim["ai_analysis"]["risk_indicators"]]

    policy_clause = policy_engine.get_clause(claim.get("policy_clause_id", ""))

    return render_template(
        "claim_details.html",
        claim=claim,
        risk_indicators=risk_indicators,
        policy_clause=policy_clause
    )

@main_bp.route("/approvals")
def approvals_page():
    claims = claim_service.get_all_claims()
    pending = [c for c in claims if "PENDING_APPROVAL" in c["status"]]
    
    # Enrich pending claims with approval records
    enriched = []
    for p in pending:
        c_detail = claim_service.get_claim_by_id(p["id"])
        enriched.append(c_detail)

    return render_template("approvals.html", pending_claims=enriched)

@main_bp.route("/execution")
@main_bp.route("/execution/<claim_id>")
def execution_page(claim_id=None):
    claims = claim_service.get_all_claims()
    ready_claims = [c for c in claims if c["status"] == "APPROVED_PENDING_EXECUTION"]

    selected_claim = None
    if claim_id:
        selected_claim = claim_service.get_claim_by_id(claim_id)
    elif ready_claims:
        selected_claim = claim_service.get_claim_by_id(ready_claims[0]["id"])

    # If selected claim has approvals, verify token preview
    token_status = None
    if selected_claim and selected_claim.get("approvals"):
        last_appr = selected_claim["approvals"][-1]
        valid, reason, payload = verify_approval_token(
            last_appr["approval_token"],
            current_claim_payload_hash=selected_claim["payload_hash"]
        )
        token_status = {"valid": valid, "reason": reason, "payload": payload}

    return render_template(
        "execution.html",
        ready_claims=ready_claims,
        selected_claim=selected_claim,
        token_status=token_status
    )

@main_bp.route("/audit")
def audit_page():
    entries = audit_ledger.read_all_entries()
    verification = audit_ledger.verify_ledger()
    return render_template(
        "audit.html",
        entries=entries,
        verification=verification
    )

@main_bp.route("/security")
def security_page():
    return render_template("security.html")

@main_bp.route("/evaluation")
def evaluation_page():
    status = get_deployment_status()
    golden_results = run_golden_evaluation()
    return render_template(
        "evaluation.html",
        status=status,
        golden_results=golden_results
    )

@main_bp.route("/login")
def login_page():
    conn = get_db_connection()
    users = [dict(r) for r in conn.execute("SELECT id, username, role, full_name FROM users").fetchall()]
    conn.close()
    return render_template("login.html", users=users)

# Switch Demo User fast
@main_bp.route("/auth/switch-user/<username>")
def switch_user_action(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if user:
        token = create_jwt_token(user["id"], user["username"], user["role"], user["full_name"])
        resp = redirect(request.referrer or url_for("main.dashboard_page"))
        resp.set_cookie("jwt_token", token, httponly=True)
        resp.set_cookie("demo_active_user", user["username"])
        return resp
    return redirect(url_for("main.dashboard_page"))

# -------------------------------------------------------------
# REST API Endpoints
# -------------------------------------------------------------

@api_bp.route("/claims", methods=["POST"])
def api_create_claim():
    user = get_current_user_from_request() or {"username": "agent_alice"}
    data = request.get_json() or {}
    try:
        new_claim = claim_service.create_claim(
            customer_id=data.get("customer_id"),
            transaction_id=data.get("transaction_id"),
            amount=float(data.get("amount", 0.0)),
            reason=data.get("reason"),
            description=data.get("description", ""),
            actor_username=user.get("username", "agent_alice")
        )
        return jsonify({"success": True, "claim": new_claim}), 201
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@api_bp.route("/claims/<claim_id>/analyze", methods=["POST"])
def api_analyze_claim(claim_id):
    user = get_current_user_from_request() or {"username": "system"}
    try:
        result = classify_claim(claim_id, actor_username=user.get("username", "system"))
        return jsonify({"success": True, "data": result}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@api_bp.route("/claims/<claim_id>/approve", methods=["POST"])
def api_approve_claim(claim_id):
    user = get_current_user_from_request()
    if not user:
        return jsonify({"success": False, "error": "Authentication required to approve."}), 401

    data = request.get_json() or {}
    decision = data.get("decision", "APPROVED")
    step = int(data.get("step", 1))
    notes = data.get("notes", "")

    try:
        result = submit_approval_decision(
            claim_id=claim_id,
            approver_username=user["username"],
            approver_role=user["role"],
            decision=decision,
            step=step,
            notes=notes
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@api_bp.route("/claims/<claim_id>/execute", methods=["POST"])
def api_execute_refund(claim_id):
    user = get_current_user_from_request() or {"username": "system", "role": "ADMIN"}
    data = request.get_json() or {}
    idempotency_key = data.get("idempotency_key") or f"IDEM-{uuid.uuid4().hex[:8].upper()}"

    try:
        result = claim_service.execute_refund(
            claim_id=claim_id,
            idempotency_key=idempotency_key,
            actor_username=user.get("username", "system"),
            actor_role=user.get("role", "ADMIN")
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@api_bp.route("/ledger/verify", methods=["GET", "POST"])
def api_verify_ledger():
    report = audit_ledger.verify_ledger()
    return jsonify(report)

@api_bp.route("/ledger/tamper", methods=["POST"])
def api_tamper_ledger():
    user = get_current_user_from_request() or {"username": "tester"}
    success = audit_ledger.simulate_tampering(target_seq=1)
    return jsonify({"success": success, "message": "Tampered with ledger entry #1 to demonstrate integrity detection."})

@api_bp.route("/ledger/reset", methods=["POST"])
def api_reset_ledger():
    audit_ledger.reset_to_genesis()
    return jsonify({"success": True, "message": "Ledger reset to genesis baseline."})

@api_bp.route("/security/run-tests", methods=["POST"])
def api_run_security_tests():
    suite = SecurityAdversarialTestSuite()
    report = suite.run_all()
    return jsonify(report)

@api_bp.route("/evaluation/run", methods=["POST"])
def api_run_evaluation():
    user = get_current_user_from_request() or {"username": "admin_dave"}
    result = run_governance_gate_evaluation(actor_username=user.get("username", "admin_dave"))
    return jsonify(result)

@api_bp.route("/evaluation/promote", methods=["POST"])
def api_promote_stage():
    user = get_current_user_from_request() or {"username": "admin_dave"}
    data = request.get_json() or {}
    target_stage = data.get("target_stage", "PRODUCTION")
    try:
        res = promote_stage(target_stage=target_stage, actor_username=user.get("username", "admin_dave"))
        return jsonify(res)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@api_bp.route("/evaluation/demote", methods=["POST"])
def api_demote_stage():
    user = get_current_user_from_request() or {"username": "admin_dave"}
    data = request.get_json() or {}
    reason = data.get("reason", "Manual administrative demotion")
    res = demote_stage(reason=reason, actor_username=user.get("username", "admin_dave"))
    return jsonify(res)
