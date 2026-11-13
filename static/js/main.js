// Claims Resolution Agent (PS2) - Main Interactive Script

function showToast(message, type = 'info') {
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
    }

    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center text-bg-${type} border-0`;
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');

    toastEl.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;

    container.appendChild(toastEl);
    const bsToast = new bootstrap.Toast(toastEl, { delay: 4000 });
    bsToast.show();

    toastEl.addEventListener('hidden.bs.toast', () => {
        toastEl.remove();
    });
}

// 1. Submit New Claim
async function submitNewClaim(event) {
    event.preventDefault();
    const btn = document.getElementById('submitClaimBtn');
    if (btn) btn.disabled = true;

    const custSelect = document.getElementById('claimCustomer');
    const txnSelect = document.getElementById('claimTransaction');
    const amountInput = document.getElementById('claimAmount');
    const reasonSelect = document.getElementById('claimReason');
    const descInput = document.getElementById('claimDescription');

    const payload = {
        customer_id: custSelect.value,
        transaction_id: txnSelect.value,
        amount: parseFloat(amountInput.value),
        reason: reasonSelect.value,
        description: descInput.value
    };

    try {
        const resp = await fetch('/api/claims', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await resp.json();
        if (data.success) {
            showToast('Claim created successfully! Initial policy classified.', 'success');
            setTimeout(() => {
                window.location.href = `/claims/${data.claim.id}`;
            }, 800);
        } else {
            showToast(`Failed to create claim: ${data.error}`, 'danger');
            if (btn) btn.disabled = false;
        }
    } catch (err) {
        showToast(`Network error: ${err.message}`, 'danger');
        if (btn) btn.disabled = false;
    }
}

// 2. Trigger AI Analysis
async function triggerAIAnalysis(claimId) {
    const btn = document.getElementById(`analyzeBtn-${claimId}`) || document.getElementById('triggerAiBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Analyzing with Groq...`;
    }

    try {
        const resp = await fetch(`/api/claims/${claimId}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await resp.json();
        if (data.success) {
            showToast('AI analysis completed and governed policy evaluated!', 'success');
            setTimeout(() => {
                window.location.reload();
            }, 600);
        } else {
            showToast(`Analysis failed: ${data.error}`, 'danger');
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<i class="bi bi-cpu me-1"></i> Trigger AI Analysis`;
            }
        }
    } catch (err) {
        showToast(`Request failed: ${err.message}`, 'danger');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="bi bi-cpu me-1"></i> Trigger AI Analysis`;
        }
    }
}

// 3. Submit Approval
async function handleApproval(claimId, decision, step = 1) {
    const notes = prompt(`Enter optional review notes for ${decision}:`) || '';
    try {
        const resp = await fetch(`/api/claims/${claimId}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision, step, notes })
        });
        const data = await resp.json();
        if (data.success) {
            showToast(`Claim decision '${decision}' recorded with cryptographic token!`, 'success');
            setTimeout(() => {
                window.location.reload();
            }, 800);
        } else {
            showToast(`Approval failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast(`Error: ${err.message}`, 'danger');
    }
}

// 4. Execute Governed Refund
async function executeRefundAction(claimId) {
    const btn = document.getElementById('executeRefundBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Executing Secure Payout...`;
    }

    const idempotencyKey = document.getElementById('idempotencyKeyInput')?.value || `IDEM-${Date.now()}`;

    try {
        const resp = await fetch(`/api/claims/${claimId}/execute`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ idempotency_key: idempotencyKey })
        });
        const data = await resp.json();
        if (data.success) {
            showToast('Refund executed successfully and committed to ledger!', 'success');
            setTimeout(() => {
                window.location.reload();
            }, 800);
        } else {
            showToast(`Execution rejected: ${data.error}`, 'danger');
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<i class="bi bi-shield-check me-1"></i> Execute Governed Refund`;
            }
        }
    } catch (err) {
        showToast(`Execution failed: ${err.message}`, 'danger');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="bi bi-shield-check me-1"></i> Execute Governed Refund`;
        }
    }
}

// 5. Ledger Actions
async function verifyLedgerAction() {
    const btn = document.getElementById('verifyLedgerBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Verifying Hashes...`;
    }

    try {
        const resp = await fetch('/api/ledger/verify');
        const data = await resp.json();
        const banner = document.getElementById('ledgerStatusBanner');
        if (banner) {
            if (data.is_valid) {
                banner.className = 'alert alert-success d-flex align-items-center mb-4';
                banner.innerHTML = `<i class="bi bi-check-circle-fill me-2 fs-5"></i> <div><strong>Hash Chain Intact:</strong> ${data.message}</div>`;
                showToast('Ledger verification passed!', 'success');
            } else {
                banner.className = 'alert alert-danger d-flex align-items-center mb-4';
                banner.innerHTML = `<i class="bi bi-exclamation-triangle-fill me-2 fs-5"></i> <div><strong>Tamper Alert:</strong> ${data.message} (Failed at Sequence #${data.failed_at_seq})</div>`;
                showToast('Integrity violation detected!', 'danger');
            }
        }
    } catch (err) {
        showToast(`Verification error: ${err.message}`, 'danger');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="bi bi-patch-check me-1"></i> Verify Ledger Integrity`;
        }
    }
}

async function tamperLedgerAction() {
    if (!confirm('This will intentionally tamper with Ledger Entry #1 to demonstrate cryptographic hash chain failure. Proceed?')) return;
    try {
        const resp = await fetch('/api/ledger/tamper', { method: 'POST' });
        const data = await resp.json();
        showToast(data.message, 'warning');
        setTimeout(() => {
            window.location.reload();
        }, 800);
    } catch (err) {
        showToast(`Error: ${err.message}`, 'danger');
    }
}

async function resetLedgerAction() {
    try {
        const resp = await fetch('/api/ledger/reset', { method: 'POST' });
        const data = await resp.json();
        showToast(data.message, 'success');
        setTimeout(() => {
            window.location.reload();
        }, 800);
    } catch (err) {
        showToast(`Error: ${err.message}`, 'danger');
    }
}

// 6. Run Security Test Suite
async function runSecurityTestSuite() {
    const btn = document.getElementById('runSecurityTestsBtn');
    const container = document.getElementById('securityResultsContainer');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Executing 8 Security Attack Vectors...`;
    }

    try {
        const resp = await fetch('/api/security/run-tests', { method: 'POST' });
        const data = await resp.json();

        if (container) {
            let html = `
                <div class="alert ${data.passed === data.total ? 'alert-success' : 'alert-danger'} d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h5 class="mb-1"><i class="bi bi-shield-shaded me-2"></i>Security Suite Execution Complete</h5>
                        <p class="mb-0 text-muted">Executed ${data.total} automated adversarial attack vectors at ${data.timestamp}.</p>
                    </div>
                    <div class="text-end">
                        <span class="badge ${data.passed === data.total ? 'bg-success' : 'bg-danger'} fs-6 px-3 py-2">
                            ${data.passed} / ${data.total} Passed (${data.pass_rate}%)
                        </span>
                    </div>
                </div>
                <div class="row g-3">
            `;

            data.tests.forEach(t => {
                html += `
                    <div class="col-md-6">
                        <div class="card h-100 border-${t.passed ? 'success' : 'danger'} shadow-sm">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start mb-2">
                                    <h6 class="card-title fw-bold mb-0">${t.name}</h6>
                                    <span class="badge ${t.passed ? 'bg-success' : 'bg-danger'}">${t.passed ? 'PASSED' : 'FAILED'}</span>
                                </div>
                                <p class="card-text text-muted small mb-2">${t.details}</p>
                                <div class="p-2 rounded bg-light border font-monospace small">
                                    <strong>Evidence:</strong> ${t.evidence || t.error || 'N/A'}
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            });

            html += `</div>`;
            container.innerHTML = html;
        }

        showToast(`Security suite finished: ${data.passed}/${data.total} tests passed!`, 'success');
    } catch (err) {
        showToast(`Security test execution failed: ${err.message}`, 'danger');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="bi bi-play-circle me-1"></i> Run Complete Security Suite`;
        }
    }
}

// 7. Deployment Gating & Evaluation
async function runDeploymentGateAction() {
    const btn = document.getElementById('runGateBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Evaluating Golden Set & Security Gate...`;
    }

    try {
        const resp = await fetch('/api/evaluation/run', { method: 'POST' });
        const data = await resp.json();
        showToast(data.message, data.qualified ? 'success' : 'danger');
        setTimeout(() => {
            window.location.reload();
        }, 1000);
    } catch (err) {
        showToast(`Evaluation gate failed: ${err.message}`, 'danger');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="bi bi-clipboard-check me-1"></i> Run Deployment Gate Evaluation`;
        }
    }
}

async function promoteDeploymentStage(stage) {
    if (!confirm(`Are you sure you want to promote deployment stage to ${stage}?`)) return;
    try {
        const resp = await fetch('/api/evaluation/promote', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_stage: stage })
        });
        const data = await resp.json();
        if (data.success) {
            showToast(data.message, 'success');
            setTimeout(() => {
                window.location.reload();
            }, 800);
        } else {
            showToast(`Promotion denied: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast(`Error: ${err.message}`, 'danger');
    }
}

async function demoteDeploymentStage() {
    const reason = prompt('Enter justification for administrative demotion:') || 'Manual demotion trigger';
    try {
        const resp = await fetch('/api/evaluation/demote', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason })
        });
        const data = await resp.json();
        showToast(data.message, 'warning');
        setTimeout(() => {
            window.location.reload();
        }, 800);
    } catch (err) {
        showToast(`Error: ${err.message}`, 'danger');
    }
}
