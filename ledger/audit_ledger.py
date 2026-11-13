import os
import json
import hashlib
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

LEDGER_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ledger")
LEDGER_FILE = os.path.join(LEDGER_DIR, "audit.jsonl")
GENESIS_HASH = "0" * 64

class AuditLedger:
    def __init__(self, ledger_file: str = LEDGER_FILE):
        self.ledger_file = ledger_file
        self.lock = threading.RLock()
        os.makedirs(os.path.dirname(self.ledger_file), exist_ok=True)
        if not os.path.exists(self.ledger_file):
            with open(self.ledger_file, "w", encoding="utf-8") as f:
                pass  # create empty file

    def _compute_entry_hash(self, seq: int, claim_id: str, action: str, amount: float, actor: str, timestamp: str, prev_hash: str) -> str:
        # Strict canonical string serialization
        canonical_str = f"{seq}|{claim_id}|{action}|{amount:.2f}|{actor}|{timestamp}|{prev_hash}"
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def get_last_entry(self) -> Optional[Dict[str, Any]]:
        with self.lock:
            if not os.path.exists(self.ledger_file) or os.path.getsize(self.ledger_file) == 0:
                return None
            last_line = None
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
            if last_line:
                return json.loads(last_line)
            return None

    def append_entry(self, claim_id: str, action: str, amount: float, actor: str, actor_role: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self.lock:
            last_entry = None
            if os.path.exists(self.ledger_file) and os.path.getsize(self.ledger_file) > 0:
                with open(self.ledger_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            last_entry = json.loads(line.strip())

            seq = (last_entry["seq"] + 1) if last_entry else 1
            prev_hash = last_entry["curr_hash"] if last_entry else GENESIS_HASH
            timestamp = datetime.now(timezone.utc).isoformat()

            curr_hash = self._compute_entry_hash(
                seq=seq,
                claim_id=claim_id,
                action=action,
                amount=amount,
                actor=actor,
                timestamp=timestamp,
                prev_hash=prev_hash
            )

            entry = {
                "seq": seq,
                "claim_id": claim_id,
                "action": action,
                "amount": round(float(amount), 2),
                "actor": actor,
                "actor_role": actor_role,
                "timestamp": timestamp,
                "metadata": metadata or {},
                "prev_hash": prev_hash,
                "curr_hash": curr_hash
            }

            with open(self.ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

            return entry

    def read_all_entries(self) -> List[Dict[str, Any]]:
        with self.lock:
            if not os.path.exists(self.ledger_file):
                return []
            entries = []
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except Exception:
                            continue
            return entries

    def verify_ledger(self) -> Dict[str, Any]:
        """
        Cryptographically validates the hash chain of the entire audit ledger.
        Returns detailed verification report including exact failed sequence if compromised.
        """
        with self.lock:
            if not os.path.exists(self.ledger_file) or os.path.getsize(self.ledger_file) == 0:
                return {
                    "is_valid": True,
                    "total_entries": 0,
                    "message": "Ledger is pristine (empty).",
                    "failed_at_seq": None,
                    "expected_hash": None,
                    "actual_hash": None
                }

            entries = []
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except Exception as e:
                            return {
                                "is_valid": False,
                                "total_entries": len(entries),
                                "message": f"Malformed JSON entry encountered: {e}",
                                "failed_at_seq": len(entries) + 1
                            }

            expected_prev_hash = GENESIS_HASH
            for i, entry in enumerate(entries):
                seq = entry.get("seq")
                expected_seq = i + 1

                if seq != expected_seq:
                    return {
                        "is_valid": False,
                        "total_entries": len(entries),
                        "failed_at_seq": seq,
                        "message": f"Sequence discontinuity: entry has seq {seq}, expected {expected_seq}."
                    }

                # Check previous hash linkage
                prev_hash = entry.get("prev_hash")
                if prev_hash != expected_prev_hash:
                    return {
                        "is_valid": False,
                        "total_entries": len(entries),
                        "failed_at_seq": seq,
                        "expected_hash": expected_prev_hash,
                        "actual_hash": prev_hash,
                        "message": f"Hash chain broken at seq {seq}: prev_hash does not match preceding block's curr_hash."
                    }

                # Recompute current hash
                recomputed_hash = self._compute_entry_hash(
                    seq=seq,
                    claim_id=entry.get("claim_id", ""),
                    action=entry.get("action", ""),
                    amount=entry.get("amount", 0.0),
                    actor=entry.get("actor", ""),
                    timestamp=entry.get("timestamp", ""),
                    prev_hash=prev_hash
                )

                if recomputed_hash != entry.get("curr_hash"):
                    return {
                        "is_valid": False,
                        "total_entries": len(entries),
                        "failed_at_seq": seq,
                        "expected_hash": recomputed_hash,
                        "actual_hash": entry.get("curr_hash"),
                        "message": f"Payload integrity violation at seq {seq}: data was modified after signing!"
                    }

                expected_prev_hash = entry.get("curr_hash")

            return {
                "is_valid": True,
                "total_entries": len(entries),
                "message": f"All {len(entries)} ledger entries cryptographically verified. Hash chain is intact.",
                "failed_at_seq": None
            }

    def simulate_tampering(self, target_seq: int = 1) -> bool:
        """
        Adversarially mutates an entry in the ledger file to demonstrate tamper detection.
        """
        with self.lock:
            entries = self.read_all_entries()
            if not entries:
                return False

            tampered = False
            for entry in entries:
                if entry.get("seq") == target_seq or (target_seq == 1 and not tampered):
                    # Tamper with the amount or action
                    entry["amount"] = entry["amount"] + 9999.00
                    entry["action"] = "UNAUTHORIZED_TAMPERED_ACTION"
                    tampered = True
                    break

            if tampered:
                with open(self.ledger_file, "w", encoding="utf-8") as f:
                    for entry in entries:
                        f.write(json.dumps(entry) + "\n")
                return True
            return False

    def reset_to_genesis(self):
        """
        Resets and re-seeds ledger with initial baseline entries.
        """
        with self.lock:
            with open(self.ledger_file, "w", encoding="utf-8") as f:
                pass
            # Seed 3 initial governance events
            self.append_entry("CLM-5001", "CLAIM_CREATED", 42.50, "agent_alice", "AGENT", {"reason": "DAMAGED_ITEM"})
            self.append_entry("CLM-5002", "CLAIM_CREATED", 185.00, "agent_alice", "AGENT", {"reason": "DEFECTIVE"})
            self.append_entry("CLM-5003", "CLAIM_CREATED", 899.00, "agent_alice", "AGENT", {"reason": "DAMAGED_ITEM"})
            self.append_entry("CLM-5004", "CLAIM_CREATED", 1850.00, "agent_alice", "AGENT", {"reason": "ITEM_NOT_RECEIVED"})
            self.append_entry("CLM-5005", "CLAIM_CREATED", 450.00, "agent_alice", "AGENT", {"reason": "SUSPICIOUS_UNAUTHORIZED"})

audit_ledger = AuditLedger()
