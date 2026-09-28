from trustgate.approval import approval_valid
from trustgate.mandate import purchase_allowed, verify_mandate
from trustgate.request import request_valid, NonceStore
from trustgate.risk import ALLOW, CHALLENGE, DENY, decide


class Gate:
    """Deterministic trust gate. Holds only PUBLIC keys; never signs anything."""

    def __init__(self, agent_public_key, human_public_key, mandate,
                 mandate_signature, risk_provider, audit,
                 nonce_store=None, approver=None):
        self.agent_public_key = agent_public_key
        self.human_public_key = human_public_key
        self.mandate = mandate
        self.mandate_signature = mandate_signature
        self.risk = risk_provider
        self.audit = audit
        self.nonce_store = nonce_store or NonceStore()
        self.approver = approver
        self.history = []

    def evaluate(self, request: dict, signature: bytes) -> dict:
    
            if not request_valid(self.agent_public_key, request, signature,
                                 self.nonce_store):
                return self._finish(request, DENY, "invalid_request", None)
    
            if (self.human_public_key is None or self.mandate_signature is None or not verify_mandate(self.human_public_key, self.mandate, self.mandate_signature)):
                return self._finish(request, DENY, "invalid_mandate", None)
    
            if not purchase_allowed(self.mandate, request["amount_cents"],
                                    request["merchant"]):
                return self._finish(request, DENY, "outside_mandate", None)
    
            score = self.risk.score(request, self.mandate, self.history)
            decision = decide(score)
    
            if decision == CHALLENGE:
                if self.approver is None:
                    return self._finish(request, DENY, "no_approver", score)
    
                approval_sig = self.approver.approve(request)
                if approval_sig is None:
                    return self._finish(request, DENY, "human_declined", score)
    
                if not approval_valid(self.human_public_key, request, approval_sig):
                    return self._finish(request, DENY, "invalid_approval", score)
    
                return self._finish(request, ALLOW, "human_approved", score)
    
            reason = "within_policy" if decision == ALLOW else "risk_too_high"
            return self._finish(request, decision, reason, score)
    
    def _finish(self, request, decision, reason, score):
        self.audit.append(
            "decision",
            decision=decision,
            reason=reason,
            amount_cents=request["amount_cents"],
            merchant=request["merchant"],
            nonce=request["nonce"],
            risk_score=score,
            )
        if decision == ALLOW:
               self.history.append(request)
        return {"request": request, "decision": decision,
                "reason": reason, "risk_score": score}
