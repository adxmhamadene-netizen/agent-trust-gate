from trustgate.mandate import purchase_allowed
from trustgate.request import create_request, sign_request, request_valid, NonceStore
from trustgate.risk import ALLOW, CHALLENGE, DENY, decide


class AgentLoop:
    """Runs a shopping agent whose proposals must clear the trust gate."""

    def __init__(self, llm, risk_provider, mandate, agent_private_key,
                 agent_public_key, audit, nonce_store=None, approver=None):
        self.llm = llm
        self.risk = risk_provider
        self.mandate = mandate
        self.agent_private_key = agent_private_key
        self.agent_public_key = agent_public_key
        self.audit = audit
        self.nonce_store = nonce_store or NonceStore()
        self.approver = approver
        self.history = []

    def run(self, goal: str, catalog: list[dict], max_steps: int = 5) -> list[dict]:
        outcomes = []

        for _ in range(max_steps):
            proposal = self.llm.propose(goal, catalog)
            if proposal is None:
                break

            outcome = self.evaluate(proposal)
            outcomes.append(outcome)

            if outcome["decision"] == ALLOW:
                self.history.append(outcome["request"])

        return outcomes

    def evaluate(self, proposal: dict) -> dict:
        request = create_request(proposal["amount_cents"], proposal["merchant"])
        signature = sign_request(self.agent_private_key, request)

        if not request_valid(self.agent_public_key, request, signature,
                             self.nonce_store):
            return self._finish(request, DENY, "invalid_request", None)

        if not purchase_allowed(self.mandate, request["amount_cents"],
                                request["merchant"]):
            return self._finish(request, DENY, "outside_mandate", None)

        score = self.risk.score(request, self.mandate, self.history)
        decision = decide(score)

        if decision == CHALLENGE:
            if self.approver and self.approver.approve(request):
                return self._finish(request, ALLOW, "human_approved", score)
            return self._finish(request, DENY, "human_declined", score)

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
        return {"request": request, "decision": decision,
                "reason": reason, "risk_score": score}