from trustgate.request import create_request, sign_request


class AgentLoop:
    """Runs a shopping agent whose proposals must clear the trust gate."""

    def __init__(self, llm, gate, agent_private_key):
        self.llm = llm
        self.gate = gate
        self.agent_private_key = agent_private_key
        

    def run(self, goal: str, catalog: list[dict], max_steps: int = 5) -> list[dict]:
        outcomes = []

        for _ in range(max_steps):
            proposal = self.llm.propose(goal, catalog)
            if proposal is None:
                break
            request = create_request(proposal["amount_cents"], proposal["merchant"])
            signature = sign_request(self.agent_private_key, request)
            outcomes.append(self.gate.evaluate(request,signature))
        return outcomes
