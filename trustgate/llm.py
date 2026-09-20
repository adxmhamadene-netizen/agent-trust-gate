import json

import anthropic


class LLMClient:
    """Interface: given a goal and a catalog, propose one purchase.
    Returns a dict with "amount_cents" and "merchant", or None to stop."""

    def propose(self, goal: str, catalog: list[dict]) -> dict | None:
        raise NotImplementedError


class ScriptedLLMClient(LLMClient):
    """Canned proposals, for deterministic tests."""

    def __init__(self, proposals):
        self.proposals = proposals
        self.i = 0

    def propose(self, goal, catalog):
        if self.i >= len(self.proposals):
            return None
        p = self.proposals[self.i]
        self.i += 1
        return p


class AnthropicLLMClient(LLMClient):
    """Real model. Asks for JSON only, parses it."""

    def __init__(self, model="claude-haiku-4-5-20251001"):
        self.client = anthropic.Anthropic()
        self.model = model

    def propose(self, goal, catalog):
        prompt = (
            f"Goal: {goal}\n\n"
            f"Catalog:\n{json.dumps(catalog, indent=2)}\n\n"
            "Propose ONE purchase that advances the goal. "
            'Respond with JSON only, no prose, no markdown fences: '
            '{"amount_cents": <int>, "merchant": "<string>"}. '
            'If no purchase fits, respond with: {"done": true}'
        )
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if data.get("done"):
            return None
        return {"amount_cents": data["amount_cents"], "merchant": data["merchant"]}