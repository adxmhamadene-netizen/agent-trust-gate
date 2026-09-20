ALLOW = "ALLOW"
CHALLENGE = "CHALLENGE"
DENY = "DENY"

# score < 0.5 → ALLOW, 0.5 to < 0.8 → CHALLENGE, 0.8+ → DENY
CHALLENGE_THRESHOLD = 0.5
DENY_THRESHOLD = 0.8

# how much each signal matters (they add up to 1.0)
WEIGHTS = {"cap_ratio": 0.5, "new_merchant": 0.3, "velocity": 0.2}


class RiskProvider:
    """Interface: every risk scorer must have a score() method.
    In production, an external trust signal (e.g. Experian's Agent Trust) plugs in here."""

    def score(self, request: dict, mandate: dict, history: list[dict]) -> float:
        """Return a risk score from 0.0 (safe) to 1.0 (risky)."""
        raise NotImplementedError


class LocalRiskProvider(RiskProvider):
    """A simple stand-in scorer using signals we can compute ourselves."""

    def signals(self, request: dict, mandate: dict, history: list[dict]) -> dict:
        """Return a dict of three signals, each from 0.0 to 1.0:
        - "cap_ratio": amount / the mandate's max (how close to the limit), capped at 1.0
        - "new_merchant": 1.0 if no past purchase in history used this merchant, else 0.0
        - "velocity": number of past purchases in the last hour / 5, capped at 1.0
        "Last hour" means within 3600 seconds of request["timestamp"]."""

        cap_ratio = min(request['amount_cents'] / mandate['max_amount_cents'], 1.0)

        past_merchants = []
        for x in history:
            past_merchants.append(x['merchant'])    
        
        if request['merchant'] not in past_merchants:
            new_merchant = 1.0
        else:
            new_merchant = 0.0

        count = 0
        for x in history:
            if request["timestamp"] - x["timestamp"] <= 3600:
                count += 1
        velocity = min(count / 5, 1.0)  
    
        return {"cap_ratio": cap_ratio, "new_merchant": new_merchant, "velocity": velocity}


    def score(self, request: dict, mandate: dict, history: list[dict]) -> float:
        """Return the weighted sum of the signals:
        cap_ratio * 0.5 + new_merchant * 0.3 + velocity * 0.2"""
        s = self.signals(request, mandate, history)
        return (s["cap_ratio"] * WEIGHTS["cap_ratio"]
                + s["new_merchant"] * WEIGHTS["new_merchant"]
                + s["velocity"] * WEIGHTS["velocity"])


def decide(score: float) -> str:
    """Return ALLOW if score < CHALLENGE_THRESHOLD,
    CHALLENGE if score < DENY_THRESHOLD,
    otherwise DENY."""
    if score < CHALLENGE_THRESHOLD:
        return ALLOW
    elif score < DENY_THRESHOLD:
        return CHALLENGE
    else:
        return DENY