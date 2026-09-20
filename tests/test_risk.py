import pytest

from trustgate.mandate import create_mandate
from trustgate.request import create_request
from trustgate.risk import RiskProvider, LocalRiskProvider, decide, ALLOW, CHALLENGE, DENY

MANDATE = create_mandate(5000, ["Nike", "Adidas", "Puma"], expires_at=99999)


def test_normal_purchase_allowed():
    """$30 of $50 cap, known merchant, nothing recent → 0.3 → ALLOW."""
    request = create_request(3000, "Nike", now=10000)
    history = [{"merchant": "Nike", "timestamp": 1000}]
    score = LocalRiskProvider().score(request, MANDATE, history)
    assert decide(score) == ALLOW


def test_new_merchant_challenged():
    """Same purchase but at a merchant never used before → 0.6 → CHALLENGE."""
    request = create_request(3000, "Adidas", now=10000)
    history = [{"merchant": "Nike", "timestamp": 1000}]
    score = LocalRiskProvider().score(request, MANDATE, history)
    assert decide(score) == CHALLENGE


def test_everything_risky_denied():
    """Full cap, new merchant, 5 purchases in the last hour → 1.0 → DENY."""
    request = create_request(5000, "Puma", now=10000)
    history = [{"merchant": "Nike", "timestamp": 10000 - i * 60} for i in range(1, 6)]
    score = LocalRiskProvider().score(request, MANDATE, history)
    assert decide(score) == DENY


def test_velocity_only_counts_last_hour():
    """A purchase 100s ago counts; one 9000s ago does not → velocity 1/5 = 0.2."""
    request = create_request(3000, "Nike", now=10000)
    history = [{"merchant": "Nike", "timestamp": 9900},
               {"merchant": "Nike", "timestamp": 1000}]
    signals = LocalRiskProvider().signals(request, MANDATE, history)
    assert signals["velocity"] == 0.2


def test_decide_thresholds():
    """Boundaries: just under 0.5 → ALLOW, exactly 0.5 → CHALLENGE, exactly 0.8 → DENY."""
    assert decide(0.49) == ALLOW
    assert decide(0.5) == CHALLENGE
    assert decide(0.8) == DENY


def test_base_provider_is_only_an_interface():
    """The base RiskProvider can't score on its own; subclasses must implement score()."""
    with pytest.raises(NotImplementedError):
        RiskProvider().score({}, {}, [])