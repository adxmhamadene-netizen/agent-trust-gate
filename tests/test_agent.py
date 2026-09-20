import time

import pytest

from trustgate.agent import AgentLoop
from trustgate.audit import AuditLog
from trustgate.crypto import generate_keypair
from trustgate.llm import ScriptedLLMClient
from trustgate.mandate import create_mandate
from trustgate.risk import ALLOW, DENY, LocalRiskProvider


@pytest.fixture
def setup(tmp_path):
    private_key, public_key = generate_keypair()
    mandate = create_mandate(
        max_amount_cents=5000,
        allowed_merchants=["cafe", "bookstore"],
        expires_at=time.time() + 3600,
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    return private_key, public_key, mandate, audit


def build(setup, proposals, approver=None):
    private_key, public_key, mandate, audit = setup
    return AgentLoop(
        llm=ScriptedLLMClient(proposals),
        risk_provider=LocalRiskProvider(),
        mandate=mandate,
        agent_private_key=private_key,
        agent_public_key=public_key,
        audit=audit,
        approver=approver,
    ), audit


def test_small_known_purchase_is_allowed(setup):
    agent, _ = build(setup, [{"amount_cents": 500, "merchant": "cafe"}])
    agent.history.append({"merchant": "cafe", "timestamp": time.time() - 7200})
    outcomes = agent.run("buy coffee", [])
    assert outcomes[0]["decision"] == ALLOW


def test_merchant_not_in_mandate_is_denied(setup):
    agent, _ = build(setup, [{"amount_cents": 500, "merchant": "casino"}])
    outcomes = agent.run("buy chips", [])
    assert outcomes[0]["decision"] == DENY
    assert outcomes[0]["reason"] == "outside_mandate"


def test_over_cap_is_denied(setup):
    agent, _ = build(setup, [{"amount_cents": 999999, "merchant": "cafe"}])
    outcomes = agent.run("buy everything", [])
    assert outcomes[0]["decision"] == DENY
    assert outcomes[0]["reason"] == "outside_mandate"


def test_loop_stops_when_llm_returns_none(setup):
    agent, _ = build(setup, [{"amount_cents": 500, "merchant": "cafe"}])
    outcomes = agent.run("buy coffee", [], max_steps=10)
    assert len(outcomes) == 1


def test_every_decision_is_logged(setup):
    agent, audit = build(setup, [
        {"amount_cents": 500, "merchant": "cafe"},
        {"amount_cents": 500, "merchant": "casino"},
    ])
    agent.run("shop", [])
    entries = audit.read_all()
    assert len(entries) == 2
    assert all(e["event"] == "decision" for e in entries)