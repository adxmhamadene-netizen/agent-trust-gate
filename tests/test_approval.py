import time

import pytest

from trustgate.agent import AgentLoop
from trustgate.approval import AutoApprover, approval_valid
from trustgate.audit import AuditLog
from trustgate.crypto import generate_keypair, sign
from trustgate.llm import ScriptedLLMClient
from trustgate.mandate import create_mandate
from trustgate.request import request_bytes
from trustgate.risk import ALLOW, DENY, LocalRiskProvider


def build(tmp_path, proposals, approver=None, human_public_key=None):
    agent_priv, agent_pub = generate_keypair()
    mandate = create_mandate(
        max_amount_cents=5000,
        allowed_merchants=["cafe", "bookstore"],
        expires_at=time.time() + 3600,
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    agent = AgentLoop(
        llm=ScriptedLLMClient(proposals),
        risk_provider=LocalRiskProvider(),
        mandate=mandate,
        agent_private_key=agent_priv,
        agent_public_key=agent_pub,
        audit=audit,
        approver=approver,
        human_public_key=human_public_key,
    )
    return agent, audit


# a new merchant at 80% of cap lands in the CHALLENGE band:
# cap_ratio 0.8*0.5 + new_merchant 1.0*0.3 = 0.70
CHALLENGE_PROPOSAL = [{"amount_cents": 4000, "merchant": "bookstore"}]


def test_approved_challenge_becomes_allow(tmp_path):
    human_priv, human_pub = generate_keypair()
    agent, audit = build(tmp_path, CHALLENGE_PROPOSAL,
                         approver=AutoApprover(human_priv, decision=True),
                         human_public_key=human_pub)
    outcomes = agent.run("buy a book", [])
    assert outcomes[0]["decision"] == ALLOW
    assert outcomes[0]["reason"] == "human_approved"


def test_declined_challenge_is_denied(tmp_path):
    human_priv, human_pub = generate_keypair()
    agent, _ = build(tmp_path, CHALLENGE_PROPOSAL,
                     approver=AutoApprover(human_priv, decision=False),
                     human_public_key=human_pub)
    outcomes = agent.run("buy a book", [])
    assert outcomes[0]["decision"] == DENY
    assert outcomes[0]["reason"] == "human_declined"


def test_no_approver_denies(tmp_path):
    agent, _ = build(tmp_path, CHALLENGE_PROPOSAL)
    outcomes = agent.run("buy a book", [])
    assert outcomes[0]["decision"] == DENY
    assert outcomes[0]["reason"] == "no_approver"


def test_forged_approval_is_rejected(tmp_path):
    _, human_pub = generate_keypair()
    attacker_priv, _ = generate_keypair()
    agent, _ = build(tmp_path, CHALLENGE_PROPOSAL,
                     approver=AutoApprover(attacker_priv, decision=True),
                     human_public_key=human_pub)
    outcomes = agent.run("buy a book", [])
    assert outcomes[0]["decision"] == DENY
    assert outcomes[0]["reason"] == "invalid_approval"


def test_approval_valid_rejects_modified_request(tmp_path):
    human_priv, human_pub = generate_keypair()
    request = {"amount_cents": 500, "merchant": "cafe",
               "nonce": "abc", "timestamp": time.time()}
    sig = sign(human_priv, request_bytes(request))
    assert approval_valid(human_pub, request, sig)
    request["amount_cents"] = 999999
    assert not approval_valid(human_pub, request, sig)