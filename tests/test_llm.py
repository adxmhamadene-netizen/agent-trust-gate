from trustgate.llm import ScriptedLLMClient


def test_returns_proposals_in_order():
    llm = ScriptedLLMClient([
        {"amount_cents": 500, "merchant": "cafe"},
        {"amount_cents": 900, "merchant": "bookstore"},
    ])
    assert llm.propose("goal", [])["merchant"] == "cafe"
    assert llm.propose("goal", [])["merchant"] == "bookstore"


def test_returns_none_when_exhausted():
    llm = ScriptedLLMClient([{"amount_cents": 500, "merchant": "cafe"}])
    llm.propose("goal", [])
    assert llm.propose("goal", []) is None


def test_empty_script_returns_none():
    llm = ScriptedLLMClient([])
    assert llm.propose("goal", []) is None