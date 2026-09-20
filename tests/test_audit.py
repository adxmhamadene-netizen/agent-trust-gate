import json

from trustgate.audit import AuditLog


def test_append_and_read(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("decision", decision="ALLOW", amount_cents=500)
    entries = log.read_all()
    assert len(entries) == 1
    assert entries[0]["event"] == "decision"
    assert entries[0]["decision"] == "ALLOW"
    assert entries[0]["amount_cents"] == 500
    assert "ts" in entries[0]


def test_appends_accumulate(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("decision", decision="ALLOW")
    log.append("decision", decision="DENY")
    assert [e["decision"] for e in log.read_all()] == ["ALLOW", "DENY"]


def test_read_all_empty_when_no_file(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.read_all() == []


def test_creates_missing_directory(tmp_path):
    log = AuditLog(tmp_path / "logs" / "audit.jsonl")
    log.append("startup")
    assert log.path.exists()


def test_each_line_is_valid_json(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("decision", decision="ALLOW")
    log.append("decision", decision="DENY")
    lines = log.path.read_text().strip().split("\n")
    assert len(lines) == 2
    assert all(json.loads(line) for line in lines)