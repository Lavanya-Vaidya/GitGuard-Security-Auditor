import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "src" / "dashboard" / "app.py"
spec = importlib.util.spec_from_file_location("dashboard_app", MODULE_PATH)
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)


class FakeTable:
    def __init__(self, items=None, item=None, cursor=None):
        self.items = items or []
        self.item = item
        self.cursor = cursor
        self.scan_args = None
        self.get_args = None

    def scan(self, **kwargs):
        self.scan_args = kwargs
        result = {"Items": self.items}
        if self.cursor:
            result["LastEvaluatedKey"] = self.cursor
        return result

    def get_item(self, **kwargs):
        self.get_args = kwargs
        return {"Item": self.item} if self.item else {}


def sample_item():
    return {
        "PK": "octo/private-repo#42",
        "SK": "0123456789abcdef0123456789abcdef01234567",
        "status": "COMPLETED",
        "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
        "findings": json.dumps({"src/auth.py": [{
            "line": 17, "severity": "critical", "title": "Missing authorization",
            "cwe": "CWE-862", "explanation": "Stored explanation", "fix": "Stored fix",
        }]}),
        "timestamp": 1700000000,
        "files_scanned": 3,
        "files_skipped": 1,
        "is_truncated": False,
    }


def decode_response(result):
    return result["statusCode"], json.loads(result["body"])


def test_audit_id_round_trip_and_validation():
    item = sample_item()
    identifier = dashboard.audit_id("octo/private-repo", 42, item["SK"])
    assert dashboard.parse_audit_id(identifier) == ("octo/private-repo", 42, item["SK"])
    with pytest.raises(ValueError):
        dashboard.parse_audit_id("../../private")


def test_dashboard_flattens_only_real_stored_findings(monkeypatch):
    item = sample_item()
    table = FakeTable(items=[{"PK": "delivery#abc", "SK": "delivery"}, item])
    monkeypatch.setattr(dashboard, "_table", table)
    status, body = decode_response(dashboard.dashboard_handler({"queryStringParameters": {"limit": "20"}}))
    assert status == 200
    assert len(body["audits"]) == 1
    assert body["audits"][0]["id"] == dashboard.audit_id("octo/private-repo", 42, item["SK"])
    assert "title" not in body["audits"][0]
    assert body["findings"][0]["file"] == "src/auth.py"
    assert body["findings"][0]["line"] == 17
    assert body["repositories"] == [{
        "name": "octo/private-repo", "owner": "octo", "audits": 1,
        "latestTimestamp": 1700000000, "status": "COMPLETED",
    }]
    assert table.scan_args["Limit"] == 20


def test_audit_detail_uses_exact_key_and_consistent_read(monkeypatch):
    item = sample_item()
    table = FakeTable(item=item)
    monkeypatch.setattr(dashboard, "_table", table)
    identifier = dashboard.audit_id("octo/private-repo", 42, item["SK"])
    status, body = decode_response(dashboard.audit_handler({"pathParameters": {"id": identifier}}))
    assert status == 200
    assert body["findingDetails"][0]["cwe"] == "CWE-862"
    assert table.get_args == {
        "Key": {"PK": "octo/private-repo#42", "SK": item["SK"]},
        "ConsistentRead": True,
    }


def test_invalid_input_is_rejected_and_missing_audit_is_404(monkeypatch):
    status, body = decode_response(dashboard.dashboard_handler({"queryStringParameters": {"limit": "1000"}}))
    assert status == 400
    assert "temporarily" not in body["error"]
    monkeypatch.setattr(dashboard, "_table", FakeTable())
    status, _ = decode_response(dashboard.audit_handler({"pathParameters": {"id": "bad"}}))
    assert status == 400
    identifier = dashboard.audit_id("octo/private-repo", 42, sample_item()["SK"])
    status, body = decode_response(dashboard.audit_handler({"pathParameters": {"id": identifier}}))
    assert status == 404
    assert "PK" not in body["error"]


def test_expired_audit_is_not_returned(monkeypatch):
    item = sample_item()
    item["ttl"] = 1
    monkeypatch.setattr(dashboard, "_table", FakeTable(item=item))
    identifier = dashboard.audit_id("octo/private-repo", 42, item["SK"])
    status, body = decode_response(dashboard.audit_handler({"pathParameters": {"id": identifier}}))
    assert status == 404
    assert body["error"] == "Audit not found."


def test_scan_cursor_is_opaque_and_bounded():
    cursor = {"PK": "octo/repo#1", "SK": "abcdef0123456789"}
    token = dashboard.encode_cursor(cursor)
    assert dashboard.decode_cursor(token) == cursor
    with pytest.raises(ValueError):
        dashboard.parse_limit({"limit": "0"})
    with pytest.raises(ValueError):
        dashboard.decode_cursor("%%%")


def test_malformed_findings_json_returns_no_fabricated_findings(caplog):
    item = sample_item()
    item["findings"] = "{bad json"
    record = dashboard.serialize_audit(item)
    assert record["findingDetails"] == []
    assert "malformed" in caplog.text
