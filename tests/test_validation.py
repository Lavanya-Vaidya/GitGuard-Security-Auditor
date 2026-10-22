import pytest
from app import strip_code_fences, validate_and_filter_findings


def test_strip_code_fences():
    fenced_1 = "```json\n{\"findings\": []}\n```"
    assert strip_code_fences(fenced_1) == '{"findings": []}'

    fenced_2 = "```\n{\"findings\": []}\n```"
    assert strip_code_fences(fenced_2) == '{"findings": []}'

    plain = '{"findings": []}'
    assert strip_code_fences(plain) == '{"findings": []}'


def test_validate_and_filter_valid_findings():
    raw_json = """{
      "findings": [
        {
          "line": 42,
          "severity": "critical",
          "cwe": "CWE-89",
          "title": "SQL Injection",
          "explanation": "Unsanitized user input passed directly to SQL query.",
          "fix": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
        }
      ]
    }"""
    valid_added_lines = {41, 42, 43}

    findings = validate_and_filter_findings(raw_json, valid_added_lines)
    assert len(findings) == 1
    assert findings[0]["line"] == 42
    assert findings[0]["severity"] == "critical"
    assert findings[0]["cwe"] == "CWE-89"


def test_validate_drops_findings_outside_added_lines():
    raw_json = """{
      "findings": [
        {
          "line": 100,
          "severity": "high",
          "cwe": "CWE-79",
          "title": "XSS",
          "explanation": "Reflected XSS in template.",
          "fix": "escape(input)"
        }
      ]
    }"""
    valid_added_lines = {10, 11, 12}  # Line 100 is NOT in added lines

    findings = validate_and_filter_findings(raw_json, valid_added_lines)
    assert len(findings) == 0


def test_validate_normalizes_unknown_severity():
    raw_json = """{
      "findings": [
        {
          "line": 15,
          "severity": "extreme_danger",
          "cwe": "CWE-94",
          "title": "Code Injection",
          "explanation": "Eval used",
          "fix": "remove eval"
        }
      ]
    }"""
    valid_added_lines = {15}

    findings = validate_and_filter_findings(raw_json, valid_added_lines)
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"  # Fallback to medium


def test_validate_empty_findings_payload():
    raw_json = '{"findings": []}'
    findings = validate_and_filter_findings(raw_json, {1, 2, 3})
    assert findings == []


def test_validate_malformed_json_raises():
    with pytest.raises(Exception):
        validate_and_filter_findings("not json at all", {1, 2})
