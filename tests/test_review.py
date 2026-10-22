import pytest
from review import format_inline_comment_body, build_review_payload


def test_format_inline_comment_body():
    finding = {
        "severity": "critical",
        "title": "Hardcoded AWS Secret Key",
        "cwe": "CWE-798",
        "explanation": "AWS secret keys should never be committed into source code.",
        "fix": "Use environment variables or AWS Secrets Manager.",
    }
    body = format_inline_comment_body(finding)

    assert "🔴 **[CRITICAL]** Hardcoded AWS Secret Key (CWE-798)" in body
    assert "AWS secret keys should never be committed" in body
    assert "```suggestion\nUse environment variables" in body


def test_build_review_payload_clean():
    summary_body, comments = build_review_payload(
        findings_by_file={},
        files_scanned=5,
        files_skipped=2,
        is_truncated=False,
    )

    assert "No security vulnerabilities or policy violations detected" in summary_body
    assert "**Files Scanned:** 5" in summary_body
    assert "**Files Skipped:** 2" in summary_body
    assert len(comments) == 0


def test_build_review_payload_with_findings():
    findings = {
        "src/api/auth.py": [
            {
                "line": 25,
                "severity": "critical",
                "cwe": "CWE-89",
                "title": "SQL Injection",
                "explanation": "Direct string concat in query",
                "fix": "cursor.execute(..., params)",
            },
            {
                "line": 40,
                "severity": "medium",
                "cwe": "CWE-327",
                "title": "Weak Hash Function",
                "explanation": "MD5 is obsolete",
                "fix": "hashlib.sha256()",
            },
        ]
    }

    summary_body, comments = build_review_payload(
        findings_by_file=findings,
        files_scanned=1,
        files_skipped=0,
        is_truncated=True,
    )

    assert "Found 2 security finding(s)" in summary_body
    assert "🔴 Critical | 1" in summary_body
    assert "🟡 Medium | 1" in summary_body
    assert "Diff size exceeded" in summary_body
    assert len(comments) == 2

    c1 = comments[0]
    assert c1["path"] == "src/api/auth.py"
    assert c1["line"] == 25
    assert c1["side"] == "RIGHT"
    assert "SQL Injection" in c1["body"]
