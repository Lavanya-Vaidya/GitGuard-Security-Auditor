"""Read-only dashboard API for stored GitGuard audit records."""
import base64
import binascii
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

_table = None
DEFAULT_LIMIT = 100
MAX_LIMIT = 100
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
SHA_RE = re.compile(r"^[A-Fa-f0-9]{7,64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,2048}$")
SEVERITIES = ("critical", "high", "medium", "low")


def get_table():
    global _table
    if _table is None:
        _table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
    return _table


def response(status: int, body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps(body, separators=(",", ":")),
    }


def audit_id(repo: str, number: int, sha: str) -> str:
    raw = f"{repo}#{number}#{sha}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def parse_audit_id(value: Any) -> Tuple[str, int, str]:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise ValueError("invalid audit id")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid audit id") from exc
    parts = decoded.split("#")
    if len(parts) != 3:
        raise ValueError("invalid audit id")
    repo, number_text, sha = parts
    if not REPO_RE.fullmatch(repo) or not number_text.isdigit() or not SHA_RE.fullmatch(sha):
        raise ValueError("invalid audit id")
    number = int(number_text)
    if number < 1 or number > 2**31 - 1:
        raise ValueError("invalid audit id")
    if audit_id(repo, number, sha) != value:
        raise ValueError("invalid audit id")
    return repo, number, sha


def decode_findings(value: Any, repo: str, number: int, record_id: str) -> List[Dict[str, Any]]:
    if value in (None, ""):
        return []
    try:
        grouped = json.loads(value) if isinstance(value, str) else value
    except (json.JSONDecodeError, TypeError):
        logger.warning("Audit contains malformed stored findings JSON")
        return []
    if not isinstance(grouped, dict):
        logger.warning("Audit findings are not grouped by filename")
        return []

    flat: List[Dict[str, Any]] = []
    for filename, items in grouped.items():
        if not isinstance(filename, str) or not isinstance(items, list):
            continue
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            finding = {key: item[key] for key in ("severity", "title", "line", "category", "cwe", "explanation", "fix") if key in item}
            finding.update({
                "id": f"{record_id}:{filename}:{index}",
                "auditId": record_id,
                "repo": repo,
                "pr": number,
                "file": filename,
            })
            flat.append(finding)
    return flat


def serialize_audit(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    pk, sha = item.get("PK"), item.get("SK")
    if not isinstance(pk, str) or not isinstance(sha, str) or "#" not in pk:
        return None
    repo, number_text = pk.rsplit("#", 1)
    if not REPO_RE.fullmatch(repo) or not number_text.isdigit() or not SHA_RE.fullmatch(sha):
        return None
    number = int(number_text)
    if number < 1 or number > 2**31 - 1:
        return None
    record_id = audit_id(repo, number, sha)
    raw_counts = item.get("counts") if isinstance(item.get("counts"), dict) else {}
    counts = {severity: _nonnegative_int(raw_counts.get(severity, 0)) for severity in SEVERITIES}
    details = decode_findings(item.get("findings"), repo, number, record_id)
    timestamp = _nonnegative_int(item.get("timestamp", 0))
    return {
        "id": record_id,
        "repo": repo,
        "number": number,
        "sha": sha,
        "status": str(item.get("status", "Unknown")),
        "timestamp": timestamp,
        "counts": counts,
        "findingDetails": details,
        "findings": details,
        "files_scanned": _nonnegative_int(item.get("files_scanned", 0)),
        "files_skipped": _nonnegative_int(item.get("files_skipped", 0)),
        "is_truncated": bool(item.get("is_truncated", False)),
    }


def _nonnegative_int(value: Any) -> int:
    try:
        result = int(value)
        return max(result, 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def parse_limit(query: Dict[str, Any]) -> int:
    raw = query.get("limit", str(DEFAULT_LIMIT))
    if not isinstance(raw, str) or not raw.isdigit():
        raise ValueError("invalid limit")
    limit = int(raw)
    if limit < 1 or limit > MAX_LIMIT:
        raise ValueError("limit out of range")
    return limit


def decode_cursor(token: Any) -> Optional[Dict[str, str]]:
    if token is None or token == "":
        return None
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise ValueError("invalid cursor")
    try:
        data = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
        key = {name: data[name] for name in ("PK", "SK")}
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, TypeError, KeyError) as exc:
        raise ValueError("invalid cursor") from exc
    if not all(isinstance(value, str) and value for value in key.values()):
        raise ValueError("invalid cursor")
    return key


def encode_cursor(key: Optional[Dict[str, Any]]) -> Optional[str]:
    if not key:
        return None
    compact = json.dumps({name: key[name] for name in ("PK", "SK")}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(compact).decode("ascii").rstrip("=")


def scan_audits(limit: int, cursor: Optional[Dict[str, str]]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    params: Dict[str, Any] = {
        "FilterExpression": (
            Attr("counts").exists()
            & Attr("findings").exists()
            & Attr("timestamp").exists()
            & (Attr("ttl").not_exists() | Attr("ttl").gt(int(time.time())))
        ),
        "Limit": limit,
    }
    if cursor:
        params["ExclusiveStartKey"] = cursor
    result = get_table().scan(**params)
    records = []
    for item in result.get("Items", []):
        audit = serialize_audit(item)
        if audit:
            records.append(audit)
    records.sort(key=lambda audit: audit["timestamp"], reverse=True)
    return records, encode_cursor(result.get("LastEvaluatedKey"))


def dashboard_handler(event: Dict[str, Any]) -> Dict[str, Any]:
    query = event.get("queryStringParameters") or {}
    try:
        limit = parse_limit(query)
        cursor = decode_cursor(query.get("nextToken"))
    except ValueError:
        return response(400, {"error": "Invalid pagination parameters."})
    try:
        audits, next_token = scan_audits(limit, cursor)
    except (ClientError, BotoCoreError):
        logger.exception("DynamoDB dashboard read failed")
        return response(503, {"error": "Audit data is temporarily unavailable."})
    except Exception:
        logger.exception("Unexpected dashboard read failure")
        return response(500, {"error": "Dashboard request could not be completed."})

    findings = [finding for audit in audits for finding in audit["findingDetails"]]
    repositories: Dict[str, Dict[str, Any]] = {}
    for audit in audits:
        repo = repositories.setdefault(audit["repo"], {
            "name": audit["repo"], "owner": audit["repo"].split("/", 1)[0],
            "audits": 0, "latestTimestamp": audit["timestamp"], "status": audit["status"],
        })
        repo["audits"] += 1
        if audit["timestamp"] > repo["latestTimestamp"]:
            repo["latestTimestamp"] = audit["timestamp"]
            repo["status"] = audit["status"]
    logger.info("Dashboard records read", extra={"audit_count": len(audits), "finding_count": len(findings), "repository_count": len(repositories)})
    return response(200, {
        "audits": audits,
        "findings": findings,
        "repositories": list(repositories.values()),
        "nextToken": next_token,
    })


def audit_handler(event: Dict[str, Any]) -> Dict[str, Any]:
    path_params = event.get("pathParameters") or {}
    try:
        repo, number, sha = parse_audit_id(path_params.get("id"))
    except ValueError:
        return response(400, {"error": "Invalid audit id."})
    try:
        result = get_table().get_item(Key={"PK": f"{repo}#{number}", "SK": sha}, ConsistentRead=True)
    except (ClientError, BotoCoreError):
        logger.exception("DynamoDB audit detail read failed")
        return response(503, {"error": "Audit data is temporarily unavailable."})
    except Exception:
        logger.exception("Unexpected audit detail read failure")
        return response(500, {"error": "Audit request could not be completed."})
    item = result.get("Item")
    if item and item.get("ttl") is not None and _nonnegative_int(item.get("ttl")) <= int(time.time()):
        item = None
    audit = serialize_audit(item) if item else None
    if not audit:
        return response(404, {"error": "Audit not found."})
    logger.info("Audit detail record served")
    return response(200, audit)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    route = event.get("routeKey", "")
    if route == "GET /dashboard":
        return dashboard_handler(event)
    if route == "GET /audits/{id}":
        return audit_handler(event)
    logger.warning("Dashboard Lambda received unsupported route", extra={"route": route})
    return response(404, {"error": "Route not found."})
