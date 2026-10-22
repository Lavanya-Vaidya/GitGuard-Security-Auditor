import importlib.util
import os

# Load ingest app module directly to prevent module collisions with worker app
ingest_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "ingest", "app.py"))
spec = importlib.util.spec_from_file_location("ingest_app", ingest_path)
ingest_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ingest_app)


import base64
import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch
import pytest
from botocore.exceptions import ClientError


@pytest.fixture(autouse=True)
def reset_ingest_state():
    ingest_app._cached_webhook_secret = None
    ingest_app._secrets_client = None
    ingest_app._dynamodb_resource = None
    ingest_app._lambda_client = None


def test_verify_signature_valid():
    secret = "my_super_secret_webhook_key"
    payload = b'{"action": "opened"}'
    sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    header = f"sha256={sig}"

    assert ingest_app.verify_signature(secret, payload, header) is True


def test_verify_signature_invalid():
    secret = "my_super_secret_webhook_key"
    payload = b'{"action": "opened"}'
    header = "sha256=invalid_hash_signature"

    assert ingest_app.verify_signature(secret, payload, header) is False


def test_verify_signature_missing_header():
    secret = "my_super_secret_webhook_key"
    payload = b'{"action": "opened"}'

    assert ingest_app.verify_signature(secret, payload, None) is False
    assert ingest_app.verify_signature(secret, payload, "invalid_format_no_prefix") is False


@patch.object(ingest_app, "get_secrets_client")
def test_handler_invalid_signature(mock_secrets):
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"webhook_secret": "test_secret"})
    }
    mock_secrets.return_value = mock_client

    event = {
        "headers": {
            "x-hub-signature-256": "sha256=wrong",
            "x-github-event": "pull_request",
        },
        "body": '{"action": "opened"}',
        "isBase64Encoded": False,
    }

    resp = ingest_app.lambda_handler(event, None)
    assert resp["statusCode"] == 401
    assert "Invalid signature" in resp["body"]


@patch.object(ingest_app, "get_secrets_client")
def test_handler_ignore_non_pr_event(mock_secrets):
    secret = "test_secret"
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"webhook_secret": secret})
    }
    mock_secrets.return_value = mock_client

    body_str = '{"action": "created"}'
    sig = hmac.new(secret.encode(), body_str.encode(), hashlib.sha256).hexdigest()

    event = {
        "headers": {
            "x-hub-signature-256": f"sha256={sig}",
            "x-github-event": "push",
        },
        "body": body_str,
        "isBase64Encoded": False,
    }

    resp = ingest_app.lambda_handler(event, None)
    assert resp["statusCode"] == 200
    assert "Ignored event type 'push'" in resp["body"]


@patch.object(ingest_app, "get_secrets_client")
def test_handler_ignore_unsupported_pr_action(mock_secrets):
    secret = "test_secret"
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"webhook_secret": secret})
    }
    mock_secrets.return_value = mock_client

    body_str = json.dumps({"action": "closed", "pull_request": {"number": 1}})
    sig = hmac.new(secret.encode(), body_str.encode(), hashlib.sha256).hexdigest()

    event = {
        "headers": {
            "x-hub-signature-256": f"sha256={sig}",
            "x-github-event": "pull_request",
        },
        "body": body_str,
        "isBase64Encoded": False,
    }

    resp = ingest_app.lambda_handler(event, None)
    assert resp["statusCode"] == 200
    assert "Ignored pull_request action 'closed'" in resp["body"]


@patch.object(ingest_app, "get_lambda_client")
@patch.object(ingest_app, "get_dynamodb_table")
@patch.object(ingest_app, "get_secrets_client")
def test_handler_duplicate_delivery_idempotent(mock_secrets, mock_table, mock_lambda):
    secret = "test_secret"
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"webhook_secret": secret})
    }
    mock_secrets.return_value = mock_client

    table_mock = MagicMock()
    table_mock.put_item.side_effect = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem"
    )
    mock_table.return_value = table_mock

    body_str = json.dumps({
        "action": "opened",
        "repository": {"full_name": "owner/repo"},
        "pull_request": {"number": 1, "head": {"sha": "abc1234"}},
        "installation": {"id": 9999}
    })
    sig = hmac.new(secret.encode(), body_str.encode(), hashlib.sha256).hexdigest()

    event = {
        "headers": {
            "x-hub-signature-256": f"sha256={sig}",
            "x-github-event": "pull_request",
            "x-github-delivery": "guid-12345",
        },
        "body": body_str,
        "isBase64Encoded": False,
    }

    resp = ingest_app.lambda_handler(event, None)
    assert resp["statusCode"] == 200
    assert "Duplicate delivery ignored" in resp["body"]
    mock_lambda.return_value.invoke.assert_not_called()


@patch.object(ingest_app, "get_lambda_client")
@patch.object(ingest_app, "get_dynamodb_table")
@patch.object(ingest_app, "get_secrets_client")
def test_handler_successful_async_worker_invocation(mock_secrets, mock_table, mock_lambda):
    secret = "test_secret"
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"webhook_secret": secret})
    }
    mock_secrets.return_value = mock_client

    table_mock = MagicMock()
    mock_table.return_value = table_mock

    lambda_mock = MagicMock()
    mock_lambda.return_value = lambda_mock

    body_str = json.dumps({
        "action": "synchronize",
        "repository": {"full_name": "acme/corp"},
        "pull_request": {"number": 42, "head": {"sha": "fedcba987"}},
        "installation": {"id": 8888}
    })
    sig = hmac.new(secret.encode(), body_str.encode(), hashlib.sha256).hexdigest()

    event = {
        "headers": {
            "x-hub-signature-256": f"sha256={sig}",
            "x-github-event": "pull_request",
            "x-github-delivery": "unique-delivery-999",
        },
        "body": body_str,
        "isBase64Encoded": False,
    }

    resp = ingest_app.lambda_handler(event, None)
    assert resp["statusCode"] == 202
    assert "Audit scan queued" in resp["body"]

    # Verify worker was invoked asynchronously
    lambda_mock.invoke.assert_called_once()
    call_args = lambda_mock.invoke.call_args[1]
    assert call_args["InvocationType"] == "Event"
    payload = json.loads(call_args["Payload"])
    assert payload["repo_full_name"] == "acme/corp"
    assert payload["pr_number"] == 42
    assert payload["head_sha"] == "fedcba987"
    assert payload["installation_id"] == 8888
