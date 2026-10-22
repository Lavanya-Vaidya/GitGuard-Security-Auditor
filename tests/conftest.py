import os
import sys
import pytest

# Add src directories to sys.path so test suites can import modules directly
src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(src_dir, "ingest"))
sys.path.insert(0, os.path.join(src_dir, "worker"))

# Set required dummy env vars for boto3 and app initializers
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["TABLE_NAME"] = "MockSecurityAuditTable"
os.environ["GITHUB_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789012:secret:github-app-mock"
os.environ["WORKER_FUNCTION_ARN"] = "arn:aws:lambda:us-east-1:123456789012:function:WorkerFunction"
os.environ["BEDROCK_MODEL_ID"] = "us.google.gemma-2-27b-it-v1:0"
os.environ["MAX_DIFF_SIZE"] = "100000"
