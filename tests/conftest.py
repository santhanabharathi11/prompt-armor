import os
import pytest
from fastapi.testclient import TestClient

# Set test-safe env vars before importing the app
os.environ.setdefault("ARMOR_AUDIT_LOG_PATH", "/tmp/prompt-armor-test-audit.jsonl")
os.environ.setdefault("ARMOR_AUDIT_LOG_ENABLED", "false")
os.environ.setdefault("ARMOR_RATE_LIMIT_ENABLED", "false")

from prompt_armor.main import app


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as c:
        yield c
