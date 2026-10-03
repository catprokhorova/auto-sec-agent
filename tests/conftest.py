"""Pytest configuration and shared async fixtures."""

import os
import pytest
from typing import AsyncGenerator, Dict, Any

from src.core.config import Settings, get_settings


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Fixture providing test configuration settings."""
    os.environ["USE_MOCK_LLM"] = "true"
    os.environ["LANGFUSE_ENABLED"] = "false"
    os.environ["MAX_LOOP_COUNT"] = "3"
    return get_settings()


@pytest.fixture
def sample_sast_alert() -> Dict[str, Any]:
    """Fixture returning sample static analysis vulnerability alert."""
    return {
        "tool": "semgrep",
        "check_id": "python.django.security.injection.sql-injection",
        "path": "services/user_service/views.py",
        "start_line": 42,
        "end_line": 45,
        "message": "User input concatenated directly into raw SQL query",
        "severity": "HIGH",
    }


@pytest.fixture
def sample_python_traceback() -> str:
    """Fixture returning realistic verbose build/test failure output with stack trace."""
    return """
[INFO] Container build step 1/8: FROM python:3.11-slim
[INFO] Container build step 2/8: WORKDIR /app
[INFO] Dependencies installed successfully.
============================= test session starts ==============================
platform linux -- Python 3.11.3, pytest-8.2.0, pluggy-1.5.0
rootdir: /app
collected 5 items

tests/test_auth.py ..F..                                                 [100%]

=================================== FAILURES ===================================
______________________________ test_user_login _______________________________

    def test_user_login():
>       token = authenticate_user("admin", "password' OR '1'='1")

services/auth/service.py:34: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

username = 'admin', password = "password' OR '1'='1"

    def authenticate_user(username: str, password: str) -> str:
        query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
>       cursor.execute(query)
E       sqlite3.OperationalError: unrecognized token: "'1'='1"

services/auth/service.py:18: OperationalError
=========================== short test summary info ============================
FAILED tests/test_auth.py::test_user_login - sqlite3.OperationalError: unrecognized token: "'1'='1"
========================= 1 failed, 4 passed in 0.42s ==========================
"""


@pytest.fixture
def mock_git_diff() -> str:
    """Fixture returning sample unified git diff patch."""
    return """--- a/services/auth/service.py
+++ b/services/auth/service.py
@@ -17,2 +17,2 @@
-    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
-    cursor.execute(query)
+    query = "SELECT id FROM users WHERE username = ? AND password = ?"
+    cursor.execute(query, (username, password))
"""
