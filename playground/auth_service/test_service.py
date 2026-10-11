"""Test suite demonstrating intentional SQL injection failure and secure behavior."""

import pytest

from playground.auth_service.service import AuthService


@pytest.fixture
def auth_service() -> AuthService:
    """Fixture providing initialized AuthService instance."""
    return AuthService()


def test_valid_admin_login(auth_service: AuthService):
    """Test standard authentication with legitimate credentials."""
    user = auth_service.authenticate_user("admin", "SuperSecretPass123!")
    assert user is not None
    assert user["username"] == "admin"
    assert user["role"] == "admin"


def test_invalid_login(auth_service: AuthService):
    """Test authentication failure with incorrect credentials."""
    user = auth_service.authenticate_user("admin", "WrongPassword")
    assert user is None


def test_sql_injection_bypass_prevented(auth_service: AuthService):
    """Security test asserting that SQL injection payloads do NOT bypass authentication.

    FAILS on vulnerable code: ' OR '1'='1 returns admin user or raises OperationalError.
    PASSES on remediated code: injection payload treated as literal string.
    """
    injection_payload = "' OR '1'='1"
    user = auth_service.authenticate_user("random_user", injection_payload)
    # On secure implementation, unauthorized attacker must NOT be logged in
    assert (
        user is None
    ), "Vulnerability detected: SQL injection authentication bypass succeeded!"
