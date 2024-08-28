"""The test module for keycloak users"""
import pytest
from ..scripts.keycloak_users import UsersAdmin
from .conftest import MockResponse, init_auth_details


@pytest.fixture
#pylint: disable=unused-argument
def initialize_keycloak_users_tests(monkeypatch):
    """Initialize tests for keycloak users module."""
    def mock_json(*args, **kwargs):
        response_json = [{"username": "fake_user"}]
        return response_json
    monkeypatch.setattr(MockResponse, "json", mock_json)


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_users_get_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                         initialize_keycloak_users_tests):
    """Test keycloak keycloak users get function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    user_admin = UsersAdmin(auth_details, rest_client)
    assert user_admin.get("fake_user") == {"username": "fake_user"}


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_users_create_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                            initialize_keycloak_users_tests):
    """Test keycloak keycloak users create function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    user_admin = UsersAdmin(auth_details, rest_client)
    user_admin.create("fake_user_1", "fake_password_1")
