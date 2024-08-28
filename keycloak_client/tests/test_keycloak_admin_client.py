"""The test module for keycloak admin client"""
import pytest

from ..scripts.keycloak_admin_client import AdminCliClient
from .conftest import MockResponse, init_auth_details


@pytest.fixture
#pylint: disable=unused-argument
def initialize_keycloak_admin_client_tests(monkeypatch):
    """Initialize tests for keycloak admin client module."""
    def mock_json(*args, **kwargs):
        response_json = {'access_token': 'cMGSM0x7h5sGpaiAxJpt6J2qO43RGrUwGAG1VAGlofY',
                         'token_type': 'bearer',
                         'not-before-policy': 0,
                         'session_state': 'be611526-73e4-462a-a425-1d4f819a4c29',
                         'scope': 'dummy_response',
                         'refresh_token': True}
        return response_json
    monkeypatch.setattr(MockResponse, "json", mock_json)
    monkeypatch.setattr(MockResponse, "content", mock_json)


#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_admin_login_logout_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                                  initialize_keycloak_admin_client_tests):
    """Test keycloak login /logout functions to see if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    admin_client = AdminCliClient(auth_details, rest_client)
    assert admin_client.login() == 'cMGSM0x7h5sGpaiAxJpt6J2qO43RGrUwGAG1VAGlofY'
    admin_client.logout()
