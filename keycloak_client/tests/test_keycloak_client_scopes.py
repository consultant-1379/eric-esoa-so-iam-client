"""The test module for keycloak client scopes"""
import json
import pytest

from keycloak_client.scripts.keycloak_client_scopes import ClientScopeAdmin
from .conftest import MockResponse, init_auth_details

@pytest.fixture
def initialize_keycloak_client_scope_tests(monkeypatch):
    """Initialize tests for keycloak client scope module."""
    # pylint: disable=unused-argument
    def mock_client_scope_json(*args, **kwargs):
        response_json = [{"name": "fake_client_scope_name",
                          "id": "fake_client_scope_id"}]
        return response_json

    monkeypatch.setattr(MockResponse, "json", mock_client_scope_json)

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_client_scope_create_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_client_scope_tests, tmp_path):
    """Test keycloak client scope create function if tls verification is enabled."""
    fake_client_scope_config_file_json = {"name": "fake_name"}
    with open(tmp_path / "fake_client_scope_config.json", "w") as client_scope_config_path:
        json.dump(fake_client_scope_config_file_json, client_scope_config_path)

    auth_details, rest_client = init_auth_details()
    client_scope_admin = ClientScopeAdmin(auth_details, rest_client)
    client_scope_admin.create(tmp_path / "fake_client_scope_config.json")

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_client_scope_update_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_client_scope_tests, tmp_path):
    """Test keycloak client scope update function if tls verification is enabled."""
    fake_client_scope_config_file_json = {"name": "fake_name"}
    with open(tmp_path / "fake_client_scope_config.json", "w") as client_scope_config_path:
        json.dump(fake_client_scope_config_file_json, client_scope_config_path)

    auth_details, rest_client = init_auth_details()
    client_scope_admin = ClientScopeAdmin(auth_details, rest_client)
    client_scope_admin.update("fake_client_scope_name", tmp_path / "fake_client_scope_config.json")

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_client_scope_delete_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_client_scope_tests):
    """Test keycloak client scope delete function if tls verification is enabled."""

    auth_details, rest_client = init_auth_details()
    client_scope_admin = ClientScopeAdmin(auth_details, rest_client)
    client_scope_admin.delete("fake_client_scope_name")

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_client_scope_get_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_client_scope_tests):
    """Test keycloak client scope get function if tls verification is enabled."""

    auth_details, rest_client = init_auth_details()
    client_scope_admin = ClientScopeAdmin(auth_details, rest_client)
    assert client_scope_admin.get("fake_client_scope_name") == {"name": "fake_client_scope_name",
                                                                "id": "fake_client_scope_id"}
