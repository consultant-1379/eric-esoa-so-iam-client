"""The test module for keycloak client scope mappings"""
import json
import pytest

from keycloak_client.scripts.keycloak_client_scope_mappings import ClientScopeMappingAdmin
from keycloak_client.scripts.keycloak_client_scopes import ClientScopeAdmin
from keycloak_client.scripts.keycloak_clients import ClientAdmin
from .conftest import MockResponse, init_auth_details




# pylint: disable=duplicate-code
@pytest.fixture
def initialize_keycloak_client_scope_mapping_tests(monkeypatch):
    """Initialize tests for keycloak client scope mapping module."""
    # pylint: disable=unused-argument
    def mock_client_scope_mapping_json(*args, **kwargs):
        response_json = [{"name": "fake_client_scope_mapping_name"}]
        return response_json

    # pylint: disable=unused-argument
    def mock_client_scope_json(*args, **kwargs):
        response_json = {"id": "fake_client_scope_id",
                         "name": "fake_client_scope_name"}
        return response_json

    # pylint: disable=unused-argument
    def mock_client_json(*args, **kwargs):
        response_json = {"name": "fake_client_scope_name",
                         "id": "fake_client_id"}
        return response_json

    monkeypatch.setattr(MockResponse, "json", mock_client_scope_mapping_json)
    monkeypatch.setattr(ClientScopeAdmin, "get", mock_client_scope_json)
    monkeypatch.setattr(ClientAdmin, "get", mock_client_json)

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_client_scope_mapping_create_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_client_scope_mapping_tests, tmp_path):
    """Test keycloak client scope mapping create function if tls verification is enabled."""
    fake_client_scope_mappings_config_file_json = [{"name": "fake_name"}]
    with open(tmp_path / "fake_client_scope_mapping_config.json", "w") as client_scope_mappings_config_path:
        json.dump(fake_client_scope_mappings_config_file_json, client_scope_mappings_config_path)

    auth_details, rest_client = init_auth_details()
    client_scope_mapping_admin = ClientScopeMappingAdmin(auth_details, rest_client)
    client_scope_mapping_admin.create(
        "fake_client_scope_name", "fake_client_name", tmp_path / "fake_client_scope_mapping_config.json"
    )

# pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_client_scope_mapping_delete_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_client_scope_mapping_tests, tmp_path):
    """Test keycloak client scope mapping delete function if tls verification is enabled."""
    fake_client_scope_mappings_config_file_json = [{"name": "fake_client_scope_mapping_name"}]
    with open(tmp_path / "fake_client_scope_mapping_config.json", "w") as client_scope_mappings_config_path:
        json.dump(fake_client_scope_mappings_config_file_json, client_scope_mappings_config_path)

    auth_details, rest_client = init_auth_details()
    client_scope_mapping_admin = ClientScopeMappingAdmin(auth_details, rest_client)
    client_scope_mapping_admin.delete(
        "fake_client_scope_name", "fake_client_name", tmp_path / "fake_client_scope_mapping_config.json"
    )

# pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_client_scope_mapping_get_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_client_scope_mapping_tests):
    """Test keycloak client scope mapping get function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    client_scope_mapping_admin = ClientScopeMappingAdmin(auth_details, rest_client)
    assert client_scope_mapping_admin.get() == [{"name": "fake_client_scope_mapping_name"}]
