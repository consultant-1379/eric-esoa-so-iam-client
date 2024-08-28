"""The test module for keycloak protocol mappers"""
import json
import pytest

from keycloak_client.scripts.keycloak_protocol_mappers import ProtocolMapperAdmin
from keycloak_client.scripts.keycloak_client_scopes import ClientScopeAdmin
from .conftest import MockResponse, init_auth_details


# pylint: disable=duplicate-code
@pytest.fixture
def initialize_keycloak_protocol_mapper_tests(monkeypatch):
    """Initialize tests for keycloak protocol mapper module."""
    # pylint: disable=unused-argument
    def mock_protocol_mappers_json(*args, **kwargs):
        response_json = [{"name": "fake_protocol_mapper_name",
                          "id": "fake_protocol_mapper_id"}]
        return response_json

    # pylint: disable=unused-argument
    def mock_client_scope_json(*args, **kwargs):
        response_json = {"name": "fake_client_scope_name",
                         "id": "fake_client_scope_id"}
        return response_json

    monkeypatch.setattr(MockResponse, "json", mock_protocol_mappers_json)
    monkeypatch.setattr(ClientScopeAdmin, "get", mock_client_scope_json)

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_protocol_mapper_create_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_protocol_mapper_tests, tmp_path):
    """Test keycloak protocol mapper create function if tls verification is enabled."""
    fake_protocol_mapper_config_file_json = [{"name": "fake_name"}]
    with open(tmp_path / "fake_protocol_mapper_config.json", "w") as protocol_mapper_config_path:
        json.dump(fake_protocol_mapper_config_file_json, protocol_mapper_config_path)

    auth_details, rest_client = init_auth_details()
    protocol_mapper_admin = ProtocolMapperAdmin(auth_details, rest_client)
    protocol_mapper_admin.create("fake_client_scope_name", tmp_path / "fake_protocol_mapper_config.json")

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_protocol_mapper_update_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_protocol_mapper_tests, tmp_path):
    """Test keycloak protocol mapper update function if tls verification is enabled."""
    fake_protocol_mapper_config_file_json = {"name": "fake_protocol_mapper_name"}
    with open(tmp_path / "fake_protocol_mapper_config.json", "w") as protocol_mapper_config_path:
        json.dump(fake_protocol_mapper_config_file_json, protocol_mapper_config_path)

    auth_details, rest_client = init_auth_details()
    protocol_mapper_admin = ProtocolMapperAdmin(auth_details, rest_client)
    protocol_mapper_admin.update("fake_client_scope_name",
                                 "fake_protocol_mapper_name", tmp_path / "fake_protocol_mapper_config.json")

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_protocol_mapper_delete_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_protocol_mapper_tests):
    """Test keycloak protocol mapper delete function if tls verification is enabled."""

    auth_details, rest_client = init_auth_details()
    protocol_mapper_admin = ProtocolMapperAdmin(auth_details, rest_client)
    protocol_mapper_admin.delete("fake_client_scope_name", "fake_protocol_mapper_name")

# pylint: disable=unused-argument
def test_keycloak_protocol_mapper_get_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_protocol_mapper_tests):
    """Test keycloak protocol mapper get function if tls verification is enabled."""

    auth_details, rest_client = init_auth_details()
    protocol_mapper_admin = ProtocolMapperAdmin(auth_details, rest_client)
    protocol_mapper_admin.mapping_endpoint = "fake_mapping_edpoint"
    assert protocol_mapper_admin.get() == [{"name": "fake_protocol_mapper_name", "id": "fake_protocol_mapper_id"}]
