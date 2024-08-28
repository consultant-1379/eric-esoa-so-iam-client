"""The test module for keycloak users realm role mappings"""
import json
import pytest
from ..scripts.keycloak_users_realm_role_mappings import UserRealmRoleMappingsAdmin
from ..scripts.keycloak_users import UsersAdmin
from .conftest import MockResponse, init_auth_details


@pytest.fixture
def initialize_keycloak_users_realm_role_mappings_tests(monkeypatch):
    """Initialize tests for keycloak users role mappings module."""
    #pylint: disable=unused-argument
    def mock_user_get(*args, **kwargs):
        return {"username": "fake_user", "id": "00"}
    #pylint: disable=unused-argument
    def mock_role_json(*args, **kwargs):
        response_json = {"role": "fake_role",
                         "id": "00"}
        return response_json
    monkeypatch.setattr(UsersAdmin, "get", mock_user_get)
    monkeypatch.setattr(MockResponse, "json", mock_role_json)

#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_mapping_create_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                              initialize_keycloak_users_realm_role_mappings_tests,
                                                              tmp_path):
    """Test keycloak keycloak keycloak users realm role mappings create function if tls verification is enabled."""
    fake_mappings_config_file_json = [{"fake_realm_config": True,
                                       "name": "fake_role",
                                       "id": "00"}]
    with open(tmp_path/"mapping_config.json", 'w') as mappings_config_path:
        json.dump(fake_mappings_config_file_json, mappings_config_path)
    auth_details, rest_client = init_auth_details()
    user_admin = UserRealmRoleMappingsAdmin(auth_details, rest_client)
    user_admin.create("fake_user", tmp_path/"mapping_config.json")
