"""The test module for keycloak groups"""
import json
import pytest

from keycloak_client.scripts.keycloak_groups import GroupAdmin
from .conftest import MockResponse, init_auth_details


@pytest.fixture
def initialize_keycloak_group_tests(monkeypatch):
    """Initialize tests for keycloak group module."""
    # pylint: disable=unused-argument
    def mock_groups_json(*args, **kwargs):
        response_json = [{"name": "fake_group_name",
                          "id": "fake_group_id"}]
        return response_json

    monkeypatch.setattr(MockResponse, "json", mock_groups_json)

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_multiple_groups_create_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_group_tests, tmp_path):
    """Test keycloak group create function if tls verification is enabled."""
    fake_group_config_file_json = [{"name": "fake_name"}, {"name": "group_test"}]
    with open(tmp_path / "fake_group_config.json", "w") as group_config_path:
        json.dump(fake_group_config_file_json, group_config_path)
    auth_details, rest_client = init_auth_details()
    group_admin = GroupAdmin(auth_details, rest_client)
    group_admin.create(tmp_path / "fake_group_config.json")

def test_keycloak_group_create_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_group_tests, tmp_path):
    """Test keycloak group create function if tls verification is enabled."""
    fake_group_config_file_json = {"name": "fake_name"}
    with open(tmp_path / "fake_group_config.json", "w") as group_config_path:
        json.dump(fake_group_config_file_json, group_config_path)
    auth_details, rest_client = init_auth_details()
    group_admin = GroupAdmin(auth_details, rest_client)
    group_admin.create(tmp_path / "fake_group_config.json")

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_group_update_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_group_tests, tmp_path):
    """Test keycloak group update function if tls verification is enabled."""
    fake_group_config_file_json = {"name": "fake_name"}
    with open(tmp_path / "fake_group_config.json", "w") as group_config_path:
        json.dump(fake_group_config_file_json, group_config_path)

    auth_details, rest_client = init_auth_details()
    group_admin = GroupAdmin(auth_details, rest_client)
    group_admin.update("fake_group_name", tmp_path / "fake_group_config.json")

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_group_delete_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_group_tests):
    """Test keycloak group delete function if tls verification is enabled."""

    auth_details, rest_client = init_auth_details()
    group_admin = GroupAdmin(auth_details, rest_client)
    group_admin.delete("fake_group_name")

# pylint: disable=unused-argument,  redefined-outer-name
def test_keycloak_group_get_has_tls_verification_enabled(
        initialize_tls_verify_tests, initialize_keycloak_group_tests):
    """Test keycloak group get function if tls verification is enabled."""

    auth_details, rest_client = init_auth_details()
    group_admin = GroupAdmin(auth_details, rest_client)
    assert group_admin.get() == [{"name": "fake_group_name", "id": "fake_group_id"}]
