"""The test module for keycloak clients"""
import json
from unittest.mock import Mock

import pytest

from ..scripts.keycloak_clients import ClientAdmin
from .conftest import MockResponse, init_auth_details


#pylint: disable=unused-argument
def mock_json_with_results(*args, **kwargs):
    """Mock Response.json() with results"""
    response_json = [{"mock_json": True, "id": "00", "clientId": "fake_client", "defaultClientScopes": ["openid"]}]
    return response_json

#pylint: disable=unused-argument
def mock_scopes_json_with_results(*args, **kwargs):
    """Mock Response.json() with results"""
    response_json = [{"id": "1", "name": "openid"}, {"id": "2", "name": "profile"}]
    return response_json


#pylint: disable=unused-argument
def mock_json_without_results(*args, **kwargs):
    """Mock Response.json() without results"""
    return None


#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_client_admin_get_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                                monkeypatch):
    """Test keycloak client admin get function if tls verification is enabled."""
    monkeypatch.setattr(MockResponse, "json", mock_json_with_results)
    auth_details, rest_client = init_auth_details()
    client_admin = ClientAdmin(auth_details, rest_client)
    result = client_admin.get("fake_client")
    assert result == {"mock_json": True, "id": "00", "clientId": "fake_client", "defaultClientScopes": ["openid"]}


@pytest.mark.parametrize("input_json,mock_json_method",
                         [({"clientId": "fake_client", "defaultClientScopes": ["openid"]}, mock_json_with_results),
                          ({"clientId": "fake_client", "defaultClientScopes": ["openid"]}, mock_json_without_results)])
#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_client_admin_create_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                                   tmp_path, monkeypatch,
                                                                   input_json, mock_json_method):
    """Test keycloak client admin create function if tls verification is enabled."""
    monkeypatch.setattr(MockResponse, "json", mock_json_method)
    fake_client_config_json = input_json
    with open(tmp_path/"client_config.json", 'w') as client_config_path:
        json.dump(fake_client_config_json, client_config_path)
    auth_details, rest_client = init_auth_details()
    client_admin = ClientAdmin(auth_details, rest_client)
    client_admin.create(tmp_path/"client_config.json")


#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_client_admin_delete_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                                   monkeypatch):
    """Test keycloak client admin delete function if tls verification is enabled."""
    monkeypatch.setattr(MockResponse, "json", mock_json_with_results)
    auth_details, rest_client = init_auth_details()
    client_admin = ClientAdmin(auth_details, rest_client)
    client_admin.delete("fake_client")


@pytest.mark.parametrize("input_json,mock_json_method", [({"clientId": "fake_client"}, mock_json_with_results),
                                                         ({"clientId": "fake_client"}, mock_json_without_results)
                                                         ])
#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_client_create_ext_client(initialize_tls_verify_tests,
                                           monkeypatch, input_json, mock_json_method):
    """Test keycloak client admin create external client function if tls verification is enabled."""
    monkeypatch.setattr(MockResponse, "json", mock_json_method)
    test_response = Mock(side_effect=iter([200, 204, 200, 204, 200, 204]))
    monkeypatch.setattr(MockResponse, "status_code", test_response())
    auth_details, rest_client = init_auth_details()
    client_admin = ClientAdmin(auth_details, rest_client)
    client_admin.create_ext_client("bdr-test")


# pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_client_admin_get_client_scope_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                                             monkeypatch):
    """Test keycloak client admin get client scope function if tls verification is enabled."""
    monkeypatch.setattr(MockResponse, "json", mock_scopes_json_with_results)
    auth_details, rest_client = init_auth_details()
    client_admin = ClientAdmin(auth_details, rest_client)
    result = client_admin.get_client_scope("openid")
    assert result == (True, {"id": "1", "name": "openid"})


# pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_client_admin_update_client_scope_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                                                monkeypatch):
    """Test keycloak client admin update client scope function if tls verification is enabled."""
    monkeypatch.setattr(MockResponse, "json", mock_json_with_results)
    auth_details, rest_client = init_auth_details()
    client_admin = ClientAdmin(auth_details, rest_client)
    client_admin.update_client_scope_to_client("fake_client", {"id": "1", "name": "openid"})
