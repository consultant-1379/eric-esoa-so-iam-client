"""The test module for keycloak OpenID IDP"""
from unittest.mock import MagicMock

import pytest

from ..scripts.keycloak_idp import IDPAdmin
from ..scripts.keycloak_clients import ClientAdmin
from ..scripts.keycloak_protocol_mappers import ProtocolMapperAdmin

from .conftest import MockResponse, init_auth_details


@pytest.fixture
#pylint: disable=unused-argument
def initialize_keycloak_idp_tests(monkeypatch):
    """Initialize tests for keycloak OpenID IDP module."""
    def mock_json(*args, **kwargs):
        response_json = [{"alias": "oidc", "secret": "something", "clientId": "test", "id": "1234"}]
        return response_json
    monkeypatch.setattr(MockResponse, "json", mock_json)


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_idp_get_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                       initialize_keycloak_idp_tests):
    """Test keycloak keycloak OpenID IDP get function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    idp_admin = IDPAdmin(auth_details, rest_client)
    assert idp_admin.get() == {"alias": "oidc", "secret": "something", "clientId": "test", "id": "1234"}


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_idp_create_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                          initialize_keycloak_idp_tests):
    """Test keycloak keycloak OpenID IDP create function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    idp_admin = IDPAdmin(auth_details, rest_client)
    idp_admin.get = MagicMock()
    expected_well_known_resp = {
        "authorization_endpoint": "https://example.com",
        "token_endpoint": "https://example.com"
    }
    idp_admin.rest_client.request = MagicMock(return_value=(expected_well_known_resp, 200))
    idp_admin.create("bdr-test", "something")


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_idp_create_config(initialize_tls_verify_tests,
                                    initialize_keycloak_idp_tests):
    """Test keycloak keycloak OpenID IDP configuration when tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    idp_admin = IDPAdmin(auth_details, rest_client)
    idp_admin.get = MagicMock()
    expected_well_known_resp = {
        "authorization_endpoint": "https://example.com",
        "token_endpoint": "https://example.com"
    }
    idp_admin.rest_client.request = MagicMock(return_value=(expected_well_known_resp, 200))
    idp_admin.create("bdr-test", "something")

    admin_instance = ClientAdmin(auth_details, rest_client)
    proto_mapper_admin = ProtocolMapperAdmin(auth_details, rest_client)
    proto_mapper_admin.create_from_dict = MagicMock()
    expected_client = {"alias": "oidc", "secret": "something", "clientId": "test", "id": "1234"}
    admin_instance.get = MagicMock(return_value=expected_client)
    idp_admin.configure_client(admin_instance, proto_mapper_admin, "bdr-test")
    assert idp_admin.get.called
    assert len(proto_mapper_admin.create_from_dict.call_args_list) == 2

    assert proto_mapper_admin.create_from_dict.call_args_list[0][0][0] == "1234"
    assert proto_mapper_admin.create_from_dict.call_args_list[0][0][1] == "test"
    assert proto_mapper_admin.create_from_dict.call_args_list[0][0][2] == "oidc-audience-mapper"
    assert proto_mapper_admin.create_from_dict.call_args_list[0][0][3] == {
        'included.client.audience': 'test',
        'id.token.claim': 'false',
        'access.token.claim': 'true'
    }
    assert proto_mapper_admin.create_from_dict.call_args_list[1][0][0] == "1234"
    assert proto_mapper_admin.create_from_dict.call_args_list[1][0][1] == "test"
    assert proto_mapper_admin.create_from_dict.call_args_list[1][0][2] == "oidc-hardcoded-claim-mapper"
    assert proto_mapper_admin.create_from_dict.call_args_list[1][0][3] == {
        'id.token.claim': 'true',
        'access.token.claim': 'true',
        'userinfo.token.claim': 'true',
        'access.tokenResponse.claim': 'false',
        'claim.name': 'policy',
        'claim.value': 'readwrite'
    }
