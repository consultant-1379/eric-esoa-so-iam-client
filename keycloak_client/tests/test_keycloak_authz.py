"""The test module for keycloak authz"""
import json

from .conftest import init_auth_details
from ..scripts.keycloak_authz import AuthzAdmin


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_import_client_authz_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test if tls verification is enabled in _import_client_authz"""
    auth_details, rest_client = init_auth_details()
    authz_admin = AuthzAdmin(auth_details, rest_client)
    fake_authz_config = json.dumps({"fake_auth_config": True})
    authz_admin._import_client_authz(fake_authz_config)

#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_update_resource_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test if tls verification is enabled in _update_resource"""
    auth_details, rest_client = init_auth_details()
    authz_admin = AuthzAdmin(auth_details, rest_client)
    authz_admin._update_resource("00", "fake_resource")

#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_delete_resource_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test if tls verification is enabled in _delete_resource"""
    auth_details, rest_client = init_auth_details()
    authz_admin = AuthzAdmin(auth_details, rest_client)
    authz_admin._delete_resource("00")

#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_update_policy_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test if tls verification is enabled in _update_policy"""
    auth_details, rest_client = init_auth_details()
    authz_admin = AuthzAdmin(auth_details, rest_client)
    fake_policy = {"type": "js"}
    authz_admin._update_policy("00", fake_policy)

#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_delete_policy_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test if tls verification is enabled in _delete_policy"""
    auth_details, rest_client = init_auth_details()
    authz_admin = AuthzAdmin(auth_details, rest_client)
    fake_policy = {"id": "00", "type": "js"}
    authz_admin._delete_policy(fake_policy)
