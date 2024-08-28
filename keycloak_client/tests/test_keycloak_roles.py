"""The test module for keycloak roles"""
from .conftest import init_auth_details
from ..scripts.keycloak_roles import RoleAdmin


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_roles_get_realm_role_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test keycloak keycloak roles _get_realm_role function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    role_admin = RoleAdmin(auth_details, rest_client)
    assert role_admin._get_realm_role("fake_role") == {"mock_json": True, 'realm': 'master'}


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_roles_create_realm_role_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test keycloak keycloak roles _create_realm_role function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    role_admin = RoleAdmin(auth_details, rest_client)
    role_admin._create_realm_role("fake_role")


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_roles_update_realm_role_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test keycloak keycloak roles _update_realm_role function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    role_admin = RoleAdmin(auth_details, rest_client)
    role_admin._update_realm_role({"fake_role": True, "id": "00"})


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_roles_delete_realm_role_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test keycloak keycloak roles _delete_realm_role function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    role_admin = RoleAdmin(auth_details, rest_client)
    role_admin._delete_realm_role("fake_role")


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_roles_add_composite_roles_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test keycloak keycloak roles _add_composite_roles function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    role_admin = RoleAdmin(auth_details, rest_client)
    role_admin._add_composite_roles({"fake_role": True, "id": "00"}, {"fake_associated_roles": True})


#pylint: disable=unused-argument, redefined-outer-name, protected-access
def test_keycloak_roles_remove_composite_roles_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test keycloak keycloak roles _remove_composite_roles function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    role_admin = RoleAdmin(auth_details, rest_client)
    role_admin._remove_composite_roles({"fake_role": True, "id": "00"}, {"fake_associated_roles": True})
