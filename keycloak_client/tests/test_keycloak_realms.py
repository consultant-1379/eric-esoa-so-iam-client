"""The test module for keycloak realms"""
import json

from .conftest import init_auth_details
from ..scripts.keycloak_realms import RealmAdmin


#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_realms_get_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test keycloak keycloak realms get function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    realm_admin = RealmAdmin(auth_details, rest_client)
    assert realm_admin.get() == {'mock_json': True, 'realm': 'master'}


#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_realms_update_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                             tmp_path, monkeypatch):
    """Test keycloak keycloak realms update function if tls verification is enabled."""
    fake_client_config_json = {"fake_realm_config": True}
    with open(tmp_path/"realm_config.json", 'w') as client_config_path:
        json.dump(fake_client_config_json, client_config_path)
    auth_details, rest_client = init_auth_details()
    realm_admin = RealmAdmin(auth_details, rest_client)
    realm_admin.update(tmp_path/"realm_config.json")

#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_update_all_realms_has_tls_verification_enabled(initialize_tls_verify_tests,
                                                                 tmp_path, monkeypatch):
    """Test keycloak keycloak all realms update function if tls verification is enabled."""
    fake_client_config_json = {"fake_realm_config": True}
    with open(tmp_path/"realm_config.json", 'w') as client_config_path:
        json.dump(fake_client_config_json, client_config_path)
    auth_details, rest_client = init_auth_details()
    realm_admin = RealmAdmin(auth_details, rest_client)
    realm_admin.update_all_realms(tmp_path/"realm_config.json")

#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_realms_export_has_tls_verification_enabled(initialize_tls_verify_tests):
    """Test keycloak keycloak realms export function if tls verification is enabled."""
    auth_details, rest_client = init_auth_details()
    realm_admin = RealmAdmin(auth_details, rest_client)
    assert realm_admin.export() == {'mock_json': True, 'realm': 'master'}
