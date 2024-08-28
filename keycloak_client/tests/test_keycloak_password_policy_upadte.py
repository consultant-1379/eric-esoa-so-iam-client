"""The test module for keycloak password policy update"""
from keycloak_client.scripts.keycloak_password_policy_update import PasswordPolicyUpdate
from keycloak_client.tests.conftest import init_auth_details


#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_password_policy_update(initialize_tls_verify_tests):
    """Test keycloak keycloak password update policy with no passwordPolicy in realm response"""
    auth_details, rest_client = init_auth_details()
    password_policy = PasswordPolicyUpdate(auth_details, rest_client)
    policy_to_remove = ['hashIterations']
    assert password_policy.delete(policy_to_remove) is None


#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_password_policy_update_success(initialize_delete_policy_success):
    """Test keycloak keycloak password update policy"""
    auth_details, rest_client = init_auth_details()
    password_policy = PasswordPolicyUpdate(auth_details, rest_client)
    policy_to_remove = ['hashIterations']
    assert password_policy.delete(policy_to_remove) is None

#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_password_policy_update_with_policy_to_remove_not_present(initialize_delete_policy_success):
    """Test keycloak keycloak password update policy for policy to remove not present"""
    auth_details, rest_client = init_auth_details()
    password_policy = PasswordPolicyUpdate(auth_details, rest_client)
    policy_to_remove = ['test']
    assert password_policy.delete(policy_to_remove) is None

#pylint: disable=unused-argument, redefined-outer-name
def test_keycloak_password_policy_update_success_for_all_realms(initialize_delete_policy_success):
    """Test keycloak keycloak password update policy"""
    auth_details, rest_client = init_auth_details()
    password_policy = PasswordPolicyUpdate(auth_details, rest_client)
    policy_to_remove = ['hashIterations']
    assert password_policy.delete_from_all(policy_to_remove) is None
