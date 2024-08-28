"""The module is for managing keycloak password policy."""
import collections
import logging

from keycloak_client.scripts.keycloak_realms import RealmAdmin


class PasswordPolicyUpdate:
    """The class for managing password policy"""
    BOOLEAN_PASSWORD_POLICY = ['notUsername', 'notEmail']
    ACCEPTED_PASSWORD_POLICY = ['hashIterations', 'passwordHistory', 'length', 'specialChars', 'upperCase', 'lowerCase',
                                'digits', 'hashAlgorithm', 'filteredForceExpiredPwdChange']
    PASSWORD_POLICY = 'passwordPolicy'
    PASSWORD_POLICY_SEPERATOR = ' and '
    POLICY_STRING = '{}({})'

    def __init__(self, auth_details, rest_client):
        self.auth_details = auth_details
        self.ACCEPTED_PASSWORD_POLICY.extend(self.BOOLEAN_PASSWORD_POLICY)
        self.rest_client = rest_client
        self.realm_admin = RealmAdmin(self.auth_details, self.rest_client)

    def __delete_password_policy(self, realm_response, policy_to_remove):
        """The method is for deleting password policy present in the realm without updating others"""
        if realm_response and self.PASSWORD_POLICY in realm_response and realm_response[self.PASSWORD_POLICY]:
            password_policy_from_response = realm_response[self.PASSWORD_POLICY]
            all_policy_from_response = password_policy_from_response.split(self.PASSWORD_POLICY_SEPERATOR)
            all_policy_to_remove = policy_to_remove
            temp_all_policy_from_response = all_policy_from_response.copy()
            for policy in all_policy_to_remove:
                for policy_in_response in temp_all_policy_from_response:
                    if policy in policy_in_response:
                        all_policy_from_response.remove(policy_in_response)
            if collections.Counter(all_policy_from_response) != collections.Counter(temp_all_policy_from_response):
                policy_to_update = self.PASSWORD_POLICY_SEPERATOR.join(all_policy_from_response)
                password_policy = {self.PASSWORD_POLICY: policy_to_update}
                self.realm_admin.update_realm(realm_response["realm"], password_policy)
        else:
            logging.warning("No password policy configured for the realm '%s'", realm_response['realm'])

    def delete(self, policy_to_remove):
        """The method is for deleting password policy present in the realm"""
        realm_response = self.realm_admin.get()
        self.__delete_password_policy(realm_response, policy_to_remove)

    def delete_from_all(self, policy_to_remove):
        """The method is for deleting password policy present in qll the realm"""
        all_realm_response = self.realm_admin.get_all_realms()
        if all_realm_response:
            for realm in all_realm_response:
                self.__delete_password_policy(realm, policy_to_remove)

    def update(self, policy_to_add, value=None):
        """The method is for adding a password policy to the realm without updating others"""
        realm_response = self.realm_admin.get()
        password_policy = {}
        if realm_response and self.PASSWORD_POLICY in realm_response and realm_response[self.PASSWORD_POLICY]:
            password_policy_from_response = realm_response[self.PASSWORD_POLICY]
            password_policy_from_response += self.PASSWORD_POLICY_SEPERATOR
            if policy_to_add in self.BOOLEAN_PASSWORD_POLICY:
                password_policy_from_response += policy_to_add
                password_policy[self.PASSWORD_POLICY] = password_policy_from_response
            else:
                password_policy_from_response += self.POLICY_STRING.format(policy_to_add, value)
                password_policy[self.PASSWORD_POLICY] = password_policy_from_response
        else:
            if policy_to_add in self.BOOLEAN_PASSWORD_POLICY:
                password_policy[self.PASSWORD_POLICY] = policy_to_add
            else:
                password_policy[self.PASSWORD_POLICY] = self.POLICY_STRING.format(policy_to_add, value)
        if len(password_policy) != 0:
            self.realm_admin.update_realm(realm_response["realm"], password_policy)
