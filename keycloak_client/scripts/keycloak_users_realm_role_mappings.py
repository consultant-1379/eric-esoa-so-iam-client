"""The module manages keycloak role mappings."""
import json
import logging
import urllib3

from keycloak_client.scripts.keycloak_users import UsersAdmin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#pylint: disable=too-few-public-methods
class UserRealmRoleMappingsAdmin:
    """The class manages keycloak role mappings."""
    def __init__(self, auth_details, rest_client):
        self.certificate_ca_path = auth_details.ca_cert_path
        self.keycloak_admin_url = auth_details.admin_url
        self.access_token = auth_details.token
        self.users_admin = UsersAdmin(auth_details, rest_client)
        self.rest_client = rest_client

    def create(self, username, user_realm_role_mappings_config_file):
        """The method to create new keycloak role mapping."""
        logging.info("Updating realm role mappings for user '%s'", username)
        user = self.users_admin.get(username)
        if user is None:
            raise UsernameNotFoundError("Username " + username + " was not found")

        keycloak_user_realm_role_mappings_url = '{}/users/{}/role-mappings/realm'.format(self.keycloak_admin_url,
                                                                                         user['id'])
        with open(user_realm_role_mappings_config_file) as json_file:
            user_realm_role_mappings_config = json.load(json_file)

        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        for user_realm_role_mapping in user_realm_role_mappings_config:
            role_name = user_realm_role_mapping['name']
            logging.info("Gathering information about the specified role '%s'", role_name)
            role_url = '{}/roles/{}'.format(self.keycloak_admin_url, role_name)
            response_message_get, status_code_get = self.rest_client.request('GET', role_url, headers=headers)
            if status_code_get != 200:
                logging.error("Unable to get realm role details due to (%s): %s", status_code_get, response_message_get)
                raise RuntimeError("Unable to create realm role due to " + str(response_message_get))
            user_realm_role_mapping['id'] = response_message_get['id']

        response_message, status_code = self.rest_client.request('POST', keycloak_user_realm_role_mappings_url,
                                                                 json=user_realm_role_mappings_config, headers=headers)
        if status_code != 204:
            logging.error("Unable to create realm role details due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to create realm role due to " + str(response_message))
        logging.info("Updated realm role mappings for user '%s'", username)


class UsernameNotFoundError(Exception):
    """The exception when a given user is not found in keycloak server."""
