"""The module manages keycloak users."""
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UsersAdmin:
    """The class manages keycloak users."""
    def __init__(self, auth_details, rest_client):
        self.certificate_ca_path = auth_details.ca_cert_path
        self.keycloak_users_url = '{}/users'.format(auth_details.admin_url)
        self.access_token = auth_details.token
        self.rest_client = rest_client

    def get(self, username):
        """The method to get available keycloak users."""
        params = {'username': username}
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('GET', self.keycloak_users_url, headers=headers,
                                                                 params=params)
        if status_code != 200:
            logging.error("Unable to get user details due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to create user details due to " + str(response_message))
        # If the username even partially matches users found in keycloak, it can return many users
        # So we need to compensate to check for an exact match in the returned list ourselves
        for user in response_message:
            if user['username'] == username:
                return user
        return None

    def create(self, username, password):
        """The method to create a keycloak user"""
        logging.info("Creating user '%s'", username)
        user = self.get(username)
        user_config = {
            "enabled": True,
            "username": username,
            "credentials": [
                {
                    "temporary": False,
                    "type": "password",
                    "value": password
                }
            ]
        }
        if user is None:
            headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
            response_message, status_code = self.rest_client.request('POST', self.keycloak_users_url, json=user_config,
                                                                     headers=headers)
            if status_code != 201:
                logging.error("unable to create user details due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to create user details due to " + str(response_message))
            logging.info("Created user '%s'", username)
        else:
            logging.info("User '%s' already exists", username)
