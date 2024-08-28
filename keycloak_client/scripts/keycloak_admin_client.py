"""The module for keycloak admin functions."""
import logging

import requests
import urllib3
from retrying import retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _retry_if_connect_error(exception):
    return isinstance(exception, requests.exceptions.ConnectionError)


class AdminCliClient:
    """The class for keycloak admin functions."""

    def __init__(self, auth_details, rest_client):
        self.auth_details = auth_details
        self.keycloak_token_url = '{}/protocol/openid-connect/token'.format(auth_details.realm_url)
        self.keycloak_logout_url = '{}/protocol/openid-connect/logout'.format(auth_details.realm_url)
        self.token = ""
        self.rest_client = rest_client

    # retry login in case network for pod is not yet available
    @retry(wait_fixed=2000, stop_max_delay=60000, retry_on_exception=_retry_if_connect_error)
    def login(self):
        """This method is used to login as keycloak admin."""
        try:
            logging.info("Logging in to keycloak: user=%s, url=%s", self.auth_details.keycloak_user,
                         self.keycloak_token_url)
            payload = {'client_id': 'admin-cli',
                       'username': self.auth_details.keycloak_user,
                       'password': self.auth_details.keycloak_password,
                       'grant_type': 'password'}
            response_message, status_code = self.rest_client.request('POST', self.keycloak_token_url, data=payload)
            if status_code >= 500:
                raise requests.exceptions.ConnectionError()
            if status_code != 200:
                logging.error("Keycloak login failed due to (%s): %s", status_code, response_message)
                raise RuntimeError("Login failed due to " + str(response_message))
            self.token = response_message
            return self.token['access_token']
        except Exception:
            logging.error("Keycloak login failed")
            raise RuntimeError("Keycloak login failed")

    def logout(self):
        """This method is used to logout from keycloak admin."""
        if self.token and 'refresh_token' in self.token:
            logging.info("Logging in to keycloak: user=%s, url=%s", self.auth_details.keycloak_user,
                         self.keycloak_logout_url)
            payload = {'client_id': 'admin-cli',
                       'refresh_token': self.token['refresh_token']}
            response_message, status_code = self.rest_client.request('POST', self.keycloak_logout_url, data=payload)
            if status_code != 204:
                logging.error("Keycloak logout failed %s", response_message)
                raise RuntimeError("Logout failed due to " + str(response_message))
