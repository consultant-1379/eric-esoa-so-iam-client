"""The module for managing keycloak realms."""
import json
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RealmAdmin:
    """The class for managing keycloak realms."""
    def __init__(self, auth_details, rest_client):
        self.certificate_ca_path = auth_details.ca_cert_path
        self.keycloak_admin_url = auth_details.admin_url
        self.keycloak_admin_realm_url = auth_details.admin_realm_url
        self.access_token = auth_details.token
        self.rest_client = rest_client

    def get(self):
        """The method for listing existing realms from keycloak."""
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('GET', self.keycloak_admin_url, headers=headers)
        if status_code != 200:
            logging.error("Unable to get realm details due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to get realm details due to " + str(response_message))
        return response_message

    def get_all_realms(self):
        """The method for listing existing realms from keycloak."""
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('GET', self.keycloak_admin_realm_url, headers=headers)
        if status_code != 200:
            logging.error("Unable to get realm details due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to get realm details due to " + str(response_message))
        return response_message

    def update_realm(self, realm_name, realm_config):
        """The method for updating an existing realm in keycloak."""
        logging.info("Updating realm '%s'", realm_name)
        if realm_name:
            headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
            realm_url = self.keycloak_admin_realm_url + "/" + realm_name
            response_message, status_code = self.rest_client.request('PUT', realm_url, headers=headers,
                                                                     json=realm_config)
            if status_code != 204:
                logging.error("Unable to update realm details due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to update realm details due to " + str(response_message))
            logging.info("Updated realm '%s'", realm_name)
        else:
            logging.info("Realm '%s' not found", realm_name)

    def update(self, realm_config_path):
        """The method for updating an existing realm in keycloak."""
        realm_name = 'master'
        logging.info("Updating realm '%s'", realm_name)
        realm = self.get()
        if realm:
            with open(realm_config_path) as json_file:
                realm_config = json.load(json_file)
            headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
            response_message, status_code = self.rest_client.request('PUT', self.keycloak_admin_url, headers=headers,
                                                                     json=realm_config)
            if status_code != 204:
                logging.error("Unable to update realm details due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to update realm details due to " + str(response_message))
            logging.info("Updated realm '%s'", realm_name)
        else:
            logging.info("Realm '%s' not found", realm_name)

    def update_all_realms(self, realm_config_path):
        """The method for updating all existing realms in keycloak."""
        realms = self.get_all_realms()
        if realms:
            headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
            with open(realm_config_path) as json_file:
                realm_config = json.load(json_file)
                for realm in realms:
                    logging.info("Updating realm '%s'", realm["realm"])
                    realm_url = self.keycloak_admin_realm_url + "/" + realm["realm"]
                    response_message, status_code = self.rest_client.request('PUT', realm_url, headers=headers,
                                                                             json=realm_config)
                    if status_code != 204:
                        logging.error("Unable to update realm details due to (%s): %s", status_code, response_message)
                        raise RuntimeError("Unable to update realm details due to " + str(response_message))
                    logging.info("Updated realm '%s'", realm["realm"])
        else:
            logging.info("Realms not found")

    def export(self):
        """The method for exporting an existing realm in keycloak."""
        url = self.keycloak_admin_url + "/partial-export?exportClients=true&exportGroupsAndRoles=true"
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('POST', url, headers=headers)
        if status_code != 200:
            logging.error("Unable to export realm details due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to export realm details due to " + str(response_message))
        return response_message
