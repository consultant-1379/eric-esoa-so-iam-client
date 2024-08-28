"""This module has the methods to manage keycloak client scope mapping resources."""
import json
import logging
import urllib3

from keycloak_client.scripts.keycloak_client_scopes import ClientScopeAdmin
from keycloak_client.scripts.keycloak_clients import ClientAdmin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ClientScopeMappingAdmin:
    """This class has the methods to manage keycloak client scope mapping resources"""

    def __init__(self, auth_details, rest_client):
        self.auth_details = auth_details
        self.keycloak_client_scope_mapping_base_url = auth_details.admin_url + "/client-scopes"
        self.access_token = auth_details.token
        self.rest_client = rest_client
        self.client_scope_id = None
        self.client_id = None
        self.mapping_endpoint = None

    @classmethod
    def _mapping_exists(cls, existing_mappings, new_mapping):
        """The method to check whether a mapping exists"""
        for existing_mapping in existing_mappings:
            if existing_mapping["name"] == new_mapping["name"]:
                return True
        return False

    def _can_create_mappings(self, existing_mappings, create_mappings):
        """The method to check whether every mapping that has to be created does not exist"""
        can_create = True
        for create_mapping in create_mappings:
            if self._mapping_exists(existing_mappings, create_mapping):
                logging.error(
                    """Can not create client scope mapping. """
                    """Mapping with name: %s already exists""",
                    create_mapping["name"],
                )
                can_create = False
        return can_create

    def _can_delete_mappings(self, existing_mappings, delete_mappings):
        """The method to check whether every mapping that has to be deleted exists"""
        can_delete = True
        for delete_mapping in delete_mappings:
            if self._mapping_exists(existing_mappings, delete_mapping) is False:
                logging.error(
                    "Cannot delete client scope mapping. Mapping with name: %s does not exist",
                    delete_mapping["name"],
                )
                can_delete = False
        return can_delete

    def _set_mapping_endpoint(self, client_scope_name, client_name):
        """The method to set the endpoint for the queries"""
        client_scope_object = ClientScopeAdmin(self.auth_details, self.rest_client).get(client_scope_name)
        if client_scope_object:
            self.client_scope_id = client_scope_object["id"]
            logging.info(
                """Client scope object loaded, client scope id set to: """
                """%s for client scope name: %s""",
                self.client_scope_id,
                client_scope_name,
            )
        else:
            logging.error("Client scope object can not be loaded")
            return False

        client_object = ClientAdmin(self.auth_details, self.rest_client).get(client_name)
        if client_object:
            self.client_id = client_object["id"]
            logging.info(
                """Client object loaded, client id set to: """
                """%s for client name: %s""",
                self.client_id,
                client_name,
            )
        else:
            logging.error("Client object can not be loaded")
            return False

        self.mapping_endpoint = (
            self.keycloak_client_scope_mapping_base_url
            + "/"
            + self.client_scope_id
            + "/scope-mappings/clients/"
            + self.client_id
        )
        logging.info("Mapping endpoint set to: %s", self.mapping_endpoint)
        return True

    def get(self):
        """The method to get client scope mapping array"""
        headers = {"Authorization": "Bearer " + self.access_token}
        response_message, status_code = self.rest_client.request('GET', self.mapping_endpoint, headers=headers)
        if status_code != 200:
            logging.error("Unable to get client scope mapping due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to get client scope mapping due to " + str(response_message))
        if response_message:
            return response_message
        return []

    def create(self, client_scope_name, client_name, client_scope_mapping_config_path):
        """The method to create client scope mappings"""
        if self._set_mapping_endpoint(client_scope_name, client_name):
            with open(client_scope_mapping_config_path, encoding="UTF-8") as json_file:
                client_scope_mapping_config = json.load(json_file)

            if self._can_create_mappings(self.get(), client_scope_mapping_config):
                response_message, status_code = self.rest_client.request('POST', self.mapping_endpoint,
                                                                         json=client_scope_mapping_config,
                                                                         headers={"Authorization": "Bearer "
                                                                                                   + self.access_token})
                if status_code != 204:
                    logging.error("Unable to create scope mapping due to (%s): %s", status_code, response_message)
                    raise RuntimeError("Unable to create scope mapping due to " + str(response_message))
                for mapping in client_scope_mapping_config:
                    logging.info("Created client scope mapping %s", mapping["name"])
            else:
                raise Exception(
                    """Can not create client scope mapping, """
                    """there are already existing mappings in the config file""")
        else:
            raise Exception(
                "Can not create client scope mapping, because the mapping endpoint can not be set")

    def delete(self, client_scope_name, client_name, client_scope_mapping_config_path):
        """The method to delete client scope mappings"""
        if self._set_mapping_endpoint(client_scope_name, client_name):
            with open(client_scope_mapping_config_path, encoding="UTF-8") as json_file:
                client_scope_mapping_config = json.load(json_file)

            if self._can_delete_mappings(self.get(), client_scope_mapping_config):
                response_message, status_code = self.rest_client.request('DELETE', self.mapping_endpoint,
                                                                         json=client_scope_mapping_config,
                                                                         headers={"Authorization": "Bearer "
                                                                                                   + self.access_token})
                if status_code != 204:
                    log_message = "Unable to delete client scope mapping due to (%s): %s"
                    logging.error(log_message, status_code, response_message)
                    raise RuntimeError("Unable to delete client scope mapping due to " + str(response_message))
                for mapping in client_scope_mapping_config:
                    logging.info("Deleted client scope mapping %s", mapping["name"])
            else:
                raise Exception(
                    "Can not delete client scope mapping, there are non-existent mappings in the config file")
        else:
            raise Exception(
                "Can not delete client scope mapping, because the mapping endpoint can not be set")
