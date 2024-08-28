"""This module has the methods to manage keycloak client scope resources."""

import logging
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ClientScopeAdmin:
    """This class has the methods to manage keycloak client scope resources."""

    def __init__(self, auth_details, rest_client):
        self.keycloak_client_scope_base_url = auth_details.admin_url + "/client-scopes"
        self.keycloak_admin_url = auth_details.admin_url
        self.access_token = auth_details.token
        self.rest_client = rest_client

    def get(self, client_scope_name):
        """The method to get a client scope with a specific name"""
        headers = {"Authorization": "Bearer " + self.access_token}
        response_message, status_code = self.rest_client.request('GET', self.keycloak_client_scope_base_url,
                                                                 headers=headers)
        if status_code != 200:
            logging.error("Unable to get client scopes due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to get client scopes due to " + str(response_message))
        if response_message:
            client_scope = [response for response in response_message
                            if response["name"] == client_scope_name]
            if client_scope:
                return client_scope[0]
        return None

    def create(self, client_scope_config_path):
        """The method to create a new keycloak client scope resource."""
        with open(client_scope_config_path, encoding="UTF-8") as json_file:
            client_scope_config = json.load(json_file)

        if self.get(client_scope_config["name"]) is None:
            response_message, status_code = self.rest_client.request('POST', self.keycloak_client_scope_base_url,
                                                                     json=client_scope_config,
                                                                     headers={"Authorization": "Bearer "
                                                                                               + self.access_token})
            if status_code != 201:
                logging.error("Unable to create client scopes due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to create client scopes due to " + str(response_message))
            logging.info("Created client scope %s", client_scope_config["name"])
        else:
            logging.info("Can not create client scope %s, because it already exists", client_scope_config["name"])
            #raise Exception(
            #    "Can not create client scope {}, because it already exists".format(client_scope_config["name"]))

    def update(self, client_scope_name, client_scope_config_path):
        """The method to update a keycloak client scope resource."""
        client_scope = self.get(client_scope_name)

        if client_scope:
            with open(client_scope_config_path, encoding="UTF-8") as json_file:
                client_scope_config = json.load(json_file)

            response_message, status_code = self.rest_client.request('PUT', self.keycloak_client_scope_base_url + "/" +
                                                                     client_scope["id"], json=client_scope_config,
                                                                     headers={"Authorization": "Bearer " +
                                                                                               self.access_token})
            if status_code != 204:
                logging.error("Unable to update client scopes due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to update client scopes due to " + str(response_message))
            logging.info("Updated client scope %s", client_scope_config["name"])
        else:
            logging.info("Can not update client scope %s", client_scope_name)
            #raise Exception(
            #    "Can not update client scope {}, because it does not exist".format(client_scope_name))

    def delete(self, client_scope_name):
        """The method to delete a keycloak client scope resource."""
        client_scope = self.get(client_scope_name)

        if client_scope:
            response_message, status_code = self.rest_client.request('DELETE', self.keycloak_client_scope_base_url +
                                                                     "/" + client_scope["id"],
                                                                     headers={"Authorization": "Bearer " +
                                                                                               self.access_token})
            if status_code != 204:
                logging.error("Unable to delete client scopes due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to delete client scopes due to " + str(response_message))
            logging.info("Deleted client scope %s", client_scope_name)
        else:
            raise Exception(
                "Can not delete client scope {}, because it does not exist".format(client_scope_name))
