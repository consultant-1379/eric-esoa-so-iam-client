"""This module has the methods to manage keycloak client resources."""
import json
import logging
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ClientAdmin:
    """This class has the methods to manage keycloak client resources."""
    def __init__(self, auth_details, rest_client):
        self.keycloak_clients_url = '{}/clients'.format(auth_details.admin_url)
        self.keycloak_admin_url = auth_details.admin_url
        self.access_token = auth_details.token
        self.rest_client = rest_client

    def get(self, client_name):
        """The method to get a list of existing keycloak client resources."""
        params = {'clientId': client_name}
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('GET', self.keycloak_clients_url, headers=headers,
                                                                 params=params)
        if status_code != 200:
            logging.error("Unable to get client details due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to get client details due to {} ({})".format(response_message, status_code))
        if not response_message:
            logging.warning("Unable to get client with name %s", client_name)
            return None
        return response_message[0]

    def create(self, client_config_path):
        """
        The method to create a new keycloak client resource.

        Reads CLIENT_SECRET environment variable, if exist, replaces client secret.
        """
        with open(client_config_path) as json_file:
            client_config = json.load(json_file)
        client_name = client_config['clientId']

        client_secret_env = os.getenv('CLIENT_SECRET')
        client = self.get(client_name)
        if client_secret_env:
            client_config['secret'] = client_secret_env
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}

        if client is None:
            logging.info("Creating client'%s'", client_name)
            response_message, status_code = self.rest_client.request('POST', self.keycloak_clients_url,
                                                                     json=client_config, headers=headers)
            if status_code != 201:
                logging.error("Unable to create client due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to create client due to " + str(response_message))
            logging.info("Created client '%s'", client_name)
        else:
            logging.info("Updating client'%s'", client_name)
            response_message, status_code = self.rest_client.request('PUT', self.keycloak_clients_url + '/' +
                                                                     client['id'], json=client_config, headers=headers)
            if status_code != 204:
                logging.error("Unable to update realm due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to update client due to " + str(response_message))
            logging.info("Updated client '%s'", client_name)
            #code added to map defaultScopes to existing client starts
            client_scopes_to_add = list(set(client_config["defaultClientScopes"]) - set(client["defaultClientScopes"]))
            if client_scopes_to_add:
                for scope_name in client_scopes_to_add:
                    scope_exists, client_scope = self.get_client_scope(scope_name)
                    if scope_exists:
                        self.update_client_scope_to_client(client_name, client_scope)
                        logging.info("Updated '%s' client scope to client '%s' ", scope_name, client_name)
            # code added to map defaultScopes to existing client starts

    def create_ext_client(self, client_name):
        """
        The method to create a new keycloak client resource.

        The following settings are applied to new account, in order to allow external access for rApps.
        - "publicClient": false -- "confidential" account ( require clients to specify id/secret )
        - "clientAuthenticatorType": "client-secret"
        - "directAccessGrantsEnabled": true,
        - "protocol": "openid-connect" -- authentication method
        - "protocolMappers" -- add common attributes to KeyCloak auth responses
        - "enabled": true
        """
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}

        mapping = {
            "Name":"external-service",
            "Mapper Type":"User Attribute",
            "User Attribute":"policy",
            "Token Claim Name":"policy",
            "Claim JSON Type":"string"
        }
        client_config = {
            "clientId": client_name,
            "name": client_name,
            "clientAuthenticatorType": "client-secret",
            "publicClient": False,
            "protocol": "openid-connect",
            "enabled": True,
            "rootUrl": "${authBaseUrl}",
            "baseUrl":"/realms/master/{}/".format(client_name),
            "redirectUris": ["/realms/master/{}/*".format(client_name)], # for oauth2
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": True,
            "attributes": {
                "oauth2.device.authorization.grant.enabled": "true",
                "use.refresh.tokens": "true",
                "acr.loa.map": json.dumps(mapping)
            }
        }
        client = self.get(client_name)
        if client is None:
            logging.info("Creating client'%s'", client_name)

            response_message, status_code = self.rest_client.request('POST', self.keycloak_clients_url,
                                                                     json=client_config, headers=headers)
            if status_code != 201:
                logging.error("Unable to create client due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to create client due to " + str(response_message))

            logging.info("Created external client '%s'", client_name)

        logging.info("External client '%s' exists", client_name)

    def delete(self, client_name):
        """The method to delete an existing keycloak client resource."""
        logging.info("Deleting client '%s'", client_name)
        client = self.get(client_name)
        if client:
            client_id = client['id']
            url = self.keycloak_clients_url + "/" + client_id
            headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
            response_message, status_code = self.rest_client.request('DELETE', url, headers=headers)
            if status_code != 204:
                logging.error("Unable to delete client due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to delete client due to " + str(response_message))
            logging.info("Deleted client '%s'", client_name)
        else:
            logging.info("Client '%s' not found", client_name)

    def get_client_scope(self, scope_name):
        """The method to get a scope from existing keycloak client scopes."""
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('GET', self.keycloak_admin_url + '/client-scopes',
                                                                 headers=headers)
        if status_code != 200:
            logging.error("Unable to get client scopes due to (%s): %s", status_code, response_message)
            raise RuntimeError(
                "Unable to get client scopes details due to {} ({})".format(response_message, status_code))
        if response_message:
            for client_scope in response_message:
                if client_scope["name"] == scope_name:
                    return True, client_scope
            logging.error("Client scope details %s not found", scope_name)
        return False, None

    def update_client_scope_to_client(self, client_name, client_scope):
        """The method to update a client scope to  keycloak client resource."""
        client = self.get(client_name)
        if client is not None:
            headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
            url = self.keycloak_clients_url + "/" + client["id"] + "/default-client-scopes/" + client_scope["id"]
            response_message, status_code = self.rest_client.request('PUT', url, headers=headers)
            if status_code != 204:
                logging.error("Unable to update (%s) client scope to (%s) due to (%s): %s", client_scope["name"],
                              client_name, status_code, response_message)
                raise RuntimeError("Unable to update client scope due to {} ({})".format(response_message, status_code))
