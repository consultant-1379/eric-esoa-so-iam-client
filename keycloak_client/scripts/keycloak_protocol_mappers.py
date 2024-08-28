"""This module has the methods to manage keycloak protocol mapper resources."""
import json
import logging
import urllib3

from keycloak_client.scripts.keycloak_client_scopes import ClientScopeAdmin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ProtocolMapperAdmin:
    """This class has the methods to manage keycloak protocol mapper resources."""

    def __init__(self, auth_details, rest_client):
        self.auth_details = auth_details
        self.keycloak_protocol_mapper_base_url = auth_details.admin_url + "/client-scopes"
        self.keycloak_admin_url = auth_details.admin_url
        self.access_token = auth_details.token
        self.client_scope_id = None
        self.mapping_endpoint = None
        self.rest_client = rest_client

    @classmethod
    def _can_create_mappers(cls, existing_mappers, create_mappers):
        can_create = True
        for existing_mapper in existing_mappers:
            for create_mapper in create_mappers:
                if existing_mapper["name"] == create_mapper["name"]:
                    logging.error(
                        """Cannot create protocol mapper. Mapper with name: %s """
                        """already exists""",
                        create_mapper["name"],
                    )
                    can_create = False
        return can_create

    def _set_mapping_endpoint(self, client_scope_name):
        client_scope_object = ClientScopeAdmin(self.auth_details, self.rest_client).get(client_scope_name)
        if client_scope_object:
            self.client_scope_id = client_scope_object["id"]
            logging.info(
                """Loaded client scope object, client scope id set to: """
                """%s for client scope name: %s""", self.client_scope_id, client_scope_name)
        else:
            logging.error("Client scope object can not be loaded")
            return False

        self.mapping_endpoint = (
            self.keycloak_protocol_mapper_base_url + "/" + self.client_scope_id + "/protocol-mappers"
        )
        logging.info("Mapping endpoint set to: %s", self.mapping_endpoint)
        return True

    def get_by_name(self, protocol_mapper_name):
        """The method to get a protcol mapper by its name"""
        protocol_mappers = self.get()
        for protocol_mapper in protocol_mappers:
            if protocol_mapper["name"] == protocol_mapper_name:
                return protocol_mapper
        return None

    def get(self):
        """The method to get protocol mappers array"""
        headers = {"Authorization": "Bearer " + self.access_token}
        response_message, status_code = self.rest_client.request("GET", self.mapping_endpoint + "/models",
                                                                 headers=headers)
        if status_code != 200:
            logging.error("Unable to get protocol mappers due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to get protocol mapper due to " + str(response_message))
        if response_message:
            return response_message
        return []

    def create(self, client_scope_name, protocol_mapper_config_path):
        """The method to create protocol mappers"""

        if self._set_mapping_endpoint(client_scope_name):
            with open(protocol_mapper_config_path, encoding="UTF-8") as json_file:
                protocol_mapper_config = json.load(json_file)

            if self._can_create_mappers(self.get(), protocol_mapper_config):
                response_message, status_code = self.rest_client.request("POST", self.mapping_endpoint + "/add-models",
                                                                         json=protocol_mapper_config,
                                                                         headers={"Authorization": "Bearer "
                                                                                                   + self.access_token})

                if status_code != 204:
                    logging.error("unable to create protocol mapper due to (%s): %s", status_code, response_message)
                    raise RuntimeError("Unable to create protocol mapper due to " + str(response_message))
                for mapping in protocol_mapper_config:
                    logging.info("Created protocol mapper %s", mapping["name"])
            else:
                raise Exception(
                    """Can not create protocol mappers, """
                    """there are already existing mappers in the config file"""
                )
        else:
            raise Exception(
                """Can not create protocol mappers, """
                """because the mapping endpoint can not be set"""
            )

    def create_from_dict(self, client_id, client_name, protocol_mapper_name, config):
        """
        The method to create protocol mappers from string
        ``client_id`` -- Client ID to create mapper for
        ``client_name`` -- name of that client (used in name of mapper)
        ``protocol_mapper_name`` -- KeyCloak's mapper name
        ``config`` -- dict with mapper attributes

        This method assumes mapper do not exist.
        """
        json_data = {
            "protocol": "openid-connect",
            "name": "{}-{}".format(client_name, protocol_mapper_name),
            "protocolMapper": protocol_mapper_name,
            "config": config
        }
        self.mapping_endpoint = "{}/clients/{}/protocol-mappers".format(self.auth_details.admin_url, client_id)
        logging.info("Mapping endpoint set to: %s", self.mapping_endpoint)
        uri = "{}/models".format(self.mapping_endpoint)
        response_message, status_code = self.rest_client.request(
            "POST", uri, json=json_data,
            headers={"Authorization": "Bearer {}".format(self.access_token)})
        if status_code == 409:
            logging.warning("Mapper '%s' exists for client '%s'", protocol_mapper_name, client_name)
            return None
        if status_code != 201:
            logging.error("unable to create protocol mapper due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to create protocol mapper due to " + str(response_message))
        logging.info("Created protocol mapper '%s'", json_data["name"])
        return None

    def update(self, client_scope_name, protocol_mapper_name, protocol_mapper_config_path):
        """The method to update a protocol mapper"""

        if self._set_mapping_endpoint(client_scope_name):

            protocol_mapper = self.get_by_name(protocol_mapper_name)

            if protocol_mapper:
                with open(protocol_mapper_config_path, encoding="UTF-8") as json_file:
                    protocol_mapper_config = json.load(json_file)

                protocol_mapper_config["id"] = protocol_mapper["id"]
                response_message, status_code = self.rest_client.request("PUT", self.mapping_endpoint + "/models/"
                                                                         + protocol_mapper["id"],
                                                                         json=protocol_mapper_config,
                                                                         headers={"Authorization": "Bearer "
                                                                                                   + self.access_token})
                if status_code != 204:
                    logging.error("Unable to update protocol mapper due to (%s): %s", status_code, response_message)
                    raise RuntimeError("Unable to update protocol mapper due to " + str(response_message))
                logging.info("Updated protocol mapper %s", protocol_mapper["name"])
            else:
                raise Exception("Can not update protocol mapper, mapper does not exist")
        else:
            raise Exception(
                """Can not update protocol mapper, """
                """because the mapping endpoint can not be set"""
            )

    def delete(self, client_scope_name, protocol_mapper_name):
        """The method to delete a protocol mapper"""

        if self._set_mapping_endpoint(client_scope_name):
            protocol_mapper = self.get_by_name(protocol_mapper_name)
            if protocol_mapper:
                response_message, status_code = self.rest_client.request("DELETE", self.mapping_endpoint + "/models/"
                                                                         + protocol_mapper["id"],
                                                                         headers={"Authorization": "Bearer "
                                                                                                   + self.access_token})
                if status_code != 204:
                    logging.error("Unable to delete protocol mapper due to (%s): %s", status_code, response_message)
                    raise RuntimeError("Unable to delete protocol mapper due to " + str(response_message))
                logging.info("Deleted protocol mapper %s", protocol_mapper["name"])
            else:
                raise Exception("Can not delete protocol mapper, mapper does not exist")
        else:
            raise Exception(
                """Can not delete protocol mapper, """
                """because the mapping endpoint can not be set"""
            )
