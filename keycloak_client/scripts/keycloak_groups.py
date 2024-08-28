"""This module has the methods to manage keycloak group resources."""
import logging
import json

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class GroupAdmin:
    """This class has the methods to manage keycloak group resources."""

    def __init__(self, auth_details, rest_client):
        self.keycloak_group_url = auth_details.admin_url + "/groups"
        self.keycloak_admin_url = auth_details.admin_url
        self.access_token = auth_details.token
        self.rest_client = rest_client

    def get_by_name(self, group_name):
        """The method to get a group by name"""
        groups = self.get()
        for group in groups:
            if group["name"] == group_name:
                return group
        return None

    def get(self):
        """The method to get groups"""
        headers = {"Authorization": "Bearer " + self.access_token}
        response_message, status_code = self.rest_client.request('GET', self.keycloak_group_url, headers=headers)
        if status_code != 200:
            logging.error("Unable to get group details due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to get group details due to " + str(response_message))
        if response_message:
            return response_message
        return []

    def create(self, group_config_path):
        """The method to create a group"""
        with open(group_config_path, encoding="UTF-8") as json_file:
            group_config = json.load(json_file)

        if isinstance(group_config, list):
            for group in group_config:
                self.create_group_by_name(group)
        else:
            self.create_group_by_name(group_config)

    def create_group_by_name(self, group_config):
        """The method to create a group by name"""
        if self.get_by_name(group_config["name"]) is None:
            response_message, status_code = self.rest_client.request('POST', self.keycloak_group_url,
                                                                     json=group_config,
                                                                     headers={"Authorization": "Bearer "
                                                                                               + self.access_token})
            if status_code != 201:
                logging.error("unable to create group details due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to create group details due to " + str(response_message))
            logging.info("Created group %s", group_config["name"])

        else:
            logging.info("Can not create group, a group with the name: %s already exists", group_config["name"])

    def update(self, group_name, group_config_path):
        """The method to update a group"""
        group = self.get_by_name(group_name)

        if group:
            with open(group_config_path, encoding="UTF-8") as json_file:
                group_config = json.load(json_file)

            response_message, status_code = self.rest_client.request('PUT', self.keycloak_group_url + "/" + group["id"],
                                                                     json=group_config,
                                                                     headers={"Authorization": "Bearer "
                                                                                               + self.access_token})
            if status_code != 204:
                logging.error("Unable to update groups due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to update group due to " + str(response_message))
            logging.info("Updated group %s", group_config["name"])

        else:
            raise Exception("Can not update group, group with name: {} does not exist".format(group_name))

    def delete(self, group_name):
        """The method to delete a group"""
        group = self.get_by_name(group_name)

        if group:
            response_message, status_code = self.rest_client.request('DELETE', self.keycloak_group_url + "/"
                                                                     + group["id"],
                                                                     headers={"Authorization": "Bearer "
                                                                                               + self.access_token})
            if status_code != 204:
                logging.error("Unable to delete groups due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to delete group due to " + str(response_message))
            logging.info("Deleted group %s", group_name)

        else:
            raise Exception(
                "Can not delete group, group with name: {} does not exist".format(group_name))
