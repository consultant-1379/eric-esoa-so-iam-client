"""The module for managing keycloak resources / policies."""
import json
import logging
import urllib3
from .keycloak_clients import ClientAdmin
from .keycloak_roles import RoleAdmin
from .keycloak_realms import RealmAdmin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

KEYCLOAK_AUTHZ_RESOURCES_URL = '{}/clients/{}/authz/resource-server/resource'
KEYCLOAK_AUTHZ_RESOURCE_URL = KEYCLOAK_AUTHZ_RESOURCES_URL + '/{}'
KEYCLOAK_AUTHZ_POLICY_URL = '{}/clients/{}/authz/resource-server/policy/{}'
KEYCLOAK_AUTHZ_ROLE_POLICY_URL = '{}/clients/{}/authz/resource-server/policy/role/{}'
KEYCLOAK_AUTHZ_JS_POLICY_URL = '{}/clients/{}/authz/resource-server/policy/js/{}'
KEYCLOAK_AUTHZ_PERMISSION_URL = '{}/clients/{}/authz/resource-server/permission/{}'
KEYCLOAK_AUTHZ_SCOPE_PERMISSION_URL = '{}/clients/{}/authz/resource-server/permission/scope/{}'
KEYCLOAK_AUTHZ_RESOURCE_PERMISSION_URL = '{}/clients/{}/authz/resource-server/permission/resource/{}'
KEYCLOAK_AUTHZ_IMPORT_URL = '{}/clients/{}/authz/resource-server/import'


class AuthzAdmin:
    """The class for managing keycloak resources / policies"""
    def __init__(self, auth_details, rest_client):
        self.auth_details = auth_details
        self.rest_client = rest_client
        self.access_token = auth_details.token
        self.client_admin = ClientAdmin(auth_details, rest_client)
        self.role_admin = RoleAdmin(auth_details, rest_client)
        self.exported_client_auth = None
        self.client_id = None

    def create(self, provider, authz_config_path, client_name):
        """The method for creating new resources / policies."""
        client = self.client_admin.get(client_name)
        if not client:
            raise Exception("Client {} does not exist".format(client_name))

        with open(authz_config_path) as json_file:
            authz_config = json.load(json_file)

        roles = authz_config.get('roles', [])
        client_authz_config = authz_config.get('authorization', [])
        AuthzAdmin._add_provider_attribute_to_resources(provider, client_authz_config)

        # create roles, update existing roles if changed, delete existing if no longer referenced in latest config
        self.role_admin.create(roles, provider)

        # export current client authorization configuration
        self._export_client_authorization_config(client_name)

        # get existing resources, policies and permissions for the provider from the exported config
        provider_resources_by_name = self._get_provider_resources_by_name(provider)

        # import authorization config which will create new resources, polices and permissions. keycloak
        # authorization import does not update existing config
        logging.info("Importing auth config. All new resources and polices will be added")
        self._import_client_authz(client_authz_config)

        # if existing configuration, then update if changed or possibly delete if no longer referenced in latest config
        if provider_resources_by_name:
            logging.info("Existing resources found for provider: %s", list(provider_resources_by_name))
            configured_resources = {resource['name']: resource for resource in client_authz_config['resources']}
            policies_by_name = {p['name']: AuthzAdmin._parse_policy(p) for p in self.exported_client_auth['policies']}
            current_provider_policies = AuthzAdmin._get_resource_policies(policies_by_name, provider_resources_by_name)
            configured_policies_by_name = \
                {policy['name']: AuthzAdmin._parse_policy(policy) for policy in client_authz_config['policies']}

            self._update_existing_resources(provider_resources_by_name, configured_resources)
            self._update_existing_policies(current_provider_policies, configured_policies_by_name)
            self._delete_unreferenced_policies(current_provider_policies, configured_policies_by_name)
            self._delete_unreferenced_resources(provider_resources_by_name, configured_resources)

    def delete(self, provider, client_name):
        """The method for deleting existing resources / policies"""
        logging.info("Deleting authorization resources for provider %s", provider)

        client = self.client_admin.get(client_name)
        if not client:
            raise Exception("Client {} does not exist".format(client_name))

        # export current client authorization configuration
        self._export_client_authorization_config(client_name)

        provider_resources_by_name = self._get_provider_resources_by_name(provider)
        logging.info("Found provider resources '%s'", list(provider_resources_by_name))

        exported_policies_by_name = \
            {p['name']: AuthzAdmin._parse_policy(p) for p in self.exported_client_auth['policies']}

        provider_polices = AuthzAdmin._get_resource_policies(exported_policies_by_name, provider_resources_by_name)
        logging.info("Found provider policies '%s'", list(provider_polices))

        for policy in provider_polices.values():
            self._delete_policy(policy)
            logging.info("Deleted policy '%s'", policy['name'])

        for resource in provider_resources_by_name.values():
            self._delete_resource(resource['_id'])
            logging.info("Deleted resource '%s'", resource['name'])

        self.role_admin.delete(provider)

    def _export_client_authorization_config(self, client_name):
        realm_export = RealmAdmin(self.auth_details, self.rest_client).export()
        exported_client = \
            next((client for client in realm_export['clients'] if client['clientId'] == client_name), None)
        self.client_id = exported_client['id']
        self.exported_client_auth = exported_client['authorizationSettings']

    def _get_provider_resources_by_name(self, provider):
        provider_resources = {}
        for resource in self.exported_client_auth.get('resources', {}):
            resources_attributes = resource.get('attributes', {})
            if ('provider' in resources_attributes and
                    provider in resources_attributes['provider']):
                provider_resources[resource['name']] = resource
        return provider_resources

    def _import_client_authz(self, client_authz_config):
        url = KEYCLOAK_AUTHZ_IMPORT_URL.format(self.auth_details.admin_url, self.client_id)
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('POST', url, json=client_authz_config, headers=headers)
        if status_code != 204:
            logging.error("unable to import client auth due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to import client auth due to " + str(response_message))

    def _update_existing_resources(self, current_resources, configured_resources):
        updated_resources = []
        for resource_name in [name for name in configured_resources.keys() if name in current_resources.keys()]:
            if not AuthzAdmin._is_subset(configured_resources[resource_name], current_resources[resource_name]):
                logging.info("updated_resource_name:%s", resource_name)
                updated_resources.append(resource_name)

        if updated_resources:
            logging.info("Updated resources: %s", updated_resources)
            for resource_name in updated_resources:
                self._update_resource(current_resources.get(resource_name).get('_id'),
                                      configured_resources.get(resource_name))
        else:
            logging.info("No resources updated")

    def _delete_unreferenced_resources(self, current_resources, configured_resources):
        removed_resources = [name for name in current_resources.keys() if name not in configured_resources.keys()]
        if removed_resources:
            logging.info("Removed resources: %s", removed_resources)
            for resource_name in removed_resources:
                self._delete_resource(current_resources.get(resource_name)['_id'])
        else:
            logging.info("No resources removed")

    def _update_existing_policies(self, current_provider_policies_by_name, configured_policies_by_name):
        updated_policies = []
        for policy_name in [name for name in configured_policies_by_name.keys()
                            if name in current_provider_policies_by_name.keys()]:
            current_policy = current_provider_policies_by_name.get(policy_name)
            configured_policy = configured_policies_by_name.get(policy_name)
            if not AuthzAdmin._is_subset(configured_policy, current_policy):
                updated_policies.append(policy_name)

        if updated_policies:
            logging.info("Updated policies: %s", updated_policies)
            for policy_name in updated_policies:
                policy_request = AuthzAdmin._create_policy_request(configured_policies_by_name.get(policy_name))
                self._update_policy(current_provider_policies_by_name.get(policy_name)['id'],
                                    policy_request)
        else:
            logging.info("No policies updated")

    def _delete_unreferenced_policies(self, current_provider_policies_by_name, configured_policies_by_name):
        removed_policies = [name for name in current_provider_policies_by_name.keys()
                            if name not in configured_policies_by_name.keys()]

        if removed_policies:
            logging.info("Removed policies: %s", removed_policies)
            for policy_name in removed_policies:
                self._delete_policy(current_provider_policies_by_name[policy_name])
        else:
            logging.info("No policies removed")

    def _update_resource(self, resource_id, resource):
        url = KEYCLOAK_AUTHZ_RESOURCE_URL.format(self.auth_details.admin_url, self.client_id, resource_id)
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('PUT', url, json=resource, headers=headers)
        if status_code != 204:
            logging.error("Unable to update resource due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to update resources due to " + str(response_message))

    def _delete_resource(self, resource_id):
        url = KEYCLOAK_AUTHZ_RESOURCE_URL.format(self.auth_details.admin_url, self.client_id, resource_id)
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('DELETE', url, headers=headers)
        if status_code != 404:
            logging.error("Unable to delete resources due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to delete resources due to " + str(response_message))

    def _update_policy(self, policy_id, policy):
        policy_type = policy['type']
        url = None
        if policy_type == 'js':
            url = KEYCLOAK_AUTHZ_JS_POLICY_URL.format(self.auth_details.admin_url, self.client_id, policy_id)
        elif policy_type == 'role':
            url = KEYCLOAK_AUTHZ_ROLE_POLICY_URL.format(self.auth_details.admin_url, self.client_id, policy_id)
        elif policy_type == 'scope':
            url = KEYCLOAK_AUTHZ_SCOPE_PERMISSION_URL.format(self.auth_details.admin_url, self.client_id, policy_id)
        elif policy_type == 'resource':
            url = KEYCLOAK_AUTHZ_RESOURCE_PERMISSION_URL.format(self.auth_details.admin_url, self.client_id, policy_id)
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('PUT', url, json=policy, headers=headers)
        if status_code != 204:
            logging.error("Unable to update policy due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to update policy due to " + str(response_message))

    def _delete_policy(self, policy):
        policy_type = policy['type']
        url = None
        if policy_type in ('js', 'role'):
            url = KEYCLOAK_AUTHZ_POLICY_URL.format(self.auth_details.admin_url, self.client_id, policy['id'])
        elif policy_type in ('scope', 'resource'):
            url = KEYCLOAK_AUTHZ_PERMISSION_URL.format(self.auth_details.admin_url, self.client_id, policy['id'])
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('DELETE', url, headers=headers)
        if status_code != 404:
            logging.error("Unable to delete policy due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to delete policy due to " + str(response_message))

    @staticmethod
    def _is_subset(subset, superset):
        if isinstance(subset, dict):
            return all(key in superset and AuthzAdmin._is_subset(val, superset[key]) for key, val in subset.items())
        if isinstance(subset, (list, set)):
            return all(
                any(AuthzAdmin._is_subset(sub_item, super_item) for super_item in superset) for sub_item in subset)
        return subset == superset

    @staticmethod
    def _add_provider_attribute_to_resources(provider, client_authz_config):
        for resource in client_authz_config['resources']:
            resource_attrs = resource.get('attributes', {})
            resource_attrs.update({'provider': [provider]})
            resource['attributes'] = resource_attrs

    @staticmethod
    def _get_resource_policies(policies_by_name, resources_by_name):
        resource_names = resources_by_name.keys()
        resource_types = [r['type'] for r in resources_by_name.values() if 'type' in r]
        resource_policies = {}
        # find all policies associated with the provider resources
        for policy_name, policy in policies_by_name.items():
            if 'resources' in policy['config']:
                policy_resources = policy['config']['resources']
                if any(name in resource_names for name in policy_resources):
                    resource_policies[policy_name] = policy
                    for apply_policy_name in policy['config']['applyPolicies']:
                        resource_policies[apply_policy_name] = policies_by_name[apply_policy_name]
            elif 'resourceType' in policy['config']:
                policy_resource_type = policy['config']['resourceType']
                if policy_resource_type in resource_types:
                    resource_policies[policy_name] = policy
                    for apply_policy_name in policy['config']['applyPolicies']:
                        resource_policies[apply_policy_name] = policies_by_name[apply_policy_name]
        return resource_policies

    @staticmethod
    def _parse_policy(policy):
        # keycloak exports policy['config'] values as json string e.g "scopes":"[\"PUT\",\"PATCH\",\"POST\",\"DELETE\"]"
        # parse exported policy to convert such values to a list
        for key, value in policy['config'].items():
            if isinstance(value, str) and (value.startswith('[') and value.endswith(']')):
                policy['config'][key] = json.loads(value)
        return policy

    @staticmethod
    def _create_policy_request(policy_config):
        policy_type = policy_config['type']
        # transform policy from config file into format for keycloak policy and permission endpoints
        policy_request = {"name": policy_config['name'],
                          "type": policy_config['type'],
                          "logic": policy_config['logic'],
                          "description": policy_config.get('description', ''),
                          "decisionStrategy":  policy_config['decisionStrategy']
                          }
        if policy_type == 'scope':
            policy_request['resources'] = policy_config['config']['resources']
            policy_request['scopes'] = policy_config['config'].get('scopes', [])
        elif policy_type == 'resource':
            if 'resourceType' in policy_config['config']:
                policy_request['resourceType'] = policy_config['config'].get('resourceType')
            else:
                policy_request['resources'] = policy_config['config']['resources']
        elif policy_type == 'role':
            policy_request['roles'] = policy_config['config'].get('roles')
        elif policy_type == 'js':
            policy_request['code'] = policy_config['config'].get('code')
        return policy_request
