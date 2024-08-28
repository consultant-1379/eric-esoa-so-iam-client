"""The module manages keycloak roles."""
import logging
import urllib3
from .keycloak_realms import RealmAdmin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#pylint: disable=no-else-return
class RoleAdmin:
    """The class manages keycloak roles."""
    def __init__(self, auth_details, rest_client):
        self.auth_details = auth_details
        self.access_token = auth_details.token
        self.roles_url = '{}/roles'.format(self.auth_details.admin_url)
        self.role_by_id_url = '{}/roles-by-id'.format(self.auth_details.admin_url)
        self.exported_realm_roles = None
        self.exported_client_roles = None
        self.rest_client = rest_client

    def create(self, roles, provider):
        """The method to create new keycloak role."""
        self._export_roles()

        role_names = [r['name'] for r in roles]
        existing_provider_roles = {r['name']: r for r in self.get_exported_provider_realm_roles(provider)}
        logging.info("Creating roles '%s' for provider '%s'", role_names, provider)
        for role in roles:
            role_name = role['name']
            if role_name not in existing_provider_roles:
                self._create_realm_role(role_name)
                persisted_role = self._get_realm_role(role_name)
            else:
                logging.info("Role '%s' already exists", role_name)
                persisted_role = existing_provider_roles[role['name']]
            self._configure_role_attributes(role.get('attributes', {}), provider, persisted_role)
            self._configure_composite_roles(persisted_role, role.get('composites', {}))

        removed_role_names = [r for r in existing_provider_roles.keys() if r not in role_names]
        if removed_role_names:
            logging.info("Deleting old roles '%s'", removed_role_names)
            for role_name in removed_role_names:
                self._delete_realm_role(role_name)

    def delete(self, provider):
        """The method to delete an existing keycloak role."""
        self._export_roles()
        logging.info("Deleting all roles for provider %s", provider)
        provider_roles = self.get_exported_provider_realm_roles(provider)
        provider_role_names = [r['name'] for r in provider_roles]
        logging.info("Found provider roles '%s'", provider_role_names)
        for role in provider_roles:
            self._delete_realm_role(role['name'])

    def get(self, provider):
        """The method to get available keycloak roles."""
        self._export_roles()
        return self.get_exported_provider_realm_roles(provider)

    def _export_roles(self):
        realm_export = RealmAdmin(self.auth_details, self.rest_client).export()
        self.exported_realm_roles = {r['name']: r for r in realm_export['roles']['realm']}
        self.exported_client_roles = {}
        for client_name, roles in realm_export['roles']['client'].items():
            roles_by_name = {r['name']: r for r in roles}
            self.exported_client_roles.update({client_name: roles_by_name})

    def get_exported_provider_realm_roles(self, provider):
        """The method to get available keycloak roles."""
        provider_roles = []
        for role in self.exported_realm_roles.values():
            role_attributes = role.get('attributes', {})
            if 'provider' in role_attributes and provider in role_attributes['provider']:
                provider_roles.append(role)
        return provider_roles

    def _get_realm_role(self, role_name):
        url = self.roles_url + "/" + role_name
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('GET', url, headers=headers)
        if status_code == 404:
            return None
        elif status_code != 200:
            logging.error("Unable to get realm details due to (%s): %s", status_code, response_message)
            raise RuntimeError("unable to get the realm details due to " + str(response_message))
        return response_message

    def _create_realm_role(self, role_name):
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        payload = {'name': role_name}
        response_message, status_code = self.rest_client.request('POST', self.roles_url, json=payload, headers=headers)
        if status_code == 201:
            logging.info("Created role '%s'", role_name)
        elif status_code == 409:  # role already exists.
            logging.info("Role '%s' already exists", role_name)
        else:
            logging.error("unable to create realm role due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to create realm details due to " + str(response_message))

    def _update_realm_role(self, role):
        url = self.role_by_id_url + "/" + role['id']
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('PUT', url, json=role, headers=headers)
        if status_code != 204:
            logging.error("Unable to update realm details due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to update realm details due to " + str(response_message))

    def _delete_realm_role(self, role_name):
        url = self.roles_url + "/" + role_name
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('DELETE', url, headers=headers)
        if status_code != 204:
            logging.error("Unable to delete realm role due to (%s): %s", status_code, response_message)
            raise RuntimeError('Unable to delete realm role due to ' + str(response_message))
        logging.info("Deleted role '%s'", role_name)

    def _configure_role_attributes(self, attributes, provider, created_role):
        current_attributes = created_role.get('attributes', {})
        logging.info("Current role attributes: %s", current_attributes)
        attributes.update({'provider': [provider]})
        logging.info("Configured role attributes: %s", attributes)
        if not attributes == current_attributes:
            created_role['attributes'] = attributes
            self._update_realm_role(created_role)
            logging.info("Set role attributes '%s'", attributes)
        else:
            logging.info("No change to role attributes")

    def _configure_composite_roles(self, role, composite_roles):
        logging.info("Configure composite roles: %s", composite_roles)

        current_realm_roles = role.get('composites', {}).get('realm', [])
        current_client_roles = role.get('composites', {}).get('client', {})
        logging.info("Current composite roles: realm=%s, client=%s", current_realm_roles, current_client_roles)
        configured_realm_roles = composite_roles.get('realm', [])
        configured_client_roles = composite_roles.get('client', {})

        new_realm_roles = [r for r in configured_realm_roles if r not in current_realm_roles]
        new_client_roles = RoleAdmin._diff_client_roles(configured_client_roles, current_client_roles)
        if new_realm_roles or new_client_roles:
            logging.info("Add composite roles: realm=%s, client=%s", new_realm_roles, new_client_roles)
            self._add_composite_realm_and_client_roles(role, new_realm_roles, new_client_roles)

        removed_realm_roles = [r for r in current_realm_roles if r not in configured_realm_roles]
        removed_client_roles = RoleAdmin._diff_client_roles(current_client_roles, configured_client_roles)
        if removed_realm_roles or removed_client_roles:
            logging.info("Remove composite roles: realm=%s, client=%s", removed_realm_roles, removed_client_roles)
            self._remove_composite_realm_and_client_roles(role, removed_realm_roles, removed_client_roles)

    def _add_composite_realm_and_client_roles(self, role, composite_realm_roles, composite_client_roles):
        composite_roles = []
        for realm_role_name in composite_realm_roles:
            realm_role = self.exported_realm_roles.get(realm_role_name, self._get_realm_role(realm_role_name))
            if realm_role is not None:
                composite_roles.append(realm_role)
            else:
                logging.warning("Composite realm role %s does not exist, skipping.", realm_role_name)

        for client_name, roles in composite_client_roles.items():
            for roles_name in roles:
                client_role = self.exported_client_roles.get(client_name, {}).get(roles_name)
                if client_role is not None:
                    composite_roles.append(client_role)
                else:
                    logging.warning("Composite client role %s:%s does not exist, skipping.", client_name, roles_name)

        if composite_roles:
            self._add_composite_roles(role, composite_roles)

    def _remove_composite_realm_and_client_roles(self, role, composite_realm_roles, composite_client_roles):
        removed_composite_roles = []
        for role_name in composite_realm_roles:
            realm_role = self.exported_realm_roles.get(role_name)
            if realm_role:
                removed_composite_roles.append(realm_role)

        for client_name, roles in composite_client_roles.items():
            for role_name in roles:
                client_role = self.exported_client_roles.get(client_name).get(role_name)
                if client_role:
                    removed_composite_roles.append(client_role)

        if removed_composite_roles:
            self._remove_composite_roles(role, removed_composite_roles)

    @staticmethod
    def _diff_client_roles(to_roles, from_roles):
        diff = {}
        for client_name, roles in to_roles.items():
            if client_name in from_roles:
                new_roles = [r for r in roles if r not in from_roles[client_name]]
                if new_roles:
                    diff[client_name] = new_roles
            else:
                diff[client_name] = roles
        return diff

    def _add_composite_roles(self, role, associated_roles):
        url = self.role_by_id_url + "/" + role['id'] + "/composites"
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('POST', url, json=associated_roles, headers=headers)
        if status_code != 204:
            logging.error("Unable to update realm details due to (%s): %s", status_code, response_message)
            raise RuntimeError('unable to update realm due to ' + str(response_message))

    def _remove_composite_roles(self, role, removed_assoc_roles):
        url = self.role_by_id_url + "/" + role['id'] + "/composites"
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('DELETE', url, json=removed_assoc_roles,
                                                                 headers=headers)
        if status_code != 204:
            logging.error("Unable to update realm details due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to delete realm details due to " + str(response_message))
