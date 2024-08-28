"""Main script for keycloak_client package. This module handles all command line arguments."""
#!/usr/bin/env python
import argparse
import json

import urllib3

from keycloak_client.scripts.keycloak_groups import GroupAdmin
from keycloak_client.scripts.keycloak_protocol_mappers import ProtocolMapperAdmin
from keycloak_client.scripts.common.rest_client import RestClient
from keycloak_client.scripts.common.auth_details import AuthDetails
from keycloak_client.scripts.common.http_protocol import HttpProtocol
from keycloak_client.scripts.keycloak_client_scope_mappings import ClientScopeMappingAdmin
from keycloak_client.scripts.keycloak_client_scopes import ClientScopeAdmin
from keycloak_client.scripts.keycloak_admin_client import AdminCliClient
from keycloak_client.scripts.keycloak_clients import ClientAdmin
from keycloak_client.scripts.keycloak_password_policy_update import PasswordPolicyUpdate
from keycloak_client.scripts.keycloak_realms import RealmAdmin
from keycloak_client.scripts.keycloak_roles import RoleAdmin
from keycloak_client.scripts.keycloak_authz import AuthzAdmin
from keycloak_client.scripts.keycloak_users import UsersAdmin
from keycloak_client.scripts.keycloak_idp import IDPAdmin
from keycloak_client.scripts.keycloak_users_realm_role_mappings import UserRealmRoleMappingsAdmin


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def admin_cli_client_login(func):
    """This method is the interface to allow loging in as keycloak admin."""
    def func_wrapper(args):
        keycloak_admin_client = None
        try:
            auth_details = AuthDetails(args.keycloak_hostname, args.keycloak_user, args.keycloak_password,
                                       args.ca_cert_path, 443, HttpProtocol.HTTPS)
            rest_client = RestClient(auth_details)
            keycloak_admin_client = AdminCliClient(auth_details, rest_client)
            auth_details.token = keycloak_admin_client.login()
            func(args, auth_details, rest_client)
        finally:
            if keycloak_admin_client:
                keycloak_admin_client.logout()
    return func_wrapper


@admin_cli_client_login
def _update_realm(args, auth_details, rest_client):
    RealmAdmin(auth_details, rest_client).update(args.config)


@admin_cli_client_login
def _update_all_realms(args, auth_details, rest_client):
    RealmAdmin(auth_details, rest_client).update_all_realms(args.config)


@admin_cli_client_login
def _create_user_realm_role_mappings(args, auth_details, rest_client):
    UserRealmRoleMappingsAdmin(auth_details, rest_client).create(args.username, args.config)


@admin_cli_client_login
def _get_client_secret(args, auth_details, rest_client):
    client = ClientAdmin(auth_details, rest_client).get(args.client_id)
    if client:
        print(client["secret"])


@admin_cli_client_login
def _create_client(args, auth_details, rest_client):
    ClientAdmin(auth_details, rest_client).create(args.config)


@admin_cli_client_login
def _create_ext_client(args, auth_details, rest_client):
    ClientAdmin(auth_details, rest_client).create_ext_client(args.client_id)


@admin_cli_client_login
def _create_ext_client_configuration(args, auth_details, rest_client):
    client_admin_instance = ClientAdmin(auth_details, rest_client)
    proto_mapper_admin = ProtocolMapperAdmin(auth_details, rest_client)
    IDPAdmin(auth_details, rest_client).configure_client(client_admin_instance, proto_mapper_admin, args.client_id)


@admin_cli_client_login
def _delete_client(args, auth_details, rest_client):
    ClientAdmin(auth_details, rest_client).delete(args.client_name)


@admin_cli_client_login
def _create_roles(args, auth_details, rest_client):
    with open(args.config) as json_file:
        roles = json.load(json_file)
    RoleAdmin(auth_details, rest_client).create(roles, args.provider)


@admin_cli_client_login
def _delete_role(args, auth_details, rest_client):
    RoleAdmin(auth_details, rest_client).delete(args.provider)


@admin_cli_client_login
def _create_authz(args, auth_details, rest_client):
    AuthzAdmin(auth_details, rest_client).create(args.provider, args.config, args.client_name)


@admin_cli_client_login
def _delete_authz(args, auth_details, rest_client):
    AuthzAdmin(auth_details, rest_client).delete(args.provider, args.client_name)


@admin_cli_client_login
def _create_user(args, auth_details, rest_client):
    UsersAdmin(auth_details, rest_client).create(args.username, args.password)


@admin_cli_client_login
def _create_client_scope(args, auth_details, rest_client):
    ClientScopeAdmin(auth_details, rest_client).create(args.config)

@admin_cli_client_login
def _update_client_scope(args, auth_details, rest_client):
    ClientScopeAdmin(auth_details, rest_client).update(args.client_scope_name, args.config)


@admin_cli_client_login
def _delete_client_scope(args, auth_details, rest_client):
    ClientScopeAdmin(auth_details, rest_client).delete(args.client_scope_name)


@admin_cli_client_login
def _create_client_scope_mapping(args, auth_details, rest_client):
    ClientScopeMappingAdmin(auth_details, rest_client).create(args.client_scope_name, args.client_name, args.config)


@admin_cli_client_login
def _delete_client_scope_mapping(args, auth_details, rest_client):
    ClientScopeMappingAdmin(auth_details, rest_client).delete(args.client_scope_name, args.client_name, args.config)


@admin_cli_client_login
def _create_protocol_mapper(args, auth_details, rest_client):
    ProtocolMapperAdmin(auth_details, rest_client).create(args.client_scope_name, args.config)


@admin_cli_client_login
#pylint: disable=unused-argument
def _get_idp(args, auth_details, rest_client):
    print(IDPAdmin(auth_details, rest_client).get())


@admin_cli_client_login
def _create_idp(args, auth_details, rest_client):
    IDPAdmin(auth_details, rest_client).create(args.client_id, args.client_secret)


@admin_cli_client_login
def _update_protocol_mapper(args, auth_details, rest_client):
    ProtocolMapperAdmin(auth_details, rest_client).update(args.client_scope_name, args.protocol_mapper_name,
                                                          args.config)


@admin_cli_client_login
def _delete_protocol_mapper(args, auth_details, rest_client):
    ProtocolMapperAdmin(auth_details, rest_client).delete(args.client_scope_name, args.protocol_mapper_name)


@admin_cli_client_login
def _create_group(args, auth_details, rest_client):
    GroupAdmin(auth_details, rest_client).create(args.config)


@admin_cli_client_login
def _update_group(args, auth_details, rest_client):
    GroupAdmin(auth_details, rest_client).update(args.group_name, args.config)


@admin_cli_client_login
def _delete_group(args, auth_details, rest_client):
    GroupAdmin(auth_details, rest_client).delete(args.group_name)


def _check_supported_password_policy_type(value):
    if value not in PasswordPolicyUpdate.ACCEPTED_PASSWORD_POLICY:
        raise argparse.ArgumentTypeError('%s is not the supported value please use values from %s'
                                         % (value, PasswordPolicyUpdate.ACCEPTED_PASSWORD_POLICY))
    return value


@admin_cli_client_login
def _delete_password_policy(args, auth_details, rest_client):
    PasswordPolicyUpdate(auth_details, rest_client).delete_from_all(args.policy)


def _define_get_commands(subparsers, credentials_parser):
    get_parser = subparsers.add_parser('get', help="Get keycloak resources")
    get_subparser = get_parser.add_subparsers(title="actions")
    get_subparser.required = True

    get_idp_parser = get_subparser.add_parser(
        "idp",
        help="Get KeyCloak OpenID IDP configuration in the master realm.",
        parents=[credentials_parser])
    get_idp_parser.add_argument("--client-id", required=True)
    get_idp_parser.set_defaults(func=_get_idp)

    get_client_secret_parser = get_subparser.add_parser(
        "client_secret",
        help="Get keycloak Client Secret.",
        parents=[credentials_parser])
    get_client_secret_parser.add_argument("--client-id", required=True)
    get_client_secret_parser.set_defaults(func=_get_client_secret)


#pylint: disable=too-many-locals
def _define_create_commands(subparsers, credentials_parser):
    create_parser = subparsers.add_parser('create', help="Create keycloak resources")
    create_subparser = create_parser.add_subparsers(title="actions")
    create_subparser.required = True
    create_client_parser = create_subparser.add_parser(
        "client",
        help="Create keycloak client. Does nothing if the client already exists.",
        parents=[credentials_parser])
    create_client_parser.add_argument("--config", required=True)
    create_client_parser.set_defaults(func=_create_client)

    create_ext_client_parser = create_subparser.add_parser(
        "ext-client",
        help=("Create keycloak client with settings for external access. "
              "Does nothing if the client already exists."),
        parents=[credentials_parser])
    create_ext_client_parser.add_argument("--client-id", required=True)
    create_ext_client_parser.set_defaults(func=_create_ext_client)

    create_ext_client_config_parser = create_subparser.add_parser(
        "ext-client-config",
        help=("Configures keycloak client with settings for external access. "
              "Does nothing if the client already exists."),
        parents=[credentials_parser])
    create_ext_client_config_parser.add_argument("--client-id", required=True)
    create_ext_client_config_parser.set_defaults(func=_create_ext_client_configuration)

    create_role_parser = create_subparser.add_parser(
        "roles",
        help="Create keycloak roles. If role already exists then role is updated if any changes to "
             "attribute or composite role configuration. Existing roles which are no longer referenced "
             "in the config will be removed",
        parents=[credentials_parser])
    create_role_parser.add_argument("--provider", required=True)
    create_role_parser.add_argument("--config", required=True)
    create_role_parser.set_defaults(func=_create_roles)

    create_authz_parser = create_subparser.add_parser(
        "authz",
        help="Create keycloak authorization resources and policies. If resources and policies already "
             "exist for the provider then they will be updated with the new configuration. Existing resources and "
             "policies which are no longer referenced in the config will be removed.",
        parents=[credentials_parser])
    create_authz_parser.add_argument("--provider", required=True)
    create_authz_parser.add_argument("--config", required=True)
    create_authz_parser.add_argument('--client_name', required=True)
    create_authz_parser.set_defaults(func=_create_authz)

    create_user_parser = create_subparser.add_parser(
        "user",
        help="Create keycloak user in the master realm.",
        parents=[credentials_parser])
    create_user_parser.add_argument("--username", required=True)
    create_user_parser.add_argument("--password", required=True)
    create_user_parser.set_defaults(func=_create_user)

    create_user_realm_role_mappings_parser = create_subparser.add_parser(
        "user_realm_role_mappings",
        help="Create a users realm role mappings.",
        parents=[credentials_parser])
    create_user_realm_role_mappings_parser.add_argument("--config", required=True)
    create_user_realm_role_mappings_parser.add_argument("--username", required=True)
    create_user_realm_role_mappings_parser.set_defaults(func=_create_user_realm_role_mappings)

    create_client_scope_parser = create_subparser.add_parser(
        "client_scope",
        help="Create keycloak client scope in the master realm.",
        parents=[credentials_parser])
    create_client_scope_parser.add_argument("--config", required=True)
    create_client_scope_parser.set_defaults(func=_create_client_scope)

    create_client_scope_mapping_parser = create_subparser.add_parser(
        "client_scope_mapping",
        help="Create keycloak client scope mapping in the master realm.",
        parents=[credentials_parser])
    create_client_scope_mapping_parser.add_argument("--client_scope_name", required=True)
    create_client_scope_mapping_parser.add_argument("--client_name", required=True)
    create_client_scope_mapping_parser.add_argument("--config", required=True)
    create_client_scope_mapping_parser.set_defaults(func=_create_client_scope_mapping)

    create_protocol_mapper_parser = create_subparser.add_parser(
        "protocol_mapper",
        help="Create keycloak protocol mappers for a client scope in the master realm.",
        parents=[credentials_parser])
    create_protocol_mapper_parser.add_argument("--client_scope_name", required=True)
    create_protocol_mapper_parser.add_argument("--config", required=True)
    create_protocol_mapper_parser.set_defaults(func=_create_protocol_mapper)

    create_group_parser = create_subparser.add_parser(
        "group",
        help="Create keycloak group in the master realm.",
        parents=[credentials_parser])
    create_group_parser.add_argument("--config", required=True)
    create_group_parser.set_defaults(func=_create_group)

    create_idp_parser = create_subparser.add_parser(
        "idp",
        help="Create KeyCloak OpenID IDP configuration in the master realm.",
        parents=[credentials_parser])
    create_idp_parser.add_argument("--client-id", required=True)
    create_idp_parser.add_argument("--client-secret", required=True)
    create_idp_parser.set_defaults(func=_create_idp)


def _define_update_commands(subparsers, credentials_parser):
    update_parser = subparsers.add_parser('update', help="Update keycloak resources")
    update_subparser = update_parser.add_subparsers(title="actions")
    update_subparser.required = True
    update_realm_parser = update_subparser.add_parser(
        "realm",
        help="Update keycloak realm.",
        parents=[credentials_parser])
    update_realm_parser.add_argument("--config", required=True)
    update_realm_parser.set_defaults(func=_update_realm)
    update_realms_all_parser = update_subparser.add_parser(
        "realms",
        help="Update all keycloak realms.",
        parents=[credentials_parser])
    update_realms_all_parser.add_argument("--config", required=True)
    update_realms_all_parser.set_defaults(func=_update_all_realms)

    update_client_scope_parser = update_subparser.add_parser(
        "client_scope",
        help="Update a keycloak client scope.",
        parents=[credentials_parser])
    update_client_scope_parser.add_argument("--client_scope_name", required=True)
    update_client_scope_parser.add_argument("--config", required=True)
    update_client_scope_parser.set_defaults(func=_update_client_scope)

    update_protocol_mapper_parser = update_subparser.add_parser(
        "protocol_mapper",
        help="Update a keycloak protocol mapper.",
        parents=[credentials_parser])
    update_protocol_mapper_parser.add_argument("--client_scope_name", required=True)
    update_protocol_mapper_parser.add_argument("--protocol_mapper_name", required=True)
    update_protocol_mapper_parser.add_argument("--config", required=True)
    update_protocol_mapper_parser.set_defaults(func=_update_protocol_mapper)

    update_group_parser = update_subparser.add_parser(
        "group",
        help="Update a keycloak group.",
        parents=[credentials_parser])
    update_group_parser.add_argument("--group_name", required=True)
    update_group_parser.add_argument("--config", required=True)
    update_group_parser.set_defaults(func=_update_group)


def _define_delete_commands(subparsers, credentials_parser):
    delete_parser = subparsers.add_parser('delete', help="Delete keycloak resources")
    delete_subparser = delete_parser.add_subparsers()
    delete_subparser.required = True
    delete_client_parser = delete_subparser.add_parser(
        "client", parents=[credentials_parser], help="Delete the specified keycloak client")
    delete_client_parser.add_argument("--client_name", required=True)
    delete_client_parser.set_defaults(func=_delete_client)
    delete_roles_parser = delete_subparser.add_parser(
        "roles", parents=[credentials_parser], help="Delete all keycloak roles for the specified provider")
    delete_roles_parser.add_argument("--provider", required=True)
    delete_roles_parser.set_defaults(func=_delete_role)
    delete_authz_parser = delete_subparser.add_parser("authz", parents=[credentials_parser],
                                                      help="Delete all keycloak roles, resources and "
                                                           "policies comprising the authz configuration "
                                                           "for the specified provider")
    delete_authz_parser.add_argument("--provider", required=True)
    delete_authz_parser.add_argument('--client_name', required=True)
    delete_authz_parser.set_defaults(func=_delete_authz)

    delete_client_scope_parser = delete_subparser.add_parser(
        "client_scope",
        help="Delete a keycloak client scope with the specified name",
        parents=[credentials_parser])
    delete_client_scope_parser.add_argument("--client_scope_name", required=True)
    delete_client_scope_parser.set_defaults(func=_delete_client_scope)

    delete_client_scope_mapping_parser = delete_subparser.add_parser(
        "client_scope_mapping",
        help="Delete a keycloak client scope mapping.",
        parents=[credentials_parser])
    delete_client_scope_mapping_parser.add_argument("--client_scope_name", required=True)
    delete_client_scope_mapping_parser.add_argument("--client_name", required=True)
    delete_client_scope_mapping_parser.add_argument("--config", required=True)
    delete_client_scope_mapping_parser.set_defaults(func=_delete_client_scope_mapping)

    delete_protocol_mapper_parser = delete_subparser.add_parser(
        "protocol_mapper",
        help="Delete a keycloak protocol mapper.",
        parents=[credentials_parser])
    delete_protocol_mapper_parser.add_argument("--client_scope_name", required=True)
    delete_protocol_mapper_parser.add_argument("--protocol_mapper_name", required=True)
    delete_protocol_mapper_parser.set_defaults(func=_delete_protocol_mapper)

    delete_group_parser = delete_subparser.add_parser(
        "group",
        help="Delete a keycloak group.",
        parents=[credentials_parser])
    delete_group_parser.add_argument("--group_name", required=True)
    delete_group_parser.set_defaults(func=_delete_group)

    delete_password_policy = delete_subparser.add_parser(
        "password_policy",
        help="Delete a password policy without removing other password policy",
        parents=[credentials_parser])
    delete_password_policy.add_argument("--policy", required=True, nargs='+',
                                        type=_check_supported_password_policy_type)
    delete_password_policy.set_defaults(func=_delete_password_policy)


def main():
    """ main """
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='Commands')
    subparsers.required = True

    credentials_parser = argparse.ArgumentParser(add_help=False)
    credentials_parser.add_argument('--keycloak_hostname', help='keycloak hostname', required=True)
    credentials_parser.add_argument(
        '--keycloak_user', default="keycloak", help='keycloak admin user', required=False)
    credentials_parser.add_argument(
        '--keycloak_password', default="keycloak", help='keycloak admin password', required=False)
    credentials_parser.add_argument(
        '--ca_cert_path', default="/mnt/certs/iam/ca.crt", help='keycloak ca cert path', required=False)

    _define_get_commands(subparsers, credentials_parser)
    _define_create_commands(subparsers, credentials_parser)
    _define_update_commands(subparsers, credentials_parser)
    _define_delete_commands(subparsers, credentials_parser)

    args = parser.parse_args()
    args.func(args)
