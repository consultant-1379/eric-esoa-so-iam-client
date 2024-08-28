1. General

RBAC in SO is implemented centrally in the api-gateway. The api-gateway attempts to map an incoming
request to a keycloak resource by matching the uri of the request to a configured resource uri.
If a match is found then an authorization check is performed on the request in which all permissions associated
with the resource are evaluated. If a scope is defined for the resource which matches the name of the requested http
method then the scope will be included in the authorization check. Otherwise authorization is evaluated on
the resource only.

This repo contains example hooks and configmaps to enable microservices to contribute
RBAC configuration in keycloak via helm hooks.

The example hooks demonstrate creation of client, roles and authorization configuration in keycloak.

A keycloak-client container is built which provides a cli to perform the following
operations towards keycloak.

    - Create a client
    - Create authorization configuration (RBAC)
    - Create roles

Example hooks should be updated to use the latest version of the keycloak-client container.

1.1 Referencing the image in helm charts
When using this image the details should be referenced in the `eric-product-info.yaml` as follows:
```yaml
iamClient:
  productName: "Identity Access Management Client"
  productNumber: "CXA 301 140"
  registry: "armdocker.rnd.ericsson.se"
  repoPath: "proj-esoa-so"
  name: "eric-esoa-iam-client"
  tag: <VERSION>
```
Where <VERSION> is replaced with the latest released version of the image.
This can be found in the `artifact.properties` of the release job:
https://fem2s11-eiffel052.eiffel.gic.ericsson.se:8443/jenkins/job/eric-esoa-so-iam-client_Release/
This can then be read into the deployment using the "Any image path" Helm helper function for DR-D1121-067.
```yaml
initContainers:
- name: iam-client
  image: image: {{ template "<microservice-name>.imagePath" (dict "imageId" "iamClient" "values" .Values "files" .Files) }}
```



2. Create a client

Create a client in keycloak using the example hook 'hook_create_iam_client.yaml' and
configMap 'configmap_iam_client.yaml'.

The client configuration in the configMap can be updated as per keycloak clients resource representation,
https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clients_resource.

The client secret can be provided directly in the configMap. Alternatively it can be provided
as an env variable named 'CLIENT_SECRET' which for example could be read from a kubernetes secret
as per the example hook


3. Create RBAC configuration

Create RBAC configuration in keycloak using the example hook 'hook_create_rbac_configuration.yaml' and
configMap 'configmap_rbac_configuration.yaml'.

RBAC configuration in keycloak consists of creating roles, resources, policies and permissions.

The role configuration can be updated as per keycloak role resource respresentation,
https://www.keycloak.org/docs-api/6.0/rest-api/index.html#_roles_resource.

The authorization configuration is not documented directly in keycloak but is equivalent to importing an authorization
configuration file, https://www.keycloak.org/docs/18.0/authorization_services/#importing-a-configuration-file.


3.1 Roles

Roles are used to control access to the resources via role-based policies


3.2 Scopes

Scopes define the actions that can be performed on a resource. Only Http method names (GET, POST etc.) are supported.
Other scopes will be ignored by api-gateway and not included in the authorization evaluation context


3.3 Resources

The resources to be protected are identified by a set of uris and optionally scopes.
The uri definition supports ant-style path patterns.
Use scopes for finer grained access control where access to resource actions is restricted

https://www.keycloak.org/docs/latest/authorization_services/index.html#_resource_overview

3.4 Policies

Role-based policies define conditions for permissions where a set of one or more roles is permitted to access
a resource. Policy can be configured such that user must have all the specified roles or any of the specified roles.

https://www.keycloak.org/docs/latest/authorization_services/index.html#_policy_rbac


3.5 Permissions

Permissions associate a protected resource and the policies that must be evaluated to decide whether
access should be granted to the resource. Permissions may be resource or scope based. Scope-based
permission allow control of the actions that may be performed on a resource. Current only http verbs are
supported as actions.

https://www.keycloak.org/docs/latest/authorization_services/index.html#_permission_overview

Note: Permission are also defined under policies in the rbac configuration.

4. Create roles

Create realm roles in keycloak using the example hook 'hook_create_roles_configuration.yaml' and
configMap 'configmap_roles_configuration.yaml'.

The role configuration can be updated as per keycloak role resource respresentation,
https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_roles_resource

5. Update master realm

Update master realm configuration in keycloak using the example hook 'hook_update_realm_configuration.yaml' and
configMap 'configmap_realm_configuration.yaml'.

Realm configuration in keycloak can be used to control realm level configuration like bruteForceProtected
settings and password policies for the realm.

The realm configuration can be updated as per the keycloak top-level representation of the realm,
https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_realms_admin_resource

5.1 Update all realms

Update all realms configuration in keycloak using the example hook 'hook_update_realms_configuration.yaml' and
configMap 'configmap_realm_configuration.yaml'.

Realms configuration in keycloak can be used to configure some attributes like ssoSessionIdleTimeout and ssoSessionMaxLifespan 
on all existing realms (including master). 

The realm configuration can be updated as per the keycloak top-level representation of the realm,
https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_realms_admin_resource

6. Create user

Create user in keycloak using the example hook 'hook_create_user.yaml'.

The created user will be created with the given password, in an enabled state and without a requirement to change the password at login.

7. Create users realm role mappings

Create realm role mappings for a given user in keycloak using the example hook
'hook_create_user_realm_role_mappings.yaml' and configMap 'configmap_user_realm_role_mappings'.

Realm role mappings allow a user to be associated with a given list of realm roles.

The role-mappings can be updated as per keycloak representation of the users realm role-mappings,
https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_role_mapper_resource

8. Client Scopes

While creating Client Scopes it is also possible to create Client Scope Mappings so they do not have to be created separately

Helm hook example - Example for create only, based on this example the other operations are easily implementable

Python examples

Create

python -m keycloak_client create client_scope --keycloak_hostname=<HOST> --keycloak_user=<USER> --keycloak_password=<PASSWORD> --config=<PATH_TO_CONFIG_FILE>

Update

python -m keycloak_client update client_scope --keycloak_hostname=<HOST> --keycloak_user=<USER> --keycloak_password=<PASSWORD> --client_scope_name=<CLIENT_SCOPE_NAME> --config=<PATH_TO_CONFIG_FILE>

Delete

python -m keycloak_client delete client_scope --keycloak_hostname=<HOST> --keycloak_user=<USER> --keycloak_password=<PASSWORD> --client_scope_name=<CLIENT_SCOPE_NAME>

9. Client Scope Mappings

Helm hook example - Example for create only, based on this example the other operations are easily implementable

Python examples

Create

python -m keycloak_client create client_scope_mapping --keycloak_hostname=<HOST> --keycloak_user=<USER> --keycloak_password=<PASSWORD> --client_scope_name=<CLIENT_SCOPE_NAME> --client_name=<CLIENT_NAME> --config=<PATH_TO_CONFIG_FILE>

Update

Update is not allowed by Keycloak.

Delete

python -m keycloak_client delete client_scope_mapping --keycloak_hostname=<HOST> --keycloak_user=<USER> --keycloak_password=<PASSWORD> --client_scope_name=<CLIENT_SCOPE_NAME> --client_name=<CLIENT_NAME> --config=<PATH_TO_CONFIG_FILE>

10. Protocol Mappers for Client Scopes

Helm hook example - Example for create only, based on this example the other operations are easily implementable

Python examples

Create - Expects a json array of protocol mappers

python -m keycloak_client create protocol_mapper --keycloak_hostname=<HOST> --keycloak_user=<USER> --keycloak_password=<PASSWORD> --client_scope_name=<CLIENT_SCOPE_NAME> --config=<PATH_TO_CONFIG_FILE>

Update - Expects a single json object (not array as for creation) - Updating Protocol, ID, Name and Mapper Type is not allowed

python -m keycloak_client update protocol_mapper --keycloak_hostname=<HOST> --keycloak_user=<USER> --keycloak_password=<PASSWORD> --client_scope_name=<CLIENT_SCOPE_NAME> --protocol_mapper_name=<PROTOCOL_MAPPER_NAME> --config=<PATH_TO_CONFIG_FILE>

Delete

python -m keycloak_client delete protocol_mapper --keycloak_hostname=<HOST> --keycloak_user=<USER> --keycloak_password=<PASSWORD> --client_scope_name=<CLIENT_SCOPE_NAME> --protocol_mapper_name=<PROTOCOL_MAPPER_NAME>

11. Groups

Helm hook example - Example for create only, based on this example the other operations are easily implementable

Python examples

Create

python -m keycloak_client create group --keycloak_hostname=<HOST> --keycloak_user=<USER> --keycloak_password=<PASSWORD> --config=<PATH_TO_CONFIG_FILE>

Update

python -m keycloak_client update group --keycloak_hostname=<HOST> --keycloak_user=<USER> --keycloak_password=<PASSWORD> --group_name=<GROUP_NAME> --config=<PATH_TO_CONFIG_FILE>

Delete

python -m keycloak_client delete group --keycloak_hostname=<HOST> --keycloak_user=<USER> --keycloak_password=<PASSWORD> --group_name=<GROUP_NAME>