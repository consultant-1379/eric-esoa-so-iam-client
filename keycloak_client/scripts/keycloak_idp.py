"""The module manages keycloak OpenID Identity Provider."""
import logging
from urllib.parse import urlparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IDPAdmin:
    """The class manages Keycloak OpenID Identity Provider."""
    def __init__(self, auth_details, rest_client):
        self.certificate_ca_path = auth_details.ca_cert_path
        bits = urlparse(auth_details.admin_url)
        self.well_known_url = '{}://{}/auth/realms/master/.well-known/openid-configuration'.format(
            bits.scheme, bits.netloc)
        self.keycloak_idp_url = '{}/identity-provider/instances'.format(auth_details.admin_url)
        self.access_token = auth_details.token
        self.rest_client = rest_client

    def get(self):
        """The method to get available Keycloak OpenID Identity Provider."""
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('GET', self.keycloak_idp_url, headers=headers)
        if status_code != 200:
            logging.error("Unable to get IDP details due to (%s): %s", status_code, response_message)
            raise RuntimeError("Unable to get IDP due to " + str(response_message))
        # If the username even partially matches users found in keycloak, it can return many users
        # So we need to compensate to check for an exact match in the returned list ourselves
        for record in response_message:
            if record['alias'] == "oidc":
                return record
        logging.warning("Unable to get idp 'oidc'")
        return None

    def create(self, client_id, client_secret):
        """The method to create an OpenID keycloak configuration."""
        logging.info("Creating IDP 'oidc'")

        # Get authorization URL and token URL from .well-known API endpoint,
        # as KeyCloak might be running without --hostname option, in which case
        # ${authBaseUrl} variable will not be available.
        headers = {'Authorization': 'Bearer {}'.format(self.access_token)}
        response_message, status_code = self.rest_client.request('GET', self.well_known_url, headers=headers)
        auth_endpoint = None
        token_endpoint = None
        if status_code == 200:
            auth_endpoint = response_message["authorization_endpoint"]
            token_endpoint = response_message["token_endpoint"]
        idp_config = {
            "config": {
                "useJwksUrl": "true",
                "syncMode": "IMPORT",
                "hideOnLoginPage": "",
                "loginHint": "",
                "uiLocales": "",
                "backchannelSupported": "",
                "disableUserInfo": "",
                "acceptsPromptNoneForwardFromClient": "",
                "validateSignature": "",
                "pkceEnabled": "",
                "authorizationUrl": auth_endpoint,
                "tokenUrl": token_endpoint,
                "clientAuthMethod": "client_secret_post",
                "clientId": client_id,
                "clientSecret": client_secret
            },
            "alias": "oidc",
            "providerId": "oidc",
            "enabled": True,
            "authenticateByDefault": False,
            "firstBrokerLoginFlowAlias": "first broker login",
            "postBrokerLoginFlowAlias": "",
            "trustEmail": True,
            "storeToken": "",
            "addReadTokenRoleOnCreate": "",
            "linkOnly": ""
        }
        existing_idp = self.get()
        if existing_idp is None:
            response_message, status_code = self.rest_client.request('POST', self.keycloak_idp_url, json=idp_config,
                                                                     headers=headers)
            if status_code != 201:
                logging.error("unable to create OpenIDP due to (%s): %s", status_code, response_message)
                raise RuntimeError("Unable to create OpenID IDP due to " + str(response_message))
            logging.info("Created OpenID IDP 'oidc'")
        else:
            logging.info("OpenID IDP config 'oidc' exists already")

    def configure_client(self, client_admin_instance, proto_mapper_admin, client_name):
        """
        - Creates KeyCloak client for external use
        - Configures that client
        - Defines OpenID configuration
        """
        client_admin_instance.create_ext_client(client_name)
        client = client_admin_instance.get(client_name)
        if client:
            client_id = client["id"]
            client_name = client["clientId"]
            client_secret = client["secret"]
            # External services usually require the following two attributes
            proto_mapper_admin.create_from_dict(client_id, client_name, "oidc-audience-mapper", {
                "included.client.audience": client_name,
                "id.token.claim": "false",
                "access.token.claim": "true"
            })
            proto_mapper_admin.create_from_dict(client_id, client_name, "oidc-hardcoded-claim-mapper", {
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
                "access.tokenResponse.claim": "false",
                "claim.name": "policy",
                "claim.value": "readwrite"
            })
            self.create(client_name, client_secret)
