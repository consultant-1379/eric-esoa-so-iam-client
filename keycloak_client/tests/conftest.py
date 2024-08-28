"""pyTest fixtures are added to this module."""
import pytest
import requests

from keycloak_client.scripts.common.rest_client import RestClient
from keycloak_client.scripts.common.auth_details import AuthDetails


POST_201_URL = ['https://fake.keycloak/auth/admin/realms/master/client-scopes/fake_client_scope_id/scope-mappings/'
                'clients/fake_client_id', 'https://fake.keycloak/auth/admin/realms/master/client-scopes',
                'https://fake.keycloak/auth/admin/realms/master/clients',
                'https://fake.keycloak/auth/admin/realms/master/groups',
                'https://fake.keycloak/auth/admin/realms/master/client-scopes/fake_client_scope_id/protocol-mappers/'
                'add-models', 'https://fake.keycloak/auth/admin/realms/master/roles',
                'https://fake.keycloak/auth/admin/realms/master/users']

POST_204_URL = ['https://fake.keycloak/auth/realms/master/protocol/openid-connect/logout',
                'https://fake.keycloak/auth/admin/realms/master/clients/None/authz/resource-server/import',
                'https://fake.keycloak/auth/admin/realms/master/users/00/role-mappings/realm',
                'https://fake.keycloak/auth/admin/realms/master/roles-by-id/00/composites',
                'https://fake.keycloak/auth/admin/realms/master/client-scopes/fake_client_scope_id/'
                'protocol-mappers/add-models',
                'https://fake.keycloak/auth/admin/realms/master/client-scopes/fake_client_scope_id/'
                'scope-mappings/clients/fake_client_id']

PUT_204_URL = ['https://fake.keycloak/auth/admin/realms/master/clients/None/authz/resource-server/policy/js/00',
               'https://fake.keycloak/auth/admin/realms/master/clients/None/authz/resource-server/policy/00',
               'https://fake.keycloak/auth/admin/realms/master/clients/None/authz/resource-server/resource/00',
               'https://fake.keycloak/auth/admin/realms/master/client-scopes/fake_client_scope_id',
               'https://fake.keycloak/auth/admin/realms/master/clients/00',
               'https://fake.keycloak/auth/admin/realms/master/groups/fake_group_id',
               'https://fake.keycloak/auth/admin/realms/master/client-scopes/fake_client_scope_id/'
               'protocol-mappers/models/fake_protocol_mapper_id',
               'https://fake.keycloak/auth/admin/realms/master/roles-by-id/00',
               'https://fake.keycloak/auth/admin/realms/master',
               'https://fake.keycloak/auth/admin/realms/tenant1',
               'https://fake.keycloak/auth/admin/realms/master/clients/00/default-client-scopes/1'
               ]

DELETE_204_URL = ['https://fake.keycloak/auth/admin/realms/master/client-scopes/fake_client_scope_id/scope-mappings/'
                  'clients/fake_client_id',
                  'https://fake.keycloak/auth/admin/realms/master/client-scopes/fake_client_scope_id',
                  'https://fake.keycloak/auth/admin/realms/master/clients/00',
                  'https://fake.keycloak/auth/admin/realms/master/groups/fake_group_id',
                  'https://fake.keycloak/auth/admin/realms/master/client-scopes/fake_client_scope_id/'
                  'protocol-mappers/models/fake_protocol_mapper_id',
                  'https://fake.keycloak/auth/admin/realms/master/roles/fake_role',
                  'https://fake.keycloak/auth/admin/realms/master/roles-by-id/00/composites']

DELETE_404_URL = ['https://fake.keycloak/auth/admin/realms/master/clients/None/authz/resource-server/resource/00',
                  'https://fake.keycloak/auth/admin/realms/master/clients/None/authz/resource-server/policy/00']


class MockResponse:
    """Mock class to replace requests.Response"""
    status_code = 200
    #pylint: disable=no-self-use
    def json(self):
        """Mock json() method"""
        response_json = {"realm": "master", "mock_json": True}
        return response_json

    # pylint: disable=no-self-use
    def content(self):
        """Mock json() method"""
        response_json = {"realm": "master", "mock_json": True}
        return response_json
    #pylint: disable=no-self-use, duplicate-code
    def raise_for_status(self):
        """Mock raise_for_status() method"""
        return True


class MockRealmResponse:
    """Mock class to replace requests.Response"""
    status_code = 200
    #pylint: disable=no-self-use
    def json(self):
        """Mock json() method"""
        response_json = {"realm": "master", "passwordPolicy": "hashIterations(27500) and passwordHistory(12) "
                                                              "and length(12) and notUsername and specialChars(1) "
                                                              "and upperCase(1) and lowerCase(1) and digits(1) and "
                                                              "hashAlgorithm(pbkdf2-sha256) and notEmail and "
                                                              "filteredForceExpiredPwdChange(90)"}
        return response_json

    def content(self):
        """Mock content() method"""
        response_json = {"realm": "master", "passwordPolicy": "hashIterations(27500) and passwordHistory(12) "
                                                              "and length(12) and notUsername and specialChars(1) "
                                                              "and upperCase(1) and lowerCase(1) and digits(1) and "
                                                              "hashAlgorithm(pbkdf2-sha256) and notEmail and "
                                                              "filteredForceExpiredPwdChange(90)"}
        return response_json

    #pylint: disable=no-self-use, duplicate-code
    def raise_for_status(self):
        """Mock raise_for_status() method"""
        return True

class MockResponseGetAllRealms:
    """Mock class to replace requests.Response"""
    status_code = 200
    #pylint: disable=no-self-use
    def json(self):
        """Mock json() method"""
        response_json = [{"realm": "master", "passwordPolicy": "hashIterations(27500) and passwordHistory(12) "
                                                               "and length(12) and notUsername and specialChars(1) "
                                                               "and upperCase(1) and lowerCase(1) and digits(1) and "
                                                               "hashAlgorithm(pbkdf2-sha256) and notEmail and "
                                                               "filteredForceExpiredPwdChange(90)"},
                         {"realm": "tenant1"}]
        return response_json
    def content(self):
        """Mock content() method"""
        response_json = [{"realm": "master", "passwordPolicy": "hashIterations(27500) and passwordHistory(12) "
                                                               "and length(12) and notUsername and specialChars(1) "
                                                               "and upperCase(1) and lowerCase(1) and digits(1) and "
                                                               "hashAlgorithm(pbkdf2-sha256) and notEmail and "
                                                               "filteredForceExpiredPwdChange(90)"},
                         {"realm": "tenant1"}]
        return response_json
    #pylint: disable=no-self-use, duplicate-code
    def raise_for_status(self):
        """Mock raise_for_status() method"""
        return True


@pytest.fixture
def initialize_tls_verify_tests(monkeypatch):
    """Pytest fixture to initialize tls verification related tests."""
    #pylint: disable=unused-argument, duplicate-code
    def mock_requests_get(*args, **kwargs):
        if kwargs['verify']:
            if "https://fake.keycloak/getAllRealms" in args or 'https://fake.keycloak/auth/admin/realms' in args:
                return MockResponseGetAllRealms()
            return MockResponse()
        raise Exception
    #pylint: disable=unused-argument, duplicate-code, no-else-return
    def mock_requests_post(*args, **kwargs):
        if kwargs['verify']:
            if args[0] in POST_204_URL:
                mock_response = MockResponse()
                mock_response.status_code = 204
                return mock_response
            elif args[0] in POST_201_URL:
                mock_response = MockResponse()
                mock_response.status_code = 201
                return mock_response
            else:
                return MockResponse()
        raise Exception
    #pylint: disable=unused-argument, no-else-return
    def mock_requests_put(*args, **kwargs):
        if kwargs['verify']:
            if args[0] in PUT_204_URL:
                mock_response = MockResponse()
                mock_response.status_code = 204
                return mock_response
            else:
                return MockResponse()
        raise Exception
    #pylint: disable=unused-argument, no-else-return
    def mock_requests_delete(*args, **kwargs):
        if kwargs['verify']:
            if args[0] in DELETE_204_URL:
                mock_response = MockResponse()
                mock_response.status_code = 204
                return mock_response
            elif args[0] in DELETE_404_URL:
                mock_response = MockResponse()
                mock_response.status_code = 404
                return mock_response
            else:
                return MockResponse()
        raise Exception
    monkeypatch.setattr(requests, "get", mock_requests_get)
    monkeypatch.setattr(requests, "post", mock_requests_post)
    monkeypatch.setattr(requests, "put", mock_requests_put)
    monkeypatch.setattr(requests, "delete", mock_requests_delete)
    monkeypatch.setattr(requests, "Response", MockResponse)


@pytest.fixture
def initialize_delete_policy_success(monkeypatch):
    """Pytest fixture to initialize tls verification related tests."""
    #pylint: disable=unused-argument, duplicate-code
    def mock_requests_get(*args, **kwargs):
        if kwargs['verify']:
            if "https://fake.keycloak/getAllRealms" in args or 'https://fake.keycloak/auth/admin/realms' in args:
                return MockResponseGetAllRealms()
            return MockRealmResponse()
        raise Exception
    # pylint: disable=unused-argument, no-else-return
    def mock_requests_put(*args, **kwargs):
        if kwargs['verify']:
            if args[0] in PUT_204_URL:
                mock_response = MockResponse()
                mock_response.status_code = 204
                return mock_response
            else:
                return MockResponse()
        raise Exception
    monkeypatch.setattr(requests, "get", mock_requests_get)
    monkeypatch.setattr(requests, "put", mock_requests_put)
    monkeypatch.setattr(requests, "Response", MockResponse)

def init_auth_details():
    """Init method to initialize auth details in test"""
    auth_details = AuthDetails("https://fake.keycloak", "test_keycloak_user", "test_keycloak_password",
                               "/mnt/certs/iam/ca.crt")
    auth_details.token = 'cMGSM0x7h5sGpaiAxJpt6J2qO43RGrUwGAG1VAGlofY'
    return auth_details, RestClient(auth_details)
