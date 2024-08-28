"""The module for keycloak authentication model"""
from keycloak_client.scripts.common.http_protocol import HttpProtocol


#pylint: disable=too-many-instance-attributes, too-many-arguments, no-else-return
class AuthDetails:
    """The class is for passing authentication details"""

    ADMIN_REALM_URI = 'auth/admin/realms'
    ADMIN_URI = ADMIN_REALM_URI + '/master'
    REALM_URI = 'auth/realms/master'
    URL_FORMAT = '%s://%s:%s/%s'
    URL_FORMAT_WITH_PROTOCOL = '%s/%s'

    def __init__(self, keycloak_host, keycloak_user, keycloak_password, ca_cert_path, keycloak_port=443,
                 http_protocol=HttpProtocol.HTTPS):
        self.keycloak_host = keycloak_host
        self.keycloak_user = keycloak_user
        self.keycloak_password = keycloak_password
        self.ca_cert_path = ca_cert_path
        self.keycloak_port = keycloak_port
        self.http_protocol = http_protocol
        self.admin_url = self.__keycloak_admin_url()
        self.realm_url = self.__keycloak_realms_url()
        self.admin_realm_url = self.__keycloak_admin_realms_url()
        self.token = None

    @property
    def keycloak_host(self):
        """The method get the host"""
        return self.__keycloak_host

    @keycloak_host.setter
    def keycloak_host(self, keycloak_host):
        """The method sets the host"""
        if keycloak_host and isinstance(keycloak_host, str) and len(keycloak_host.strip()) != 0:
            self.__keycloak_host = keycloak_host
        else:
            raise Exception('keycloak host should not be null or empty')

    @property
    def keycloak_user(self):
        """The method gets user"""
        return self.__keycloak_user

    @keycloak_user.setter
    def keycloak_user(self, keycloak_user):
        """The sets the user"""
        if keycloak_user and isinstance(keycloak_user, str) and len(keycloak_user.strip()) != 0:
            self.__keycloak_user = keycloak_user
        else:
            raise Exception('keycloak user should not be null or empty')

    @property
    def keycloak_password(self):
        """The method get the password"""
        return self.__keycloak_password

    @keycloak_password.setter
    def keycloak_password(self, keycloak_password):
        """The method sets the password"""
        if keycloak_password and isinstance(keycloak_password, str) and len(keycloak_password.strip()) != 0:
            self.__keycloak_password = keycloak_password
        else:
            raise Exception('keycloak password should not be null or empty')

    @property
    def ca_cert_path(self):
        """The method get the cert path"""
        return self.__ca_cert_path

    @ca_cert_path.setter
    def ca_cert_path(self, ca_cert_path):
        """The method sets the cert path"""
        if ca_cert_path and isinstance(ca_cert_path, str) and len(ca_cert_path.strip()) != 0:
            self.__ca_cert_path = ca_cert_path
        else:
            raise Exception('ca certificate path should not be null or empty')

    @property
    def keycloak_port(self):
        """The method gets the port"""
        return self.__keycloak_port

    @keycloak_port.setter
    def keycloak_port(self, keycloak_port):
        """The method sets the port"""
        if keycloak_port and isinstance(keycloak_port, int):
            self.__keycloak_port = keycloak_port
        else:
            raise Exception('keycloak port should be of type int')

    @property
    def http_protocol(self):
        """The method get the http protocol"""
        return self.__http_protocol

    @http_protocol.setter
    def http_protocol(self, http_protocol):
        """The method sets the http protocol"""
        if http_protocol and isinstance(http_protocol, HttpProtocol):
            self.__http_protocol = http_protocol
        else:
            raise Exception('only value http or https is supported for http protocol')

    def __keycloak_admin_url(self):
        """sets the admin url"""
        if not self.keycloak_host.startswith("http"):
            return self.URL_FORMAT % (self.http_protocol.value, self.keycloak_host, self.keycloak_port, self.ADMIN_URI)
        else:
            return self.URL_FORMAT_WITH_PROTOCOL % (self.keycloak_host, self.ADMIN_URI)

    def __keycloak_realms_url(self):
        """sets the realms url"""
        if not self.keycloak_host.startswith("http"):
            return self.URL_FORMAT % (self.http_protocol.value, self.keycloak_host, self.keycloak_port, self.REALM_URI)
        else:
            return self.URL_FORMAT_WITH_PROTOCOL % (self.keycloak_host, self.REALM_URI)

    def __keycloak_admin_realms_url(self):
        """sets the admin realms url"""
        if not self.keycloak_host.startswith("http"):
            return self.URL_FORMAT % (self.http_protocol.value, self.keycloak_host, self.keycloak_port,
                                      self.ADMIN_REALM_URI)
        else:
            return self.URL_FORMAT_WITH_PROTOCOL % (self.keycloak_host, self.ADMIN_REALM_URI)
