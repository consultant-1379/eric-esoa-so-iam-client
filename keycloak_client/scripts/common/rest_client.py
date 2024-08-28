"""The class to do rest call"""
import logging
import requests


#pylint: disable=too-few-public-methods, too-many-arguments, broad-except
class RestClient:
    """This class can be used to do rest call"""

    def __init__(self, auth_details):
        self.certificate_ca_path = auth_details.ca_cert_path

    def request(self, method_type, url, data=None, json=None, headers=None, params=None):
        """method to send request to the url provided"""
        response = None
        status_code = 503
        response_message = {}

        try:
            if method_type == 'POST':
                response = requests.post(url, data=data, json=json, headers=headers, params=params,
                                         verify=self.certificate_ca_path)
            elif method_type == 'GET':
                response = requests.get(url, data=data, headers=headers, params=params,
                                        verify=self.certificate_ca_path)
            elif method_type == 'PATCH':
                response = requests.patch(url, data=data, headers=headers, verify=self.certificate_ca_path)
            elif method_type == 'PUT':
                response = requests.put(url, data=data, json=json, headers=headers, verify=self.certificate_ca_path)
            elif method_type == 'DELETE':
                response = requests.delete(url, json=json, headers=headers, verify=self.certificate_ca_path)
            if response is not None:
                status_code = response.status_code
                if response.content:
                    response_message = response.json()
        except requests.exceptions.HTTPError as errh:
            response_message = errh.args[0]
            logging.error("Http Error: %s", response_message)
        except requests.exceptions.ConnectionError as errc:
            response_message = errc.args[0]
            logging.error("Error Connecting: %s", response_message)
        except Exception as exc:
            response_message = exc.args[0]
            logging.error("Exception Occurred :  %s", response_message)
        return response_message, status_code
