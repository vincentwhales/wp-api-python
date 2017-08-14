# -*- coding: utf-8 -*-

"""
Wordpress API Class
"""

__title__ = "wordpress-api"

from requests import request
from json import dumps as jsonencode
from wordpress.auth import OAuth, OAuth_3Leg, BasicAuth
from wordpress.transport import API_Requests_Wrapper
from wordpress.helpers import UrlUtils

class API(object):
    """ API Class """

    def __init__(self, url, consumer_key, consumer_secret, **kwargs):

        self.requester = API_Requests_Wrapper(url=url, **kwargs)

        auth_kwargs = dict(
            requester=self.requester,
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
        )
        auth_kwargs.update(kwargs)

        if kwargs.get('basic_auth'):
            self.auth = BasicAuth(**auth_kwargs)
        else:
            if kwargs.get('oauth1a_3leg'):
                if 'callback' not in auth_kwargs:
                    raise TypeError("callback url not specified")
                self.auth = OAuth_3Leg( **auth_kwargs )
            else:
                self.auth = OAuth( **auth_kwargs )

    @property
    def url(self):
        return self.requester.url

    @property
    def timeout(self):
        return self.requester.timeout

    @property
    def namespace(self):
        return self.requester.api

    @property
    def version(self):
        return self.requester.api_version

    @property
    def verify_ssl(self):
        return self.requester.verify_ssl

    @property
    def is_ssl(self):
        return self.requester.is_ssl

    @property
    def consumer_key(self):
        return self.auth.consumer_key

    @property
    def consumer_secret(self):
        return self.auth.consumer_secret

    @property
    def callback(self):
        return self.auth.callback

    def __request(self, method, endpoint, data):
        """ Do requests """

        endpoint_url = self.requester.endpoint_url(endpoint)
        endpoint_url = self.auth.get_auth_url(endpoint_url, method)
        auth = self.auth.get_auth()

        if data is not None:
            data = jsonencode(data, ensure_ascii=False).encode('utf-8')

        response = self.requester.request(
            method=method,
            url=endpoint_url,
            auth=auth,
            data=data
        )

        assert \
            response.status_code in [200, 201], \
            "API call to %s returned \nCODE: %s\n%s \nHEADERS: %s" % (
                response.request.url,
                str(response.status_code),
                UrlUtils.beautify_response(response),
                str(response.headers)
            )

        return response

    def get(self, endpoint):
        """ Get requests """
        return self.__request("GET", endpoint, None)

    def post(self, endpoint, data):
        """ POST requests """
        return self.__request("POST", endpoint, data)

    def put(self, endpoint, data):
        """ PUT requests """
        return self.__request("PUT", endpoint, data)

    def delete(self, endpoint):
        """ DELETE requests """
        return self.__request("DELETE", endpoint, None)

    def options(self, endpoint):
        """ OPTIONS requests """
        return self.__request("OPTIONS", endpoint, None)
