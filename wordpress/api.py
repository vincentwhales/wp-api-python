# -*- coding: utf-8 -*-

"""
Wordpress API Class
"""

__title__ = "wordpress-api"

from requests import request
from json import dumps as jsonencode
from wordpress.oauth import OAuth, OAuth_3Leg
from wordpress.transport import API_Requests_Wrapper


class API(object):
    """ API Class """

    def __init__(self, url, consumer_key, consumer_secret, **kwargs):

        self.requester = API_Requests_Wrapper(url=url, **kwargs)

        oauth_kwargs = dict(
            requester=self.requester,
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
        )

        if kwargs.get('oauth1a_3leg'):
            self.oauth1a_3leg = kwargs['oauth1a_3leg']
            oauth_kwargs['callback'] = kwargs['callback']
            oauth_kwargs['wp_user'] = kwargs['wp_user']
            oauth_kwargs['wp_pass'] = kwargs['wp_pass']
            self.oauth = OAuth_3Leg( **oauth_kwargs )
        else:
            self.oauth = OAuth( **oauth_kwargs )

    @property
    def timeout(self):
        return self.requester.timeout

    @property
    def query_string_auth(self):
        return self.requester.query_string_auth

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
        return self.oauth.consumer_key

    @property
    def consumer_secret(self):
        return self.oauth.consumer_secret

    @property
    def callback(self):
        return self.oauth.callback

    def __request(self, method, endpoint, data):
        """ Do requests """
        endpoint_url = self.requester.endpoint_url(endpoint)
        auth = None
        params = {}

        if self.requester.is_ssl is True and self.requester.query_string_auth is False:
            auth = (self.oauth.consumer_key, self.oauth.consumer_secret)
        elif self.requester.is_ssl is True and self.requester.query_string_auth is True:
            params = {
                "consumer_key": self.oauth.consumer_key,
                "consumer_secret": self.oauth.consumer_secret
            }
        else:
            endpoint_url = self.oauth.get_oauth_url(endpoint_url, method)

        if data is not None:
            data = jsonencode(data, ensure_ascii=False).encode('utf-8')

        return self.requester.request(
            method=method,
            url=endpoint_url,
            auth=auth,
            params=params,
            data=data
        )

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
