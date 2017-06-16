# -*- coding: utf-8 -*-

"""
Wordpress Requests Class
"""

__title__ = "wordpress-requests"

from requests import Request, Session
from json import dumps as jsonencode

try:
    from urllib.parse import urlencode, quote, unquote, parse_qsl, urlparse, urlunparse
    from urllib.parse import ParseResult as URLParseResult
except ImportError:
    from urllib import urlencode, quote, unquote
    from urlparse import parse_qsl, urlparse, urlunparse
    from urlparse import ParseResult as URLParseResult

from wordpress import __version__
from wordpress import __default_api_version__
from wordpress import __default_api__
from wordpress.helpers import SeqUtils, UrlUtils, StrUtils

class API_Requests_Wrapper(object):
    """ provides a wrapper for making requests that handles session info """
    def __init__(self, url, **kwargs):
        self.url = url
        self.api = kwargs.get("api", __default_api__)
        self.api_version = kwargs.get("version", __default_api_version__)
        self.timeout = kwargs.get("timeout", 5)
        self.verify_ssl = kwargs.get("verify_ssl", True)
        self.query_string_auth = kwargs.get("query_string_auth", False)
        self.session = Session()

    @property
    def is_ssl(self):
        return UrlUtils.is_ssl(self.url)

    @property
    def api_url(self):
        return UrlUtils.join_components([
            self.url,
            self.api
        ])

    @property
    def api_ver_url(self):
        return UrlUtils.join_components([
            self.url,
            self.api,
            self.api_version
        ])

    @property
    def api_ver_url_no_port(self):
        return UrlUtils.remove_port(self.api_ver_url)

    def endpoint_url(self, endpoint):
        endpoint = StrUtils.decapitate(endpoint, self.api_ver_url)
        endpoint = StrUtils.decapitate(endpoint, self.api_ver_url_no_port)
        endpoint = StrUtils.decapitate(endpoint, '/')
        return UrlUtils.join_components([
            self.url,
            self.api,
            self.api_version,
            endpoint
        ])

    def request(self, method, url, auth=None, params=None, data=None, **kwargs):
        headers = {
            "user-agent": "Wordpress API Client-Python/%s" % __version__,
            "accept": "application/json"
        }
        if data is not None:
            headers["content-type"] = "application/json;charset=utf-8"

        request_kwargs = dict(
            method=method,
            url=url,
            headers=headers,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        request_kwargs.update(kwargs)
        if auth is not None: request_kwargs['auth'] = auth
        if params is not None: request_kwargs['params'] = params
        if data is not None: request_kwargs['data'] = data
        return self.session.request(
            **request_kwargs
        )

    def get(self, *args, **kwargs):
        return self.request("GET", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self.request("POST", *args, **kwargs)
