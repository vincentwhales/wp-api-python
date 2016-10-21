# -*- coding: utf-8 -*-

"""
Wordpress OAuth1.0a Class
"""

__title__ = "wordpress-oauth"

from time import time
from random import randint
from hmac import new as HMAC
from hashlib import sha1, sha256
from base64 import b64encode
import binascii
import webbrowser


try:
    from urllib.parse import urlencode, quote, unquote, parse_qs, parse_qsl, urlparse, urlunparse
    from urllib.parse import ParseResult as URLParseResult
except ImportError:
    from urllib import urlencode, quote, unquote
    from urlparse import parse_qs, parse_qsl, urlparse, urlunparse
    from urlparse import ParseResult as URLParseResult

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

from wordpress.helpers import UrlUtils

class OAuth(object):
    oauth_version = '1.0'

    """ API Class """

    def __init__(self, requester, consumer_key, consumer_secret, **kwargs):
        self.requester = requester
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.signature_method = kwargs.get('signature_method', 'HMAC-SHA1')

    @property
    def api_version(self):
        return self.requester.api_version

    @property
    def api_namespace(self):
        return self.requester.api

    def add_params_sign(self, method, url, params):
        """ Adds the params to a given url, signs the url with secret and returns a signed url """
        urlparse_result = urlparse(url)

        if urlparse_result.query:
            for key, value in parse_qsl(urlparse_result.query):
                params[key] = value

        params["oauth_signature"] = self.generate_oauth_signature(method, params, UrlUtils.substitute_query(url))

        query_string = urlencode(params)

        return UrlUtils.substitute_query(url, query_string)

    def get_oauth_url(self, endpoint_url, method):
        """ Returns the URL with OAuth params """
        params = OrderedDict()
        params["oauth_consumer_key"] = self.consumer_key
        params["oauth_timestamp"] = self.generate_timestamp()
        params["oauth_nonce"] = self.generate_nonce()
        params["oauth_signature_method"] = self.signature_method

        return self.add_params_sign(method, endpoint_url, params)

    def generate_oauth_signature(self, method, params, url):
        """ Generate OAuth Signature """
        if "oauth_signature" in params.keys():
            del params["oauth_signature"]

        base_request_uri = quote(url, "")
        query_string = quote( self.normalize_params(params), safe='~')
        string_to_sign = "&".join([method, base_request_uri, query_string])

        if self.api_namespace == 'wc-api' \
        and self.api_version in ["v1", "v2"]:
            key = self.consumer_secret
        else:
            if hasattr(self, 'oauth_token_secret'):
                oauth_token_secret = getattr(self, 'oauth_token_secret')
            else:
                oauth_token_secret = ''
            key = "&".join([self.consumer_secret, oauth_token_secret])

        if self.signature_method == 'HMAC-SHA1':
            hmac_mod = sha1
        elif self.signature_method == 'HMAC-SHA256':
            hmac_mod = sha256
        else:
            raise UserWarning("Unknown signature_method")

        sig = HMAC(key, string_to_sign, hmac_mod)
        sig_b64 = binascii.b2a_base64(sig.digest())[:-1]
        # print "string_to_sign: ", string_to_sign
        # print "key: ", key
        # print "sig_b64: ", sig_b64
        return sig_b64

    @classmethod
    def sorted_params(cls, params):
        ordered = OrderedDict()
        base_keys = sorted(set(k.split('[')[0] for k in params.keys()))

        for base in base_keys:
            for key in params.keys():
                if key == base or key.startswith(base + '['):
                    ordered[key] = params[key]

        return ordered

    @classmethod
    def normalize_params(cls, params):
        """ Normalize parameters """
        params = cls.sorted_params(params)
        params = OrderedDict(
            [(key, UrlUtils.get_value_like_as_php(value)) for key, value in params.items()]
        )
        return urlencode(params)

    @staticmethod
    def generate_timestamp():
        """ Generate timestamp """
        return int(time())

    @staticmethod
    def generate_nonce():
        """ Generate nonce number """
        nonce = ''.join([str(randint(0, 9)) for i in range(8)])
        return HMAC(
            nonce.encode(),
            "secret".encode(),
            sha1
        ).hexdigest()

class OAuth_3Leg(OAuth):
    """ Provides 3 legged OAuth1a, mostly based off this: http://www.lexev.org/en/2015/oauth-step-step/"""

    oauth_version = '1.0A'

    def __init__(self, requester, consumer_key, consumer_secret, callback, **kwargs):
        super(OAuth_3Leg, self).__init__(requester, consumer_key, consumer_secret, **kwargs)
        self.callback = callback
        self._authentication = None
        self.request_token = None
        self.request_token_secret = None
        self.access_token = None
        self.access_token_secret = None

    @property
    def authentication(self):
        if not self._authentication:
            self._authentication = self.discover_auth()
        return self._authentication

    def discover_auth(self):
        """ Discovers the location of authentication resourcers from the API"""
        discovery_url = self.requester.api_url

        response = self.requester.request('GET', discovery_url)
        response_json = response.json()

        assert \
            response_json['authentication'], \
            "resopnse should include location of authentication resources, resopnse: %s" % response.text()

        return response_json['authentication']

    def get_request_token(self):
        params = OrderedDict()
        params["oauth_consumer_key"] = self.consumer_key
        params["oauth_timestamp"] = self.generate_timestamp()
        params["oauth_nonce"] = self.generate_nonce()
        params["oauth_signature_method"] = self.signature_method
        params["oauth_callback"] = self.callback
        # params["oauth_version"] = self.oauth_version

        request_token_url = self.authentication['oauth1']['request']
        request_token_url = self.add_params_sign("GET", request_token_url, params)

        response = self.requester.request("GET", request_token_url)
        resp_content = parse_qs(response.text)

        try:
            self.request_token = resp_content['oauth_token']
            self.request_token_secret = resp_content['oauth_token_secret']
        except:
            raise UserWarning("Could not parse request_token or request_token_secret in response from %s : %s" \
                % (repr(response.request.url), repr(response.text)))

        return self.request_token, self.request_token_secret
    # 
    # def get_user_confirmation(self):
    #     authorize_url = self.authentication['oauth1']['authorize']
    #     authorize_url = UrlUtils.add_query(authorize_url, 'oauth_token', self.request_token)
    #
    #     return self.requester.request("GET", authorize_url)
