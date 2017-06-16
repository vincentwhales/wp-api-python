# -*- coding: utf-8 -*-

"""
Wordpress OAuth1.0a Class
"""

__title__ = "wordpress-auth"

from time import time
from random import randint
from hmac import new as HMAC
from hashlib import sha1, sha256
from base64 import b64encode
import binascii
import webbrowser
import requests
from bs4 import BeautifulSoup

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


class Auth(object):
    """ Boilerplate for handling authentication stuff. """

    def __init__(self, requester):
        self.requester = requester

    @property
    def api_version(self):
        return self.requester.api_version

    @property
    def api_namespace(self):
        return self.requester.api

    @classmethod
    def normalize_params(cls, params):
        """ Normalize parameters. works with RFC 5849 logic. params is a list of key, value pairs """
        if isinstance(params, dict):
            params = params.items()
        params = \
            [(cls.normalize_str(key), cls.normalize_str(UrlUtils.get_value_like_as_php(value))) \
                for key, value in params]

        # print "NORMALIZED: %s\n" % str(params.keys())
        # resposne = urlencode(params)
        response = params
        # print "RESPONSE: %s\n" % str(resposne.split('&'))
        return response

    @classmethod
    def sorted_params(cls, params):
        """ Sort parameters. works with RFC 5849 logic. params is a list of key, value pairs """

        if isinstance(params, dict):
            params = params.items()

        # return sorted(params)
        ordered = []
        base_keys = sorted(set(k.split('[')[0] for k, v in params))
        keys_seen = []
        for base in base_keys:
            for key, value in params:
                if key == base or key.startswith(base + '['):
                    if key not in keys_seen:
                        ordered.append((key, value))
                        keys_seen.append(key)

        return ordered

    @classmethod
    def normalize_str(cls, string):
        return quote(string, '')

    @classmethod
    def flatten_params(cls, params):
        if isinstance(params, dict):
            params = params.items()
        params = cls.normalize_params(params)
        params = cls.sorted_params(params)
        return "&".join(["%s=%s"%(key, value) for key, value in params])

class BasicAuth(Auth):
    def __init__(self, requester, consumer_key, consumer_secret, **kwargs):
        super(BasicAuth, self).__init__(requester)
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret


class OAuth(Auth):
    oauth_version = '1.0'
    force_nonce = None
    force_timestamp = None

    """ API Class """

    def __init__(self, requester, consumer_key, consumer_secret, **kwargs):
        super(OAuth, self).__init__(requester)
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.signature_method = kwargs.get('signature_method', 'HMAC-SHA1')
        self.force_timestamp = kwargs.get('force_timestamp')
        self.force_nonce = kwargs.get('force_nonce')

    def get_sign_key(self, consumer_secret, token_secret=None):
        "gets consumer_secret and turns it into a string suitable for signing"
        if not consumer_secret:
            raise UserWarning("no consumer_secret provided")
        token_secret = str(token_secret) if token_secret else ''
        if self.api_namespace == 'wc-api' \
        and self.api_version in ["v1", "v2"]:
            # special conditions for wc-api v1-2
            key = consumer_secret
        else:
            key = "%s&%s" % (consumer_secret, token_secret)
        return key

    def add_params_sign(self, method, url, params, sign_key=None):
        """ Adds the params to a given url, signs the url with sign_key if provided,
        otherwise generates sign_key automatically and returns a signed url """
        if isinstance(params, dict):
            params = params.items()

        urlparse_result = urlparse(url)

        if urlparse_result.query:
            params += parse_qsl(urlparse_result.query)
            # for key, value in parse_qsl(urlparse_result.query):
            #     params += [(key, value)]

        params = self.sorted_params(params)

        params_without_signature = []
        for key, value in params:
            if key != "oauth_signature":
                params_without_signature.append((key, value))

        signature = self.generate_oauth_signature(method, params_without_signature, url, sign_key)
        params = params_without_signature + [("oauth_signature", signature)]

        query_string = self.flatten_params(params)

        return UrlUtils.substitute_query(url, query_string)

    def get_params(self):
        return [
            ("oauth_consumer_key", self.consumer_key),
            ("oauth_nonce", self.generate_nonce()),
            ("oauth_signature_method", self.signature_method),
            ("oauth_timestamp", self.generate_timestamp()),
        ]

    def get_oauth_url(self, endpoint_url, method):
        """ Returns the URL with OAuth params """
        params = self.get_params()

        return self.add_params_sign(method, endpoint_url, params)

    @classmethod
    def get_signature_base_string(cls, method, params, url):
        base_request_uri = quote(UrlUtils.substitute_query(url), "")
        query_string = quote( cls.flatten_params(params), '~')
        return "&".join([method, base_request_uri, query_string])

    def generate_oauth_signature(self, method, params, url, key=None):
        """ Generate OAuth Signature """

        string_to_sign = self.get_signature_base_string(method, params, url)

        if key is None:
            key = self.get_sign_key(self.consumer_secret)

        if self.signature_method == 'HMAC-SHA1':
            hmac_mod = sha1
        elif self.signature_method == 'HMAC-SHA256':
            hmac_mod = sha256
        else:
            raise UserWarning("Unknown signature_method")

        # print "\nstring_to_sign: %s" % repr(string_to_sign)
        # print "\nkey: %s" % repr(key)
        sig = HMAC(key, string_to_sign, hmac_mod)
        sig_b64 = binascii.b2a_base64(sig.digest())[:-1]
        # print "\nsig_b64: %s" % sig_b64
        return sig_b64

    @classmethod
    def generate_timestamp(cls):
        """ Generate timestamp """
        if cls.force_timestamp is not None:
            return cls.force_timestamp
        return int(time())

    @classmethod
    def generate_nonce(cls):
        """ Generate nonce number """
        if cls.force_nonce is not None:
            return cls.force_nonce
        nonce = ''.join([str(randint(0, 9)) for i in range(8)])
        return HMAC(
            nonce.encode(),
            "secret".encode(),
            sha1
        ).hexdigest()

class OAuth_3Leg(OAuth):
    """ Provides 3 legged OAuth1a, mostly based off this: http://www.lexev.org/en/2015/oauth-step-step/"""

    # oauth_version = '1.0A'

    def __init__(self, requester, consumer_key, consumer_secret, callback, **kwargs):
        super(OAuth_3Leg, self).__init__(requester, consumer_key, consumer_secret, **kwargs)
        self.callback = callback
        self.wp_user = kwargs.get('wp_user')
        self.wp_pass = kwargs.get('wp_pass')
        self._authentication = None
        self._request_token = None
        self.request_token_secret = None
        self._oauth_verifier = None
        self._access_token = None
        self.access_token_secret = None

    @property
    def authentication(self):
        """ This is an object holding the authentication links discovered from the API
        automatically generated if accessed before generated """
        if not self._authentication:
            self._authentication = self.discover_auth()
        return self._authentication

    @property
    def oauth_verifier(self):
        """ This is the verifier string used in authentication
        automatically generated if accessed before generated """
        if not self._oauth_verifier:
            self._oauth_verifier = self.get_verifier()
        return self._oauth_verifier

    @property
    def request_token(self):
        """ This is the oauth_token used in requesting an access_token
        automatically generated if accessed before generated """
        if not self._request_token:
            self.get_request_token()
        return self._request_token

    @property
    def access_token(self):
        """ This is the oauth_token used to sign requests to protected resources
        automatically generated if accessed before generated """
        if not self._access_token:
            self.get_access_token()
        return self._access_token

    # def get_sign_key(self, consumer_secret, oauth_token_secret=None):
    #     "gets consumer_secret and oauth_token_secret and turns it into a string suitable for signing"
    #     if not oauth_token_secret:
    #         key = super(OAuth_3Leg, self).get_sign_key(consumer_secret)
    #     else:
    #         oauth_token_secret = str(oauth_token_secret) if oauth_token_secret else ''
    #         consumer_secret = str(consumer_secret) if consumer_secret else ''
    #         # oauth_token_secret has been specified
    #         if not consumer_secret:
    #             key = str(oauth_token_secret)
    #         else:
    #             key = "&".join([consumer_secret, oauth_token_secret])
    #     return key

    def get_oauth_url(self, endpoint_url, method):
        """ Returns the URL with OAuth params """
        assert self.access_token, "need a valid access token for this step"

        params = self.get_params()
        params += [
            ('oauth_callback', self.callback),
            ('oauth_token', self.access_token)
        ]

        sign_key = self.get_sign_key(self.consumer_secret, self.access_token_secret)

        return self.add_params_sign(method, endpoint_url, params, sign_key)

        # params = OrderedDict()
        # params["oauth_consumer_key"] = self.consumer_key
        # params["oauth_timestamp"] = self.generate_timestamp()
        # params["oauth_nonce"] = self.generate_nonce()
        # params["oauth_signature_method"] = self.signature_method
        # params["oauth_token"] = self.access_token
        #
        # sign_key = self.get_sign_key(self.consumer_secret, self.access_token_secret)
        #
        # print "signing with key: %s" % sign_key
        #
        # return self.add_params_sign(method, endpoint_url, params, sign_key)

    # def get_params(self, get_access_token=False):
    #     params = super(OAuth_3Leg, self).get_params()
    #     if get_access_token:
    #         params.append(('oauth_token', self.access_token))
    #     return params

    def discover_auth(self):
        """ Discovers the location of authentication resourcers from the API"""
        discovery_url = self.requester.api_url

        response = self.requester.request('GET', discovery_url)
        response_json = response.json()

        assert \
            response_json['authentication'], \
            "resopnse should include location of authentication resources, resopnse: %s" \
                % UrlUtils.beautify_response(response)

        self._authentication = response_json['authentication']

        return self._authentication

    def get_request_token(self):
        """ Uses the request authentication link to get an oauth_token for requesting an access token """
        assert self.consumer_key, "need a valid consumer_key for this step"

        params = self.get_params()
        params += [
            ('oauth_callback', self.callback)
        ]
        # params = OrderedDict()
        # params["oauth_consumer_key"] = self.consumer_key
        # params["oauth_timestamp"] = self.generate_timestamp()
        # params["oauth_nonce"] = self.generate_nonce()
        # params["oauth_signature_method"] = self.signature_method
        # params["oauth_callback"] = self.callback
        # params["oauth_version"] = self.oauth_version

        request_token_url = self.authentication['oauth1']['request']
        request_token_url = self.add_params_sign("GET", request_token_url, params)

        response = self.requester.get(request_token_url)
        resp_content = parse_qs(response.text)

        try:
            self._request_token = resp_content['oauth_token'][0]
            self.request_token_secret = resp_content['oauth_token_secret'][0]
        except:
            raise UserWarning("Could not parse request_token or request_token_secret in response from %s : %s" \
                % (repr(response.request.url), UrlUtils.beautify_response(response)))

        return self._request_token, self.request_token_secret

    def get_form_info(self, response, form_id):
        """ parses a form specified by a given form_id in the response,
        extracts form data and form action """

        assert response.status_code is 200
        response_soup = BeautifulSoup(response.text, "lxml")
        form_soup = response_soup.select_one('form#%s' % form_id)
        assert \
            form_soup, "unable to find form with id=%s in %s " \
            % (form_id, (response_soup.prettify()).encode('ascii', errors='backslashreplace'))
        # print "login form: \n", form_soup.prettify()

        action = form_soup.get('action')
        assert \
            action, "action should be provided by form: %s" \
            % (form_soup.prettify()).encode('ascii', errors='backslashreplace')

        form_data = OrderedDict()
        for input_soup in form_soup.select('input') + form_soup.select('button'):
            # print "input, class:%5s, id=%5s, name=%5s, value=%s" % (
            #     input_soup.get('class'),
            #     input_soup.get('id'),
            #     input_soup.get('name'),
            #     input_soup.get('value')
            # )
            name = input_soup.get('name')
            if not name:
                continue
            value = input_soup.get('value')
            if name not in form_data:
                form_data[name] = []
            form_data[name].append(value)

        # print "form data: %s" % str(form_data)
        return action, form_data

    def get_verifier(self, request_token=None, wp_user=None, wp_pass=None):
        """ pretends to be a browser, uses the authorize auth link, submits user creds to WP login form to get
        verifier string from access token """

        if request_token is None:
            request_token = self.request_token
        assert request_token, "need a valid request_token for this step"

        if wp_user is None and self.wp_user:
            wp_user = self.wp_user
        if wp_pass is None and self.wp_pass:
            wp_pass = self.wp_pass

        authorize_url = self.authentication['oauth1']['authorize']
        authorize_url = UrlUtils.add_query(authorize_url, 'oauth_token', request_token)

        # we're using a different session from the usual API calls
        # (I think the headers are incompatible?)

        # self.requester.get(authorize_url)
        authorize_session = requests.Session()

        login_form_response = authorize_session.get(authorize_url)
        try:
            login_form_action, login_form_data = self.get_form_info(login_form_response, 'loginform')
        except AssertionError, e:
            #try to parse error
            login_form_soup = BeautifulSoup(login_form_response.text, 'lxml')
            error = login_form_soup.select_one('div#login_error')
            if error and "invalid token" in error.string.lower():
                raise UserWarning("Invalid token: %s" % repr(request_token))
            else:
                raise UserWarning(
                    "could not parse login form. Site is misbehaving. Original error: %s " \
                    % str(e)
                )

        for name, values in login_form_data.items():
            if name == 'log':
                login_form_data[name] = wp_user
            elif name == 'pwd':
                login_form_data[name] = wp_pass
            else:
                login_form_data[name] = values[0]

        assert 'log' in login_form_data, 'input for user login did not appear on form'
        assert 'pwd' in login_form_data, 'input for user password did not appear on form'

        # print "submitting login form to %s : %s" % (login_form_action, str(login_form_data))

        confirmation_response = authorize_session.post(login_form_action, data=login_form_data, allow_redirects=True)
        try:
            authorize_form_action, authorize_form_data = self.get_form_info(confirmation_response, 'oauth1_authorize_form')
        except AssertionError, e:
            #try to parse error
            # print "STATUS_CODE: %s" % str(confirmation_response.status_code)
            if confirmation_response.status_code != 200:
                raise UserWarning("Response was not a 200, it was a %s. original error: %s" \
                    % (str(confirmation_response.status_code)), str(e))
            # print "HEADERS: %s" % str(confirmation_response.headers)
            confirmation_soup = BeautifulSoup(confirmation_response.text, 'lxml')
            error = confirmation_soup.select_one('div#login_error')
            # print "ERROR: %s" % repr(error)
            if error and "invalid token" in error.string.lower():
                raise UserWarning("Invalid token: %s" % repr(request_token))
            else:
                raise UserWarning(
                    "could not parse login form. Site is misbehaving. Original error: %s " \
                    % str(e)
                )

        for name, values in authorize_form_data.items():
            if name == 'wp-submit':
                assert \
                    'authorize' in values, \
                    "apparently no authorize button, only %s" % str(values)
                authorize_form_data[name] = 'authorize'
            else:
                authorize_form_data[name] = values[0]

        assert 'wp-submit' in login_form_data, 'authorize button did not appear on form'

        final_response = authorize_session.post(authorize_form_action, data=authorize_form_data, allow_redirects=False)

        assert \
            final_response.status_code == 302, \
            "was not redirected by authorize screen, was %d instead. something went wrong" \
                % final_response.status_code
        assert 'location' in final_response.headers, "redirect did not provide redirect location in header"

        final_location = final_response.headers['location']

        # At this point we can chose to follow the redirect if the user wants,
        # or just parse the verifier out of the redirect url.
        # open to suggestions if anyone has any :)

        final_location_queries = parse_qs(urlparse(final_location).query)

        assert \
            'oauth_verifier' in final_location_queries, \
            "oauth verifier not provided in final redirect: %s" % final_location

        self._oauth_verifier = final_location_queries['oauth_verifier'][0]
        return self._oauth_verifier

    def get_access_token(self, oauth_verifier=None):
        """ Uses the access authentication link to get an access token """

        if oauth_verifier is None:
            oauth_verifier = self.oauth_verifier
        assert oauth_verifier, "Need an oauth verifier to perform this step"
        assert self.request_token, "Need a valid request_token to perform this step"

        params = self.get_params()
        params += [
            ('oauth_token', self.request_token),
            ('oauth_verifier', self.oauth_verifier)
        ]

        # params = OrderedDict()
        # params["oauth_consumer_key"] = self.consumer_key
        # params['oauth_token'] = self.request_token
        # params["oauth_timestamp"] = self.generate_timestamp()
        # params["oauth_nonce"] = self.generate_nonce()
        # params["oauth_signature_method"] = self.signature_method
        # params['oauth_verifier'] = oauth_verifier
        # params["oauth_callback"] = self.callback

        sign_key = self.get_sign_key(self.consumer_secret, self.request_token_secret)
        # sign_key = self.get_sign_key(None, self.request_token_secret)
        # print "request_token_secret:", self.request_token_secret

        # print "SIGNING WITH KEY:", repr(sign_key)

        access_token_url = self.authentication['oauth1']['access']
        access_token_url = self.add_params_sign("POST", access_token_url, params, sign_key)

        access_response = self.requester.post(access_token_url)

        assert \
            access_response.status_code == 200, \
            "Access request did not return 200, returned %s. HTML: %s" % (
                access_response.status_code,
                UrlUtils.beautify_response(access_response)
            )

        #
        access_response_queries = parse_qs(access_response.text)

        try:
            self._access_token = access_response_queries['oauth_token'][0]
            self.access_token_secret = access_response_queries['oauth_token_secret'][0]
        except:
            raise UserWarning("Could not parse access_token or access_token_secret in response from %s : %s" \
                % (repr(access_response.request.url), UrlUtils.beautify_response(access_response)))

        return self._access_token, self.access_token_secret
