""" API Tests """
import functools
import logging
import pdb
import random
import sys
import traceback
import unittest
import platform
from collections import OrderedDict
from copy import copy
from time import time
from tempfile import mkstemp

import wordpress
from wordpress import __default_api__, __default_api_version__, auth
from wordpress.api import API
from wordpress.auth import OAuth, Auth
from wordpress.helpers import SeqUtils, StrUtils, UrlUtils
from wordpress.transport import API_Requests_Wrapper

from httmock import HTTMock, all_requests, urlmatch

try:
    from urllib.parse import urlencode, quote, unquote, parse_qs, parse_qsl, urlparse, urlunparse
    from urllib.parse import ParseResult as URLParseResult
except ImportError:
    from urllib import urlencode, quote, unquote
    from urlparse import parse_qs, parse_qsl, urlparse, urlunparse
    from urlparse import ParseResult as URLParseResult

def debug_on(*exceptions):
    if not exceptions:
        exceptions = (AssertionError, )
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            prev_root = copy(logging.root)
            try:
                logging.basicConfig(level=logging.DEBUG)
                return f(*args, **kwargs)
            except exceptions:
                info = sys.exc_info()
                traceback.print_exception(*info)
                pdb.post_mortem(info[2])
            finally:
                logging.root = prev_root
        return wrapper
    return decorator

CURRENT_TIMESTAMP = int(time())
SHITTY_NONCE = ""

class WordpressTestCase(unittest.TestCase):
    """Test case for the client methods."""

    def setUp(self):
        self.consumer_key = "ck_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        self.consumer_secret = "cs_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        self.api = wordpress.API(
            url="http://woo.test",
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret
        )

    def test_api(self):
        """ Test default API """
        api = wordpress.API(
            url="https://woo.test",
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret
        )

        self.assertEqual(api.namespace, __default_api__)

    def test_version(self):
        """ Test default version """
        api = wordpress.API(
            url="https://woo.test",
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret
        )

        self.assertEqual(api.version, __default_api_version__)

    def test_non_ssl(self):
        """ Test non-ssl """
        api = wordpress.API(
            url="http://woo.test",
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret
        )
        self.assertFalse(api.is_ssl)

    def test_with_ssl(self):
        """ Test non-ssl """
        api = wordpress.API(
            url="https://woo.test",
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret
        )
        self.assertTrue(api.is_ssl, True)

    def test_with_timeout(self):
        """ Test non-ssl """
        api = wordpress.API(
            url="https://woo.test",
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret,
            timeout=10,
        )
        self.assertEqual(api.timeout, 10)

        @all_requests
        def woo_test_mock(*args, **kwargs):
            """ URL Mock """
            return {'status_code': 200,
                    'content': 'OK'}

        with HTTMock(woo_test_mock):
            # call requests
            status = api.get("products").status_code
        self.assertEqual(status, 200)

    def test_get(self):
        """ Test GET requests """
        @all_requests
        def woo_test_mock(*args, **kwargs):
            """ URL Mock """
            return {'status_code': 200,
                    'content': 'OK'}

        with HTTMock(woo_test_mock):
            # call requests
            status = self.api.get("products").status_code
        self.assertEqual(status, 200)

    def test_post(self):
        """ Test POST requests """
        @all_requests
        def woo_test_mock(*args, **kwargs):
            """ URL Mock """
            return {'status_code': 201,
                    'content': 'OK'}

        with HTTMock(woo_test_mock):
            # call requests
            status = self.api.post("products", {}).status_code
        self.assertEqual(status, 201)

    def test_put(self):
        """ Test PUT requests """
        @all_requests
        def woo_test_mock(*args, **kwargs):
            """ URL Mock """
            return {'status_code': 200,
                    'content': 'OK'}

        with HTTMock(woo_test_mock):
            # call requests
            status = self.api.put("products", {}).status_code
        self.assertEqual(status, 200)

    def test_delete(self):
        """ Test DELETE requests """
        @all_requests
        def woo_test_mock(*args, **kwargs):
            """ URL Mock """
            return {'status_code': 200,
                    'content': 'OK'}

        with HTTMock(woo_test_mock):
            # call requests
            status = self.api.delete("products").status_code
        self.assertEqual(status, 200)

    # @unittest.skip("going by RRC 5849 sorting instead")
    def test_oauth_sorted_params(self):
        """ Test order of parameters for OAuth signature """
        def check_sorted(keys, expected):
            params = auth.OrderedDict()
            for key in keys:
                params[key] = ''

            params = UrlUtils.sorted_params(params)
            ordered = [key for key, value in params]
            self.assertEqual(ordered, expected)

        check_sorted(['a', 'b'], ['a', 'b'])
        check_sorted(['b', 'a'], ['a', 'b'])
        check_sorted(['a', 'b[a]', 'b[b]', 'b[c]', 'c'], ['a', 'b[a]', 'b[b]', 'b[c]', 'c'])
        check_sorted(['a', 'b[c]', 'b[a]', 'b[b]', 'c'], ['a', 'b[c]', 'b[a]', 'b[b]', 'c'])
        check_sorted(['d', 'b[c]', 'b[a]', 'b[b]', 'c'], ['b[c]', 'b[a]', 'b[b]', 'c', 'd'])
        check_sorted(['a1', 'b[c]', 'b[a]', 'b[b]', 'a2'], ['a1', 'a2', 'b[c]', 'b[a]', 'b[b]'])

class HelperTestcase(unittest.TestCase):
    def setUp(self):
        self.test_url = "http://ich.local:8888/woocommerce/wc-api/v3/products?filter%5Blimit%5D=2&oauth_consumer_key=ck_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&oauth_nonce=c4f2920b0213c43f2e8d3d3333168ec4a22222d1&oauth_signature=3ibOjMuhj6JGnI43BQZGniigHh8%3D&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1481601370&page=2"


    def test_url_is_ssl(self):
        self.assertTrue(UrlUtils.is_ssl("https://woo.test:8888"))
        self.assertFalse(UrlUtils.is_ssl("http://woo.test:8888"))

    def test_url_substitute_query(self):
        self.assertEqual(
            UrlUtils.substitute_query("https://woo.test:8888/sdf?param=value", "newparam=newvalue"),
            "https://woo.test:8888/sdf?newparam=newvalue"
        )
        self.assertEqual(
            UrlUtils.substitute_query("https://woo.test:8888/sdf?param=value"),
            "https://woo.test:8888/sdf"
        )
        self.assertEqual(
            UrlUtils.substitute_query(
                "https://woo.test:8888/sdf?param=value",
                "newparam=newvalue&othernewparam=othernewvalue"
            ),
            "https://woo.test:8888/sdf?newparam=newvalue&othernewparam=othernewvalue"
        )
        self.assertEqual(
            UrlUtils.substitute_query(
                "https://woo.test:8888/sdf?param=value",
                "newparam=newvalue&othernewparam=othernewvalue"
            ),
            "https://woo.test:8888/sdf?newparam=newvalue&othernewparam=othernewvalue"
        )

    def test_url_add_query(self):
        self.assertEqual(
            "https://woo.test:8888/sdf?param=value&newparam=newvalue",
            UrlUtils.add_query("https://woo.test:8888/sdf?param=value", 'newparam', 'newvalue')
        )

    def test_url_join_components(self):
        self.assertEqual(
            'https://woo.test:8888/wp-json',
            UrlUtils.join_components(['https://woo.test:8888/', '', 'wp-json'])
        )
        self.assertEqual(
            'https://woo.test:8888/wp-json/wp/v2',
            UrlUtils.join_components(['https://woo.test:8888/', 'wp-json', 'wp/v2'])
        )

    def test_url_get_php_value(self):
        self.assertEqual(
            '1',
            UrlUtils.get_value_like_as_php(True)
        )
        self.assertEqual(
            '',
            UrlUtils.get_value_like_as_php(False)
        )
        self.assertEqual(
            'asd',
            UrlUtils.get_value_like_as_php('asd')
        )
        self.assertEqual(
            '1',
            UrlUtils.get_value_like_as_php(1)
        )
        self.assertEqual(
            '1',
            UrlUtils.get_value_like_as_php(1.0)
        )
        self.assertEqual(
            '1.1',
            UrlUtils.get_value_like_as_php(1.1)
        )

    def test_url_get_query_dict_singular(self):
        result = UrlUtils.get_query_dict_singular(self.test_url)
        self.assertEquals(
            result,
            {
                'filter[limit]': '2',
                'oauth_nonce': 'c4f2920b0213c43f2e8d3d3333168ec4a22222d1',
                'oauth_timestamp': '1481601370',
                'oauth_consumer_key': 'ck_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
                'oauth_signature_method': 'HMAC-SHA1',
                'oauth_signature': '3ibOjMuhj6JGnI43BQZGniigHh8=',
                'page': '2'
            }
        )

    def test_url_get_query_singular(self):
        result = UrlUtils.get_query_singular(self.test_url, 'oauth_consumer_key')
        self.assertEqual(
            result,
            'ck_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
        )
        result = UrlUtils.get_query_singular(self.test_url, 'filter[limit]')
        self.assertEqual(
            str(result),
            str(2)
        )

    def test_url_set_query_singular(self):
        result = UrlUtils.set_query_singular(self.test_url, 'filter[limit]', 3)
        expected = "http://ich.local:8888/woocommerce/wc-api/v3/products?filter%5Blimit%5D=3&oauth_consumer_key=ck_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&oauth_nonce=c4f2920b0213c43f2e8d3d3333168ec4a22222d1&oauth_signature=3ibOjMuhj6JGnI43BQZGniigHh8%3D&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1481601370&page=2"
        self.assertEqual(result, expected)

    def test_url_del_query_singular(self):
        result = UrlUtils.del_query_singular(self.test_url, 'filter[limit]')
        expected = "http://ich.local:8888/woocommerce/wc-api/v3/products?oauth_consumer_key=ck_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&oauth_nonce=c4f2920b0213c43f2e8d3d3333168ec4a22222d1&oauth_signature=3ibOjMuhj6JGnI43BQZGniigHh8%3D&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1481601370&page=2"
        self.assertEqual(result, expected)

    def test_url_remove_default_port(self):
        self.assertEqual(
            UrlUtils.remove_default_port('http://www.gooogle.com:80/'),
            'http://www.gooogle.com/'
        )
        self.assertEqual(
            UrlUtils.remove_default_port('http://www.gooogle.com:18080/'),
            'http://www.gooogle.com:18080/'
        )

    def test_seq_filter_true(self):
        self.assertEquals(
            ['a', 'b', 'c', 'd'],
            SeqUtils.filter_true([None, 'a', False, 'b', 'c','d'])
        )

    def test_str_remove_tail(self):
        self.assertEqual(
            'sdf',
            StrUtils.remove_tail('sdf/','/')
        )

    def test_str_remove_head(self):
        self.assertEqual(
            'sdf',
            StrUtils.remove_head('/sdf', '/')
        )

        self.assertEqual(
            'sdf',
            StrUtils.decapitate('sdf', '/')
        )

class TransportTestcases(unittest.TestCase):
    def setUp(self):
        self.requester = API_Requests_Wrapper(
            url='https://woo.test:8888/',
            api='wp-json',
            api_version='wp/v2'
        )

    def test_api_url(self):
        self.assertEqual(
            'https://woo.test:8888/wp-json',
            self.requester.api_url
        )

    def test_endpoint_url(self):
        self.assertEqual(
            'https://woo.test:8888/wp-json/wp/v2/posts',
            self.requester.endpoint_url('posts')
        )

    def test_request(self):

        @all_requests
        def woo_test_mock(*args, **kwargs):
            """ URL Mock """
            return {'status_code': 200,
                    'content': 'OK'}

        with HTTMock(woo_test_mock):
            # call requests
            response = self.requester.request("GET", "https://woo.test:8888/wp-json/wp/v2/posts")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request.url, 'https://woo.test:8888/wp-json/wp/v2/posts')

class BasicAuthTestcases(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://localhost:8888/wp-api/"
        self.api_name = 'wc-api'
        self.api_ver = 'v3'
        self.endpoint = 'products/26'
        self.signature_method = "HMAC-SHA1"

        self.consumer_key = "ck_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        self.consumer_secret = "cs_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        self.api_params = dict(
            url=self.base_url,
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret,
            basic_auth=True,
            api=self.api_name,
            version=self.api_ver,
            query_string_auth=False,
        )

    def test_endpoint_url(self):
        api = API(
            **self.api_params
        )
        endpoint_url = api.requester.endpoint_url(self.endpoint)
        endpoint_url = api.auth.get_auth_url(endpoint_url, 'GET')
        self.assertEqual(
            endpoint_url,
            UrlUtils.join_components([
                self.base_url, self.api_name, self.api_ver, self.endpoint
            ])
        )

    def test_query_string_endpoint_url(self):
        query_string_api_params = dict(**self.api_params)
        query_string_api_params.update(dict(query_string_auth=True))
        api = API(
            **query_string_api_params
        )
        endpoint_url = api.requester.endpoint_url(self.endpoint)
        endpoint_url = api.auth.get_auth_url(endpoint_url, 'GET')
        expected_endpoint_url = '%s?consumer_key=%s&consumer_secret=%s' % (self.endpoint, self.consumer_key, self.consumer_secret)
        expected_endpoint_url = UrlUtils.join_components([self.base_url, self.api_name, self.api_ver, expected_endpoint_url])
        self.assertEqual(
            endpoint_url,
            expected_endpoint_url
        )
        endpoint_url = api.requester.endpoint_url(self.endpoint)
        endpoint_url = api.auth.get_auth_url(endpoint_url, 'GET')


class OAuthTestcases(unittest.TestCase):


    def setUp(self):
        self.base_url = "http://localhost:8888/wordpress/"
        self.api_name = 'wc-api'
        self.api_ver = 'v3'
        self.endpoint = 'products/99'
        self.signature_method = "HMAC-SHA1"
        self.consumer_key = "ck_681c2be361e415519dce4b65ee981682cda78bc6"
        self.consumer_secret = "cs_b11f652c39a0afd3752fc7bb0c56d60d58da5877"

        self.wcapi = API(
            url=self.base_url,
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret,
            api=self.api_name,
            version=self.api_ver,
            signature_method=self.signature_method
        )

        # RFC EXAMPLE 1 DATA: https://tools.ietf.org/html/draft-hammer-oauth-10#section-1.2

        self.rfc1_api_url = 'https://photos.example.net/'
        self.rfc1_consumer_key = 'dpf43f3p2l4k3l03'
        self.rfc1_consumer_secret = 'kd94hf93k423kf44'
        self.rfc1_oauth_token = 'hh5s93j4hdidpola'
        self.rfc1_signature_method = 'HMAC-SHA1'
        self.rfc1_callback = 'http://printer.example.com/ready'
        self.rfc1_api = API(
            url=self.rfc1_api_url,
            consumer_key=self.rfc1_consumer_key,
            consumer_secret=self.rfc1_consumer_secret,
            api='',
            version='',
            callback=self.rfc1_callback,
            wp_user='',
            wp_pass='',
            oauth1a_3leg=True
        )
        self.rfc1_request_method = 'POST'
        self.rfc1_request_target_url = 'https://photos.example.net/initiate'
        self.rfc1_request_timestamp = '137131200'
        self.rfc1_request_nonce = 'wIjqoS'
        self.rfc1_request_params = [
            ('oauth_consumer_key', self.rfc1_consumer_key),
            ('oauth_signature_method', self.rfc1_signature_method),
            ('oauth_timestamp', self.rfc1_request_timestamp),
            ('oauth_nonce', self.rfc1_request_nonce),
            ('oauth_callback', self.rfc1_callback),
        ]
        self.rfc1_request_signature = '74KNZJeDHnMBp0EMJ9ZHt/XKycU='


        # # RFC EXAMPLE 3 DATA: https://tools.ietf.org/html/draft-hammer-oauth-10#section-3.4.1
        # self.rfc3_method = "GET"
        # self.rfc3_target_url = 'http://example.com/request'
        # self.rfc3_params_raw = [
        #     ('b5', r"=%3D"),
        #     ('a3', "a"),
        #     ('c@', ""),
        #     ('a2', 'r b'),
        #     ('oauth_consumer_key', '9djdj82h48djs9d2'),
        #     ('oauth_token', 'kkk9d7dh3k39sjv7'),
        #     ('oauth_signature_method', 'HMAC-SHA1'),
        #     ('oauth_timestamp', 137131201),
        #     ('oauth_nonce', '7d8f3e4a'),
        #     ('c2', ''),
        #     ('a3', '2 q')
        # ]
        # self.rfc3_params_encoded = [
        #     ('b5', r"%3D%253D"),
        #     ('a3', "a"),
        #     ('c%40', ""),
        #     ('a2', r"r%20b"),
        #     ('oauth_consumer_key', '9djdj82h48djs9d2'),
        #     ('oauth_token', 'kkk9d7dh3k39sjv7'),
        #     ('oauth_signature_method', 'HMAC-SHA1'),
        #     ('oauth_timestamp', '137131201'),
        #     ('oauth_nonce', '7d8f3e4a'),
        #     ('c2', ''),
        #     ('a3', r"2%20q")
        # ]
        # self.rfc3_params_sorted = [
        #     ('a2', r"r%20b"),
        #     # ('a3', r"2%20q"), # disallow multiple
        #     ('a3', "a"),
        #     ('b5', r"%3D%253D"),
        #     ('c%40', ""),
        #     ('c2', ''),
        #     ('oauth_consumer_key', '9djdj82h48djs9d2'),
        #     ('oauth_nonce', '7d8f3e4a'),
        #     ('oauth_signature_method', 'HMAC-SHA1'),
        #     ('oauth_timestamp', '137131201'),
        #     ('oauth_token', 'kkk9d7dh3k39sjv7'),
        # ]
        # self.rfc3_param_string = r"a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
        # self.rfc3_base_string = r"GET&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7"

        # test data taken from : https://dev.twitter.com/oauth/overview/creating-signatures

        self.twitter_api_url = "https://api.twitter.com/"
        self.twitter_consumer_secret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"
        self.twitter_consumer_key = "xvz1evFS4wEEPTGEFPHBog"
        self.twitter_signature_method = "HMAC-SHA1"
        self.twitter_api = API(
            url=self.twitter_api_url,
            consumer_key=self.twitter_consumer_key,
            consumer_secret=self.twitter_consumer_secret,
            api='',
            version='1',
            signature_method=self.twitter_signature_method,
        )

        self.twitter_method = "POST"
        self.twitter_target_url = "https://api.twitter.com/1/statuses/update.json?include_entities=true"
        self.twitter_params_raw = [
            ("status", "Hello Ladies + Gentlemen, a signed OAuth request!"),
            ("include_entities", "true"),
            ("oauth_consumer_key", self.twitter_consumer_key),
            ("oauth_nonce", "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"),
            ("oauth_signature_method", self.twitter_signature_method),
            ("oauth_timestamp", "1318622958"),
            ("oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"),
            ("oauth_version", "1.0"),
        ]
        self.twitter_param_string = r"include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"
        self.twitter_signature_base_string = r"POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"
        self.twitter_token_secret = 'LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE'
        self.twitter_signing_key = 'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE'
        self.twitter_oauth_signature = 'tnnArxj06cWHq44gCs1OSKk/jLY='

        self.lexev_consumer_key='your_app_key'
        self.lexev_consumer_secret='your_app_secret'
        self.lexev_callback='http://127.0.0.1/oauth1_callback'
        self.lexev_signature_method='HMAC-SHA1'
        self.lexev_version='1.0'
        self.lexev_api = API(
            url='https://bitbucket.org/',
            api='api',
            version='1.0',
            consumer_key=self.lexev_consumer_key,
            consumer_secret=self.lexev_consumer_secret,
            signature_method=self.lexev_signature_method,
            callback=self.lexev_callback,
            wp_user='',
            wp_pass='',
            oauth1a_3leg=True
        )
        self.lexev_request_method='POST'
        self.lexev_request_url='https://bitbucket.org/api/1.0/oauth/request_token'
        self.lexev_request_nonce='27718007815082439851427366369'
        self.lexev_request_timestamp='1427366369'
        self.lexev_request_params=[
               ('oauth_callback',self.lexev_callback),
               ('oauth_consumer_key',self.lexev_consumer_key),
               ('oauth_nonce',self.lexev_request_nonce),
               ('oauth_signature_method',self.lexev_signature_method),
               ('oauth_timestamp',self.lexev_request_timestamp),
               ('oauth_version',self.lexev_version),
        ]
        self.lexev_request_signature=r"iPdHNIu4NGOjuXZ+YCdPWaRwvJY="
        self.lexev_resource_url='https://api.bitbucket.org/1.0/repositories/st4lk/django-articles-transmeta/branches'

    # def test_get_sign(self):
    #     message = "POST&http%3A%2F%2Flocalhost%3A8888%2Fwordpress%2Foauth1%2Frequest&oauth_callback%3Dlocalhost%253A8888%252Fwordpress%26oauth_consumer_key%3DLCLwTOfxoXGh%26oauth_nonce%3D85285179173071287531477036693%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1477036693%26oauth_version%3D1.0"
    #     signature_method = 'HMAC-SHA1'
    #     sig_key = 'k7zLzO3mF75Xj65uThpAnNvQHpghp4X1h5N20O8hCbz2kfJq&'
    #     sig = OAuth.get_sign(message, signature_method, sig_key)
    #     expected_sig = '8T93S/PDOrEd+N9cm84EDvsPGJ4='
    #     self.assertEqual(sig, expected_sig)

    def test_get_sign_key(self):
        self.assertEqual(
            self.wcapi.auth.get_sign_key(self.consumer_secret),
            "%s&" % self.consumer_secret
        )

        self.assertEqual(
            self.wcapi.auth.get_sign_key(self.twitter_consumer_secret, self.twitter_token_secret),
            self.twitter_signing_key
        )

    def test_flatten_params(self):
        self.assertEqual(
            UrlUtils.flatten_params(self.twitter_params_raw),
            self.twitter_param_string
        )

    def test_sorted_params(self):
        # Example given in oauth.net:
        oauthnet_example_sorted = [
            ('a', '1'),
            ('c', 'hi%%20there'),
            ('f', '25'),
            ('f', '50'),
            ('f', 'a'),
            ('z', 'p'),
            ('z', 't')
        ]

        oauthnet_example = copy(oauthnet_example_sorted)
        random.shuffle(oauthnet_example)

        # oauthnet_example_sorted = [
        #     ('a', '1'),
        #     ('c', 'hi%%20there'),
        #     ('f', '25'),
        #     ('z', 'p'),
        # ]

        self.assertEqual(
            UrlUtils.sorted_params(oauthnet_example),
            oauthnet_example_sorted
        )

    def test_get_signature_base_string(self):
        twitter_param_string = OAuth.get_signature_base_string(
            self.twitter_method,
            self.twitter_params_raw,
            self.twitter_target_url
        )
        self.assertEqual(
            twitter_param_string,
            self.twitter_signature_base_string
        )

    # @unittest.skip("changed order of parms to fit wordpress api")
    def test_generate_oauth_signature(self):

        # endpoint_url = UrlUtils.join_components([self.base_url, self.api_name, self.api_ver, self.endpoint])
        #
        # params = OrderedDict()
        # params["oauth_consumer_key"] = self.consumer_key
        # params["oauth_timestamp"] = "1477041328"
        # params["oauth_nonce"] = "166182658461433445531477041328"
        # params["oauth_signature_method"] = self.signature_method
        # params["oauth_version"] = "1.0"
        # params["oauth_callback"] = 'localhost:8888/wordpress'
        #
        # sig = self.wcapi.auth.generate_oauth_signature("POST", params, endpoint_url)
        # expected_sig = "517qNKeq/vrLZGj2UH7+q8ILWAg="
        # self.assertEqual(sig, expected_sig)

        # TEST WITH RFC EXAMPLE 1 DATA

        rfc1_request_signature = self.rfc1_api.auth.generate_oauth_signature(
            self.rfc1_request_method,
            self.rfc1_request_params,
            self.rfc1_request_target_url,
            '%s&' % self.rfc1_consumer_secret
        )
        self.assertEqual(rfc1_request_signature, self.rfc1_request_signature)

        # TEST WITH RFC EXAMPLE 3 DATA

        # TEST WITH TWITTER DATA

        twitter_signature = self.twitter_api.auth.generate_oauth_signature(
            self.twitter_method,
            self.twitter_params_raw,
            self.twitter_target_url,
            self.twitter_signing_key
        )
        self.assertEqual(twitter_signature, self.twitter_oauth_signature)

        # TEST WITH LEXEV DATA

        lexev_request_signature = self.lexev_api.auth.generate_oauth_signature(
            method=self.lexev_request_method,
            params=self.lexev_request_params,
            url=self.lexev_request_url
        )
        self.assertEqual(lexev_request_signature, self.lexev_request_signature)


    def test_add_params_sign(self):
        endpoint_url = self.wcapi.requester.endpoint_url('products?page=2')

        params = OrderedDict()
        params["oauth_consumer_key"] = self.consumer_key
        params["oauth_timestamp"] = "1477041328"
        params["oauth_nonce"] = "166182658461433445531477041328"
        params["oauth_signature_method"] = self.signature_method
        params["oauth_version"] = "1.0"
        params["oauth_callback"] = 'localhost:8888/wordpress'

        signed_url = self.wcapi.auth.add_params_sign("GET", endpoint_url, params)

        signed_url_params = parse_qsl(urlparse(signed_url).query)
        # self.assertEqual('page', signed_url_params[-1][0])
        self.assertIn('page', dict(signed_url_params))

class OAuth3LegTestcases(unittest.TestCase):
    def setUp(self):
        self.consumer_key = "ck_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        self.consumer_secret = "cs_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        self.api = API(
            url="http://woo.test",
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret,
            oauth1a_3leg=True,
            wp_user='test_user',
            wp_pass='test_pass',
            callback='http://127.0.0.1/oauth1_callback'
        )

    @urlmatch(path=r'.*wp-json.*')
    def woo_api_mock(*args, **kwargs):
        """ URL Mock """
        return {
            'status_code': 200,
            'content': """
                {
                    "name": "Wordpress",
                    "description": "Just another WordPress site",
                    "url": "http://localhost:8888/wordpress",
                    "home": "http://localhost:8888/wordpress",
                    "namespaces": [
                        "wp/v2",
                        "oembed/1.0",
                        "wc/v1"
                    ],
                    "authentication": {
                        "oauth1": {
                            "request": "http://localhost:8888/wordpress/oauth1/request",
                            "authorize": "http://localhost:8888/wordpress/oauth1/authorize",
                            "access": "http://localhost:8888/wordpress/oauth1/access",
                            "version": "0.1"
                        }
                    }
                }
            """
        }

    @urlmatch(path=r'.*oauth.*')
    def woo_authentication_mock(*args, **kwargs):
        """ URL Mock """
        return {
            'status_code':200,
            'content':"""oauth_token=XXXXXXXXXXXX&oauth_token_secret=YYYYYYYYYYYY"""
        }

    def test_get_sign_key(self):
        oauth_token_secret = "PNW9j1yBki3e7M7EqB5qZxbe9n5tR6bIIefSMQ9M2pdyRI9g"

        key = self.api.auth.get_sign_key(self.consumer_secret, oauth_token_secret)
        self.assertEqual(
            key,
            "%s&%s" % (self.consumer_secret, oauth_token_secret)
        )
        self.assertEqual(type(key), type(""))


    def test_auth_discovery(self):

        with HTTMock(self.woo_api_mock):
            # call requests
            authentication = self.api.auth.authentication
        self.assertEquals(
            authentication,
            {
                "oauth1": {
                    "request": "http://localhost:8888/wordpress/oauth1/request",
                    "authorize": "http://localhost:8888/wordpress/oauth1/authorize",
                    "access": "http://localhost:8888/wordpress/oauth1/access",
                    "version": "0.1"
                }
            }
        )

    def test_get_request_token(self):

        with HTTMock(self.woo_api_mock):
            authentication = self.api.auth.authentication
            self.assertTrue(authentication)

        with HTTMock(self.woo_authentication_mock):
            request_token, request_token_secret = self.api.auth.get_request_token()
            self.assertEquals(request_token, 'XXXXXXXXXXXX')
            self.assertEquals(request_token_secret, 'YYYYYYYYYYYY')

    def test_store_access_creds(self):
        _, creds_store_path = mkstemp("wp-api-python-test-store-access-creds.json")
        api = API(
            url="http://woo.test",
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret,
            oauth1a_3leg=True,
            wp_user='test_user',
            wp_pass='test_pass',
            callback='http://127.0.0.1/oauth1_callback',
            access_token='XXXXXXXXXXXX',
            access_token_secret='YYYYYYYYYYYY',
            creds_store=creds_store_path
        )
        api.auth.store_access_creds()

        with open(creds_store_path) as creds_store_file:
            self.assertEqual(
                creds_store_file.read(),
                '{"access_token": "XXXXXXXXXXXX", "access_token_secret": "YYYYYYYYYYYY"}'
            )

    def test_retrieve_access_creds(self):
        _, creds_store_path = mkstemp("wp-api-python-test-store-access-creds.json")
        with open(creds_store_path, 'w+') as creds_store_file:
            creds_store_file.write('{"access_token": "XXXXXXXXXXXX", "access_token_secret": "YYYYYYYYYYYY"}')

        api = API(
            url="http://woo.test",
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret,
            oauth1a_3leg=True,
            wp_user='test_user',
            wp_pass='test_pass',
            callback='http://127.0.0.1/oauth1_callback',
            creds_store=creds_store_path
        )

        api.auth.retrieve_access_creds()

        self.assertEqual(
            api.auth.access_token,
            'XXXXXXXXXXXX'
        )

        self.assertEqual(
            api.auth.access_token_secret,
            'YYYYYYYYYYYY'
        )

@unittest.skipIf(platform.uname()[1] != "Derwents-MBP.lan", "should only work on my machine")
class WCApiTestCasesBase(unittest.TestCase):
    """ Base class for WC API Test cases """
    def setUp(self):
        Auth.force_timestamp = CURRENT_TIMESTAMP
        Auth.force_nonce = SHITTY_NONCE
        self.api_params = {
            'url':'http://localhost:18080/wptest/',
            'api':'wc-api',
            'version':'v3',
            'consumer_key':'ck_e1dd4a9c85f49b9685f7964a154eecb29af39d5a',
            'consumer_secret':'cs_8ef3e5d21f8a0c28cd7bc4643e92111a0326b6b1',
        }

class WCApiTestCasesLegacy(WCApiTestCasesBase):
    """ Tests for WC API V3 """
    def setUp(self):
        super(WCApiTestCasesLegacy, self).setUp()
        self.api_params['version'] = 'v3'
        self.api_params['api'] = 'wc-api'


    def test_APIGet(self):
        wcapi = API(**self.api_params)
        response = wcapi.get('products')
        # print UrlUtils.beautify_response(response)
        self.assertIn(response.status_code, [200,201])
        response_obj = response.json()
        self.assertIn('products', response_obj)
        self.assertEqual(len(response_obj['products']), 10)
        # print "test_APIGet", response_obj

    def test_APIGetWithSimpleQuery(self):
        wcapi = API(**self.api_params)
        response = wcapi.get('products?page=2')
        # print UrlUtils.beautify_response(response)
        self.assertIn(response.status_code, [200,201])

        response_obj = response.json()
        self.assertIn('products', response_obj)
        self.assertEqual(len(response_obj['products']), 10)
        # print "test_ApiGenWithSimpleQuery", response_obj

    def test_APIGetWithComplexQuery(self):
        wcapi = API(**self.api_params)
        response = wcapi.get('products?page=2&filter%5Blimit%5D=2')
        self.assertIn(response.status_code, [200,201])
        response_obj = response.json()
        self.assertIn('products', response_obj)
        self.assertEqual(len(response_obj['products']), 2)

        response = wcapi.get('products?oauth_consumer_key=ck_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&oauth_nonce=037470f3b08c9232b0888f52cb9d4685b44d8fd1&oauth_signature=wrKfuIjbwi%2BTHynAlTP4AssoPS0%3D&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1481606275&filter%5Blimit%5D=3')
        self.assertIn(response.status_code, [200,201])
        response_obj = response.json()
        self.assertIn('products', response_obj)
        self.assertEqual(len(response_obj['products']), 3)

    def test_APIPutWithSimpleQuery(self):
        wcapi = API(**self.api_params)
        response = wcapi.get('products')
        first_product = (response.json())['products'][0]
        original_title = first_product['title']
        product_id = first_product['id']

        nonce = str(random.random())
        response = wcapi.put('products/%s?filter%%5Blimit%%5D=5' % (product_id), {"product":{"title":str(nonce)}})
        request_params = UrlUtils.get_query_dict_singular(response.request.url)
        response_obj = response.json()
        self.assertEqual(response_obj['product']['title'], str(nonce))
        self.assertEqual(request_params['filter[limit]'], str(5))

        wcapi.put('products/%s' % (product_id), {"product":{"title":original_title}})

class WCApiTestCases(WCApiTestCasesBase):
    oauth1a_3leg = False
    """ Tests for New wp-json/wc/v2 API """
    def setUp(self):
        super(WCApiTestCases, self).setUp()
        self.api_params['version'] = 'wc/v2'
        self.api_params['api'] = 'wp-json'
        self.api_params['callback'] = 'http://127.0.0.1/oauth1_callback'
        if self.oauth1a_3leg:
            self.api_params['oauth1a_3leg'] = True

    # @debug_on()
    def test_APIGet(self):
        wcapi = API(**self.api_params)
        per_page = 10
        response = wcapi.get('products?per_page=%d' % per_page)
        self.assertIn(response.status_code, [200,201])
        response_obj = response.json()
        self.assertEqual(len(response_obj), per_page)


    def test_APIPutWithSimpleQuery(self):
        wcapi = API(**self.api_params)
        response = wcapi.get('products')
        first_product = (response.json())[0]
        # from pprint import pformat
        # print "first product %s" % pformat(response.json())
        original_title = first_product['name']
        product_id = first_product['id']

        nonce = str(random.random())
        response = wcapi.put('products/%s?page=2&per_page=5' % (product_id), {"name":str(nonce)})
        request_params = UrlUtils.get_query_dict_singular(response.request.url)
        response_obj = response.json()
        self.assertEqual(response_obj['name'], str(nonce))
        self.assertEqual(request_params['per_page'], '5')

        wcapi.put('products/%s' % (product_id), {"name":original_title})

@unittest.skip("these simply don't work for some reason")
class WCApiTestCases3Leg(WCApiTestCases):
    """ Tests for New wp-json/wc/v2 API with 3-leg """
    oauth1a_3leg = True


@unittest.skipIf(platform.uname()[1] != "Derwents-MBP.lan", "should only work on my machine")
class WPAPITestCasesBase(unittest.TestCase):
    def setUp(self):
        Auth.force_timestamp = CURRENT_TIMESTAMP
        Auth.force_nonce = SHITTY_NONCE
        self.creds_store = '~/wc-api-creds-test.json'
        self.api_params = {
            'url':'http://localhost:18080/wptest/',
            'api':'wp-json',
            'version':'wp/v2',
            'consumer_key':'tYG1tAoqjBEM',
            'consumer_secret':'s91fvylVrqChwzzDbEJHEWyySYtAmlIsqqYdjka1KyVDdAyB',
            'callback':'http://127.0.0.1/oauth1_callback',
            'wp_user':'wptest',
            'wp_pass':'gZ*gZk#v0t5$j#NQ@9',
            'oauth1a_3leg':True,
        }

    def test_APIGet(self):
        self.wpapi = API(**self.api_params)
        response = self.wpapi.get('users/me')
        self.assertIn(response.status_code, [200,201])
        response_obj = response.json()
        self.assertEqual(response_obj['name'], self.api_params['wp_user'])

class WPAPITestCasesBasic(WPAPITestCasesBase):
    def setUp(self):
        super(WPAPITestCasesBasic, self).setUp()
        self.api_params.update({
            'user_auth': True,
            'basic_auth': True,
            'query_string_auth': False,
        })
        self.wpapi = API(**self.api_params)

class WPAPITestCasesBasicV1(WPAPITestCasesBase):
    def setUp(self):
        super(WPAPITestCasesBasicV1, self).setUp()
        self.api_params.update({
            'user_auth': True,
            'basic_auth': True,
            'query_string_auth': False,
            'version': 'wp/v1'
        })
        self.wpapi = API(**self.api_params)

    def test_get_endpoint_url(self):
        endpoint_url = self.wpapi.requester.endpoint_url('')
        print endpoint_url


class WPAPITestCases3leg(WPAPITestCasesBase):
    def setUp(self):
        super(WPAPITestCases3leg, self).setUp()
        self.api_params.update({
            'creds_store': self.creds_store,
        })
        self.wpapi = API(**self.api_params)
        self.wpapi.auth.clear_stored_creds()

    def test_APIGetWithSimpleQuery(self):
        response = self.wpapi.get('media?page=2&per_page=2')
        # print UrlUtils.beautify_response(response)
        self.assertIn(response.status_code, [200,201])

        response_obj = response.json()
        self.assertEqual(len(response_obj), 2)
        # print "test_ApiGenWithSimpleQuery", response_obj


if __name__ == '__main__':
    unittest.main()
