""" API Tests """
import unittest
from httmock import all_requests, HTTMock, urlmatch
from collections import OrderedDict

import wordpress
from wordpress import oauth
from wordpress import __default_api_version__, __default_api__
from wordpress.helpers import UrlUtils, SeqUtils, StrUtils
from wordpress.transport import API_Requests_Wrapper
from wordpress.api import API
from wordpress.oauth import OAuth


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

    def test_oauth_sorted_params(self):
        """ Test order of parameters for OAuth signature """
        def check_sorted(keys, expected):
            params = oauth.OrderedDict()
            for key in keys:
                params[key] = ''

            ordered = list(oauth.OAuth.sorted_params(params).keys())
            self.assertEqual(ordered, expected)

        check_sorted(['a', 'b'], ['a', 'b'])
        check_sorted(['b', 'a'], ['a', 'b'])
        check_sorted(['a', 'b[a]', 'b[b]', 'b[c]', 'c'], ['a', 'b[a]', 'b[b]', 'b[c]', 'c'])
        check_sorted(['a', 'b[c]', 'b[a]', 'b[b]', 'c'], ['a', 'b[c]', 'b[a]', 'b[b]', 'c'])
        check_sorted(['d', 'b[c]', 'b[a]', 'b[b]', 'c'], ['b[c]', 'b[a]', 'b[b]', 'c', 'd'])
        check_sorted(['a1', 'b[c]', 'b[a]', 'b[b]', 'a2'], ['a1', 'a2', 'b[c]', 'b[a]', 'b[b]'])

class HelperTestcase(unittest.TestCase):
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

    # def test_get_sign(self):
    #     message = "POST&http%3A%2F%2Flocalhost%3A8888%2Fwordpress%2Foauth1%2Frequest&oauth_callback%3Dlocalhost%253A8888%252Fwordpress%26oauth_consumer_key%3DLCLwTOfxoXGh%26oauth_nonce%3D85285179173071287531477036693%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1477036693%26oauth_version%3D1.0"
    #     signature_method = 'HMAC-SHA1'
    #     sig_key = 'k7zLzO3mF75Xj65uThpAnNvQHpghp4X1h5N20O8hCbz2kfJq&'
    #     sig = OAuth.get_sign(message, signature_method, sig_key)
    #     expected_sig = '8T93S/PDOrEd+N9cm84EDvsPGJ4='
    #     self.assertEqual(sig, expected_sig)

    def test_get_sign_key(self):
        self.assertEqual(
            self.wcapi.oauth.get_sign_key(self.consumer_secret),
            "%s&" % self.consumer_secret
        )


    def test_normalize_params(self):
        params = dict([('oauth_callback', 'localhost:8888/wordpress'), ('oauth_consumer_key', 'LCLwTOfxoXGh'), ('oauth_nonce', '45474014077032100721477037582'), ('oauth_signature_method', 'HMAC-SHA1'), ('oauth_timestamp', 1477037582), ('oauth_version', '1.0')])
        expected_normalized_params = "oauth_callback=localhost%3A8888%2Fwordpress&oauth_consumer_key=LCLwTOfxoXGh&oauth_nonce=45474014077032100721477037582&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1477037582&oauth_version=1.0"
        normalized_params = OAuth.normalize_params(params)
        self.assertEqual(expected_normalized_params, normalized_params)

    def test_generate_oauth_signature(self):

        endpoint_url = UrlUtils.join_components([self.base_url, self.api_name, self.api_ver, self.endpoint])

        params = OrderedDict()
        params["oauth_consumer_key"] = self.consumer_key
        params["oauth_timestamp"] = "1477041328"
        params["oauth_nonce"] = "166182658461433445531477041328"
        params["oauth_signature_method"] = self.signature_method
        params["oauth_version"] = "1.0"
        params["oauth_callback"] = 'localhost:8888/wordpress'

        sig = self.wcapi.oauth.generate_oauth_signature("POST", params, endpoint_url)
        expected_sig = "517qNKeq/vrLZGj2UH7+q8ILWAg="
        self.assertEqual(sig, expected_sig)

    # def generate_oauth_signature(self):
    #     base_url = "http://localhost:8888/wordpress/"
    #     api_name = 'wc-api'
    #     api_ver = 'v3'
    #     endpoint = 'products/99'
    #     signature_method = "HAMC-SHA1"
    #     consumer_key = "ck_681c2be361e415519dce4b65ee981682cda78bc6"
    #     consumer_secret = "cs_b11f652c39a0afd3752fc7bb0c56d60d58da5877"
    #
    #     wcapi = API(
    #         url=base_url,
    #         consumer_key=consumer_key,
    #         consumer_secret=consumer_secret,
    #         api=api_name,
    #         version=api_ver,
    #         signature_method=signature_method
    #     )
    #
    #     endpoint_url = UrlUtils.join_components([base_url, api_name, api_ver, endpoint])
    #
    #     params = OrderedDict()
    #     params["oauth_consumer_key"] = consumer_key
    #     params["oauth_timestamp"] = "1477041328"
    #     params["oauth_nonce"] = "166182658461433445531477041328"
    #     params["oauth_signature_method"] = signature_method
    #     params["oauth_version"] = "1.0"
    #     params["oauth_callback"] = 'localhost:8888/wordpress'
    #
    #     sig = wcapi.oauth.generate_oauth_signature("POST", params, endpoint_url)
    #     expected_sig = "517qNKeq/vrLZGj2UH7+q8ILWAg="
    #     self.assertEqual(sig, expected_sig)

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

        key = self.api.oauth.get_sign_key(self.consumer_secret, oauth_token_secret)
        self.assertEqual(
            key,
            "%s&%s" % (self.consumer_secret, oauth_token_secret)
        )
        self.assertEqual(type(key), type(""))

        key = self.api.oauth.get_sign_key(None, oauth_token_secret)
        self.assertEqual(
            key,
            oauth_token_secret
        )
        self.assertEqual(type(key), type(""))
        

    def test_auth_discovery(self):

        with HTTMock(self.woo_api_mock):
            # call requests
            authentication = self.api.oauth.authentication
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
            authentication = self.api.oauth.authentication
            self.assertTrue(authentication)

        with HTTMock(self.woo_authentication_mock):
            access_token, access_token_secret = self.api.oauth.get_request_token()
            self.assertEquals(access_token, 'XXXXXXXXXXXX')
            self.assertEquals(access_token_secret, 'YYYYYYYYYYYY')
