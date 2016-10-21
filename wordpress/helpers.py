# -*- coding: utf-8 -*-

"""
Wordpress Hellpers Class
"""

__title__ = "wordpress-requests"

import posixpath

try:
    from urllib.parse import urlencode, quote, unquote, parse_qsl, urlparse, urlunparse
    from urllib.parse import ParseResult as URLParseResult
except ImportError:
    from urllib import urlencode, quote, unquote
    from urlparse import parse_qsl, urlparse, urlunparse
    from urlparse import ParseResult as URLParseResult

class StrUtils(object):
    @classmethod
    def remove_tail(cls, string, tail):
        if string.endswith(tail):
            return string[:-len(tail)]

class SeqUtils(object):
    @classmethod
    def filter_true(cls, seq):
        return [item for item in seq if item]

class UrlUtils(object):
    @classmethod
    def substitute_query(cls, url, query_string=None):
        """ Replaces the query string in the url with the provided string or
        removes the query string if none is provided """
        if not query_string:
            query_string = ''

        urlparse_result = urlparse(url)

        return urlunparse(URLParseResult(
            scheme=urlparse_result.scheme,
            netloc=urlparse_result.netloc,
            path=urlparse_result.path,
            params=urlparse_result.params,
            query=query_string,
            fragment=urlparse_result.fragment
        ))

    @classmethod
    def add_query(cls, url, new_key, new_value):
        """ adds a query parameter to the given url """
        new_query_item = '='.join([quote(new_key, safe='[]'), quote(new_value)])
        new_query_string = "&".join(SeqUtils.filter_true([
            urlparse(url).query,
            new_query_item
        ]))
        return cls.substitute_query(url, new_query_string)

    @classmethod
    def is_ssl(cls, url):
        return urlparse(url).scheme == 'https'

    @classmethod
    def join_components(cls, components):
        return reduce(posixpath.join, SeqUtils.filter_true(components))

    @staticmethod
    def get_value_like_as_php(val):
        """ Prepare value for quote """
        try:
            base = basestring
        except NameError:
            base = (str, bytes)

        if isinstance(val, base):
            return val
        elif isinstance(val, bool):
            return "1" if val else ""
        elif isinstance(val, int):
            return str(val)
        elif isinstance(val, float):
            return str(int(val)) if val % 1 == 0 else str(val)
        else:
            return ""
