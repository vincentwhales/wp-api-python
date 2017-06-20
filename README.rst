Wordpress API - Python Client
===============================

A Python wrapper for the Wordpress REST API v1-2 that also works on the WooCommerce REST API v1-3 and WooCommerce WP-API v1-2.
Forked from the excellent Woocommerce API written by Claudio Sanches and modified to work with Wordpress: https://github.com/woocommerce/wc-api-python

I created this fork because I prefer the way that the wc-api-python client interfaces with
the Wordpress API compared to the existing python client, https://pypi.python.org/pypi/wordpress_json
which does not support OAuth authentication, only Basic Authentication (very unsecure)

Any suggestions about how this repository could be improved are welcome :)

Roadmap
-------

- [x] Create initial fork
- [x] Implement 3-legged OAuth on Wordpress client
- [ ] Implement iterator for conveniant access to API items

Requirements
------------

Wordpress version 4.7+ comes pre-installed with REST API v2, so you don't need to have the WP REST API plugin if you have the latest Wordpress.

You should have the following plugins installed on your wordpress site:

- **WP REST API** (only required for WP < v4.7, recommended version: 2.0+)
- **WP REST API - OAuth 1.0a Server** (optional, if you want oauth. https://github.com/WP-API/OAuth1)
- **WP REST API - Meta Endpoints** (optional)
- **WooCommerce** (optional, if you want to use the WooCommerce API)

The following python packages are also used by the package

- **requests**
- **beautifulsoup**

Installation
------------

Install with pip

.. code-block:: bash

    pip install wordpress-api

Download this repo and use setuptools to install the package

.. code-block:: bash

    pip install setuptools
    git clone https://github.com/derwentx/wp-api-python
    python setup.py install

Testing
-------

If you have installed from source, then you can test with unittest:

.. code-block:: bash

    pip install -r requirements-test.txt
    python -m unittest -v tests

Getting started
---------------

Generate API credentials (Consumer Key & Consumer Secret) following these instructions: http://v2.wp-api.org/guide/authentication/

Simply go to Users -> Applications and create an Application, e.g. "REST API".
Enter a callback URL that you will be able to remember later such as "http://example.com/oauth1_callback" (not really important for this client).
Store the resulting Key and Secret somewhere safe.

Check out the Wordpress API endpoints and data that can be manipulated in http://v2.wp-api.org/reference/.

Setup
-----

Setup for the old Wordpress API:

.. code-block:: python

    from wordpress import API

    wpapi = API(
        url="http://example.com",
        consumer_key="XXXXXXXXXXXX",
        consumer_secret="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        api="wp-json",
        version=None,
        wp_user="XXXX",
        wp_pass="XXXX"
    )

Setup for the new WP REST API v2:

.. code-block:: python

    #...

    wpapi = API(
        url="http://example.com",
        consumer_key="XXXXXXXXXXXX",
        consumer_secret="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        api="wp-json",
        version="wp/v2",
        wp_user="XXXX",
        wp_pass="XXXX"
    )

Setup for the old WooCommerce API v3:

.. code-block:: python

    #...

    wcapi = API(
        url="http://example.com",
        consumer_key="ck_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        consumer_secret="cs_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        api="wc-api",
        version="v3"
    )

Setup for the new WP REST API integration (WooCommerce 2.6 or later):

.. code-block:: python

    #...

    wcapi = API(
        url="http://example.com",
        consumer_key="ck_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        consumer_secret="cs_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        api="wp-json",
        version="wc/v1"
    )

Options
~~~~~~~

+-----------------------+-------------+----------+-------------------------------------------------------------------------------------------------------+
|         Option        |     Type    | Required |                                              Description                                              |
+=======================+=============+==========+=======================================================================================================+
| ``url``               | ``string``  | yes      | Your Store URL, example: http://wp.dev/                                                               |
+-----------------------+-------------+----------+-------------------------------------------------------------------------------------------------------+
| ``consumerKey``       | ``string``  | yes      | Your API consumer key                                                                                 |
+-----------------------+-------------+----------+-------------------------------------------------------------------------------------------------------+
| ``consumerSecret``    | ``string``  | yes      | Your API consumer secret                                                                              |
+-----------------------+-------------+----------+-------------------------------------------------------------------------------------------------------+
| ``api``               | ``string``  | no       | Determines which api to use, defaults to ``wp-json``, can be arbitrary: ``wc-api``, ``oembed``        |
+-----------------------+-------------+----------+-------------------------------------------------------------------------------------------------------+
| ``version``           | ``string``  | no       | API version, default is ``wp/v2``, can be ``v3`` or  ``wc/v1`` if using ``wc-api``                    |
+-----------------------+-------------+----------+-------------------------------------------------------------------------------------------------------+
| ``timeout``           | ``integer`` | no       | Connection timeout, default is ``5``                                                                  |
+-----------------------+-------------+----------+-------------------------------------------------------------------------------------------------------+
| ``verify_ssl``        | ``bool``    | no       | Verify SSL when connect, use this option as ``False`` when need to test with self-signed certificates |
+-----------------------+-------------+----------+-------------------------------------------------------------------------------------------------------+
| ``query_string_auth`` | ``bool``    | no       | Force Basic Authentication as query string when ``True`` and using under HTTPS, default is ``False``  |
+-----------------------+-------------+----------+-------------------------------------------------------------------------------------------------------+

Methods
-------

+--------------+----------------+------------------------------------------------------------------+
|    Params    |      Type      |                           Description                            |
+==============+================+==================================================================+
| ``endpoint`` | ``string``     | API endpoint, example: ``posts`` or ``user/12``                  |
+--------------+----------------+------------------------------------------------------------------+
| ``data``     | ``dictionary`` | Data that will be converted to JSON                              |
+--------------+----------------+------------------------------------------------------------------+

GET
~~~

- ``.get(endpoint)``

POST
~~~~

- ``.post(endpoint, data)``

PUT
~~~

- ``.put(endpoint, data)``

DELETE
~~~~~~

- ``.delete(endpoint)``

OPTIONS
~~~~~~~

- ``.options(endpoint)``

Response
--------

All methods will return `Response <http://docs.python-requests.org/en/latest/api/#requests.Response>`_ object.

Example of returned data:

.. code-block:: bash

    >>> from wordpress import api as wpapi
    >>> r = wpapi.get("posts")
    >>> r.status_code
    200
    >>> r.headers['content-type']
    'application/json; charset=UTF-8'
    >>> r.encoding
    'UTF-8'
    >>> r.text
    u'{"posts":[{"title":"Flying Ninja","id":70,...' // Json text
    >>> r.json()
    {u'posts': [{u'sold_individually': False,... // Dictionary data


Changelog
---------

1.2.2 - 2017/06/16
~~~~~~~~~~~~~~~~~~
 - support basic auth without https
 - rename oauth module to auth (since auth covers oauth and basic auth)
 - tested with latest versions of WP and WC

1.2.1 - 2016/12/13
~~~~~~~~~~~~~~~~~~
- tested to handle complex queries like filter[limit]
- fix: Some edge cases where queries were out of order causing signature mismatch
- hardened helper and api classes and added corresponding test cases

1.2.0 - 2016/09/28
~~~~~~~~~~~~~~~~~~

- Initial fork
- Implemented 3-legged OAuth
- Tested with pagination
