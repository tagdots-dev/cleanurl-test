#!/usr/bin/env python

"""
Purpose: tests
"""
import unittest

from pkg_19544.clean_url import (
    evaluate_url,
    origin_url,
    redirect_url,
    sanitize_url,
)


class TestCore(unittest.TestCase):
    def test_evaluate_url_scheme_path_breakdown_success(self):
        user_url = "https://docs.python.org/3/library/urllib.parse.html#module-urllib.parse"
        self.assertTrue(evaluate_url(user_url, enable_log=True))

    def test_evaluate_url_scheme_no(self):
        user_url = "example.com"
        self.assertFalse(evaluate_url(user_url, allow_http=True, enable_log=True))

    def test_evaluate_url_scheme_allow_http(self):
        user_url = "http://google.com"
        self.assertTrue(evaluate_url(user_url, allow_http=True, enable_log=True))

    def test_evaluate_url_has_invalid_scheme(self):
        user_url = "ftp://docs.python.org/3/library/urllib.parse.html#module-urllib.parse"
        self.assertFalse(evaluate_url(user_url, enable_log=True))

    def test_evaluate_url_has_basic_auth(self):
        user_url = "https://user:pass@docs.python.org/3/library/urllib.parse.html#module-urllib.parse"  # checkov:skip=CKV_SECRET_4  # noqa: E501
        self.assertFalse(evaluate_url(user_url, enable_log=True))

    def test_evaluate_url_has_control_char(self):
        user_url = "https://docs.python.org/3/library/url\n\rlib.parse.html#module-urllib.parse"
        self.assertFalse(evaluate_url(user_url, enable_log=True))

    def test_evaluate_url_has_invalid_char_in_fqdn(self):
        user_url = "https://docs.pyth_on.org/3/library/urllib.parse.html#module-urllib.parse"
        self.assertFalse(evaluate_url(user_url, enable_log=True))

    def test_evaluate_url_has_invalid_fqdn_label_prefix(self):
        user_url = "https://-docs.python.org/3/library/urllib.parse.html#module-urllib.parse"
        self.assertFalse(evaluate_url(user_url, enable_log=True))

    def test_evaluate_url_has_invalid_fqdn_label_suffix(self):
        user_url = "https://docs-.python.org/3/library/urllib.parse.html#module-urllib.parse"
        self.assertFalse(evaluate_url(user_url, enable_log=True))

    def test_evaluate_url_has_invalid_tld(self):
        user_url = "https://docs.python.tld8/3/library/urllib.parse.html#module-urllib.parse"
        self.assertFalse(evaluate_url(user_url, enable_log=True))

    def test_origin_url(self):
        user_url = "https://google.com"
        self.assertTrue(origin_url(user_url))

    def test_redirect_url_redirect_success(self):
        user_url = "https://google.com"
        self.assertTrue(redirect_url(user_url))

    def test_redirect_url_redirect_failure(self):
        user_url = "https://invalidurladdress.com"
        self.assertFalse(redirect_url(user_url))

    def test_sanitize_url(self):
        user_url = "https://example.com/search?q=urlencode&gs_lcrp=EgZjaHJvbzc1NmowaA&sourceid=chrome&ie=UTF-8"
        self.assertTrue(sanitize_url(user_url))
