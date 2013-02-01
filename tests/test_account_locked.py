# -*- encoding: utf-8 -*-
__author__ = "Chmouel Boudjnah <chmouel@enovance.com>"

# Copyright 2013 eNovance.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import unittest

import swift_account_locked.middleware as middleware

from swift.common.swob import Response, Request


class FakeCache(object):
    def __init__(self, val):
        self.val = val

    def get(self, *args):
        return self.val

    def set(self, *args, **kwargs):
        pass


class FakeApp(object):
    def __init__(self, status_headers_body=None):
        self.status_headers_body = status_headers_body
        if not self.status_headers_body:
            self.status_headers_body = ('204 No Content', {}, '')

    def __call__(self, env, start_response):
        req = Request(env)
        status, headers, body = self.status_headers_body
        if req.method == 'GET':
            headers = req.headers
        return Response(status=status, headers=headers,
                        body=body)(env, start_response)


class FakeResponse(object):
    def __init__(self, headers):
        self.headers = headers
        self.status_int = 201


class FakeRequest(object):
    def __init__(self, env, method, path):
        if path.endswith('allowed'):
            self.headers = {'x-account-meta-locked': 'false'}
        elif path.endswith('denied'):
            self.headers = {'x-account-meta-locked': 'true'}
        else:
            self.headers = {}

    def get_response(self, app):
        return FakeResponse(self.headers)


class TestAccountAccessMode(unittest.TestCase):
    def _make_request(self, **kwargs):
        req = Request.blank("/v1/AUTH_account/cont", **kwargs)
        return req

    def setUp(self):
        self.conf = {
            'recheck_account_existence': 60,
            'locked_header': 'locked',
            'denied_methods': ("PUT", "DELETE", "POST"),
        }
        self.test_default = middleware.filter_factory(self.conf)(FakeApp())

    def test_allowed_to_update_when_locked(self):
        req = self._make_request(
            environ={
                'REQUEST_METHOD': 'POST',
            },
            headers={'X-Account-Meta-Locked':  'true'})

        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' not in resp.environ)

    def test_allowed_method_not_in_denied_methods(self):
        req = self._make_request(
            environ={
                'REQUEST_METHOD': 'GET',
            },
            headers={'X-Container-Meta-Locked':  'true'})

        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' not in resp.environ)

    def test_passthru_when_no_cache(self):
        req = self._make_request(
            environ={
                'REQUEST_METHOD': 'POST',
                'cache': FakeCache({}),
            })
        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' not in resp.environ)

    def test_not_allowed_with_cache(self):
        cache = FakeCache({'meta': {'locked': 'true'}})
        req = self._make_request(
            environ={
                'REQUEST_METHOD': 'POST',
                'swift.cache': cache,
            })
        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' in resp.environ)
        self.assertEquals(resp.environ['swift.authorize'],
                          self.test_default.deny)

    def test_allowed_with_cache(self):
        cache = FakeCache({'meta': {'locked': 'false'}})
        req = self._make_request(
            environ={
                'REQUEST_METHOD': 'POST',
                'swift.cache': cache,
            })
        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' not in resp.environ)

    def test_allowed_without_cache(self):
        middleware.make_pre_authed_request = FakeRequest
        req = self._make_request(
            environ={
                'REQUEST_METHOD': 'POST',
                'PATH_INFO': '/v1/acc_allowed',
                'swift.cache': FakeCache({}),
            })
        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' not in resp.environ)

    def test_deny_without_cache(self):
        middleware.make_pre_authed_request = FakeRequest
        req = self._make_request(
            environ={
                'REQUEST_METHOD': 'POST',
                'PATH_INFO': '/v1/acc_denied',
                'swift.cache': FakeCache({}),
            })
        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' in resp.environ)
        self.assertEquals(resp.environ['swift.authorize'],
                          self.test_default.deny)
