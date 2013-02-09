# -*- encoding: utf-8 -*-
__author__ = "Chmouel Boudjnah <chmouel@enovance.com>"
import unittest

import swiftclient

CONF = {
    'user': ('demo:demo', 'ADMIN'),
    'admin': ('admin:admin', 'ADMIN'),
    'auth_url': 'http://localhost:5000/v2.0',
    'header': 'X-Account-Meta-Locked',
}


class TestAccountLocked(unittest.TestCase):
    def setUp(self):
        self.user = swiftclient.client.Connection(
            CONF['auth_url'],
            CONF['user'][0],
            CONF['user'][1],
            auth_version='2.0',
        )
        self.admin = swiftclient.client.Connection(
            CONF['auth_url'],
            CONF['admin'][0],
            CONF['admin'][1],
            auth_version='2.0',
        )

    def test_fail_update_locked_header(self):
        self.assertRaises(swiftclient.ClientException, self.user.post_account,
                          {CONF['header']: "1"})

    def test_success_update_user_locked_header_with_admin_token(self):
        admin_url, admin_token = self.admin.get_auth()
        user_url, user_token = self.user.get_auth()
        swiftclient.post_account(user_url, admin_token, {CONF['header']: "1"})

    def test_fail_upload_when_locked(self):
        container_name = 'test_fail_upload_when_locked'
        admin_url, admin_token = self.admin.get_auth()
        user_url, user_token = self.user.get_auth()
        swiftclient.post_account(user_url, admin_token, {CONF['header']: "1"})
        self.assertRaises(swiftclient.ClientException,
                          self.user.put_container,
                          container_name)

    def test_success_upload_when_unlocked(self):
        container_name = 'test_fail_upload_when_locked'
        admin_url, admin_token = self.admin.get_auth()
        user_url, user_token = self.user.get_auth()
        swiftclient.post_account(user_url, admin_token, {CONF['header']: "0"})
        try:
            self.user.put_container(container_name)
        except swiftclient.ClientException:
            self.fail("cannot create container")

    def test_fail_unlock_success(self):
        container_name = 'test_fail_upload_when_locked'
        admin_url, admin_token = self.admin.get_auth()
        user_url, user_token = self.user.get_auth()
        swiftclient.post_account(user_url, admin_token, {CONF['header']: "1"})
        self.assertRaises(swiftclient.ClientException,
                          self.user.put_container,
                          container_name)
        swiftclient.post_account(user_url, admin_token, {CONF['header']: "0"})
        try:
            self.user.put_container(container_name)
        except swiftclient.ClientException:
            self.fail("cannot create container")
