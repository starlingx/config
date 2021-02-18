# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import datetime

from sysinv.openstack.common.keystone_objects import Token
from sysinv.tests.db import base

TOKEN_EXPIRATION_WINDOW = 300


class TokenTestCase(base.DbTestCase):

    def setUp(self):
        super(TokenTestCase, self).setUp()

    def tearDown(self):
        super(TokenTestCase, self).tearDown()

    def test_expired_token_outside_window(self):
        self.check_token_expiration(datetime.timedelta(
            seconds=-(TOKEN_EXPIRATION_WINDOW + 100)), True)

    def test_expired_token_inside_window(self):
        self.check_token_expiration(datetime.timedelta(
            seconds=-(TOKEN_EXPIRATION_WINDOW - 100)), True)

    def test_non_expired_token_inside_window(self):
        # a non-expired token will be considered expired if it is inside
        # the "within_seconds" window
        self.check_token_expiration(datetime.timedelta(
            seconds=TOKEN_EXPIRATION_WINDOW - 100), True)

    def test_non_expired_token_outside_window(self):
        self.check_token_expiration(datetime.timedelta(
            seconds=TOKEN_EXPIRATION_WINDOW + 100), False)

    def check_token_expiration(self, delta_from_now, expected_is_expired):
        now = datetime.datetime.utcnow()
        expires_at = now + delta_from_now

        token = self._get_token(expires_at.isoformat())

        self.assertEqual(
            token.is_expired(within_seconds=TOKEN_EXPIRATION_WINDOW),
            expected_is_expired)

    def _get_token(self, expires_at):
        token_data = {
            'token': {
                'expires_at': expires_at,
            }
        }
        token_id = 'fake-token-id'
        region_name = 'RegionOne'
        return Token(token_data, token_id, region_name)
