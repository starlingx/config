#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /isystems/ methods.
"""

from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils
from six.moves import http_client


class TestSystem(base.FunctionalTest):
    def setUp(self):
        super(TestSystem, self).setUp()

    def _get_path(self, system_id=None):
        return "/isystems/%s" % system_id if system_id else "/isystems"

    def _patch_and_check(self, path, updates, expect_errors=False):
        patch = []
        for att, val in updates.items():
            patch.append({"path": "/%s" % att,
                          "value": val,
                          "op": "replace"})

        # Updating system attributes
        response = self.patch_json(path, patch,
                                     expect_errors=expect_errors)

        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
        else:
            patched_system = response.json

            # Verify if system attributes was changed
            for att, val in updates.items():
                self.assertEqual(val, patched_system[att])


class TestSystemUpdate(TestSystem):

    def setUp(self):
        super(TestSystemUpdate, self).setUp()
        self.system = dbutils.create_test_isystem()

    def test_update_latitude_longer_than_30_chars(self):
        update = {"latitude": "00.0000000111111111122222222223"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_latitude_valid_length(self):
        update = {"latitude": "00.11223344556677"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    def test_update_latitude_null_value(self):
        update = {"latitude": None}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    def test_update_longitude_longer_than_30_chars(self):
        update = {"longitude": "00.0000000111111111122222222223"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_longitude_valid_length(self):
        update = {"longitude": "-00.11223344556677"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    def test_update_longitude_null_value(self):
        update = {"longitude": None}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)
