#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#
import random

import mock
import testtools
import uuid

from cgtsclient import exc
from cgtsclient.v1 import ipv


class IPvTest(testtools.TestCase):

    def test__find_ipv_numeric(self):
        mock_cc = mock.MagicMock()
        mock_ihost = mock.MagicMock()

        fake_id = str(random.randrange(1, 9))
        ipv._find_ipv(mock_cc, mock_ihost, fake_id)

        mock_cc.ipv.get.assert_called_with(fake_id)
        mock_cc.ipv.list.assert_not_called()

    def test__find_ipv_uuid(self):
        mock_cc = mock.MagicMock()
        mock_ihost = mock.MagicMock()
        fake_id = str(uuid.uuid4())
        mock_cc.ipv.list.return_value = [
            ipv.ipv(mock.MagicMock, info={
                "uuid": fake_id
            })
        ]

        ilvg_found = ipv._find_ipv(mock_cc, mock_ihost, fake_id)

        mock_cc.ipv.list.assert_called_with(mock_ihost.uuid)
        self.assertEqual(fake_id, ilvg_found.uuid)

    def test__find_ipv_uuid_not_found(self):
        mock_cc = mock.MagicMock()
        mock_ihost = mock.MagicMock()
        fake_id = str(uuid.uuid4())
        mock_cc.ipv.list.return_value = []

        self.assertRaisesRegexp(
            exc.CommandError,
            "physical volume not found: %s" % fake_id,
            ipv._find_ipv,
            mock_cc,
            mock_ihost,
            fake_id
        )
        mock_cc.ipv.list.assert_called_with(mock_ihost.uuid)
