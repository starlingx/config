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
from cgtsclient.v1 import ilvg


class ILvgTest(testtools.TestCase):

    def test__find_ilvg_numeric(self):
        mock_cc = mock.MagicMock()
        mock_ihost = mock.MagicMock()

        fake_id = str(random.randrange(1, 9))
        ilvg._find_ilvg(mock_cc, mock_ihost, fake_id)

        mock_cc.ilvg.get.assert_called_with(fake_id)
        mock_cc.ilvg.list.assert_not_called()

    def test__find_ilvg_uuid(self):
        mock_cc = mock.MagicMock()
        mock_ihost = mock.MagicMock()
        fake_id = str(uuid.uuid4())
        fake_name = "fake_ilvg"
        mock_cc.ilvg.list.return_value = [
            ilvg.ilvg(mock.MagicMock, info={
                "uuid": fake_id, "lvm_vg_name": fake_name
            })
        ]

        ilvg_found = ilvg._find_ilvg(mock_cc, mock_ihost, fake_id)

        mock_cc.ilvg.list.assert_called_with(mock_ihost.uuid)
        self.assertEqual(fake_id, ilvg_found.uuid)

    def test__find_ilvg_uuid_not_found(self):
        mock_cc = mock.MagicMock()
        mock_ihost = mock.MagicMock()
        fake_id = str(uuid.uuid4())
        mock_cc.ilvg.list.return_value = []

        self.assertRaisesRegexp(
            exc.CommandError,
            "Local volume group not found by name or uuid: %s" % fake_id,
            ilvg._find_ilvg,
            mock_cc,
            mock_ihost,
            fake_id
        )
        mock_cc.ilvg.list.assert_called_with(mock_ihost.uuid)

    def test__find_ilvg_name(self):
        mock_cc = mock.MagicMock()
        mock_ihost = mock.MagicMock()
        fake_id = str(uuid.uuid4())
        fake_name = "fake_ilvg"
        mock_cc.ilvg.list.return_value = [
            ilvg.ilvg(mock.MagicMock, info={
                "uuid": fake_id, "lvm_vg_name": fake_name
            })
        ]

        ilvg_found = ilvg._find_ilvg(mock_cc, mock_ihost, fake_name)

        mock_cc.ilvg.list.assert_called_with(mock_ihost.uuid)
        self.assertEqual(fake_name, ilvg_found.lvm_vg_name)

    def test__find_ilvg_name_not_found(self):
        mock_cc = mock.MagicMock()
        mock_ihost = mock.MagicMock()
        fake_name = "fake_lvg_name"
        mock_cc.ilvg.list.return_value = []

        self.assertRaisesRegexp(
            exc.CommandError,
            "Local volume group not found by name or uuid: %s" % fake_name,
            ilvg._find_ilvg,
            mock_cc,
            mock_ihost,
            fake_name
        )
        mock_cc.ilvg.list.assert_called_with(mock_ihost.uuid)
