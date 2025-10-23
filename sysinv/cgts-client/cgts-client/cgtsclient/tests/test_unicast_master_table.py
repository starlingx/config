########################################################################
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import unicast_master_table as umt
from cgtsclient.tests import utils as test_utils


class UnicastMasterTableTest(test_utils.BaseTestCase):
    def test_umt_all_with_single_or_multiple_L2_ok(self):
        umt_data = umt.UnicastMasterTable()
        err_msg = umt_data.add("table_id", "1")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("logQueryInterval", "-1")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("peer_address", "1.2.3.4")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("L2", "00:01:02:0F:AB:ff")
        self.assertEqual(err_msg, None)

        # check compliance
        err_msg = umt_data.comply()
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("L2", "00:02:03:0F:AB:ff")
        self.assertEqual(err_msg, None)

        # check compliance
        err_msg = umt_data.comply()
        self.assertEqual(err_msg, None)

    def test_umt_all_with_single_or_multiple_UDPv4_ok(self):
        umt_data = umt.UnicastMasterTable()
        err_msg = umt_data.add("table_id", "2")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("logQueryInterval", "1")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("peer_address", "1.2.3.4")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("UDPv4", "1.1.1.1")
        self.assertEqual(err_msg, None)

        # check compliance
        err_msg = umt_data.comply()
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("UDPv4", "2.2.2.2")
        self.assertEqual(err_msg, None)

        # check compliance
        err_msg = umt_data.comply()
        self.assertEqual(err_msg, None)

    def test_umt_all_with_single_or_multiple_UDPv6_ok(self):
        umt_data = umt.UnicastMasterTable()
        err_msg = umt_data.add("table_id", "2")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("logQueryInterval", "1")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("peer_address", "ff01::1")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("UDPv6", "::1")
        self.assertEqual(err_msg, None)

        # check compliance
        err_msg = umt_data.comply()
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("UDPv6", "ffff:ABCD:EF00::")
        self.assertEqual(err_msg, None)

        # check compliance
        err_msg = umt_data.comply()
        self.assertEqual(err_msg, None)

    def test_umt_table_id_fail(self):
        umt_data = umt.UnicastMasterTable()
        err_msg = umt_data.add("table_id", "-1")
        self.assertEqual(err_msg, "not positive integer")

        err_msg = umt_data.add("table_id", "0")
        self.assertEqual(err_msg, "not positive integer")

        err_msg = umt_data.add("table_id", "xx")
        self.assertEqual(err_msg, "not positive integer")

        err_msg = umt_data.add("table_id", "1")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("table_id", "2")
        self.assertEqual(err_msg, None)

        # check compliance
        repetition_err = "Repetition/Duplication not supported for parameter: table_id"
        err_msg = umt_data.comply()
        self.assertEqual(err_msg, repetition_err)

    def test_umt_logQueryInterval_fail(self):
        umt_data = umt.UnicastMasterTable()
        err_msg = umt_data.add("logQueryInterval", "xx")
        self.assertEqual(err_msg, "not integer")

        err_msg = umt_data.add("logQueryInterval", "-2")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("logQueryInterval", "10")
        self.assertEqual(err_msg, None)

        # check compliance
        repetition_err = "Repetition/Duplication not supported for parameter: logQueryInterval"
        err_msg = umt_data.comply()
        self.assertEqual(err_msg, repetition_err)

    def test_umt_peer_address_fail(self):
        umt_data = umt.UnicastMasterTable()
        err_msg = umt_data.add("peer_address", "xx")
        self.assertEqual(err_msg, "not IPv4/6 address")

        err_msg = umt_data.add("peer_address", "1.1.1")
        self.assertEqual(err_msg, "not IPv4/6 address")

        err_msg = umt_data.add("peer_address", "1.1.1.1.")
        self.assertEqual(err_msg, "not IPv4/6 address")

        err_msg = umt_data.add("peer_address", "ff::ee::")
        self.assertEqual(err_msg, "not IPv4/6 address")

        err_msg = umt_data.add("peer_address", "1.2.3.4")
        self.assertEqual(err_msg, None)

        err_msg = umt_data.add("peer_address", "FFff::")
        self.assertEqual(err_msg, None)

        # check compliance
        repetition_err = "Repetition/Duplication not supported for parameter: peer_address"
        err_msg = umt_data.comply()
        self.assertEqual(err_msg, repetition_err)

    def test_umt_L2_fail(self):
        umt_data = umt.UnicastMasterTable()
        err_msg = umt_data.add("L2", ":")
        self.assertEqual(err_msg, "not MAC address")

        err_msg = umt_data.add("L2", "1")
        self.assertEqual(err_msg, "not MAC address")

        err_msg = umt_data.add("L2", "1.2.3.4")
        self.assertEqual(err_msg, "not MAC address")

    def test_umt_UDPv4_fail(self):
        umt_data = umt.UnicastMasterTable()
        err_msg = umt_data.add("UDPv4", "::")
        self.assertEqual(err_msg, "not IPv4 address")

        err_msg = umt_data.add("UDPv4", "ffff::")
        self.assertEqual(err_msg, "not IPv4 address")

        err_msg = umt_data.add("UDPv4", "1.1.1")
        self.assertEqual(err_msg, "not IPv4 address")

    def test_umt_UDPv6_fail(self):
        umt_data = umt.UnicastMasterTable()
        err_msg = umt_data.add("UDPv6", "1.2.3.4")
        self.assertEqual(err_msg, "not IPv6 address")

        err_msg = umt_data.add("UDPv6", "1")
        self.assertEqual(err_msg, "not IPv6 address")

        err_msg = umt_data.add("UDPv6", "ff::ff::")
        self.assertEqual(err_msg, "not IPv6 address")

    def _mix_fail(self, parameters):
        err_mixed = "L2 or UPPv4 or UDPv6, these parameters can not be mixed"
        umt_data = umt.UnicastMasterTable()
        for param_keypair in parameters:
            (param_name, param_value) = param_keypair.split("=", 1)
            err_msg = umt_data.add(param_name, param_value)
            self.assertEqual(err_msg, None)

        # check compliance
        err_msg = umt_data.comply()
        self.assertEqual(err_msg, err_mixed)

    def test_umt_mix_transport_fail(self):
        l2_param = "L2=00:01:02:0F:AB:ff"
        udpv4_param = "UDPv4=1.1.1.1"
        udpv6_param = "UDPv6=ffff:ABCD:EF00::"
        parameters = [l2_param, udpv4_param, udpv6_param]
        self._mix_fail(parameters)
        parameters = [l2_param, udpv4_param]
        self._mix_fail(parameters)
        parameters = [l2_param, udpv6_param]
        self._mix_fail(parameters)
        parameters = [udpv4_param, udpv6_param]
        self._mix_fail(parameters)
