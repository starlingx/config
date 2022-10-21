#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for sysinv agent lldp

Developer Notes:
subprocess.Popen is used in sysinv.agent.lldp.drivers.lldpd.driver
which mean it needs to be mocked in that namespace
ie:  @mock.patch('sysinv.agent.lldp.drivers.lldpd.driver.subprocess.Popen')
"""

import json
import mock
import os

from sysinv.agent.lldp.drivers.lldpd.driver import SysinvLldpdAgentDriver
from sysinv.common import constants

from sysinv.tests import base


def load_data(version_dir, data_file):
    """
    Utility method to load a data file for a particular version
    Loads data from <unit test location>/data/<version_dir>/<data_file>
    Returns the data as a string
    """
    test_path = os.path.abspath(os.path.dirname(__file__))
    target_file = os.path.join(test_path, "lldp_data", version_dir, data_file)
    data_contents = None
    with open(target_file, "r") as f:
        data_contents = json.dumps(json.load(f))
    return data_contents


class LldpInterfaceDetailTestsMixin(object):
    """
    This is an abstract mixin to be used with the lldp tests
    When a new version is supported, all the properly named json files
    must be staged in that version_dir

    The 'version_dir' attribute MUST exist

    The following files must exist in that directory:
      lldp_show_configuration.json
      lldp_show_interface_detail.json
      lldp_show_neighbor_detail.json
      lldp_show_neighbor_summary.json
      lldp_show_chassis.json
    """
    def setUp(self):
        super(LldpInterfaceDetailTestsMixin, self).setUp()
        self.driver = SysinvLldpdAgentDriver()
        self.agent_list_data = load_data(self.version_dir,
                                         "lldp_show_interface_detail.json")
        self.agent_status_data = load_data(self.version_dir,
                                           "lldp_show_configuration.json")
        self.neighbours_list_data = load_data(self.version_dir,
                                              "lldp_show_neighbor_detail.json")
        self.show_chassis_data = load_data(self.version_dir,
                                           "lldp_show_chassis.json")
        self.neighbours_summary_data = load_data(self.version_dir,
                                                 "lldp_show_neighbor_summary.json")

    def test_initialize(self):
        """
        Verify initialize method
        Initialize clears the internal values. This test
        checks if one of those values gets cleared.
        """
        test_value = "MOCK CLIENT"
        self.driver.client = test_value
        self.driver.initialize()
        self.assertNotEqual(test_value, self.driver.client)

    def test_lldp_agents_clear(self):
        """
        Test the lldp_agents_clear method works.
        It clears some internal attributes including
        the current_agents
        """
        self.driver.current_agents = ["SOME AGENT",
                                      "SOME OTHER AGENT"]
        self.driver.lldp_agents_clear()
        self.assertEqual(0, len(self.driver.current_agents))

    def test_lldp_neighbours_clear(self):
        """
        Test the lldp_neighbours_clear method works.
        It clears some internal attributes including
        the current_neighbors
        """
        self.driver.current_neighbours = ["SOME NEIGHBOR",
                                          "SOME OTHER NEIGHBOR"]
        self.driver.lldp_neighbours_clear()
        self.assertEqual(0, len(self.driver.current_neighbours))

    @mock.patch('sysinv.agent.lldp.drivers.lldpd.driver.subprocess.Popen')
    def test_get_agent_status(self, mock_popen):
        """
        Verify _lldpd_get_agent_status
        That method processes output of: 'lldpcli -f json show configuration'
        The expected value is a string which is based on an rx-only attribute
        The sample data must have the rx-only value set to "no" for this test to pass.
        """
        # mock the results from the subprocess call to the CLI to return the json data
        error_data = None
        mock_comm = mock.Mock()
        attrs = {'communicate.return_value': (self.agent_status_data, error_data)}
        mock_comm.configure_mock(**attrs)
        mock_popen.return_value = mock_comm

        expected_status = "rx=enabled,tx=enabled"

        # Call the driver method to trigger the mock subprocess call
        parsed_status = self.driver._lldpd_get_agent_status()

        self.assertEqual(expected_status, parsed_status)

    @mock.patch('sysinv.agent.lldp.drivers.lldpd.driver.SysinvLldpdAgentDriver._lldpd_get_agent_status')
    @mock.patch('sysinv.agent.lldp.drivers.lldpd.driver.subprocess.Popen')
    def test_agent_list(self, mock_popen, mock_status):
        """
        Verify lldp_agents_list
        That method processes output of: 'lldpcli -f json show interface detail'
        The expected value is a list of Agents
        """
        # mock the results from the subprocess call to the CLI to return the json data
        error_data = None
        mock_comm = mock.Mock()
        attrs = {'communicate.return_value': (self.agent_list_data, error_data)}
        mock_comm.configure_mock(**attrs)
        mock_popen.return_value = mock_comm

        # mock _lldpd_get_agent_status to return a fixed string
        mock_status.return_value = "rx=enabled,tx=enabled"

        # Pass the data to the driver.
        agents = self.driver.lldp_agents_list()

        # Validate the agents have been parsed
        self.assertEqual(self.num_expected_agents, len(agents))

    @mock.patch('sysinv.agent.lldp.drivers.lldpd.driver.subprocess.Popen')
    def test_lldp_neighbours_list(self, mock_popen):
        """
        Verify lldp_neighbours_list
        That method processes output of: 'lldpcli -f json show neighbor detail'
        The expected value is a list of Neighbors
        """
        # mock the results from the subprocess call to the CLI to return the json data
        error_data = None
        mock_comm = mock.Mock()
        attrs = {'communicate.return_value': (self.neighbours_list_data, error_data)}
        mock_comm.configure_mock(**attrs)
        mock_popen.return_value = mock_comm

        # Call the driver method to trigger the mock subprocess call
        neighbors = self.driver.lldp_neighbours_list()

        # Validate the neighbors have been parsed correctly
        self.assertEqual(self.num_expected_neighbors, len(neighbors))
        for n in neighbors:
            self.assertEqual(self.expected_neighbor_ttl, n.ttl)

    @mock.patch('sysinv.agent.lldp.drivers.lldpd.driver.subprocess.Popen')
    def test_lldp_update_systemname(self, mock_popen):
        """
        Verify lldp_update_systemname
        That method processes output of: 'lldpcli -f json show chassis'
        It then invokes 'lldpcli configure system hostname' which is mocked
        """
        # mock the results from the subprocess call to the CLI to return the json data
        error_data = None
        mock_comm = mock.Mock()
        attrs = {'communicate.return_value': (self.show_chassis_data, error_data)}
        mock_comm.configure_mock(**attrs)
        mock_popen.return_value = mock_comm

        # Call the driver method to trigger the mock subprocess call
        # A second subprocess call is also invoked. We can use the same
        # mocked Popen for it, since its results are ignored.
        # If a chassis is not found, the second call is not made
        systemname = 'test_system'
        self.driver.lldp_update_systemname(systemname)
        # the newname is 'hostname:systemname' where hostname comes from the json
        newname = self.hostname + ":" + systemname

        # the mocked process was called twice.  We only care about the second call
        mock_popen.assert_called_with(
            ["lldpcli", "configure", "system", "hostname", newname], stdout=mock.ANY)

    def test_config_controller(self):
        """
        See controllerconfig/controllerconfig/controllerconfig/config_management.py
        This test isolates the code in the large methods that interact with lldp
        This just tests that the parsed results in config controller are valid
        """
        lldpcli_show_output = self.neighbours_summary_data
        # step 1. call load
        lldp_interfaces = json.loads(lldpcli_show_output)['lldp'][0]['interface']
        # step 2. walk the list
        for interface in lldp_interfaces:
            i_name = interface['name']
            i_val = interface['port'][0]['id'][0]['value']
            self.assertIn(i_name, self.expected_neighbor_interfaces)
            self.assertIn(i_val, self.expected_neighbor_port_ids)


# Centos environment is shipped with lldpcli version 0.9.0
class TestCentosLldpInterfaceDetail(LldpInterfaceDetailTestsMixin,
                                    base.TestCase):
    version_dir = "0.9.0"
    hostname = "controller-0"
    # num_expected_agents
    # parsed from lldp_show_interface_detail.json
    num_expected_agents = 5
    # num_expected_neighbors and expected_neighbor_ttl
    # parsed from  lldp_show_neighbor_detail.json
    num_expected_neighbors = 1
    expected_neighbor_ttl = "3544"
    # expected_neighbor_interfaces and expected_neighbor_port_ids
    # parsed from  lldp_show_neighbor_summary.json
    # centos has the port value as a 'ifname'
    expected_neighbor_interfaces = ["eno1", ]
    expected_neighbor_port_ids = ["Gi0/39"]

    def setUp(self):
        super(TestCentosLldpInterfaceDetail, self).setUp()
        self.mocked_get_os_type = mock.patch(
            'sysinv.common.utils.get_os_type',
            return_value=constants.OS_CENTOS)
        self.mocked_get_os_type.start()
        self.addCleanup(self.mocked_get_os_type.stop)


class TestDebianLldpInterfaceDetail(LldpInterfaceDetailTestsMixin,
                                    base.TestCase):
    version_dir = "1.0.11"
    hostname = "controller-0"
    # num_expected_agents
    # parsed from lldp_show_interface_detail.json
    num_expected_agents = 5
    # num_expected_neighbors and expected_neighbor_ttl
    # are parsed from  lldp_show_neighbor_detail.json
    num_expected_neighbors = 2
    expected_neighbor_ttl = "120"
    # expected_neighbor_interfaces and expected_neighbor_port_ids
    # parsed from  lldp_show_neighbor_summary.json
    # debian has the port value as a 'mac'
    expected_neighbor_interfaces = ["enp0s3", ]
    expected_neighbor_port_ids = ["0a:00:27:00:00:0d"]

    def setUp(self):
        super(TestDebianLldpInterfaceDetail, self).setUp()
        self.mocked_get_os_type = mock.patch(
            'sysinv.common.utils.get_os_type',
            return_value=constants.OS_DEBIAN)
        self.mocked_get_os_type.start()
        self.addCleanup(self.mocked_get_os_type.stop)
