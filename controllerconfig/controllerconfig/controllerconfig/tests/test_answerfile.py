"""
Copyright (c) 2014 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import difflib
import filecmp
import os
from mock import patch

import controllerconfig.configassistant as ca
import controllerconfig.common.constants as constants


@patch('controllerconfig.configassistant.get_rootfs_node')
@patch('controllerconfig.configassistant.get_net_device_list')
def _test_answerfile(tmpdir, filename,
                     mock_get_net_device_list,
                     mock_get_rootfs_node,
                     compare_results=True):
    """ Test import and generation of answerfile """
    mock_get_net_device_list.return_value = \
        ['eth0', 'eth1', 'eth2']
    mock_get_rootfs_node.return_value = '/dev/sda'

    assistant = ca.ConfigAssistant()

    # Create the path to the answerfile
    answerfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", filename)

    # Input the config from the answerfile
    assistant.input_config_from_file(answerfile)

    # Test the display method
    print "Output from display_config:"
    assistant.display_config()

    # Ensure we can write the configuration
    constants.CONFIG_WORKDIR = os.path.join(str(tmpdir), 'config_workdir')
    constants.CGCS_CONFIG_FILE = os.path.join(constants.CONFIG_WORKDIR,
                                              'cgcs_config')
    assistant.write_config_file()

    # Add the password to the generated file so it can be compared with the
    # answerfile
    with open(constants.CGCS_CONFIG_FILE, 'a') as f:
        f.write("\n[cAUTHENTICATION]\nADMIN_PASSWORD=Li69nux*\n")

    # Do a diff between the answerfile and the generated config file
    print "\n\nDiff of answerfile vs. generated config file:\n"
    with open(answerfile) as a, open(constants.CGCS_CONFIG_FILE) as b:
        a_lines = a.readlines()
        b_lines = b.readlines()

        differ = difflib.Differ()
        diff = differ.compare(a_lines, b_lines)
        print(''.join(diff))

    if compare_results:
        # Fail the testcase if the answerfile and generated config file don't
        # match.
        assert filecmp.cmp(answerfile, constants.CGCS_CONFIG_FILE)


def test_answerfile_default(tmpdir):
    """ Test import of answerfile with default values """

    _test_answerfile(tmpdir, "cgcs_config.default")


def test_answerfile_ipv6(tmpdir):
    """ Test import of answerfile with ipv6 oam values """

    _test_answerfile(tmpdir, "cgcs_config.ipv6")


def test_answerfile_ceph(tmpdir):
    """ Test import of answerfile with ceph backend values """

    _test_answerfile(tmpdir, "cgcs_config.ceph")


def test_answerfile_region(tmpdir):
    """ Test import of answerfile with region values """

    _test_answerfile(tmpdir, "cgcs_config.region")


def test_answerfile_region_nuage_vrs(tmpdir):
    """ Test import of answerfile with region values for nuage_vrs"""

    _test_answerfile(tmpdir, "cgcs_config.region_nuage_vrs")
