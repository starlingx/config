#
# SPDX-License-Identifier: Apache-2.0
#

import io
import mock
import six  # pylint: disable=unused-import
import sys
import testtools


class TsConfigTestCase(testtools.TestCase):

    mock_19_01_build = u"""
###
### StarlingX
###     Release 19.01
###

OS="centos"
SW_VERSION="19.01"
BUILD_TARGET="Host Installer"
BUILD_TYPE="Formal"
BUILD_ID="f/stein"

JOB="STX_build_stein_master"
BUILD_BY="starlingx.build@cengn.ca"
BUILD_NUMBER="52"
BUILD_HOST="starlingx_mirror"
BUILD_DATE="2019-02-22 19:18:29 +0000"
"""

    mock_malformed_build = u"""
###
### StarlingX
###     Release 19.01
nodetype=
"""

    mock_platform_conf_empty = u""

    # Note: subfunction list cannot contain spaces
    mock_platform_conf_minimal = u"""
nodetype=something
subfunction= subfunction1,subfunction2
"""

    mock_platform_conf = u"""
nodetype=controller
subfunction=controller
system_type=Standard
security_profile=extended
management_interface=enp10s0f1
http_port=8080
INSTALL_UUID=ab0a5348-cea7-4b08-b1b0-09d5527dd227
UUID=a1c581fc-0c74-4e68-b78e-4e26a0695f5d
oam_interface=enp0s3
infrastructure_interface=enp0s4
sdn_enabled=no
region_config=no
system_mode=duplex
sw_version=19.01
security_feature="nopti nospectre_v2"
vswitch_type=ovs-dpdk
"""

    mock_platform_conf_regions = u"""
nodetype=controller
subfunction=controller
system_type=Standard
security_profile=extended
management_interface=enp10s0f1
http_port=8081
INSTALL_UUID=ab0a5348-cea7-4b08-b1b0-09d5527dd227
UUID=a1c581fc-0c74-4e68-b78e-4e26a0695f5d
oam_interface=enp0s3
infrastructure_interface=enp0s4
sdn_enabled=no
region_config=no
region_1_name=Region1
region_2_name=Region2
distributed_cloud_role=CloudRole
system_mode=duplex
sw_version=19.01
security_feature="nopti nospectre_v2"
vswitch_type=ovs-dpdk
"""

    def tearDown(self):
        super(TsConfigTestCase, self).tearDown()
        # These are import tests so unimport tsconfig and tsconfig.tsconfig
        # during teardown, otherwise all the other tests will fail
        try:
            del sys.modules['tsconfig.tsconfig']
            del sys.modules['tsconfig']
        except KeyError:
            print('tsconfig modules failed to import, so no cleanup required')

    # If the build.info file is missing, a special version is returned
    def test_tconfig_missing_build_info(self):
        from tsconfig import tsconfig
        ver = tsconfig.SW_VERSION  # pylint: disable=no-member
        self.assertEqual(ver, "TEST.SW.VERSION")

    # If build info is malformed, the platform.conf is not loaded
    @mock.patch('logging.exception')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isfile', return_value=True)
    def test_tsconfig_missing_version(self,
                                      mock_isfile,
                                      mock_open,
                                      mock_logging_exception):
        # two files are opened by tsconfig.
        # 1st: /etc/build.info
        # 2nd: /etc/platform/platform.conf
        mock_open.return_value = io.StringIO(self.mock_malformed_build)
        from tsconfig import tsconfig
        mock_logging_exception.assert_called_once()

    # This tests the behaviour when the platform.conf is missing
    @mock.patch('logging.exception')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isfile', return_value=True)
    def test_tsconfig_missing_platform_conf(self,
                                            mock_isfile,
                                            mock_open,
                                            mock_logging_exception):
        # two files are opened by tsconfig.
        # 1st: /etc/build.info
        # 2nd: /etc/platform/platform.conf
        mock_open.return_value = io.StringIO(self.mock_19_01_build)
        from tsconfig import tsconfig
        mock_logging_exception.assert_called_once()

    # This tests the behaviour when the platform.conf is empty
    @mock.patch('logging.exception')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isfile', return_value=True)
    def test_tsconfig_empty(self,
                            mock_isfile,
                            mock_open,
                            mock_logging_exception):
        # two files are opened by tsconfig.
        # 1st: /etc/build.info
        # 2nd: /etc/platform/platform.conf
        mock_open.side_effect = [io.StringIO(self.mock_19_01_build),
                                 io.StringIO(self.mock_platform_conf_empty)]
        from tsconfig import tsconfig
        mock_logging_exception.assert_called_once()

    # This tests the behaviour when the platform.conf has the minimal entries
    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isfile', return_value=True)
    def test_tsconfig_minimal(self, mock_isfile, mock_open):
        # two files are opened by tsconfig.
        # 1st: /etc/build.info
        # 2nd: /etc/platform/platform.conf
        mock_open.side_effect = [io.StringIO(self.mock_19_01_build),
                                 io.StringIO(self.mock_platform_conf_minimal)]
        from tsconfig import tsconfig
        val = tsconfig.nodetype
        self.assertEqual(val, "something")
        val = tsconfig.subfunctions
        self.assertEqual(set(val), set(["subfunction1", "subfunction2"]))

    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isfile', return_value=True)
    def test_tsconfig(self, mock_isfile, mock_open):
        # two files are opened by tsconfig.
        # 1st: /etc/build.info
        # 2nd: /etc/platform/platform.conf
        mock_open.side_effect = [io.StringIO(self.mock_19_01_build),
                                 io.StringIO(self.mock_platform_conf)]
        from tsconfig import tsconfig
        ver = tsconfig.SW_VERSION
        self.assertEqual(ver, "19.01")

    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isfile', return_value=True)
    def test_tsconfig_reload(self, mock_isfile, mock_open):
        # two files are opened by tsconfig.
        # 1st: /etc/build.info
        # 2nd: /etc/platform/platform.conf
        # Next two files are loaded as part of reload
        mock_open.side_effect = [io.StringIO(self.mock_19_01_build),
                                 io.StringIO(self.mock_platform_conf),
                                 io.StringIO(self.mock_19_01_build),
                                 io.StringIO(self.mock_platform_conf_regions)]
        from tsconfig import tsconfig
        # Initial platform.conf has no region names
        # reload will set the region 1 and region 2 names
        self.assertIsNone(tsconfig.region_1_name)
        self.assertIsNone(tsconfig.region_2_name)
        # the platform.conf is changed, call load again to see the change
        tsconfig._load()  # pylint: disable=protected-access
        self.assertIsNotNone(tsconfig.region_1_name)
        self.assertIsNotNone(tsconfig.region_2_name)
