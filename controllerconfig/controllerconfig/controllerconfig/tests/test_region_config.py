"""
Copyright (c) 2014-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from __future__ import print_function
from six.moves import configparser
import difflib
import filecmp
import fileinput
import mock
from mock import patch
import os
import pytest
import shutil
import sys

import configutilities.common.exceptions as exceptions
from configutilities import validate, REGION_CONFIG
import controllerconfig.common.keystone as keystone
import test_answerfile

sys.modules['fm_core'] = mock.Mock()

import controllerconfig.systemconfig as cr  # noqa: E402

FAKE_SERVICE_DATA = {u'services': [
    {u'type': u'keystore', u'description': u'Barbican Key Management Service',
     u'enabled': True, u'id': u'9029af23540f4eecb0b7f70ac5e00152',
     u'name': u'barbican'},
    {u'type': u'network', u'description': u'OpenStack Networking service',
     u'enabled': True, u'id': u'85a8a3342a644df193af4b68d5b65ce5',
     u'name': u'neutron'}, {u'type': u'cloudformation',
                            u'description':
                                u'OpenStack Cloudformation Service',
                            u'enabled': True,
                            u'id': u'abbf431acb6d45919cfbefe55a0f27fa',
                            u'name': u'heat-cfn'},
    {u'type': u'object-store', u'description': u'OpenStack object-store',
     u'enabled': True, u'id': u'd588956f759f4bbda9e65a1019902b9c',
     u'name': u'swift'},
    {u'type': u'metering', u'description': u'OpenStack Metering Service',
     u'enabled': True, u'id': u'4c07eadd3d0c45eb9a3b1507baa278ba',
     u'name': u'ceilometer'},
    {u'type': u'volumev2',
     u'description': u'OpenStack Volume Service v2.0 API',
     u'enabled': True, u'id': u'e6e356112daa4af588d9b9dadcf98bc4',
     u'name': u'cinderv2'},
    {u'type': u'volume', u'description': u'OpenStack Volume Service',
     u'enabled': True, u'id': u'505aa37457774e55b545654aa8630822',
     u'name': u'cinder'}, {u'type': u'orchestration',
                           u'description': u'OpenStack Orchestration Service',
                           u'enabled': True,
                           u'id': u'5765bee52eec43bb8e0632ecb225d0e3',
                           u'name': u'heat'},
    {u'type': u'compute', u'description': u'OpenStack Compute Service',
     u'enabled': True, u'id': u'9c46a6ea929f4c52bc92dd9bb9f852ac',
     u'name': u'nova'},
    {u'type': u'identity', u'description': u'OpenStack Identity',
     u'enabled': True, u'id': u'1fe7b1de187b47228fe853fbbd149664',
     u'name': u'keystone'},
    {u'type': u'image', u'description': u'OpenStack Image Service',
     u'enabled': True, u'id': u'd41750c98a864fdfb25c751b4ad84996',
     u'name': u'glance'},
    {u'type': u'database', u'description': u'Trove Database As A Service',
     u'enabled': True, u'id': u'82265e39a77b4097bd8aee4f78e13867',
     u'name': u'trove'},
    {u'type': u'patching', u'description': u'Patching Service',
     u'enabled': True, u'id': u'8515c4f28f9346199eb8704bca4f5db4',
     u'name': u'patching'},
    {u'type': u'platform', u'description': u'SysInv Service', u'enabled': True,
     u'id': u'08758bed8d894ddaae744a97db1080b3', u'name': u'sysinv'},
    {u'type': u'computev3', u'description': u'Openstack Compute Service v3',
     u'enabled': True, u'id': u'959f2214543a47549ffd8c66f98d27d4',
     u'name': u'novav3'}]}

FAKE_ENDPOINT_DATA = {u'endpoints': [
    {u'url': u'http://192.168.204.12:8776/v1/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'505aa37457774e55b545654aa8630822',
     u'id': u'de19beb4a4924aa1ba25af3ee64e80a0',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.12:8776/v1/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'505aa37457774e55b545654aa8630822',
     u'id': u'de19beb4a4924aa1ba25af3ee64e80a1',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:8776/v1/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'505aa37457774e55b545654aa8630822',
     u'id': u'de19beb4a4924aa1ba25af3ee64e80a2',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.102:8774/v2/%(tenant_id)s',
     u'region': u'RegionTwo', u'enabled': True,
     u'service_id': u'9c46a6ea929f4c52bc92dd9bb9f852ac',
     u'id': u'373259a6bbcf493b86c9f9530e86d323',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.102:8774/v2/%(tenant_id)s',
     u'region': u'RegionTwo', u'enabled': True,
     u'service_id': u'9c46a6ea929f4c52bc92dd9bb9f852ac',
     u'id': u'373259a6bbcf493b86c9f9530e86d324',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:8774/v2/%(tenant_id)s',
     u'region': u'RegionTwo', u'enabled': True,
     u'service_id': u'9c46a6ea929f4c52bc92dd9bb9f852ac',
     u'id': u'373259a6bbcf493b86c9f9530e86d324',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.102:8004/v1/%(tenant_id)s',
     u'region': u'RegionTwo', u'enabled': True,
     u'service_id': u'5765bee52eec43bb8e0632ecb225d0e3',
     u'id': u'c51dc9354b5a41c9883ec3871b9fd271',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.102:8004/v1/%(tenant_id)s',
     u'region': u'RegionTwo', u'enabled': True,
     u'service_id': u'5765bee52eec43bb8e0632ecb225d0e3',
     u'id': u'c51dc9354b5a41c9883ec3871b9fd272',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:8004/v1/%(tenant_id)s',
     u'region': u'RegionTwo', u'enabled': True,
     u'service_id': u'5765bee52eec43bb8e0632ecb225d0e3',
     u'id': u'c51dc9354b5a41c9883ec3871b9fd273',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.12:8000/v1', u'region': u'RegionOne',
     u'enabled': True, u'interface': u'admin',
     u'id': u'e132bb9dd0fe459687c3b04074bcb1ac',
     u'service_id': u'abbf431acb6d45919cfbefe55a0f27fa'},
    {u'url': u'http://192.168.204.12:8000/v1', u'region': u'RegionOne',
     u'enabled': True, u'interface': u'internal',
     u'id': u'e132bb9dd0fe459687c3b04074bcb1ad',
     u'service_id': u'abbf431acb6d45919cfbefe55a0f27fa'},
    {u'url': u'http://10.10.10.2:8000/v1', u'region': u'RegionOne',
     u'enabled': True, u'interface': u'public',
     u'id': u'e132bb9dd0fe459687c3b04074bcb1ae',
     u'service_id': u'abbf431acb6d45919cfbefe55a0f27fa'},

    {u'url': u'http://192.168.204.102:8774/v3', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'959f2214543a47549ffd8c66f98d27d4',
     u'id': u'031bfbfd581f4a42b361f93fdc4fe266',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.102:8774/v3', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'959f2214543a47549ffd8c66f98d27d4',
     u'id': u'031bfbfd581f4a42b361f93fdc4fe267',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:8774/v3', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'959f2214543a47549ffd8c66f98d27d4',
     u'id': u'031bfbfd581f4a42b361f93fdc4fe268',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.12:8081/keystone/admin/v2.0',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'1fe7b1de187b47228fe853fbbd149664',
     u'id': u'6fa36df1cc4f4e97a1c12767c8a1159f',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.12:8081/keystone/main/v2.0',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'1fe7b1de187b47228fe853fbbd149664',
     u'id': u'6fa36df1cc4f4e97a1c12767c8a11510',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:8081/keystone/main/v2.0',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'1fe7b1de187b47228fe853fbbd149664',
     u'id': u'6fa36df1cc4f4e97a1c12767c8a11512',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.102:9696/', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'85a8a3342a644df193af4b68d5b65ce5',
     u'id': u'74a7a918dd854b66bb33f1e4e0e768bc',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.102:9696/', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'85a8a3342a644df193af4b68d5b65ce5',
     u'id': u'74a7a918dd854b66bb33f1e4e0e768bd',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:9696/', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'85a8a3342a644df193af4b68d5b65ce5',
     u'id': u'74a7a918dd854b66bb33f1e4e0e768be',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.102:6385/v1', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'08758bed8d894ddaae744a97db1080b3',
     u'id': u'd8ae3a69f08046d1a8f031bbd65381a3',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.102:6385/v1', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'08758bed8d894ddaae744a97db1080b3',
     u'id': u'd8ae3a69f08046d1a8f031bbd65381a4',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:6385/v1', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'08758bed8d894ddaae744a97db1080b5',
     u'id': u'd8ae3a69f08046d1a8f031bbd65381a3',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.12:8004/v1/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'5765bee52eec43bb8e0632ecb225d0e3',
     u'id': u'61ad227efa3b4cdd867618041a7064dc',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.12:8004/v1/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'5765bee52eec43bb8e0632ecb225d0e3',
     u'id': u'61ad227efa3b4cdd867618041a7064dd',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:8004/v1/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'5765bee52eec43bb8e0632ecb225d0e3',
     u'id': u'61ad227efa3b4cdd867618041a7064de',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.12:8888/v1', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'd588956f759f4bbda9e65a1019902b9c',
     u'id': u'be557ddb742e46328159749a21e6e286',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.12:8888/v1/AUTH_$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'd588956f759f4bbda9e65a1019902b9c',
     u'id': u'be557ddb742e46328159749a21e6e287',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.12:8888/v1/AUTH_$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'd588956f759f4bbda9e65a1019902b9c',
     u'id': u'be557ddb742e46328159749a21e6e288',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.102:8777', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'4c07eadd3d0c45eb9a3b1507baa278ba',
     u'id': u'050d07db8c5041288f29020079177f0b',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.102:8777', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'4c07eadd3d0c45eb9a3b1507baa278ba',
     u'id': u'050d07db8c5041288f29020079177f0c',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:8777', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'4c07eadd3d0c45eb9a3b1507baa278ba',
     u'id': u'050d07db8c5041288f29020079177f0d',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.102:5491', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'8515c4f28f9346199eb8704bca4f5db4',
     u'id': u'53af565e4d7245929df7af2ba0ff46db',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.102:5491', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'8515c4f28f9346199eb8704bca4f5db4',
     u'id': u'53af565e4d7245929df7af2ba0ff46dc',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:5491', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'8515c4f28f9346199eb8704bca4f5db4',
     u'id': u'53af565e4d7245929df7af2ba0ff46dd',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.12:8779/v1.0/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'82265e39a77b4097bd8aee4f78e13867',
     u'id': u'9a1cc90a7ac342d0900a0449ca4eabfe',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.12:8779/v1.0/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'82265e39a77b4097bd8aee4f78e13867',
     u'id': u'9a1cc90a7ac342d0900a0449ca4eabfe',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:8779/v1.0/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'82265e39a77b4097bd8aee4f78e13867',
     u'id': u'9a1cc90a7ac342d0900a0449ca4eabfe',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.12:9292/v2', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'd41750c98a864fdfb25c751b4ad84996',
     u'id': u'06fdb367cb63414987ee1653a016d10a',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.12:9292/v2', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'd41750c98a864fdfb25c751b4ad84996',
     u'id': u'06fdb367cb63414987ee1653a016d10b',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:9292/v2', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'd41750c98a864fdfb25c751b4ad84996',
     u'id': u'06fdb367cb63414987ee1653a016d10c',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.102:9292/v2', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'd41750c98a864fdfb25c751b4ad84996',
     u'id': u'06fdb367cb63414987ee1653a016d10a',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.102:9292/v2', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'd41750c98a864fdfb25c751b4ad84996',
     u'id': u'06fdb367cb63414987ee1653a016d10b',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.12:9292/v2', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'd41750c98a864fdfb25c751b4ad84996',
     u'id': u'06fdb367cb63414987ee1653a016d10c',
     u'interface': u'public'},


    {u'url': u'http://192.168.204.12:8777/', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'4c07eadd3d0c45eb9a3b1507baa278ba',
     u'id': u'f15d22a9526648ff8833460e2dce1431',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.12:8777/', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'4c07eadd3d0c45eb9a3b1507baa278ba',
     u'id': u'f15d22a9526648ff8833460e2dce1432',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.12:8777/', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'4c07eadd3d0c45eb9a3b1507baa278ba',
     u'id': u'f15d22a9526648ff8833460e2dce1433',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.102:8000/v1/', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'abbf431acb6d45919cfbefe55a0f27fa',
     u'id': u'5e6c6ffdbcd544f8838430937a0d81a7',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.102:8000/v1/', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'abbf431acb6d45919cfbefe55a0f27fa',
     u'id': u'5e6c6ffdbcd544f8838430937a0d81a8',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:8000/v1/', u'region': u'RegionTwo',
     u'enabled': True,
     u'service_id': u'abbf431acb6d45919cfbefe55a0f27fa',
     u'id': u'5e6c6ffdbcd544f8838430937a0d81a9',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.12:8774/v2/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'9c46a6ea929f4c52bc92dd9bb9f852ac',
     u'id': u'87dc648502ee49fb86a4ca87d8d6028d',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.12:8774/v2/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'9c46a6ea929f4c52bc92dd9bb9f852ac',
     u'id': u'87dc648502ee49fb86a4ca87d8d6028e',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.2:8774/v2/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'9c46a6ea929f4c52bc92dd9bb9f852ac',
     u'id': u'87dc648502ee49fb86a4ca87d8d6028f',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.12:9696/', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'85a8a3342a644df193af4b68d5b65ce5',
     u'id': u'd326bf63f6f94b12924b03ff42ba63bd',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.12:9696/', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'85a8a3342a644df193af4b68d5b65ce5',
     u'id': u'd326bf63f6f94b12924b03ff42ba63be',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.12:9696/', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'85a8a3342a644df193af4b68d5b65ce5',
     u'id': u'd326bf63f6f94b12924b03ff42ba63bf',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.12:8776/v2/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'e6e356112daa4af588d9b9dadcf98bc4',
     u'id': u'61b8bb77edf644f1ad4edf9b953d44c7',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.12:8776/v2/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'e6e356112daa4af588d9b9dadcf98bc4',
     u'id': u'61b8bb77edf644f1ad4edf9b953d44c8',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.12:8776/v2/$(tenant_id)s',
     u'region': u'RegionOne', u'enabled': True,
     u'service_id': u'e6e356112daa4af588d9b9dadcf98bc4',
     u'id': u'61b8bb77edf644f1ad4edf9b953d44c9',
     u'interface': u'public'},

    {u'url': u'http://192.168.204.12:9312/v1', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'9029af23540f4eecb0b7f70ac5e00152',
     u'id': u'a1aa2af22caf460eb421d75ab1ce6125',
     u'interface': u'admin'},
    {u'url': u'http://192.168.204.12:9312/v1', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'9029af23540f4eecb0b7f70ac5e00152',
     u'id': u'a1aa2af22caf460eb421d75ab1ce6126',
     u'interface': u'internal'},
    {u'url': u'http://10.10.10.12:9312/v1', u'region': u'RegionOne',
     u'enabled': True,
     u'service_id': u'9029af23540f4eecb0b7f70ac5e00152',
     u'id': u'a1aa2af22caf460eb421d75ab1ce6127',
     u'interface': u'public'}]}

FAKE_DOMAIN_DATA = {u'domains': [
    {u'id': u'default', u'enabled': True,
     u'description':
         u'Owns users and tenants (i.e. projects) available on Identity API '
         u'v2.',
     u'links': {
         u'self':
             u'http://192.168.204.12:8081/keystone/main/v3/domains/default'},
     u'name': u'Default'},
    {u'id': u'05d847889e9a4cb9aa94f541eb6b9e2e',
     u'enabled': True,
     u'description': u'Contains users and projects created by heat',
     u'links': {
         u'self':
             u'http://192.168.204.12:8081/keystone/main/v3/domains/'
             u'05d847889e9a4cb9aa94f541eb6b9e2e'},
     u'name': u'heat'}],
    u'links': {
    u'self': u'http://192.168.204.12:8081/keystone/main/v3/domains',
    u'next': None,
    u'previous': None}}


def _dump_config(config):
    """ Prints contents of config object """
    for section in config.sections():
        print("[%s]" % section)
        for (name, value) in config.items(section):
            print("%s=%s" % (name, value))


def _replace_in_file(filename, old, new):
    """ Replaces old with new in file filename. """
    for line in fileinput.FileInput(filename, inplace=1):
        line = line.replace(old, new)
        print(line, end='')
    fileinput.close()


@patch('controllerconfig.configassistant.ConfigAssistant.get_wrsroot_sig')
def _test_region_config(tmpdir, inputfile, resultfile,
                        mock_get_wrsroot_sig):
    """ Test import and generation of answerfile """

    mock_get_wrsroot_sig.return_value = None

    # Create the path to the output file
    outputfile = os.path.join(str(tmpdir), 'output')

    # Parse the region_config file
    region_config = cr.parse_system_config(inputfile)

    # Dump results for debugging
    print("Parsed region_config:\n")
    _dump_config(region_config)

    # Validate the region config file
    cr.create_cgcs_config_file(outputfile, region_config,
                               keystone.ServiceList(FAKE_SERVICE_DATA),
                               keystone.EndpointList(FAKE_ENDPOINT_DATA),
                               keystone.DomainList(FAKE_DOMAIN_DATA))

    # Make a local copy of the results file
    local_resultfile = os.path.join(str(tmpdir), 'result')
    shutil.copyfile(resultfile, local_resultfile)

    # Do a diff between the output and the expected results
    print("\n\nDiff of output file vs. expected results file:\n")
    with open(outputfile) as a, open(local_resultfile) as b:
        a_lines = a.readlines()
        b_lines = b.readlines()

        differ = difflib.Differ()
        diff = differ.compare(a_lines, b_lines)
        print(''.join(diff))
    # Fail the testcase if the output doesn't match the expected results
    assert filecmp.cmp(outputfile, local_resultfile)

    # Now test that configassistant can parse this answerfile. We can't
    # compare the resulting cgcs_config file because the ordering, spacing
    # and comments are different between the answerfile generated by
    # systemconfig and ConfigAssistant.
    test_answerfile._test_answerfile(tmpdir, outputfile, compare_results=False)

    # Validate the region config file.
    # Using onboard validation since the validator's reference version number
    # is only set at build-time when validating offboard
    validate(region_config, REGION_CONFIG, None, False)


def test_region_config_simple(tmpdir):
    """ Test import of simple region_config file """

    regionfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "region_config.simple")
    resultfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "region_config.simple.result")

    _test_region_config(tmpdir, regionfile, resultfile)


def test_region_config_simple_can_ips(tmpdir):
    """ Test import of simple region_config file with unit ips for CAN """
    print("IN TEST ################################################")
    regionfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "region_config.simple.can_ips")
    resultfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "region_config.simple.result")

    _test_region_config(tmpdir, regionfile, resultfile)


def test_region_config_lag_vlan(tmpdir):
    """ Test import of region_config file with lag and vlan """

    regionfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "region_config.lag.vlan")
    resultfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "region_config.lag.vlan.result")

    _test_region_config(tmpdir, regionfile, resultfile)


def test_region_config_security(tmpdir):
    """ Test import of region_config file with security config """

    regionfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "region_config.security")
    resultfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "region_config.security.result")
    _test_region_config(tmpdir, regionfile, resultfile)


def test_region_config_nuage_vrs(tmpdir):
    """ Test import of region_config file with nuage vrs config """

    regionfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "region_config.nuage_vrs")
    resultfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "region_config.nuage_vrs.result")
    _test_region_config(tmpdir, regionfile, resultfile)


def test_region_config_share_keystone_only(tmpdir):
    """ Test import of Titanium Cloud region_config file with
        shared keystone  """

    regionfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "TiS_region_config.share.keystoneonly")
    resultfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "TiS_region_config.share.keystoneonly.result")
    _test_region_config(tmpdir, regionfile, resultfile)


def test_region_config_share_keystone_glance_cinder(tmpdir):
    """ Test import of Titanium Cloud region_config file with shared keystone,
        glance and cinder """

    regionfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "TiS_region_config.shareall")
    resultfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "TiS_region_config.shareall.result")
    _test_region_config(tmpdir, regionfile, resultfile)


def test_region_config_validation():
    """ Test detection of various errors in region_config file """

    # Create the path to the region_config files
    simple_regionfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "region_config.simple")
    lag_vlan_regionfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "region_config.lag.vlan")
    nuage_vrs_regionfile = os.path.join(os.getcwd(),
                                        "controllerconfig/tests/files/",
                                        "region_config.nuage_vrs")

    # Test detection of non-required CINDER_* parameters
    region_config = cr.parse_system_config(simple_regionfile)
    region_config.set('STORAGE', 'CINDER_BACKEND', 'lvm')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, True)

    region_config = cr.parse_system_config(simple_regionfile)
    region_config.set('STORAGE', 'CINDER_DEVICE',
                      '/dev/disk/by-path/pci-0000:00:0d.0-ata-3.0')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    region_config = cr.parse_system_config(simple_regionfile)
    region_config.set('STORAGE', 'CINDER_STORAGE', '10')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test detection of an invalid PXEBOOT_CIDR
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.set('REGION2_PXEBOOT_NETWORK', 'PXEBOOT_CIDR',
                      '192.168.1.4/24')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    region_config.set('REGION2_PXEBOOT_NETWORK', 'PXEBOOT_CIDR',
                      'FD00::0000/64')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    region_config.set('REGION2_PXEBOOT_NETWORK', 'PXEBOOT_CIDR',
                      '192.168.1.0/29')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    region_config.remove_option('REGION2_PXEBOOT_NETWORK', 'PXEBOOT_CIDR')
    with pytest.raises(configparser.NoOptionError):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(configparser.NoOptionError):
        validate(region_config, REGION_CONFIG, None, False)

    # Test overlap of CLM_CIDR
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.set('CLM_NETWORK', 'CLM_CIDR', '192.168.203.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test invalid CLM LAG_MODE
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.set('LOGICAL_INTERFACE_1', 'LAG_MODE', '2')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test CLM_VLAN not allowed
    region_config = cr.parse_system_config(simple_regionfile)
    region_config.set('CLM_NETWORK', 'CLM_VLAN', '123')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test CLM_VLAN missing
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.remove_option('CLM_NETWORK', 'CLM_VLAN')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test overlap of BLS_CIDR
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.set('BLS_NETWORK', 'BLS_CIDR', '192.168.203.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    region_config.set('BLS_NETWORK', 'BLS_CIDR', '192.168.204.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test invalid BLS LAG_MODE
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.add_section('LOGICAL_INTERFACE_2')
    region_config.set('LOGICAL_INTERFACE_2', 'LAG_INTERFACE', 'Y')
    region_config.set('LOGICAL_INTERFACE_2', 'LAG_MODE', '3')
    region_config.set('LOGICAL_INTERFACE_2', 'INTERFACE_MTU', '1500')
    region_config.set('LOGICAL_INTERFACE_2', 'INTERFACE_PORTS', 'eth3,eth4')
    region_config.set('BLS_NETWORK', 'BLS_LOGICAL_INTERFACE',
                      'LOGICAL_INTERFACE_2')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test BLS_VLAN overlap
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.set('BLS_NETWORK', 'BLS_VLAN', '123')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test overlap of CAN_CIDR
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.set('CAN_NETWORK', 'CAN_CIDR', '192.168.203.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    region_config.set('CAN_NETWORK', 'CAN_CIDR', '192.168.204.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    region_config.set('CAN_NETWORK', 'CAN_CIDR', '192.168.205.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test invalid CAN LAG_MODE
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.add_section('LOGICAL_INTERFACE_2')
    region_config.set('LOGICAL_INTERFACE_2', 'LAG_INTERFACE', 'Y')
    region_config.set('LOGICAL_INTERFACE_2', 'LAG_MODE', '3')
    region_config.set('LOGICAL_INTERFACE_2', 'INTERFACE_MTU', '1500')
    region_config.set('LOGICAL_INTERFACE_2', 'INTERFACE_PORTS', 'eth3,eth4')
    region_config.set('CAN_NETWORK', 'CAN_LOGICAL_INTERFACE',
                      'LOGICAL_INTERFACE_2')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test CAN_VLAN overlap
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.set('CAN_NETWORK', 'CAN_VLAN', '123')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    region_config.set('CAN_NETWORK', 'CAN_VLAN', '124')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test CAN_VLAN missing
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.remove_option('CAN_NETWORK', 'CAN_VLAN')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test missing gateway
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.remove_option('CLM_NETWORK', 'CLM_GATEWAY')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test two gateways
    region_config = cr.parse_system_config(lag_vlan_regionfile)
    region_config.set('CAN_NETWORK', 'CAN_GATEWAY', '10.10.10.1')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test detection of invalid VSWITCH_TYPE
    region_config = cr.parse_system_config(nuage_vrs_regionfile)
    region_config.set('NETWORK', 'VSWITCH_TYPE', 'invalid')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test detection of neutron in wrong region for VSWITCH_TYPE
    region_config = cr.parse_system_config(nuage_vrs_regionfile)
    region_config.set('NETWORK', 'VSWITCH_TYPE', 'ovs-dpdk')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)

    # Test detection of neutron in wrong region for NUAGE_VRS VSWITCH_TYPE
    region_config = cr.parse_system_config(nuage_vrs_regionfile)
    region_config.remove_option('SHARED_SERVICES', 'NEUTRON_USER_NAME')
    region_config.remove_option('SHARED_SERVICES', 'NEUTRON_PASSWORD')
    region_config.remove_option('SHARED_SERVICES', 'NEUTRON_SERVICE_NAME')
    region_config.remove_option('SHARED_SERVICES', 'NEUTRON_SERVICE_TYPE')
    region_config.set('REGION_2_SERVICES', 'NEUTRON_USER_NAME', 'neutron')
    region_config.set('REGION_2_SERVICES', 'NEUTRON_PASSWORD', 'password2WO*')
    region_config.set('REGION_2_SERVICES', 'NEUTRON_SERVICE_NAME', 'neutron')
    region_config.set('REGION_2_SERVICES', 'NEUTRON_SERVICE_TYPE', 'network')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, region_config, None, None, None,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(region_config, REGION_CONFIG, None, False)
