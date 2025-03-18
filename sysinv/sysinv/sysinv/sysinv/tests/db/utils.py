# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#

"""Sysinv test utilities."""
import uuid

from oslo_serialization import jsonutils as json
from oslo_utils import uuidutils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.db import api as db_api


fake_info = {"foo": "bar"}

ipmi_info = json.dumps(
            {
                'ipmi': {
                    "address": "1.2.3.4",
                    "username": "admin",
                    "password": "fake",
                }
            })

ssh_info = json.dumps(
        {
            'ssh': {
                "address": "1.2.3.4",
                "username": "admin",
                "password": "fake",
                "port": 22,
                "virt_type": "vbox",
                "key_filename": "/not/real/file",
            }
        })

pxe_info = json.dumps(
        {
            'pxe': {
                "instance_name": "fake_instance_name",
                "image_source": "glance://image_uuid",
                "deploy_kernel": "glance://deploy_kernel_uuid",
                "deploy_ramdisk": "glance://deploy_ramdisk_uuid",
                "root_gb": 100,
            }
        })

pxe_ssh_info = json.dumps(
        dict(json.loads(pxe_info), **json.loads(ssh_info)))

pxe_ipmi_info = json.dumps(
        dict(json.loads(pxe_info), **json.loads(ipmi_info)))

properties = {
            "cpu_arch": "x86_64",
            "cpu_num": "8",
            "storage": "1024",
            "memory": "4096",
        }

int_uninitialized = 999

SW_VERSION = '0.0'
SW_VERSION_NEW = '1.0'


def get_test_node(**kw):
    node = {
        'id': kw.get('id'),
        'numa_node': kw.get('numa_node', 0),
        'capabilities': kw.get('capabilities', {}),
        'forihostid': kw.get('forihostid', 1)
    }
    return node


def create_test_node(**kw):
    """Create test inode entry in DB and return inode DB object.
    Function to be used to create test inode objects in the database.
    :param kw: kwargs with overriding values for host's attributes.
    :returns: Test inode DB object.
    """
    node = get_test_node(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del node['id']
    dbapi = db_api.get_instance()
    return dbapi.inode_create(node['forihostid'], node)


def post_get_test_ihost(**kw):
    inv = get_test_ihost(**kw)
    del inv['bm_mac']
    del inv['peer_id']
    del inv['action_state']
    del inv['recordtype']
    del inv['uuid']
    del inv['kernel_running']
    del inv['kernel_config_status']
    return inv


def get_test_ihost(**kw):
    inv = \
        {
            'id': kw.get('id', 123),
            'forisystemid': kw.get('forisystemid', None),
            'peer_id': kw.get('peer_id', None),
            'recordtype': kw.get('recordtype', "standard"),
            'uuid': kw.get('uuid'),
            'hostname': kw.get('hostname', 'sysinvhostname'),
            'invprovision': kw.get('invprovision', 'unprovisioned'),
            'mgmt_mac': kw.get('mgmt_mac',
                                         '01:34:67:9A:CD:FE'),
            'personality': kw.get('personality', 'controller'),
            'administrative': kw.get('administrative', 'locked'),
            'operational': kw.get('operational', 'disabled'),
            'availability': kw.get('availability', 'offduty'),
            'serialid': kw.get('serialid', 'sysinv123456'),
            'bm_ip': kw.get('bm_ip', "128.224.150.193"),
            'bm_mac': kw.get('bm_mac', "a4:5d:36:fc:a5:6c"),
            'bm_type': kw.get('bm_type', constants.HOST_BM_TYPE_DEPROVISIONED),
            'bm_username': kw.get('bm_username', "ihostbmusername"),
            'action': kw.get('action', "none"),
            'task': kw.get('task', None),
            'capabilities': kw.get('capabilities', {}),
            'kernel_running': kw.get('kernel_running', constants.KERNEL_STANDARD),
            'kernel_config_status': kw.get('kernel_config_status', ''),
            'subfunctions': kw.get('subfunctions', "ihostsubfunctions"),
            'subfunction_oper': kw.get('subfunction_oper', "disabled"),
            'subfunction_avail': kw.get('subfunction_avail', "not-installed"),
            'reserved': kw.get('reserved', None),
            'ihost_action': kw.get('ihost_action', None),
            'action_state': kw.get('action_state', constants.HAS_REINSTALLED),
            'mtce_info': kw.get('mtce_info', '0'),
            'vim_progress_status': kw.get('vim_progress_status', "vimprogressstatus"),
            'uptime': kw.get('uptime', 0),
            'config_status': kw.get('config_status', "configstatus"),
            'config_applied': kw.get('config_applied', "config_value"),
            'config_target': kw.get('config_target', "config_value"),
            'location': kw.get('location', {}),
            'boot_device': kw.get('boot_device', 'sda'),
            'rootfs_device': kw.get('rootfs_device', 'sda'),
            'hw_settle': kw.get('hw_settle', '0'),
            'install_output': kw.get('install_output', 'text'),
            'console': kw.get('console', 'ttyS0,115200'),
            'tboot': kw.get('tboot', ''),
            'ttys_dcd': kw.get('ttys_dcd', False),
            'updated_at': None,
            'created_at': None,
            'install_state': kw.get('install_state', None),
            'install_state_info': kw.get('install_state_info', None),
            'iscsi_initiator_name': kw.get('iscsi_initiator_name', None),
            'inv_state': kw.get('inv_state', 'inventoried'),
            'clock_synchronization': kw.get('clock_synchronization', constants.NTP),
            'max_cpu_mhz_configured': kw.get('max_cpu_mhz_configured', ''),
            'min_cpu_mhz_allowed': kw.get('min_cpu_mhz_allowed', ''),
            'max_cpu_mhz_allowed': kw.get('max_cpu_mhz_allowed', ''),
            'cstates_available': kw.get('cstates_available', ''),
            'nvme_host_id': kw.get('nvme_host_id', None),
            'nvme_host_nqn': kw.get('nvme_host_nqn', None),
            'sw_version': kw.get('sw_version', SW_VERSION)
             }
    return inv


def create_test_ihost(**kw):
    """Create test host entry in DB and return Host DB object.
    Function to be used to create test Host objects in the database.
    :param kw: kwargs with overriding values for host's attributes.
    :returns: Test Host DB object.
    """
    host = get_test_ihost(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del host['id']
    dbapi = db_api.get_instance()
    return dbapi.ihost_create(host)


def get_test_isystem(**kw):
    inv = {
            'id': kw.get('id', 321),
            'name': kw.get('hostname', 'sysinvisystemname'),
            'description': kw.get('description', 'isystemdescription'),
            'capabilities': kw.get('capabilities',
                                   {"cinder_backend":
                                        constants.CINDER_BACKEND_LVM,
                                    "vswitch_type":
                                        constants.VSWITCH_TYPE_OVS_DPDK,
                                    "region_config": False,
                                    "sdn_enabled": True,
                                    "shared_services": "[]"}),
            'contact': kw.get('contact', 'isystemcontact'),
            'system_type': kw.get('system_type', constants.TIS_STD_BUILD),
            'system_mode': kw.get('system_mode', constants.SYSTEM_MODE_DUPLEX),
            'region_name': kw.get('region_name', constants.REGION_ONE_NAME),
            'location': kw.get('location', 'isystemlocation'),
            'latitude': kw.get('latitude'),
            'longitude': kw.get('longitude'),
            'services': kw.get('services', 72),
            'software_version': kw.get('software_version', SW_VERSION)
           }
    return inv


def create_test_isystem(**kw):
    """Create test system entry in DB and return System DB object.
    Function to be used to create test System objects in the database.
    :param kw: kwargs with overriding values for system's attributes.
    :returns: Test System DB object.
    """
    system = get_test_isystem(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del system['id']
    dbapi = db_api.get_instance()
    return dbapi.isystem_create(system)


def update_test_isystem(system_dict):
    """Update test system entry in DB and return System DB object.
    Function to be used to create test System objects in the database.
    :param kw: kwargs with overriding values for system's attributes.
    :returns: Test System DB object.
    """
    dbapi = db_api.get_instance()
    return dbapi.isystem_update(system_dict['uuid'], system_dict)


def post_get_test_kube_upgrade(**kw):
    upgrade = get_test_kube_upgrade(**kw)
    del upgrade['id']
    del upgrade['uuid']
    del upgrade['from_version']
    del upgrade['state']
    del upgrade['reserved_1']
    del upgrade['reserved_2']
    del upgrade['reserved_3']
    del upgrade['reserved_4']
    return upgrade


def get_test_kube_upgrade(**kw):
    upgrade = {
        'id': 1,
        'uuid': kw.get('uuid', uuidutils.generate_uuid()),
        "from_version": kw.get('from_version', 'v1.42.1'),
        "to_version": kw.get('to_version', 'v1.42.2'),
        "state": kw.get('state', 'upgrade-started'),
        "recovery_attempts": kw.get('recovery_attempts', 0),
        "reserved_1": "res1",
        "reserved_2": "res2",
        "reserved_3": "res3",
        "reserved_4": "res4",
    }
    return upgrade


def get_test_kube_host_upgrade():
    upgrade = {
        'id': 1,
        'uuid': uuidutils.generate_uuid(),
        "target_version": 'v1.42.1',
        "status": "tbd",
        "reserved_1": "",
        "reserved_2": "",
        "reserved_3": "",
        "reserved_4": "",
        "host_id": 1,
    }
    return upgrade


def get_kube_rootca_update():
    dbapi = db_api.get_instance()
    return dbapi.kube_rootca_update_get_one()


def get_test_kube_rootca_update(**kw):
    rootca_update = {
        'id': 1,
        'uuid': kw.get('uuid', uuidutils.generate_uuid()),
        "from_rootca_cert": kw.get('from_rootca_cert', 'oldCertSerial'),
        "to_rootca_cert": kw.get('to_rootca_cert', 'newCertSerial'),
        "state": kw.get('state', 'update-started'),
        "capabilities": {},
        "reserved_1": "res1",
        "reserved_2": "res2",
        "reserved_3": "res3",
    }
    return rootca_update


def post_get_test_kube_rootca_update(**kw):
    update = get_test_kube_rootca_update(**kw)
    del update['id']
    del update['uuid']
    del update['from_rootca_cert']
    del update['to_rootca_cert']
    del update['state']
    del update['capabilities']
    del update['reserved_1']
    del update['reserved_2']
    del update['reserved_3']
    return update


def get_test_kube_rootca_host_update(**kw):
    rootca_host_update = {
        'id': 1,
        'uuid': kw.get('uuid', uuidutils.generate_uuid()),
        "target_rootca_cert": kw.get('target_rootca_cert', 'newCertSerial'),
        "effective_rootca_cert": kw.get('effective_rootca_cert', 'oldCertSerial'),
        "state": kw.get('state', 'update-started'),
        "host_id": kw.get('host_id', 1),
        "capabilities": {},
        "reserved_1": "res1",
        "reserved_2": "res2",
        "reserved_3": "res3",
    }
    return rootca_host_update


def update_kube_host_upgrade(**kw):
    dbapi = db_api.get_instance()
    host_upgrade = dbapi.kube_host_upgrade_get_by_host(1)
    host_upgrade = dbapi.kube_host_upgrade_update(
        host_upgrade.id, kw)
    return host_upgrade


def create_test_kube_upgrade(**kw):
    upgrade = get_test_kube_upgrade(**kw)

    # Let DB generate ID and uuid
    if 'id' in upgrade:
        del upgrade['id']

    if 'uuid' in upgrade:
        del upgrade['uuid']

    dbapi = db_api.get_instance()
    kube_upgrade = dbapi.kube_upgrade_create(upgrade)
    # Also update the kubeadm version like the API would do.
    dbapi.kube_cmd_version_update(
        {"kubeadm_version": kube_upgrade.to_version.lstrip("v")})
    return kube_upgrade


def create_test_kube_host_upgrade():
    upgrade = get_test_kube_host_upgrade()

    # Let DB generate ID, uuid and host_id
    if 'id' in upgrade:
        del upgrade['id']

    if 'uuid' in upgrade:
        del upgrade['uuid']

    if 'host_id' in upgrade:
        del upgrade['host_id']

    dbapi = db_api.get_instance()
    hostid = 1
    return dbapi.kube_host_upgrade_create(hostid, upgrade)


def create_test_kube_rootca_update(**kw):
    update = get_test_kube_rootca_update(**kw)

    # Let DB generate ID and uuid
    if 'id' in update:
        del update['id']

    if 'uuid' in update:
        del update['uuid']

    dbapi = db_api.get_instance()
    return dbapi.kube_rootca_update_create(update)


def create_test_kube_rootca_host_update(**kw):
    host_update = get_test_kube_rootca_host_update(**kw)

    # Let DB generate ID, uuid and host_id
    if 'id' in host_update:
        del host_update['id']

    if 'uuid' in host_update:
        del host_update['uuid']

    dbapi = db_api.get_instance()
    return dbapi.kube_rootca_host_update_create(host_update['host_id'],
                                                host_update)


# Create test controller file system object
def get_test_controller_fs(**kw):
    controller_fs = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),

        'name': kw.get('name'),
        'size': kw.get('size'),
        'logical_volume': kw.get('logical_volume'),
        'replicated': kw.get('replicated', False),
        'state': kw.get('state'),
        'capabilities': kw.get('capabilities'),

        'forisystemid': kw.get('forisystemid', None),
    }
    return controller_fs


def create_test_controller_fs(**kw):
    controller_fs = get_test_controller_fs(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del controller_fs['id']
    dbapi = db_api.get_instance()
    return dbapi.controller_fs_create(controller_fs)


# Create test user object
def get_test_user(**kw):
    user = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'forisystemid': kw.get('forisystemid', None)
    }
    return user


def create_test_user(**kw):
    user = get_test_user(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del user['id']
    dbapi = db_api.get_instance()
    return dbapi.iuser_create(user)


# Create test helm override object
def get_test_helm_overrides(**kw):
    helm_overrides = {
        'id': kw.get('id'),
        'name': kw.get('name'),
        'namespace': kw.get('namespace'),
        'user_overrides': kw.get('user_overrides', None),
        'system_overrides': kw.get('system_overrides', None),
        'app_id': kw.get('app_id', None)
    }
    return helm_overrides


def create_test_helm_overrides(**kw):
    helm_overrides = get_test_helm_overrides(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del helm_overrides['id']
    dbapi = db_api.get_instance()
    return dbapi.helm_override_create(helm_overrides)


# Create test ntp object
def get_test_ntp(**kw):
    ntp = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'ntpservers': kw.get('ntpservers'),
        'forisystemid': kw.get('forisystemid', None),
        'isystem_uuid': kw.get('isystem_uuid', None)
    }
    return ntp


def create_test_ntp(**kw):
    ntp = get_test_ntp(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del ntp['id']
    dbapi = db_api.get_instance()
    return dbapi.intp_create(ntp)


def post_get_test_ntp(**kw):
    ntp = get_test_ntp(**kw)
    # When invoking a POST the following fields should not be populated:
    del ntp['uuid']
    del ntp['id']
    return ntp


# Create test ptp object
def get_test_ptp(**kw):
    ptp = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'enabled': kw.get('enabled'),
        'system_id': kw.get('system_id', None),
        'mode': kw.get('mode'),
        'transport': kw.get('transport'),
        'mechanism': kw.get('mechanism')
    }
    return ptp


def create_test_ptp(**kw):
    ptp = get_test_ptp(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del ptp['id']
    dbapi = db_api.get_instance()
    return dbapi.ptp_create(ptp)


# Utility functions to create a PTP instance for testing
def get_test_ptp_instance(**kw):
    instance = {
        'type': kw.get('type', constants.PTP_PARAMETER_OWNER_INSTANCE),
        'name': kw.get('name'),
        'service': kw.get('service', constants.PTP_INSTANCE_TYPE_PTP4L)
    }
    return instance


def create_test_ptp_instance(**kw):
    instance = get_test_ptp_instance(**kw)
    dbapi = db_api.get_instance()
    return dbapi.ptp_instance_create(instance)


# Create test ptp_interface object
def get_test_ptp_interface(**kw):
    ptp_interface = {
        'type': kw.get('type', constants.PTP_PARAMETER_OWNER_INTERFACE),
        'name': kw.get('name'),
        'ptp_instance_id': kw.get('ptp_instance_id'),
        'ptp_instance_uuid': kw.get('ptp_instance_uuid')
    }
    return ptp_interface


def create_test_ptp_interface(**kw):
    ptp_interface = get_test_ptp_interface(**kw)
    dbapi = db_api.get_instance()
    return dbapi.ptp_interface_create(ptp_interface)


# Utility functions to create a PTP parameter for testing
def get_test_ptp_parameter(**kw):
    parameter = {
        'name': kw.get('name'),
        'value': kw.get('value', None)
    }
    return parameter


def create_test_ptp_parameter(**kw):
    parameter = get_test_ptp_parameter(**kw)
    dbapi = db_api.get_instance()
    return dbapi.ptp_parameter_create(parameter)


# Create test dns object
def get_test_dns(**kw):
    dns = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'nameservers': kw.get('nameservers'),
        'forisystemid': kw.get('forisystemid', None)
    }
    return dns


def create_test_dns(**kw):
    dns = get_test_dns(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del dns['id']
    dbapi = db_api.get_instance()
    return dbapi.idns_create(dns)


def post_get_test_dns(**kw):
    dns = get_test_dns(**kw)

    # When invoking a POST the following fields should not be populated:
    del dns['uuid']
    del dns['id']

    return dns


# Create test drbd object
def get_test_drbd(**kw):
    drbd = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'forisystemid': kw.get('forisystemid', None),
        'link_util': constants.DRBD_LINK_UTIL_DEFAULT,
        'num_parallel': constants.DRBD_NUM_PARALLEL_DEFAULT,
        'rtt_ms': constants.DRBD_RTT_MS_DEFAULT,
    }
    return drbd


def create_test_drbd(**kw):
    drbd = get_test_drbd(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del drbd['id']
    dbapi = db_api.get_instance()
    return dbapi.drbdconfig_create(drbd)


# Create test remotelogging object
def get_test_remotelogging(**kw):
    remotelogging = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'enabled': kw.get('enabled'),
        'system_id': kw.get('system_id', None)
    }
    return remotelogging


def create_test_remotelogging(**kw):
    dns = get_test_remotelogging(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del dns['id']
    dbapi = db_api.get_instance()
    return dbapi.remotelogging_create(dns)


def get_test_address_pool(**kw):
    inv = {
            'id': kw.get('id'),
            'network': kw.get('network'),
            'name': kw.get('name'),
            'family': kw.get('family', 4),
            'ranges': kw.get('ranges'),
            'prefix': kw.get('prefix'),
            'order': kw.get('order', 'random'),
            'uuid': kw.get('uuid'),
            'controller0_address': kw.get('controller0_address'),
            'controller1_address': kw.get('controller1_address'),
            'floating_address': kw.get('floating_address'),
            'gateway_address': kw.get('gateway_address'),
           }
    return inv


def create_test_address_pool(**kw):
    """Create test address pool entry in DB and return AddressPool DB object.
    Function to be used to create test Address pool objects in the database.
    :param kw: kwargs with overriding values for address pool's attributes.
    :returns: Test Address pool DB object.
    """
    address_pool = get_test_address_pool(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del address_pool['id']
    dbapi = db_api.get_instance()

    floating_address = address_pool.pop('floating_address', None)
    controller0_address = address_pool.pop('controller0_address', None)
    controller1_address = address_pool.pop('controller1_address', None)
    gateway_address = address_pool.pop('gateway_address', None)

    addresses = []
    if floating_address:
        try:
            fl_addr = dbapi.address_get_by_address(floating_address)
            addresses.append(fl_addr)
            address_pool['floating_address_id'] = fl_addr.id
        except Exception:
            pass
    if controller0_address:
        try:
            c0_addr = dbapi.address_get_by_address(controller0_address)
            addresses.append(c0_addr)
            address_pool['controller0_address_id'] = c0_addr.id
        except Exception:
            pass
    if controller1_address:
        try:
            c1_addr = dbapi.address_get_by_address(controller1_address)
            addresses.append(c1_addr)
            address_pool['controller1_address_id'] = c1_addr.id
        except Exception:
            pass
    if gateway_address:
        try:
            gw_addr = dbapi.address_get_by_address(gateway_address)
            addresses.append(gw_addr)
            address_pool['gateway_address_id'] = gw_addr.id
        except Exception:
            pass
    db_address_pool = dbapi.address_pool_create(address_pool)
    for address in addresses:
        dbapi.address_update(address.uuid, {'address_pool_id': db_address_pool.id})
    return db_address_pool


def get_test_address(**kw):
    inv = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'family': kw.get('family'),
        'address': kw.get('address'),
        'prefix': kw.get('prefix'),
        'enable_dad': kw.get('enable_dad', False),
        'name': kw.get('name', None),
        'interface_id': kw.get('interface_id', None),
        'address_pool_id': kw.get('address_pool_id', None),
    }
    return inv


def create_test_address(**kw):
    """Create test address entry in DB and return Address DB object.
    Function to be used to create test Address objects in the database.
    :param kw: kwargs with overriding values for addresses' attributes.
    :returns: Test Address DB object.
    """
    address = get_test_address(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del address['id']
    dbapi = db_api.get_instance()
    return dbapi.address_create(address)


def cleanup_address_table():
    dbapi = db_api.get_instance()
    address_list = dbapi.addresses_get_all()
    for addr in address_list:
        dbapi.address_destroy(addr.uuid)


def get_address_table():
    dbapi = db_api.get_instance()
    address_list = dbapi.addresses_get_all()
    return address_list


def get_interface_address_mode(interface_id):
    dbapi = db_api.get_instance()
    intf_addr_mode_list = dbapi.address_modes_get_by_interface_id(interface_id)
    return intf_addr_mode_list


def get_test_route(**kw):
    inv = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'family': kw.get('family'),
        'network': kw.get('network'),
        'prefix': kw.get('prefix'),
        'gateway': kw.get('gateway'),
        'metric': kw.get('metric', 1),
        'interface_id': kw.get('interface_id', None),
    }
    return inv


def create_test_route(**kw):
    """Create test route entry in DB and return Route DB object.
    Function to be used to create test Route objects in the database.
    :param kw: kwargs with overriding values for route's attributes.
    :returns: Test Route DB object.
    """
    route = get_test_route(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del route['id']
    dbapi = db_api.get_instance()
    interface_id = route.pop('interface_id')
    return dbapi.route_create(interface_id, route)


def create_test_network(**kw):
    """Create test network entry in DB and return Network DB object.
    Function to be used to create test Network objects in the database.
    :param kw: kwargs with overriding values for network's attributes.
    :returns: Test Network DB object.
    """
    network = get_test_network(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del network['id']
    dbapi = db_api.get_instance()
    return dbapi.network_create(network)


def get_test_network(**kw):
    inv = {
            'id': kw.get('id'),
            'uuid': kw.get('uuid'),
            'type': kw.get('type'),
            'dynamic': kw.get('dynamic', True),
            'address_pool_id': kw.get('address_pool_id', None),
            'primary_pool_family': kw.get('primary_pool_family', None),
            'name': kw.get('name', None)
           }
    return inv


def get_network_table():
    dbapi = db_api.get_instance()
    return dbapi.networks_get_all()


def get_test_network_addrpool(**kw):
    inv = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'address_pool_id': kw.get('address_pool_id'),
        'network_id': kw.get('network_id'),
    }
    return inv


def get_post_network_addrpool(**kw):
    inv = {
        'address_pool_uuid': kw.get('address_pool_uuid'),
        'network_uuid': kw.get('network_uuid'),
    }
    return inv


def create_test_network_addrpool(**kw):
    """Create test network-addrpool entry in DB and return NetworkAddresspool DB object.
    Function to be used to create test NetworkAddresspool objects in the database.
    :param kw: kwargs with overriding values for network-addrpool's attributes.
    :returns: Test Network DB object.
    """
    network_addrpool = get_test_network_addrpool(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del network_addrpool['id']
    dbapi = db_api.get_instance()
    return dbapi.network_addrpool_create(network_addrpool)


def cleanup_network_addrpool_table():
    """ Clean up all existing elements in the network_addrpools table
    """
    dbapi = db_api.get_instance()
    network_addrpool_list = dbapi.network_addrpool_get_all()
    for net_pool in network_addrpool_list:
        network_addrpool_list = dbapi.network_addrpool_destroy(net_pool.uuid)


def get_address_pool_table():
    """ Clean up all existing elements in the network_addrpools table
    """
    dbapi = db_api.get_instance()
    return dbapi.address_pools_get_all()


def get_test_icpu(**kw):
    inv = {
            'id': kw.get('id'),
            'uuid': kw.get('uuid'),
            'cpu': kw.get('cpu', int_uninitialized),
            'forinodeid': kw.get('forinodeid', int_uninitialized),
            'core': kw.get('core', int_uninitialized),
            'thread': kw.get('thread', 0),
            # 'coProcessors': kw.get('coProcessors', {}),
            'cpu_family': kw.get('cpu_family', 6),
            'cpu_model': kw.get('cpu_model', 'Intel(R) Core(TM)'),
            'allocated_function': kw.get('allocated_function', 'Platform'),
            'forihostid': kw.get('forihostid', None),  # 321 ?
            'updated_at': None,
            'created_at': None,
             }
    return inv


def get_test_imemory(**kw):
    inv = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),

        'memtotal_mib': kw.get('memtotal_mib', 2528),
        'memavail_mib': kw.get('memavail_mib', 2528),
        'platform_reserved_mib': kw.get('platform_reserved_mib', 1200),
        'node_memtotal_mib': kw.get('node_memtotal_mib', 7753),

        'hugepages_configured': kw.get('hugepages_configured', False),

        'vswitch_hugepages_size_mib': kw.get('vswitch_hugepages_size_mib', 2),
        'vswitch_hugepages_reqd': kw.get('vswitch_hugepages_reqd'),
        'vswitch_hugepages_nr': kw.get('vswitch_hugepages_nr', 256),
        'vswitch_hugepages_avail': kw.get('vswitch_hugepages_avail', 0),

        'vm_hugepages_nr_2M_pending': kw.get('vm_hugepages_nr_2M_pending'),
        'vm_hugepages_nr_1G_pending': kw.get('vm_hugepages_nr_1G_pending'),
        'vm_hugepages_nr_2M': kw.get('vm_hugepages_nr_2M', 1008),
        'vm_hugepages_avail_2M': kw.get('vm_hugepages_avail_2M', 1264),
        'vm_hugepages_nr_1G': kw.get('vm_hugepages_nr_1G', 0),
        'vm_hugepages_avail_1G': kw.get('vm_hugepages_avail_1G'),
        'vm_hugepages_nr_4K': kw.get('vm_hugepages_nr_4K', 131072),

        'vm_hugepages_use_1G': kw.get('vm_hugepages_use_1G', False),
        'vm_hugepages_possible_2M': kw.get('vm_hugepages_possible_2M', 1264),
        'vm_hugepages_possible_1G': kw.get('vm_hugepages_possible_1G', 1),

        'capabilities': kw.get('capabilities', None),
        'forinodeid': kw.get('forinodeid', None),
        'forihostid': kw.get('forihostid', None),
        'updated_at': None,
        'created_at': None,
    }
    return inv


def get_test_idisk(**kw):
    inv = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'device_node': kw.get('device_node'),
        'device_path': kw.get('device_path',
                              '/dev/disk/by-path/pci-0000:00:0d.0-ata-1.0'),
        'device_num': kw.get('device_num', 2048),
        'device_type': kw.get('device_type'),
        'rpm': kw.get('rpm', 'Undetermined'),
        'serial_id': kw.get('serial_id', 'VBf34cf425-ff9d1c77'),
        'forihostid': kw.get('forihostid', 2),
        'foristorid': kw.get('foristorid', 2),
        'foripvid': kw.get('foripvid', 2),
        'available_mib': kw.get('available_mib', 100),
        'updated_at': None,
        'created_at': None,
    }
    return inv


def create_test_idisk(**kw):
    """Create test idisk entry in DB and return idisk DB object.
    Function to be used to create test idisk objects in the database.
    :param kw: kwargs with overriding values for idisk's attributes.
    :returns: Test idisk DB object.
    """
    idisk = get_test_idisk(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del idisk['id']
    if 'foripvid' not in kw:
        del idisk['foripvid']
    if 'foristorid' not in kw:
        del idisk['foristorid']
    dbapi = db_api.get_instance()
    return dbapi.idisk_create(idisk['forihostid'], idisk)


def get_test_stor(**kw):
    stor = {
        'id': kw.get('id', 2),
        'function': kw.get('function'),
        'idisk_uuid': kw.get('idisk_uuid', 2),
        'forihostid': kw.get('forihostid', 2),
        'forilvgid': kw.get('forilvgid', 2),
    }
    return stor


def get_test_mon(**kw):
    mon = {
        'id': kw.get('id', 2),
        'uuid': kw.get('uuid'),

        'device_path': kw.get('device_path', ''),
        'ceph_mon_gib': kw.get('ceph_mon_gib', 20),
        'state': kw.get('state', 'configured'),
        'task': kw.get('task', None),

        'forihostid': kw.get('forihostid', 0),
        'ihost_uuid': kw.get('ihost_uuid', '1be26c0b-03f2-4d2e-ae87-c02d7f33c781'),
        'hostname': kw.get('hostname', 'controller-0'),
    }
    return mon


def get_test_host_fs(**kw):
    host_fs = {
        'id': kw.get('id', 2),
        'uuid': kw.get('uuid'),
        'name': kw.get('name'),
        'size': kw.get('size', 2029),
        'logical_volume': kw.get('logical_volume', 'scratch-lv'),
        'forihostid': kw.get('forihostid', 1),
        'state': kw.get('state'),
        'capabilities': kw.get('capabilities'),
    }
    return host_fs


def create_test_host_fs(**kw):
    host_fs = get_test_host_fs(**kw)
    if 'uuid' not in kw:
        del host_fs['uuid']
    dbapi = db_api.get_instance()
    forihostid = host_fs['forihostid']
    return dbapi.host_fs_create(forihostid, host_fs)


def get_test_istors(**kw):
    istor = {
        'id': kw.get('id', 2),
        'uuid': kw.get('uuid'),
        'forihostid': kw.get('forihostid', 1),
        'ihost_uuid': kw.get('ihost_uuid', '1be26c0b-03f2-4d2e-ae87-c02d7f33c781'),
        'fortierid': kw.get('fortierid', None),
        'tier_uuid': kw.get('tier_uuid', None),
        'tier_name': kw.get('tier_name', None),
        'osdid': kw.get('osdid', 0),
        'idisk_uuid': kw.get('idisk_uuid', '2991d71b-f553-4f1c-bdbe-cc04f69ff830'),
        'state': kw.get('state', 'configuring-with-app'),
        'function': kw.get('function', 'osd'),
        'capabilities': kw.get('capabilities', None),
        'journal_location': kw.get('journal_location', None),
        'journal_size_mib': kw.get('journal_size_mib', None),
        'journal_path': kw.get('journal_path', None)
    }

    return istor


def create_test_istors(**kw):
    istor = get_test_istors(**kw)
    if 'uuid' not in kw:
        del istor['uuid']
    dbapi = db_api.get_instance()
    forihostid = istor['forihostid']
    return dbapi.istor_create(forihostid, istor)


def get_test_lvg(**kw):
    lvg = {
        'id': kw.get('id', 2),
        'uuid': kw.get('uuid'),
        'lvm_vg_name': kw.get('lvm_vg_name'),
        'lvm_vg_size': kw.get('lvm_vg_size', 202903650304),
        'lvm_vg_total_pe': kw.get('lvm_vg_total_pe', 6047),
        'lvm_vg_free_pe': kw.get('lvm_vg_free_pe', 1541),
        'forihostid': kw.get('forihostid', 2),
    }
    return lvg


def create_test_lvg(**kw):
    """Create test lvg entry in DB and return LogicalVolumeGroup DB object.
    Function to be used to create test objects in the database.
    :param kw: kwargs with overriding values for attributes.
    kw requires: lvm_vg_name
    :returns: Test LogicalVolumeGroup DB object.
    """
    lvg = get_test_lvg(**kw)
    if 'uuid' not in kw:
        del lvg['uuid']
    dbapi = db_api.get_instance()
    forihostid = lvg['forihostid']
    return dbapi.ilvg_create(forihostid, lvg)


def get_test_pv(**kw):
    pv = {
        'id': kw.get('id', 2),
        'uuid': kw.get('uuid'),
        'pv_state': kw.get('pv_state', 'unprovisioned'),
        'lvm_vg_name': kw.get('lvm_vg_name'),
        'disk_or_part_uuid': kw.get('disk_or_part_uuid', str(uuid.uuid4())),
        'disk_or_part_device_path': kw.get('disk_or_part_device_path',
            '/dev/disk/by-path/pci-0000:00:0d.0-ata-3.0'),
        'forihostid': kw.get('forihostid', 2),
        'forilvgid': kw.get('forilvgid', 2),
    }
    return pv


def create_test_pv(**kw):
    """Create test pv entry in DB and return PV DB object.
    Function to be used to create test PV objects in the database.
    :param kw: kwargs with overriding values for pv's attributes.
    kw typically requires forihostid, forilvgid
    :returns: Test PV DB object.
    """
    pv = get_test_pv(**kw)
    if 'uuid' not in kw:
        del pv['uuid']
    dbapi = db_api.get_instance()
    forihostid = pv['forihostid']
    return dbapi.ipv_create(forihostid, pv)


def post_get_test_pv(**kw):
    pv = get_test_pv(**kw)

    # When invoking a POST the following fields should not be populated:
    del pv['uuid']
    del pv['id']

    return pv


def get_test_storage_backend(**kw):
    inv = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'backend': kw.get('backend', None),
        'state': kw.get('state', None),
        'task': kw.get('task', None),
        'services': kw.get('services', None),
        'capabilities': kw.get('capabilities', {}),
        'forisystemid': kw.get('forisystemid', None)
    }
    return inv


def get_test_ceph_storage_backend(**kw):
    inv = {
        'id': kw.get('id', 2),
        'uuid': kw.get('uuid'),
        'name': kw.get('name', constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH]),
        'backend': kw.get('backend', constants.SB_TYPE_CEPH),
        'state': kw.get('state', None),
        'task': kw.get('task', None),
        'services': kw.get('services', None),
        'tier_id': kw.get('tier_id'),
        'capabilities': kw.get('capabilities', constants.CEPH_BACKEND_CAP_DEFAULT),
        'forisystemid': kw.get('forisystemid', None),
        'cinder_pool_gib': kw.get('cinder_pool_gib', 80),
        'glance_pool_gib': kw.get('glance_pool_gib', 10),
        'ephemeral_pool_gib': kw.get('ephemeral_pool_gib', 0),
        'object_pool_gib': kw.get('object_pool_gib', 0),
        'object_gateway': kw.get('object_gateway', False)
    }
    return inv


def get_test_file_storage_backend(**kw):
    inv = {
        'id': kw.get('id', 3),
        'uuid': kw.get('uuid'),
        'name': kw.get('name', constants.SB_DEFAULT_NAMES[constants.SB_TYPE_FILE]),
        'backend': kw.get('backend', constants.SB_TYPE_FILE),
        'state': kw.get('state', None),
        'task': kw.get('task', None),
        'services': kw.get('services', None),
        'capabilities': kw.get('capabilities', {}),
        'forisystemid': kw.get('forisystemid', None)
    }
    return inv


def get_test_lvm_storage_backend(**kw):
    inv = {
        'id': kw.get('id', 4),
        'uuid': kw.get('uuid'),
        'name': kw.get('name', constants.SB_DEFAULT_NAMES[constants.SB_TYPE_LVM]),
        'backend': kw.get('backend', constants.SB_TYPE_LVM),
        'state': kw.get('state', None),
        'task': kw.get('task', None),
        'services': kw.get('services', None),
        'capabilities': kw.get('capabilities', {}),
        'forisystemid': kw.get('forisystemid', None)
    }
    return inv


def get_test_ceph_rook_storage_backend(**kw):
    storage_ceph_rook = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'backend': kw.get('backend', constants.SB_TYPE_CEPH_ROOK),
        'name': kw.get('name',
                       constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH_ROOK]),
        'state': kw.get('state', None),
        'task': kw.get('task', None),
        'services': kw.get('services', "{},{}".format(
            constants.SB_SVC_CEPH_ROOK_BLOCK,
            constants.SB_SVC_CEPH_ROOK_FILESYSTEM)),
        'capabilities': kw.get('capabilities',
                               constants.CEPH_ROOK_BACKEND_CAP_DEFAULT),
        'forisystemid': kw.get('forisystemid', None),
    }
    return storage_ceph_rook


def create_ceph_rook_storage_backend(**kw):
    """Create test Rook storage backend in DB and return DB object.

    :param kw: kwargs with overriding values for datanework attributes.
    :returns: Test datanetwork DB object.
    """
    rook_backend = get_test_ceph_rook_storage_backend(**kw)

    if 'uuid' not in kw:
        del rook_backend['uuid']

    dbapi = db_api.get_instance()
    return dbapi.storage_backend_create(rook_backend)


def get_test_port(**kw):
    port = {
        'id': kw.get('id', 987),
        'uuid': kw.get('uuid', '1be26c0b-03f2-4d2e-ae87-c02d7f33c781'),
        'host_id': kw.get('host_id'),
        'node_id': kw.get('node_id'),
        'interface_id': kw.get('interface_id'),
        'name': kw.get('name'),
        'pciaddr': kw.get('pciaddr'),
        'pclass': kw.get('pclass'),
        'pvendor': kw.get('pvendor'),
        'psdevice': kw.get('psdevice'),
        'dpdksupport': kw.get('dpdksupport'),
        'numa_node': kw.get('numa_node'),
        'dev_id': kw.get('dev_id'),
        'sriov_totalvfs': kw.get('sriov_totalvfs'),
        'sriov_numvfs': kw.get('sriov_numvfs'),
        'sriov_vfs_pci_address': kw.get('sriov_vfs_pci_address'),
        'sriov_vf_driver': kw.get('sriov_vf_driver'),
        'sriov_vf_pdevice_id': kw.get('sriov_vf_pdevice_id'),
        'driver': kw.get('driver'),
        'capabilities': kw.get('capabilities'),
        'created_at': kw.get('created_at'),
        'updated_at': kw.get('updated_at'),
    }

    return port


def get_test_chassis(**kw):
    chassis = {
        'id': kw.get('id', 42),
        'uuid': kw.get('uuid', 'e74c40e0-d825-11e2-a28f-0800200c9a66'),
        'extra': kw.get('extra', {}),
        'description': kw.get('description', 'data-center-1-chassis'),
        'created_at': kw.get('created_at'),
        'updated_at': kw.get('updated_at'),
    }

    return chassis


def get_test_ethernet_port(**kw):
    ethernet_port = {
        'id': kw.get('id', 24),
        'mac': kw.get('mac', '08:00:27:ea:93:8e'),
        'mtu': kw.get('mtu', '1500'),
        'speed': kw.get('speed', 1000),
        'link_mode': kw.get('link_mode', 0),
        'duplex': kw.get('duplex', None),
        'autoneg': kw.get('autoneg', None),
        'bootp': kw.get('bootp', None),
        'name': kw.get('name'),
        'host_id': kw.get('host_id'),
        'interface_id': kw.get('interface_id'),
        'interface_uuid': kw.get('interface_uuid'),
        'pciaddr': kw.get('pciaddr'),
        'pdevice': kw.get('pdevice'),
        'pvendor': kw.get('pvendor'),
        'dpdksupport': kw.get('dpdksupport'),
        'dev_id': kw.get('dev_id'),
        'sriov_totalvfs': kw.get('sriov_totalvfs'),
        'sriov_numvfs': kw.get('sriov_numvfs'),
        'sriov_vf_driver': kw.get('sriov_vf_driver'),
        'sriov_vf_pdevice_id': kw.get('sriov_vf_pdevice_id'),
        'sriov_vfs_pci_address': kw.get('sriov_vfs_pci_address'),
        'driver': kw.get('driver'),
        'numa_node': kw.get('numa_node', -1)
    }
    return ethernet_port


def get_test_datanetwork(**kw):
    datanetwork = {
        'uuid': kw.get('uuid'),
        'name': kw.get('name'),
        'network_type': kw.get('network_type', 'vxlan'),
        'mtu': kw.get('mtu', '1500'),
        'multicast_group': kw.get('multicast_group', '239.0.2.1'),
        'port_num': kw.get('port_num', 8472),
        'ttl': kw.get('ttl', 10),
        'mode': kw.get('mode', 'dynamic'),
    }
    return datanetwork


def create_test_datanetwork(**kw):
    """Create test datanetwork entry in DB and return datanetwork DB object.
    Function to be used to create test datanetwork objects in the database.
    :param kw: kwargs with overriding values for datanework attributes.
    :returns: Test datanetwork DB object.
    """
    datanetwork = get_test_datanetwork(**kw)

    if 'uuid' not in kw:
        del datanetwork['uuid']

    if kw['network_type'] != constants.DATANETWORK_TYPE_VXLAN:
        # Remove DB fields which are specific to VXLAN
        del datanetwork['multicast_group']
        del datanetwork['port_num']
        del datanetwork['ttl']
        del datanetwork['mode']

    dbapi = db_api.get_instance()
    return dbapi.datanetwork_create(datanetwork)


def create_test_ethernet_port(**kw):
    """Create test ethernet port entry in DB and return ethernet port DB object.
    Function to be used to create test ethernet port objects in the database.
    :param kw: kwargs with overriding values for ethernet port's attributes.
    :returns: Test ethernet port DB object.
    """
    ethernet_port = get_test_ethernet_port(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del ethernet_port['id']
    dbapi = db_api.get_instance()
    return dbapi.ethernet_port_create(ethernet_port['host_id'], ethernet_port)


def get_test_interface(**kw):
    interface = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'forihostid': kw.get('forihostid'),
        'ihost_uuid': kw.get('ihost_uuid'),
        'ifname': kw.get('ifname', 'enp0s3'),
        'iftype': kw.get('iftype', 'ethernet'),
        'imac': kw.get('imac', '11:22:33:44:55:66'),
        'imtu': kw.get('imtu', 1500),
        'ifclass': kw.get('ifclass', None),
        'networktypelist': kw.get('networktypelist', []),
        'aemode': kw.get('aemode'),
        'txhashpolicy': kw.get('txhashpolicy', None),
        'primary_reselect': kw.get('primary_reselect', None),
        'vlan_id': kw.get('vlan_id', None),
        'uses': kw.get('uses', []),
        'used_by': kw.get('used_by', []),
        'ipv4_mode': kw.get('ipv4_mode'),
        'ipv6_mode': kw.get('ipv6_mode'),
        'ipv4_pool': kw.get('ipv4_pool'),
        'ipv6_pool': kw.get('ipv6_pool'),
        'sriov_numvfs': kw.get('sriov_numvfs', None),
        'sriov_vf_driver': kw.get('sriov_vf_driver', None),
        'sriov_vf_pdevice_id': kw.get('sriov_vf_pdevice_id', None),
        'ptp_role': kw.get('ptp_role', None),
        'max_tx_rate': kw.get('max_tx_rate', None)
    }
    return interface


def create_test_interface(**kw):
    """Create test interface entry in DB and return Interface DB object.
    Function to be used to create test Interface objects in the database.
    :param kw: kwargs with overriding values for interface's attributes.
    :returns: Test Interface DB object.
    """
    interface = get_test_interface(**kw)
    datanetworks_list = interface.get('datanetworks') or []
    networks_list = interface.get('networks') or []

    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del interface['id']

    if 'datanetworks' in interface:
        del interface['datanetworks']

    if 'networks' in interface:
        del interface['networks']

    dbapi = db_api.get_instance()
    forihostid = kw.get('forihostid')
    interface_obj = dbapi.iinterface_create(forihostid, interface)

    ipv4_mode = interface.get('ipv4_mode', None)
    if ipv4_mode:
        values = {'family': constants.IPV4_FAMILY, 'mode': ipv4_mode}
        if ipv4_mode == constants.IPV4_POOL:
            pool = dbapi.address_pool_get(interface.get('ipv4_pool'))
            values['address_pool_id'] = pool.id
            interface_obj.ipv4_pool = pool.uuid
        dbapi.address_mode_update(interface_obj.id, values)
        interface_obj.ipv4_mode = ipv4_mode

    ipv6_mode = interface.get('ipv6_mode', None)
    if ipv6_mode:
        values = {'family': constants.IPV6_FAMILY, 'mode': ipv6_mode}
        if ipv6_mode == constants.IPV6_POOL:
            pool = dbapi.address_pool_get(interface.get('ipv6_pool'))
            values['address_pool_id'] = pool.id
            interface_obj.ipv6_pool = pool.uuid
        dbapi.address_mode_update(interface_obj.id, values)
        interface_obj.ipv6_mode = ipv6_mode

    # assign the network to the interface
    for network in networks_list:
        if not network:
            continue
        net = dbapi.network_get(network)
        values = {'interface_id': interface_obj.id,
                  'network_id': net.id}
        dbapi.interface_network_create(values)

    # assign the interface to the datanetwork
    for datanetwork in datanetworks_list:
        if not datanetwork:
            continue
        dn = dbapi.datanetwork_get(datanetwork)
        values = {'interface_id': interface_obj.id,
                  'datanetwork_id': dn.id}
        dbapi.interface_datanetwork_create(values)

    return interface_obj


def create_test_interface_network(**kw):
    """Create test network interface entry in DB and return Network DB
    object. Function to be used to create test Network objects in the database.
    :param kw: kwargs with overriding values for network's attributes.
    :returns: Test Network DB object.
    """
    interface_network = get_test_interface_network(**kw)
    if 'id' not in kw:
        del interface_network['id']
    dbapi = db_api.get_instance()
    return dbapi.interface_network_create(interface_network)


def create_test_interface_network_assign(interface_id, network_id):
    """Create test network interface entry in DB and return Network DB
    object. Function to be used to create test Network objects in the database.
    :param interface_id: interface object id.
    :param network_id: interface object id.
    :returns: Test Network DB object.
    """
    dbapi = db_api.get_instance()
    net = dbapi.network_get(network_id)
    values = {'interface_id': interface_id,
                'network_id': net.id}
    return dbapi.interface_network_create(values)


def create_test_interface_network_type_assign(interface_id, network_type):
    """Create test interface-network entry in DB and return InterfaceNetwork
    object. Function to be used to create test InterfaceNetwork objects in the database.
    :param interface_id: interface object id.
    :param network_type: network type.
    :returns: Test Network DB object.
    """
    dbapi = db_api.get_instance()
    net = dbapi.network_get_by_type(network_type)
    values = {'interface_id': interface_id,
                'network_id': net.id}
    return dbapi.interface_network_create(values)


def get_test_interface_network(**kw):
    inv = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'interface_id': kw.get('interface_id'),
        'network_id': kw.get('network_id'),
    }
    return inv


def post_get_test_interface_network(**kw):
    inv = {
        'interface_uuid': kw.get('interface_uuid'),
        'network_uuid': kw.get('network_uuid'),
    }
    return inv


def create_test_interface_datanetwork(**kw):
    """Create test datanetwork interface entry in DB and return Network DB
    object. Function to be used to create test Network objects in the database.
    :param kw: kwargs with overriding values for network's attributes.
    :returns: Test Network DB object.
    """
    interface_network = get_test_interface_datanetwork(**kw)
    if 'id' not in kw:
        del interface_network['id']
    dbapi = db_api.get_instance()
    return dbapi.interface_datanetwork_create(interface_network)


def get_test_interface_datanetwork(**kw):
    inv = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'interface_id': kw.get('interface_id'),
        'datanetwork_id': kw.get('datanetwork_id'),
    }
    return inv


def get_test_partition(**kw):
    """get_test_partition will fail unless
       forihostid is provided
       disk_id is provided
       size_mib must be a valid number
    """
    partition = {
        'uuid': kw.get('uuid'),
        'start_mib': kw.get('start_mib'),
        'end_mib': kw.get('end_mib'),
        'size_mib': kw.get('size_mib'),
        'device_path': kw.get('device_path'),
        'device_node': kw.get('device_node'),
        'forihostid': kw.get('forihostid'),
        'idisk_id': kw.get('idisk_id'),
        'idisk_uuid': kw.get('idisk_uuid'),
        'type_guid': kw.get('type_guid'),
        'status': kw.get('status',
                         constants.PARTITION_CREATE_ON_UNLOCK_STATUS),
    }
    return partition


def create_test_partition(**kw):
    """Create test partition entry in DB and return Partition DB
    object. Function to be used to create test Partition objects in the database.
    :param kw: kwargs with overriding values for partition's attributes.
    :returns: Test Partition DB object.
    """
    partition = get_test_partition(**kw)
    if 'uuid' not in kw:
        del partition['uuid']
    dbapi = db_api.get_instance()
    forihostid = partition['forihostid']
    return dbapi.partition_create(forihostid, partition)


def post_get_test_partition(**kw):
    partition = get_test_partition(**kw)

    # When invoking a POST the following fields should not be populated:
    del partition['uuid']
    del partition['status']

    return partition


def post_get_test_interface_datanetwork(**kw):
    inv = {
        'interface_uuid': kw.get('interface_uuid'),
        'datanetwork_uuid': kw.get('datanetwork_uuid'),
    }
    return inv


def get_test_storage_tier(**kw):
    tier = {
        'id': kw.get('id', 321),
        'uuid': kw.get('uuid'),

        'name': kw.get('name', constants.SB_TIER_DEFAULT_NAMES[constants.SB_TYPE_CEPH]),
        'type': kw.get('type', constants.SB_TYPE_CEPH),
        'status': kw.get('status', constants.SB_TIER_STATUS_DEFINED),
        'capabilities': kw.get('capabilities', {}),

        'forclusterid': kw.get('forclusterid'),
        'cluster_uuid': kw.get('cluster_uuid'),

        'forbackendid': kw.get('forbackendid'),
        'backend_uuid': kw.get('backend_uuid'),
    }
    return tier


def create_test_storage_tier(**kw):
    """Create test storage_tier entry in DB and return storage_tier DB object.
    Function to be used to create test storage_tier objects in the database.
    :param kw: kwargs with overriding values for system's attributes.
    :returns: Test System DB object.
    """
    storage_tier = get_test_storage_tier(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del storage_tier['id']
        dbapi = db_api.get_instance()
    return dbapi.storage_tier_create(storage_tier)


def get_test_cluster(**kw):
    cluster = {
        'id': kw.get('id', 321),
        'uuid': kw.get('uuid'),
        'name': kw.get('name'),
        'type': kw.get('type', constants.SB_TYPE_CEPH),
        'capabilities': kw.get('capabilities', {}),
        'system_id': kw.get('system_id'),
        'cluster_uuid': kw.get('cluster_uuid'),
    }
    return cluster


def create_test_cluster(**kw):
    """Create test cluster entry in DB and return System DB object.
    Function to be used to create test cluster objects in the database.
    :param kw: kwargs with overriding values for system's attributes.
    :returns: Test System DB object.
    """
    cluster = get_test_cluster(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del cluster['id']
    dbapi = db_api.get_instance()
    return dbapi.cluster_create(cluster)


def get_test_app(**kw):
    app_data = {
        'id': kw.get('id', 90210),
        'name': kw.get('name', 'stx-openstack'),
        'app_version': kw.get('app_version',
                              constants.APP_VERSION_PLACEHOLDER),
        'manifest_name': kw.get('manifest_name',
                                constants.APP_MANIFEST_NAME_PLACEHOLDER),
        'manifest_file': kw.get('manifest_file',
                                constants.APP_TARFILE_NAME_PLACEHOLDER),
        'status': kw.get('status', constants.APP_UPLOAD_IN_PROGRESS),
        'active': kw.get('active', False),
    }
    return app_data


def create_test_app(**kw):
    """Create test application entry in DB and return Application DB object.
    Function to be used to create test application objects in the database.
    :param kw: kwargs with overriding values for application attributes.
    :returns: Test Application DB object.
    """
    app_data = get_test_app(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del app_data['id']
    dbapi = db_api.get_instance()
    return dbapi.kube_app_create(app_data)


def get_test_pci_device(**kw):
    pci_device = {
        'id': kw.get('id', 2345),
        'host_id': kw.get('host_id', 2),
        'name': kw.get('name', 'pci_0000_00_02_0 '),
        'pciaddr': kw.get('pciaddr', '0000:00:02.0'),
        'pclass_id': kw.get('pclass_id', '030000'),
        'pvendor_id': kw.get('pvendor_id', '8086'),
        'pdevice_id': kw.get('pdevice_id', '3ea5'),
        'pclass': kw.get('pclass', 'VGA compatible controller'),
        'pvendor': kw.get('pvendor', 'Intel Corporation'),
        'pdevice': kw.get('pdevice', 'Iris Plus Graphics 655'),
        'numa_node': kw.get('numa_node', -1),
        'enabled': kw.get('enabled', True),
        'driver': kw.get('driver', None),
        'sriov_totalvfs': kw.get('sriov_totalvfs', None),
        'sriov_numvfs': kw.get('sriov_numvfs', 0),
        'sriov_vfs_pci_address': kw.get('sriov_vfs_pci_address', ''),
        'sriov_vf_driver': kw.get('sriov_vf_driver', None),
        'sriov_vf_pdevice_id': kw.get('sriov_vf_pdevice_id', None)
    }
    return pci_device


def create_test_pci_device(**kw):
    """Create test pci devices entry in DB and return PciDevice DB object.
    Function to be used to create test pci device objects in the database.
    :param kw: kwargs with overriding values for pci device attributes.
    :returns: Test PciDevice DB object.
    """
    pci_device = get_test_pci_device(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del pci_device['id']
    dbapi = db_api.get_instance()
    return dbapi.pci_device_create(pci_device['host_id'], pci_device)


def get_test_fpga_device(**kw):
    fpga_device = {
        'id': kw.get('id', 2345),
        'host_id': kw.get('host_id', 2),
        'pci_id': kw.get('pci_id', 2),
        'pciaddr': kw.get('pciaddr', '0000:00:02.0'),
        'bmc_build_version': kw.get('bmc_build_version'),
        'bmc_fw_version': kw.get('bmc_fw_version'),
        'retimer_a_version': kw.get('retimer_a_version'),
        'retimer_b_version': kw.get('retimer_b_version'),
        'root_key': kw.get('root_key'),
        'revoked_key_ids': kw.get('revoked_key_ids'),
        'boot_page': kw.get('boot_page'),
        'bitstream_id': kw.get('bitstream_id'),
    }
    return fpga_device


def create_test_fpga_device(**kw):
    """Create test fpga devices entry in DB and return FPGADevice DB object.
    Function to be used to create test fpga device objects in the database.
    :param kw: kwargs with overriding values for fpga device attributes.
    :returns: Test FPGADevice DB object.
    """
    fpga_device = get_test_fpga_device(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del fpga_device['id']
    dbapi = db_api.get_instance()
    return dbapi.fpga_device_create(fpga_device['host_id'], fpga_device)


def get_test_label(**kw):
    label = {
        'host_id': kw.get('host_id'),
        'label_key': kw.get('label_key'),
        'label_value': kw.get('label_value'),
    }
    return label


def create_test_label(**kw):
    """Create test label in DB and return label object.
    Function to be used to create test label objects in the database.
    :param kw: kwargs with overriding values for labels's attributes.
    :returns: Test label DB object.
    """
    label = get_test_label(**kw)
    dbapi = db_api.get_instance()
    return dbapi.label_create(label['host_id'], label)


def get_test_service_parameter(**kw):
    service_parameter = {
        'section': kw.get('section'),
        'service': kw.get('service'),
        'name': kw.get('name'),
        'value': kw.get('value'),
        'resource': kw.get('resource'),
        'personality': kw.get('personality'),
    }
    return service_parameter


def create_test_service_parameter(**kw):
    """Create test service parameter in DB and return a service_parameter object.
    Function to be used to create test service parameter objects in the database.
    :param kw: kwargs with overriding values for service parameter's attributes.
    :returns: Test service parameter DB object.
    """
    service_parameter = get_test_service_parameter(**kw)
    dbapi = db_api.get_instance()
    return dbapi.service_parameter_create(service_parameter)


def create_test_oam(**kw):
    dbapi = db_api.get_instance()
    return dbapi.iextoam_get_one()


# Create test certficate object
def get_test_certificate(**kw):
    certificate = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'certtype': kw.get('certtype'),
        'signature': kw.get('signature')
    }
    return certificate


def create_test_certificate(**kw):
    certificate = get_test_certificate(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del certificate['id']
    dbapi = db_api.get_instance()
    return dbapi.certificate_create(certificate)


# Create test device image object
def get_test_device_image(**kw):
    device_image = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'bitstream_type': kw.get('bitstream_type'),
        'pci_vendor': kw.get('pci_vendor'),
        'pci_device': kw.get('pci_device'),
        'bitstream_id': kw.get('bitstream_id'),
        'key_signature': kw.get('key_signature'),
        'revoke_key_id': kw.get('revoke_key_id'),
        'name': kw.get('name'),
        'description': kw.get('description'),
        'version': kw.get('version'),
        'bmc': kw.get('bmc'),
        'retimer_included': kw.get('retimer_included'),
    }
    return device_image


def post_get_test_device_image(**kw):
    device_image = get_test_device_image(**kw)
    del device_image['id']
    del device_image['uuid']
    return device_image


def create_test_device_image(**kw):
    """Create test device image in DB and return device_image object.
    Function to be used to create test device image objects in the database.
    :param kw: kwargs with overriding values for device_image's attributes.
    :returns: Test device_image DB object.
    """
    device_image = get_test_device_image(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in device_image:
        del device_image['id']
    if 'uuid' in device_image:
        del device_image['uuid']
    dbapi = db_api.get_instance()
    return dbapi.deviceimage_create(device_image)


def get_test_kube_app(**kw):
    kube_app = {
        'name': kw.get('name'),
        'app_version': kw.get('app_version'),
        'manifest_name': kw.get('manifest_name'),
        'manifest_file': kw.get('manifest_file'),
        'status': kw.get('status'),
        'progress': kw.get('progress'),
        'active': kw.get('active'),
        'recovery_attempts': kw.get('recovery_attempts'),
        'mode': kw.get('mode'),
        'app_metadata': kw.get('app_metadata'),
    }
    return kube_app


def create_test_kube_app(**kw):
    kube_app = get_test_kube_app(**kw)
    dbapi = db_api.get_instance()
    return dbapi.kube_app_create(kube_app)


def get_primary_address_by_name(address_name, networktype):
    dbapi = db_api.get_instance()
    address = None
    try:
        networks = dbapi.networks_get_by_type(networktype)
        if networks and networks[0].pool_uuid:
            pool = dbapi.address_pool_get(networks[0].pool_uuid)
            address = dbapi.address_get_by_name_and_family(address_name,
                                                           pool.family)
    except exception.AddressNotFoundByNameAndFamily:
        pass

    return address
