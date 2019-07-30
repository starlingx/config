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
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#

"""Sysinv test utilities."""

from sysinv.common import constants
from sysinv.openstack.common import jsonutils as json
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


def get_test_node(**kw):
    node = {
        'id': kw.get('id', 1),
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
    return dbapi.inode_create(node)


def post_get_test_ihost(**kw):
    inv = get_test_ihost(**kw)
    del inv['bm_mac']
    del inv['peer_id']
    del inv['action_state']
    del inv['recordtype']
    del inv['uuid']
    return inv


def get_test_ihost(**kw):
    inv = {
            'id': kw.get('id', 123),
            'forisystemid': kw.get('forisystemid', None),
            'peer_id': kw.get('peer_id', None),
            'recordtype': kw.get('recordtype', "standard"),
            'uuid': kw.get('uuid'),
            'hostname': kw.get('hostname', 'sysinvhostname'),
            'invprovision': kw.get('invprovision', 'unprovisioned'),
            'mgmt_mac': kw.get('mgmt_mac',
                                         '01:34:67:9A:CD:FE'),
            'mgmt_ip': kw.get('mgmt_ip',
                                         '192.168.24.11'),
            'personality': kw.get('personality', 'controller'),
            'administrative': kw.get('administrative', 'locked'),
            'operational': kw.get('operational', 'disabled'),
            'availability': kw.get('availability', 'offduty'),
            'serialid': kw.get('serialid', 'sysinv123456'),
            'bm_ip': kw.get('bm_ip', "128.224.150.193"),
            'bm_mac': kw.get('bm_mac', "a4:5d:36:fc:a5:6c"),
            'bm_type': kw.get('bm_type', constants.BM_TYPE_GENERIC),
            'bm_username': kw.get('bm_username', "ihostbmusername"),
            'action': kw.get('action', "none"),
            'task': kw.get('task', None),
            'capabilities': kw.get('capabilities', {}),
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
            'config_applied': kw.get('config_applied', "configapplied"),
            'config_target': kw.get('config_target', "configtarget"),
            'location': kw.get('location', {}),
            'boot_device': kw.get('boot_device', 'sda'),
            'rootfs_device': kw.get('rootfs_device', 'sda'),
            'install_output': kw.get('install_output', 'text'),
            'console': kw.get('console', 'ttyS0,115200'),
            'tboot': kw.get('tboot', ''),
            'ttys_dcd': kw.get('ttys_dcd', None),
            'updated_at': None,
            'created_at': None,
            'install_state': kw.get('install_state', None),
            'install_state_info': kw.get('install_state_info', None),
            'iscsi_initiator_name': kw.get('iscsi_initiator_name', None),
            'inv_state': kw.get('inv_state', 'inventoried'),
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
            'location': kw.get('location', 'isystemlocation'),
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


def get_test_load(**kw):
    load = {
        "software_version": SW_VERSION,
        "compatible_version": "N/A",
        "required_patches": "N/A",
    }
    return load


def create_test_load(**kw):
    load = get_test_load(**kw)
    dbapi = db_api.get_instance()
    return dbapi.load_create(load)


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


# Create test ntp object
def get_test_ntp(**kw):
    ntp = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'enabled': kw.get('enabled'),
        'ntpservers': kw.get('ntpservers'),
        'forisystemid': kw.get('forisystemid', None)
    }
    return ntp


def create_test_ntp(**kw):
    ntp = get_test_ntp(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del ntp['id']
    dbapi = db_api.get_instance()
    return dbapi.intp_create(ntp)


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
            'uuid': kw.get('uuid')
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
    return dbapi.address_pool_create(address_pool)


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
            'address_pool_id': kw.get('address_pool_id', None)
           }
    return inv


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
        'id': kw.get('id', 2),
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


def get_test_lvg(**kw):
    lvg = {
        'id': kw.get('id', 2),
        'uuid': kw.get('uuid'),
        'lvm_vg_name': kw.get('lvm_vg_name'),
        'forihostid': kw.get('forihostid', 2),
    }
    return lvg


def get_test_pv(**kw):
    pv = {
        'id': kw.get('id', 2),
        'uuid': kw.get('uuid'),
        'lvm_vg_name': kw.get('lvm_vg_name'),
        'disk_or_part_uuid': kw.get('disk_or_part_uuid', 2),
        'disk_or_part_device_path': kw.get('disk_or_part_device_path',
            '/dev/disk/by-path/pci-0000:00:0d.0-ata-3.0'),
        'forihostid': kw.get('forihostid', 2),
        'forilvgid': kw.get('forilvgid', 2),
    }
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
        'capabilities': kw.get('capabilities', {}),
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
        'dpdksupport': kw.get('dpdksupport'),
        'dev_id': kw.get('dev_id'),
        'sriov_totalvfs': kw.get('sriov_totalvfs'),
        'sriov_numvfs': kw.get('sriov_numvfs'),
        'sriov_vf_driver': kw.get('sriov_vf_driver'),
        'driver': kw.get('driver')
    }
    return ethernet_port


def get_test_datanetwork(**kw):
    datanetwork = {
        'uuid': kw.get('uuid', '60d41820-a4a0-4c25-a6a0-2a3b98746640'),
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


def post_get_test_interface(**kw):
    interface = {
        'forihostid': kw.get('forihostid'),
        'ihost_uuid': kw.get('ihost_uuid'),
        'ifname': kw.get('ifname'),
        'iftype': kw.get('iftype', 'ethernet'),
        'imac': kw.get('imac', '11:22:33:44:55:66'),
        'imtu': kw.get('imtu', 1500),
        'ifclass': kw.get("ifclass"),
        'aemode': kw.get('aemode', 'balanced'),
        'txhashpolicy': kw.get('txhashpolicy', 'layer2'),
        'vlan_id': kw.get('vlan_id'),
        'uses': kw.get('uses', None),
        'used_by': kw.get('used_by', []),
        'ipv4_mode': kw.get('ipv4_mode'),
        'ipv6_mode': kw.get('ipv6_mode'),
        'ipv4_pool': kw.get('ipv4_pool'),
        'ipv6_pool': kw.get('ipv6_pool'),
        'sriov_numvfs': kw.get('sriov_numvfs', None),
        'sriov_vf_driver': kw.get('sriov_vf_driver', None),
    }
    return interface


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
        'vlan_id': kw.get('vlan_id', None),
        'uses': kw.get('uses', []),
        'used_by': kw.get('used_by', []),
        'ipv4_mode': kw.get('ipv4_mode'),
        'ipv6_mode': kw.get('ipv6_mode'),
        'ipv4_pool': kw.get('ipv4_pool'),
        'ipv6_pool': kw.get('ipv6_pool'),
        'sriov_numvfs': kw.get('sriov_numvfs', None),
        'sriov_vf_driver': kw.get('sriov_vf_driver', None)
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


def get_test_interface_datanetwork(**kw):
    inv = {
        'id': kw.get('id'),
        'uuid': kw.get('uuid'),
        'interface_uuid': kw.get('interface_uuid'),
        'datanetwork_uuid': kw.get('datanetwork_uuid'),
    }
    return inv


def create_test_interface_datanetwork(**kw):
    """Create test network interface entry in DB and return Network DB
    object. Function to be used to create test Network objects in the database.
    :param kw: kwargs with overriding values for network's attributes.
    :returns: Test Network DB object.
    """
    interface_datanetwork = get_test_interface_datanetwork(**kw)
    if 'id' not in kw:
        del interface_datanetwork['id']
    dbapi = db_api.get_instance()
    return dbapi.interface_datanetwork_create(interface_datanetwork)


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
