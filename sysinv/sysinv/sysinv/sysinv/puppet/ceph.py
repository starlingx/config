#
# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import netaddr
import uuid

from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common.storage_backend_conf import StorageBackendConfig

from . import openstack


# NOTE: based on openstack service for providing swift object storage services
# via Ceph RGW
class CephPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for ceph storage configuration"""

    SERVICE_PORT_MON = 6789
    SERVICE_NAME_RGW = 'swift'
    SERVICE_PORT_RGW = 7480  # civetweb port
    SERVICE_PATH_RGW = 'swift/v1'

    def get_static_config(self):
        cluster_uuid = str(uuid.uuid4())

        return {
            'platform::ceph::params::cluster_uuid': cluster_uuid,
        }

    def get_secure_static_config(self):
        kspass = self._get_service_password(self.SERVICE_NAME_RGW)

        return {
            'platform::ceph::params::rgw_admin_password': kspass,

            'platform::ceph::rgw::keystone::auth::password': kspass,
        }

    def get_system_config(self):
        ceph_backend = StorageBackendConfig.get_backend_conf(
            self.dbapi, constants.CINDER_BACKEND_CEPH)
        if not ceph_backend:
            return {}  # ceph is not configured

        ceph_mon_ips = StorageBackendConfig.get_ceph_mon_ip_addresses(
            self.dbapi)

        # TODO: k8s on AIO-SX: Temporarily need to move the ceph monitor address
        # from a loopback address to the OAM address so the ceph monitor is
        # reachable from the cluster pods.
        if (utils.is_kubernetes_config(self.dbapi) and
            (self.dbapi.isystem_get_one().system_mode ==
                 constants.SYSTEM_MODE_SIMPLEX)):
            mon_0_ip = self._get_oam_address()
        else:
            mon_0_ip = ceph_mon_ips['ceph-mon-0-ip']
        mon_1_ip = ceph_mon_ips['ceph-mon-1-ip']
        mon_2_ip = ceph_mon_ips['ceph-mon-2-ip']
        floating_mon_ip = ceph_mon_ips['ceph-floating-mon-ip']

        mon_0_addr = self._format_ceph_mon_address(mon_0_ip)
        mon_1_addr = self._format_ceph_mon_address(mon_1_ip)
        mon_2_addr = self._format_ceph_mon_address(mon_2_ip)
        floating_mon_addr = self._format_ceph_mon_address(floating_mon_ip)

        # ceph can not bind to multiple address families, so only enable IPv6
        # if the monitors are IPv6 addresses
        ms_bind_ipv6 = (netaddr.IPAddress(mon_0_ip).version ==
                        constants.IPV6_FAMILY)

        ksuser = self._get_service_user_name(self.SERVICE_NAME_RGW)

        return {
            'ceph::ms_bind_ipv6': ms_bind_ipv6,

            'platform::ceph::params::service_enabled': True,

            'platform::ceph::params::floating_mon_host':
                constants.CONTROLLER_HOSTNAME,
            'platform::ceph::params::mon_0_host':
                constants.CONTROLLER_0_HOSTNAME,
            'platform::ceph::params::mon_1_host':
                constants.CONTROLLER_1_HOSTNAME,
            'platform::ceph::params::mon_2_host':
                constants.STORAGE_0_HOSTNAME,

            'platform::ceph::params::floating_mon_ip': floating_mon_ip,
            'platform::ceph::params::mon_0_ip': mon_0_ip,
            'platform::ceph::params::mon_1_ip': mon_1_ip,
            'platform::ceph::params::mon_2_ip': mon_2_ip,

            'platform::ceph::params::floating_mon_addr': floating_mon_addr,
            'platform::ceph::params::mon_0_addr': mon_0_addr,
            'platform::ceph::params::mon_1_addr': mon_1_addr,
            'platform::ceph::params::mon_2_addr': mon_2_addr,

            'platform::ceph::params::rgw_enabled':
                ceph_backend.object_gateway,
            'platform::ceph::params::rgw_admin_user':
                ksuser,
            'platform::ceph::params::rgw_admin_domain':
                self._get_service_user_domain_name(),
            'platform::ceph::params::rgw_admin_project':
                self._get_service_tenant_name(),

            'platform::ceph::rgw::keystone::auth::auth_name':
                ksuser,
            'platform::ceph::rgw::keystone::auth::public_url':
                self._get_rgw_public_url(),
            'platform::ceph::rgw::keystone::auth::internal_url':
                self._get_rgw_internal_url(),
            'platform::ceph::rgw::keystone::auth::admin_url':
                self._get_rgw_admin_url(),
            'platform::ceph::rgw::keystone::auth::region':
                self._get_rgw_region_name(),
            'platform::ceph::rgw::keystone::auth::tenant':
                self._get_service_tenant_name(),
        }

    def _is_ceph_mon_required(self, host, operator):
        # Two conditions that we need to check for:
        # 1) If cinder is a shared service and it has a ceph backend
        # 2) If remote instance backing is configured on the host
        if (constants.SERVICE_TYPE_VOLUME in self._get_shared_services() and
                operator.region_has_ceph_backend()):
            lvgs = self.dbapi.ilvg_get_by_ihost(host.uuid)
            for lvg in lvgs:
                if lvg.capabilities.get(constants.LVG_NOVA_PARAM_BACKING) \
                        == constants.LVG_NOVA_BACKING_REMOTE:
                    return True
        return False

    def _get_remote_ceph_mon_info(self, operator):
        # retrieve the ceph monitor information from the primary
        ceph_mon_info = operator.get_ceph_mon_info()
        if ceph_mon_info is None:
            return None

        cluster_id = ceph_mon_info['cluster_id']

        mon_0_addr = self._format_ceph_mon_address(
            ceph_mon_info['ceph-mon-0-ip'])
        mon_1_addr = self._format_ceph_mon_address(
            ceph_mon_info['ceph-mon-1-ip'])
        mon_2_addr = self._format_ceph_mon_address(
            ceph_mon_info['ceph-mon-2-ip'])

        config = {
            'platform::ceph::params::configure_ceph_mon_info': True,
            'platform::ceph::params::cluster_uuid': cluster_id,
            'platform::ceph::params::mon_0_host':
                constants.CONTROLLER_0_HOSTNAME,
            'platform::ceph::params::mon_1_host':
                constants.CONTROLLER_1_HOSTNAME,
            'platform::ceph::params::mon_2_host':
                constants.STORAGE_0_HOSTNAME,
            'platform::ceph::params::mon_0_addr': mon_0_addr,
            'platform::ceph::params::mon_1_addr': mon_1_addr,
            'platform::ceph::params::mon_2_addr': mon_2_addr,
        }
        return config

    def get_host_config(self, host):
        config = {}
        if host.personality in [constants.CONTROLLER, constants.STORAGE]:
            config.update(self._get_ceph_mon_config(host))
            config.update(self._get_ceph_osd_config(host))

        # if it is a worker node and on an secondary region,
        # check if ceph mon configuration is required
        if constants.WORKER in host.subfunctions and self._region_config():
            from sysinv.conductor import openstack
            op = openstack.OpenStackOperator(self.dbapi)
            if self._is_ceph_mon_required(host, op):
                ceph_mon_info = self._get_remote_ceph_mon_info(op)
                if ceph_mon_info is not None:
                    config.update(ceph_mon_info)

        return config

    def get_public_url(self):
        return self._get_rgw_public_url()

    def get_internal_url(self):
        return self.get_rgw_internal_url()

    def get_admin_url(self):
        return self.get_rgw_admin_url()

    def _get_rgw_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME_RGW)

    def _get_rgw_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT_RGW,
                                            path=self.SERVICE_PATH_RGW)

    def _get_rgw_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT_RGW,
                                             path=self.SERVICE_PATH_RGW)

    def _get_rgw_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT_RGW,
                                             path=self.SERVICE_PATH_RGW)

    def _get_ceph_mon_config(self, host):
        ceph_mon = self._get_host_ceph_mon(host)

        mon_lv_size = None
        if ceph_mon:
            mon_lv_size = ceph_mon.ceph_mon_gib

        if mon_lv_size is None:
            mon_lv_size = constants.SB_CEPH_MON_GIB

        return {
            'platform::ceph::params::mon_lv_size': mon_lv_size,
        }

    def _get_ceph_osd_config(self, host):
        osd_config = {}
        journal_config = {}

        disks = self.dbapi.idisk_get_by_ihost(host.id)
        stors = self.dbapi.istor_get_by_ihost(host.id)

        # setup pairings between the storage entity and the backing disks
        pairs = [(s, d) for s in stors for d in disks if
                 s.idisk_uuid == d.uuid]

        for stor, disk in pairs:
            name = 'stor-%d' % stor.id

            if stor.function == constants.STOR_FUNCTION_JOURNAL:
                # Get the list of OSDs that have their journals on this stor.
                # Device nodes are allocated in order by linux, therefore we
                # need the list sorted to get the same ordering as the initial
                # inventory that is stored in the database.
                osd_stors = [s for s in stors
                             if (s.function == constants.STOR_FUNCTION_OSD and
                                 s.journal_location == stor.uuid)]
                osd_stors = sorted(osd_stors, key=lambda s: s.id)

                journal_sizes = [s.journal_size_mib for s in osd_stors]

                # platform_ceph_journal puppet resource parameters
                journal = {
                    'disk_path': disk.device_path,
                    'journal_sizes': journal_sizes
                }
                journal_config.update({name: journal})

            if stor.function == constants.STOR_FUNCTION_OSD:
                # platform_ceph_osd puppet resource parameters
                osd = {
                    'osd_id': stor.osdid,
                    'osd_uuid': stor.uuid,
                    'disk_path': disk.device_path,
                    'data_path': disk.device_path + '-part1',
                    'journal_path': stor.journal_path,
                    'tier_name': stor.tier_name,
                }
                osd_config.update({name: osd})

        return {
            'platform::ceph::storage::osd_config': osd_config,
            'platform::ceph::storage::journal_config': journal_config,
        }

    def _format_ceph_mon_address(self, ip_address):
        if netaddr.IPAddress(ip_address).version == constants.IPV4_FAMILY:
            return '%s:%d' % (ip_address, self.SERVICE_PORT_MON)
        else:
            return '[%s]:%d' % (ip_address, self.SERVICE_PORT_MON)

    def _get_host_ceph_mon(self, host):
        ceph_mons = self.dbapi.ceph_mon_get_by_ihost(host.uuid)
        if ceph_mons:
            return ceph_mons[0]
        return None
