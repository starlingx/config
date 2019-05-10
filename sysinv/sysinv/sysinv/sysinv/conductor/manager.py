# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
# Copyright 2013 Hewlett-Packard Development Company, L.P.
# Copyright 2013 International Business Machines Corporation
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
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#

"""Conduct all activity related system inventory.

A single instance of :py:class:`sysinv.conductor.manager.ConductorManager` is
created within the *sysinv-conductor* process, and is responsible for
performing all actions for hosts managed by system inventory.
Commands are received via RPC calls. The conductor service also performs
collection of inventory data for each host.

"""

import errno
import filecmp
import fnmatch
import glob
import math
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ElementTree
from contextlib import contextmanager

import tsconfig.tsconfig as tsc
from collections import namedtuple
from cgcs_patch.patch_verify import verify_files
from controllerconfig.upgrades import management as upgrades_management
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from eventlet import greenthread
from fm_api import constants as fm_constants
from fm_api import fm_api
from netaddr import IPAddress
from netaddr import IPNetwork
from oslo_config import cfg
from platform_util.license import license
from sqlalchemy.orm import exc
from six.moves import http_client as httplib
from sysinv.agent import rpcapi as agent_rpcapi
from sysinv.api.controllers.v1 import address_pool
from sysinv.api.controllers.v1 import cpu_utils
from sysinv.api.controllers.v1 import kube_app as kube_api
from sysinv.api.controllers.v1 import mtce_api
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import vim_api
from sysinv.common import constants
from sysinv.common import ceph as cceph
from sysinv.common import exception
from sysinv.common import fm
from sysinv.common import fernet
from sysinv.common import health
from sysinv.common import kubernetes
from sysinv.common import retrying
from sysinv.common import service
from sysinv.common import utils as cutils
from sysinv.common.retrying import retry
from sysinv.common.storage_backend_conf import StorageBackendConfig
from cephclient import wrapper as ceph
from sysinv.conductor import ceph as iceph
from sysinv.conductor import kube_app
from sysinv.conductor import openstack
from sysinv.db import api as dbapi
from sysinv.objects import base as objects_base
from sysinv.objects import kube_app as kubeapp_obj
from sysinv.openstack.common import excutils
from sysinv.openstack.common import jsonutils
from sysinv.openstack.common import log
from sysinv.openstack.common import periodic_task
from sysinv.openstack.common import timeutils
from sysinv.openstack.common import uuidutils
from sysinv.openstack.common.gettextutils import _
from sysinv.puppet import common as puppet_common
from sysinv.puppet import puppet
from sysinv.helm import helm
from sysinv.helm import common as helm_common

MANAGER_TOPIC = 'sysinv.conductor_manager'

LOG = log.getLogger(__name__)

conductor_opts = [
       cfg.StrOpt('api_url',
                  default=None,
                  help=('Url of SysInv API service. If not set SysInv can '
                        'get current value from Keystone service catalog.')),
       cfg.IntOpt('audit_interval',
                  default=60,
                  help='Interval to run conductor audit'),
       cfg.IntOpt('osd_remove_retry_count',
                  default=11,
                  help=('Maximum number of retries in case Ceph OSD remove '
                        'requests fail because OSD is still up.')),
       cfg.IntOpt('osd_remove_retry_interval',
                  default=5,
                  help='Interval in seconds between retries to remove Ceph OSD.'),
                  ]

CONF = cfg.CONF
CONF.register_opts(conductor_opts, 'conductor')

# doesn't work otherwise for ceph-manager RPC calls; reply is lost
#
CONF.amqp_rpc_single_reply_queue = True

# configuration flags
CFS_DRBDADM_RECONFIGURED = os.path.join(
    tsc.PLATFORM_CONF_PATH, ".cfs_drbdadm_reconfigured")

# volatile flags
CONFIG_CONTROLLER_ACTIVATE_FLAG = os.path.join(tsc.VOLATILE_PATH,
                                               ".config_controller_activate")
CONFIG_CONTROLLER_FINI_FLAG = os.path.join(tsc.VOLATILE_PATH,
                                           ".config_controller_fini")
CONFIG_FAIL_FLAG = os.path.join(tsc.VOLATILE_PATH, ".config_fail")

# configuration UUID reboot required flag (bit)
CONFIG_REBOOT_REQUIRED = (1 << 127)

LOCK_NAME_UPDATE_CONFIG = 'update_config_'


class ConductorManager(service.PeriodicService):
    """Sysinv Conductor service main class."""

    RPC_API_VERSION = '1.1'
    my_host_id = None

    def __init__(self, host, topic):
        serializer = objects_base.SysinvObjectSerializer()
        super(ConductorManager, self).__init__(host, topic,
                                               serializer=serializer)
        self.dbapi = None
        self.fm_api = None
        self.fm_log = None
        self._app = None
        self._ceph = None
        self._ceph_api = ceph.CephWrapper(
            endpoint='http://localhost:5001')
        self._kube = None
        self._fernet = None

        self._openstack = None
        self._api_token = None
        self._mtc_address = constants.LOCALHOST_HOSTNAME
        self._mtc_port = 2112

        # Timeouts for adding & removing operations
        self._pv_op_timeouts = {}
        self._stor_bck_op_timeouts = {}

    def start(self):
        self._start()
        # accept API calls and run periodic tasks after
        # initializing conductor manager service
        super(ConductorManager, self).start()

    def _start(self):
        self.dbapi = dbapi.get_instance()
        self.fm_api = fm_api.FaultAPIs()
        self.fm_log = fm.FmCustomerLog()

        self._openstack = openstack.OpenStackOperator(self.dbapi)
        self._puppet = puppet.PuppetOperator(self.dbapi)

        # create /var/run/sysinv if required. On DOR, the manifests
        # may not run to create this volatile directory.
        cutils.check_lock_path()

        system = self._create_default_system()

        # Besides OpenStack and Puppet operators, all other operators
        # should be initialized after the default system is in place.
        # For instance, CephOperator expects a system to exist to initialize
        # correctly. With Ansible bootstrap deployment, sysinv conductor is
        # brought up during bootstrap manifest apply and is not restarted
        # until host unlock and we need ceph-mon up in order to configure
        # ceph for the initial unlock.
        self._app = kube_app.AppOperator(self.dbapi)
        self._ceph = iceph.CephOperator(self.dbapi)
        self._helm = helm.HelmOperator(self.dbapi)
        self._kube = kubernetes.KubeOperator(self.dbapi)
        self._kube_app_helper = kube_api.KubeAppHelper(self.dbapi)
        self._fernet = fernet.FernetOperator()

        # Upgrade start tasks
        self._upgrade_init_actions()

        self._handle_restore_in_progress()

        cutils.refresh_helm_repo_information()

        LOG.info("sysinv-conductor start committed system=%s" %
                 system.as_dict())

    def periodic_tasks(self, context, raise_on_error=False):
        """ Periodic tasks are run at pre-specified intervals. """
        return self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    @contextmanager
    def session(self):
        session = dbapi.get_instance().get_session(autocommit=True)
        try:
            yield session
        finally:
            session.remove()

    def _create_default_system(self):
        """Populate the default system tables"""

        system = None
        try:
            system = self.dbapi.isystem_get_one()

            # fill in empty remotelogging system_id fields
            self.dbapi.remotelogging_fill_empty_system_id(system.id)
            # fill in empty ptp system_id fields
            self.dbapi.ptp_fill_empty_system_id(system.id)

            return system  # system already configured
        except exception.NotFound:
            pass  # create default system

        # Create the default system entry
        mode = None
        if tsc.system_mode is not None:
            mode = tsc.system_mode

        security_profile = None
        if tsc.security_profile is not None:
            security_profile = tsc.security_profile

        security_feature = constants.SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_DEFAULT_OPTS
        if tsc.security_feature is not None:
            security_feature = tsc.security_feature

        system = self.dbapi.isystem_create({
            'name': uuidutils.generate_uuid(),
            'system_mode': mode,
            'software_version': cutils.get_sw_version(),
            'capabilities': {},
            'security_profile': security_profile,
            'security_feature': security_feature
        })

        # Populate the default system tables, referencing the newly created
        # table (additional attributes will be populated during
        # config_controller configuration population)
        values = {'forisystemid': system.id}

        self.dbapi.iuser_create(values)
        self.dbapi.idns_create(values)
        self.dbapi.intp_create(values)

        self.dbapi.drbdconfig_create({
            'forisystemid': system.id,
            'uuid': uuidutils.generate_uuid(),
            'link_util': constants.DRBD_LINK_UTIL_DEFAULT,
            'num_parallel': constants.DRBD_NUM_PARALLEL_DEFAULT,
            'rtt_ms': constants.DRBD_RTT_MS_DEFAULT
        })

        # remotelogging and ptp tables have attribute 'system_id' not 'forisystemid'
        system_id_attribute_value = {'system_id': system.id}
        self.dbapi.remotelogging_create(system_id_attribute_value)
        self.dbapi.ptp_create(system_id_attribute_value)

        # populate service table
        for optional_service in constants.ALL_OPTIONAL_SERVICES:
            self.dbapi.service_create({'name': optional_service,
                                       'enabled': False})

        self._create_default_service_parameter()
        return system

    def _upgrade_init_actions(self):
        """ Perform any upgrade related startup actions"""
        try:
            upgrade = self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # Not upgrading. No need to update status
            return

        hostname = socket.gethostname()
        if hostname == constants.CONTROLLER_0_HOSTNAME:
            if os.path.isfile(tsc.UPGRADE_ROLLBACK_FLAG):
                self._set_state_for_rollback(upgrade)
            elif os.path.isfile(tsc.UPGRADE_ABORT_FLAG):
                self._set_state_for_abort(upgrade)
        elif hostname == constants.CONTROLLER_1_HOSTNAME:
            self._init_controller_for_upgrade(upgrade)

        system_mode = self.dbapi.isystem_get_one().system_mode
        if system_mode == constants.SYSTEM_MODE_SIMPLEX:
            self._init_controller_for_upgrade(upgrade)

        self._upgrade_default_service()
        self._upgrade_default_service_parameter()

    def _handle_restore_in_progress(self):
        if os.path.isfile(tsc.RESTORE_IN_PROGRESS_FLAG):
            if StorageBackendConfig.has_backend(
                    self.dbapi,
                    constants.CINDER_BACKEND_CEPH):
                StorageBackendConfig.update_backend_states(
                    self.dbapi,
                    constants.CINDER_BACKEND_CEPH,
                    task=constants.SB_TASK_RESTORE)

    def _set_state_for_abort(self, upgrade):
        """ Update the database to reflect the abort"""
        LOG.info("Upgrade Abort detected. Correcting database state.")

        # Update the upgrade state
        self.dbapi.software_upgrade_update(
            upgrade.uuid, {'state': constants.UPGRADE_ABORTING})

        try:
            os.remove(tsc.UPGRADE_ABORT_FLAG)
        except OSError:
            LOG.exception("Failed to remove upgrade rollback flag")

    def _set_state_for_rollback(self, upgrade):
        """ Update the database to reflect the rollback"""
        LOG.info("Upgrade Rollback detected. Correcting database state.")

        # Update the upgrade state
        self.dbapi.software_upgrade_update(
            upgrade.uuid, {'state': constants.UPGRADE_ABORTING_ROLLBACK})

        # At this point we are swacting to controller-0 which has just been
        # downgraded.
        # Before downgrading controller-0 all storage/worker nodes were locked
        # The database of the from_load is not aware of this, so we set the
        # state in the database to match the state of the system. This does not
        # actually lock the nodes.
        hosts = self.dbapi.ihost_get_list()
        for host in hosts:
            if host.personality not in [constants.WORKER, constants.STORAGE]:
                continue
            self.dbapi.ihost_update(host.uuid, {
                'administrative': constants.ADMIN_LOCKED})

        # Remove the rollback flag, we only want to modify the database once
        try:
            os.remove(tsc.UPGRADE_ROLLBACK_FLAG)
        except OSError:
            LOG.exception("Failed to remove upgrade rollback flag")

    def _init_controller_for_upgrade(self, upgrade):
        # Raise alarm to show an upgrade is in progress
        # After upgrading controller-1 and swacting to it, we must
        # re-raise the upgrades alarm, because alarms are not preserved
        # from the previous release.
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                        constants.CONTROLLER_HOSTNAME)

        if not self.fm_api.get_fault(
                fm_constants.FM_ALARM_ID_UPGRADE_IN_PROGRESS,
                entity_instance_id):
            fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_UPGRADE_IN_PROGRESS,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
                reason_text="System Upgrade in progress.",
                # operational
                alarm_type=fm_constants.FM_ALARM_TYPE_7,
                # congestion
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_8,
                proposed_repair_action="No action required.",
                service_affecting=False)
            self.fm_api.set_fault(fault)

            # Regenerate dnsmasq.hosts and dnsmasq.addn_hosts.
            # This is necessary to handle the case where a lease expires during
            # an upgrade, in order to allow hostnames to be resolved from
            # the dnsmasq.addn_hosts file before unlocking controller-0 forces
            # dnsmasq.addn_hosts to be regenerated.
            self._generate_dnsmasq_hosts_file()

    DEFAULT_PARAMETERS = [
        {'service': constants.SERVICE_TYPE_IDENTITY,
         'section': constants.SERVICE_PARAM_SECTION_IDENTITY_ASSIGNMENT,
         'name': constants.SERVICE_PARAM_ASSIGNMENT_DRIVER,
         'value': constants.SERVICE_PARAM_IDENTITY_ASSIGNMENT_DRIVER_SQL
         },
        {'service': constants.SERVICE_TYPE_IDENTITY,
         'section': constants.SERVICE_PARAM_SECTION_IDENTITY_IDENTITY,
         'name': constants.SERVICE_PARAM_IDENTITY_DRIVER,
         'value': constants.SERVICE_PARAM_IDENTITY_IDENTITY_DRIVER_SQL
         },
        {'service': constants.SERVICE_TYPE_IDENTITY,
         'section': constants.SERVICE_PARAM_SECTION_IDENTITY_CONFIG,
         'name': constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION,
         'value': constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION_DEFAULT
         },
        {'service': constants.SERVICE_TYPE_HORIZON,
         'section': constants.SERVICE_PARAM_SECTION_HORIZON_AUTH,
         'name': constants.SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_PERIOD_SEC,
         'value': constants.SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_PERIOD_SEC_DEFAULT
         },
        {'service': constants.SERVICE_TYPE_HORIZON,
         'section': constants.SERVICE_PARAM_SECTION_HORIZON_AUTH,
         'name': constants.SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_RETRIES,
         'value': constants.SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_RETRIES_DEFAULT
         },
        {'service': constants.SERVICE_TYPE_CINDER,
         'section': constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX,
         'name': constants.SERVICE_PARAM_CINDER_EMC_VNX_ENABLED,
         'value': False
         },
        {'service': constants.SERVICE_TYPE_CINDER,
         'section': constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX_STATE,
         'name': constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS,
         'value': constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_DISABLED
         },
        {'service': constants.SERVICE_TYPE_CINDER,
         'section': constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR,
         'name': constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED,
         'value': False
         },
        {'service': constants.SERVICE_TYPE_CINDER,
         'section': constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND,
         'name': constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED,
         'value': False
         },
        {'service': constants.SERVICE_TYPE_CINDER,
         'section': constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR_STATE,
         'name': 'status',
         'value': 'disabled'
         },
        {'service': constants.SERVICE_TYPE_CINDER,
         'section': constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND_STATE,
         'name': 'status',
         'value': 'disabled'
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_PLATFORM,
         'section': constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
         'name': constants.SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT,
         'value': constants.SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT_DEFAULT,
         },
        {'service': constants.SERVICE_TYPE_SWIFT,
         'section': constants.SERVICE_PARAM_SECTION_SWIFT_CONFIG,
         'name': constants.SERVICE_PARAM_NAME_SWIFT_SERVICE_ENABLED,
         'value': False},
        {'service': constants.SERVICE_TYPE_SWIFT,
         'section': constants.SERVICE_PARAM_SECTION_SWIFT_CONFIG,
         'name': constants.SERVICE_PARAM_NAME_SWIFT_FS_SIZE_MB,
         'value': constants.SERVICE_PARAM_SWIFT_FS_SIZE_MB_DEFAULT},
        {'service': constants.SERVICE_TYPE_HTTP,
         'section': constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
         'name': constants.SERVICE_PARAM_HTTP_PORT_HTTP,
         'value': constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT
         },
        {'service': constants.SERVICE_TYPE_HTTP,
         'section': constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
         'name': constants.SERVICE_PARAM_HTTP_PORT_HTTPS,
         'value': constants.SERVICE_PARAM_HTTP_PORT_HTTPS_DEFAULT
         },
    ]

    for i in range(2, constants.SERVICE_PARAM_MAX_HPE3PAR + 1):
        section = "{0}{1}".format(constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR, i)
        DEFAULT_PARAMETERS.extend([
            {'service': constants.SERVICE_TYPE_CINDER,
             'section': section,
             'name': constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED,
             'value': False
             }]
        )

    def _create_default_service_parameter(self):
        """ Populate the default service parameters"""
        for p in ConductorManager.DEFAULT_PARAMETERS:
            self.dbapi.service_parameter_create(p)

    def _upgrade_default_service_parameter(self):
        """ Update the default service parameters when upgrade is done"""
        parms = self.dbapi.service_parameter_get_all()
        for p_new in ConductorManager.DEFAULT_PARAMETERS:
            found = False
            for p_db in parms:
                if (p_new['service'] == p_db.service and
                            p_new['section'] == p_db.section and
                            p_new['name'] == p_db.name):
                    found = True
                    break
            if not found:
                self.dbapi.service_parameter_create(p_new)

    def _get_service_parameter_sections(self, service):
        """ Given a service, returns all sections defined"""
        params = self.dbapi.service_parameter_get_all(service)
        return params

    def _upgrade_default_service(self):
        """ Update the default service when upgrade is done"""
        services = self.dbapi.service_get_all()
        for s_new in constants.ALL_OPTIONAL_SERVICES:
            found = False
            for s_db in services:
                if (s_new == s_db.name):
                    found = True
                    break
            if not found:
                self.dbapi.service_create({'name': s_new,
                                          'enabled': False})

    def _lookup_static_ip_address(self, name, networktype):
        """"Find a statically configured address based on name and network
        type."""
        try:
            # address names are refined by network type to ensure they are
            # unique across different address pools
            name = cutils.format_address_name(name, networktype)
            address = self.dbapi.address_get_by_name(name)
            return address.address
        except exception.AddressNotFoundByName:
            return None

    def _using_static_ip(self, ihost, personality=None, hostname=None):
        using_static = False
        if ihost:
            ipersonality = ihost['personality']
            ihostname = ihost['hostname'] or ""
        else:
            ipersonality = personality
            ihostname = hostname or ""

        if ipersonality and ipersonality == constants.CONTROLLER:
            using_static = True
        elif ipersonality and ipersonality == constants.STORAGE:
            # only storage-0 and storage-1 have static (later storage-2)
            if (ihostname[:len(constants.STORAGE_0_HOSTNAME)] in
               [constants.STORAGE_0_HOSTNAME, constants.STORAGE_1_HOSTNAME]):
                using_static = True

        return using_static

    def handle_dhcp_lease(self, context, tags, mac, ip_address, cid=None):
        """Synchronously, have a conductor handle a DHCP lease update.

        Handling depends on the interface:
        - management interface: do nothing
        - pxeboot interface: create i_host

        :param context: request context.
        :param tags: specifies the interface type (mgmt)
        :param mac: MAC for the lease
        :param ip_address: IP address for the lease
        """

        LOG.info("receiving dhcp_lease: %s %s %s %s %s" %
                 (context, tags, mac, ip_address, cid))
        # Get the first field from the tags
        first_tag = tags.split()[0]

        if 'pxeboot' == first_tag:
            mgmt_network = self.dbapi.network_get_by_type(
                constants.NETWORK_TYPE_MGMT)
            if not mgmt_network.dynamic:
                return

            # This is a DHCP lease for a node on the pxeboot network
            # Create the ihost (if necessary).
            ihost_dict = {'mgmt_mac': mac}
            self.create_ihost(context, ihost_dict, reason='dhcp pxeboot')

    def handle_dhcp_lease_from_clone(self, context, mac):
        """Handle dhcp request from a cloned controller-1.
           If MAC address in DB is still set to well known
           clone label, then this is the first boot of the
           other controller. Real MAC address from PXE request
           is updated in the DB."""
        controller_hosts =\
                self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        for host in controller_hosts:
            if (constants.CLONE_ISO_MAC in host.mgmt_mac and
                    host.personality == constants.CONTROLLER and
                    host.administrative == constants.ADMIN_LOCKED):
                LOG.info("create_ihost (clone): Host found: {}:{}:{}->{}"
                         .format(host.hostname, host.personality,
                                 host.mgmt_mac, mac))
                values = {'mgmt_mac': mac}
                self.dbapi.ihost_update(host.uuid, values)
                host.mgmt_mac = mac
                self._configure_controller_host(context, host)
                if host.personality and host.hostname:
                    ihost_mtc = host.as_dict()
                    ihost_mtc['operation'] = 'modify'
                    ihost_mtc = cutils.removekeys_nonmtce(ihost_mtc)
                    mtce_api.host_modify(
                             self._api_token, self._mtc_address,
                             self._mtc_port, ihost_mtc,
                             constants.MTC_DEFAULT_TIMEOUT_IN_SECS)
                return host
        return None

    def create_ihost(self, context, values, reason=None):
        """Create an ihost with the supplied data.

        This method allows an ihost to be created.

        :param context: an admin context
        :param values: initial values for new ihost object
        :returns: updated ihost object, including all fields.
        """

        if 'mgmt_mac' not in values:
            raise exception.SysinvException(_(
                "Invalid method call: create_ihost requires mgmt_mac."))

        try:
            mgmt_update_required = False
            mac = values['mgmt_mac']
            mac = mac.rstrip()
            mac = cutils.validate_and_normalize_mac(mac)
            ihost = self.dbapi.ihost_get_by_mgmt_mac(mac)
            LOG.info("Not creating ihost for mac: %s because it "
                      "already exists with uuid: %s" % (values['mgmt_mac'],
                                                        ihost['uuid']))
            mgmt_ip = values.get('mgmt_ip') or ""

            if mgmt_ip and not ihost.mgmt_ip:
                LOG.info("%s create_ihost setting mgmt_ip to %s" %
                         (ihost.uuid, mgmt_ip))
                mgmt_update_required = True
            elif mgmt_ip and ihost.mgmt_ip and \
               (ihost.mgmt_ip.strip() != mgmt_ip.strip()):
                # Changing the management IP on an already configured
                # host should not occur nor be allowed.
                LOG.error("DANGER %s create_ihost mgmt_ip dnsmasq change "
                          "detected from %s to %s." %
                          (ihost.uuid, ihost.mgmt_ip, mgmt_ip))

            if mgmt_update_required:
                ihost = self.dbapi.ihost_update(ihost.uuid, values)

                if ihost.personality and ihost.hostname:
                    ihost_mtc = ihost.as_dict()
                    ihost_mtc['operation'] = 'modify'
                    ihost_mtc = cutils.removekeys_nonmtce(ihost_mtc)
                    LOG.info("%s create_ihost update mtce %s " %
                             (ihost.hostname, ihost_mtc))
                    mtce_api.host_modify(
                             self._api_token, self._mtc_address, self._mtc_port,
                             ihost_mtc,
                             constants.MTC_DEFAULT_TIMEOUT_IN_SECS)

            return ihost
        except exception.NodeNotFound:
            # If host is not found, check if this is cloning scenario.
            # If yes, update management MAC in the DB and create PXE config.
            clone_host = self.handle_dhcp_lease_from_clone(context, mac)
            if clone_host:
                return clone_host

        # assign default system
        system = self.dbapi.isystem_get_one()
        values.update({'forisystemid': system.id})
        values.update({constants.HOST_ACTION_STATE: constants.HAS_REINSTALLING})

        # get tboot value from the active controller
        active_controller = None
        hosts = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        for h in hosts:
            if utils.is_host_active_controller(h):
                active_controller = h
                break
        software_load = None
        if active_controller is not None:
            tboot_value = active_controller.get('tboot')
            if tboot_value is not None:
                values.update({'tboot': tboot_value})
            software_load = active_controller.software_load
            LOG.info("create_ihost software_load=%s" % software_load)

        ihost = self.dbapi.ihost_create(values, software_load=software_load)

        # A host is being created, generate discovery log.
        self._log_host_create(ihost, reason)

        ihost_id = ihost.get('uuid')
        LOG.debug("RPC create_ihost called and created ihost %s." % ihost_id)

        return ihost

    def update_ihost(self, context, ihost_obj):
        """Update an ihost with the supplied data.

        This method allows an ihost to be updated.

        :param context: an admin context
        :param ihost_obj: a changed (but not saved) ihost object
        :returns: updated ihost object, including all fields.
        """

        ihost_id = ihost_obj['uuid']
        LOG.debug("RPC update_ihost called for ihost %s." % ihost_id)

        delta = ihost_obj.obj_what_changed()
        if ('id' in delta) or ('uuid' in delta):
            raise exception.SysinvException(_(
                "Invalid method call: update_ihost cannot change id or uuid "))

        ihost_obj.save(context)
        return ihost_obj

    def _dnsmasq_host_entry_to_string(self, ip_addr, hostname,
                                     mac_addr=None, cid=None):
        if IPNetwork(ip_addr).version == constants.IPV6_FAMILY:
            ip_addr = "[%s]" % ip_addr
        if cid:
            line = "id:%s,%s,%s,1d\n" % (cid, hostname, ip_addr)
        elif mac_addr:
            line = "%s,%s,%s,1d\n" % (mac_addr, hostname, ip_addr)
        else:
            line = "%s,%s\n" % (hostname, ip_addr)
        return line

    def _dnsmasq_addn_host_entry_to_string(self, ip_addr, hostname,
                                           aliases=[]):
        line = "%s %s" % (ip_addr, hostname)
        for alias in aliases:
            line = "%s %s" % (line, alias)
        line = "%s\n" % line
        return line

    def _generate_dnsmasq_hosts_file(self, existing_host=None,
                                     deleted_host=None):
        """Regenerates the dnsmasq host and addn_hosts files from database.

        :param existing_host: Include this host in list of hosts.
        :param deleted_host: Skip over writing MAC address for this host.
        """
        if (self.topic == 'test-topic'):
            dnsmasq_hosts_file = '/tmp/dnsmasq.hosts'
        else:
            dnsmasq_hosts_file = tsc.CONFIG_PATH + 'dnsmasq.hosts'

        if (self.topic == 'test-topic'):
            dnsmasq_addn_hosts_file = '/tmp/dnsmasq.addn_hosts'
        else:
            dnsmasq_addn_hosts_file = tsc.CONFIG_PATH + 'dnsmasq.addn_hosts'

        if deleted_host:
            deleted_hostname = deleted_host.hostname
        else:
            deleted_hostname = None

        temp_dnsmasq_hosts_file = dnsmasq_hosts_file + '.temp'
        temp_dnsmasq_addn_hosts_file = dnsmasq_addn_hosts_file + '.temp'
        mgmt_network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT
        )

        with open(temp_dnsmasq_hosts_file, 'w') as f_out,\
                open(temp_dnsmasq_addn_hosts_file, 'w') as f_out_addn:

            # Write entry for pxecontroller into addn_hosts file
            try:
                self.dbapi.network_get_by_type(
                    constants.NETWORK_TYPE_PXEBOOT
                )
                address = self.dbapi.address_get_by_name(
                    cutils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                               constants.NETWORK_TYPE_PXEBOOT)
                )
            except exception.NetworkTypeNotFound:
                address = self.dbapi.address_get_by_name(
                    cutils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                               constants.NETWORK_TYPE_MGMT)
                )
            addn_line = self._dnsmasq_addn_host_entry_to_string(
                address.address, constants.PXECONTROLLER_HOSTNAME
            )
            f_out_addn.write(addn_line)

            # Loop through mgmt addresses to write to file
            for address in self.dbapi._addresses_get_by_pool_uuid(
                    mgmt_network.pool_uuid):
                line = None
                hostname = re.sub("-%s$" % constants.NETWORK_TYPE_MGMT,
                                  '', str(address.name))

                if address.interface:
                    mac_address = address.interface.imac
                    # For cloning scenario, controller-1 MAC address will
                    # be updated in ethernet_interfaces table only later
                    # when sysinv-agent is initialized on controller-1.
                    # So, use the mac_address passed in (got from PXE request).
                    if (existing_host and
                            constants.CLONE_ISO_MAC in mac_address and
                            hostname == existing_host.hostname):
                        LOG.info("gen dnsmasq (clone):{}:{}->{}"
                                 .format(hostname, mac_address,
                                         existing_host.mgmt_mac))
                        mac_address = existing_host.mgmt_mac
                # If host is being deleted, don't check ihost
                elif deleted_hostname and deleted_hostname == hostname:
                    mac_address = None
                else:
                    try:
                        ihost = self.dbapi.ihost_get_by_hostname(hostname)
                        mac_address = ihost.mgmt_mac
                    except exception.NodeNotFound:
                        if existing_host and existing_host.hostname == hostname:
                            mac_address = existing_host.mgmt_mac
                        else:
                            mac_address = None
                line = self._dnsmasq_host_entry_to_string(address.address,
                                                          hostname,
                                                          mac_address)
                f_out.write(line)

        # Update host files atomically and reload dnsmasq
        if (not os.path.isfile(dnsmasq_hosts_file) or
                not filecmp.cmp(temp_dnsmasq_hosts_file, dnsmasq_hosts_file)):
            os.rename(temp_dnsmasq_hosts_file, dnsmasq_hosts_file)
        if (not os.path.isfile(dnsmasq_addn_hosts_file) or
                not filecmp.cmp(temp_dnsmasq_addn_hosts_file,
                                dnsmasq_addn_hosts_file)):
            os.rename(temp_dnsmasq_addn_hosts_file, dnsmasq_addn_hosts_file)

        # If there is no distributed cloud addn_hosts file, create an empty one
        # so dnsmasq will not complain.
        dnsmasq_addn_hosts_dc_file = os.path.join(tsc.CONFIG_PATH, 'dnsmasq.addn_hosts_dc')
        temp_dnsmasq_addn_hosts_dc_file = os.path.join(tsc.CONFIG_PATH, 'dnsmasq.addn_hosts_dc.temp')

        if not os.path.isfile(dnsmasq_addn_hosts_dc_file):
            with open(temp_dnsmasq_addn_hosts_dc_file, 'w') as f_out_addn_dc:
                f_out_addn_dc.write(' ')
            os.rename(temp_dnsmasq_addn_hosts_dc_file, dnsmasq_addn_hosts_dc_file)

        os.system("pkill -HUP dnsmasq")

    def _update_pxe_config(self, host, load=None):
        """Set up the PXE config file for this host so it can run
           the installer.

           This method must always be backward compatible with the previous
           software release. During upgrades, this method is called when
           locking/unlocking hosts running the previous release and when
           downgrading a host. In both cases, it must be able to re-generate
           the host's pxe config files appropriate to that host's software
           version, using the pxeboot-update-<release>.sh script from the
           previous release.

        :param host: host object.
        """
        sw_version = tsc.SW_VERSION
        if load:
            sw_version = load.software_version
        else:
            # No load provided, look it up...
            host_upgrade = self.dbapi.host_upgrade_get_by_host(host.id)
            target_load = self.dbapi.load_get(host_upgrade.target_load)
            sw_version = target_load.software_version

        if (host.personality == constants.CONTROLLER and
                constants.WORKER in tsc.subfunctions):
            if constants.LOWLATENCY in host.subfunctions:
                pxe_config = "pxe-smallsystem_lowlatency-install-%s" % sw_version
            else:
                pxe_config = "pxe-smallsystem-install-%s" % sw_version
        elif host.personality == constants.CONTROLLER:
            pxe_config = "pxe-controller-install-%s" % sw_version
        elif host.personality == constants.WORKER:
            if constants.LOWLATENCY in host.subfunctions:
                pxe_config = "pxe-worker_lowlatency-install-%s" % sw_version
            else:
                pxe_config = "pxe-worker-install-%s" % sw_version
        elif host.personality == constants.STORAGE:
            pxe_config = "pxe-storage-install-%s" % sw_version

        # Defaults for configurable install parameters
        install_opts = []

        boot_device = host.get('boot_device') or "sda"
        install_opts += ['-b', boot_device]

        rootfs_device = host.get('rootfs_device') or "sda"
        install_opts += ['-r', rootfs_device]

        install_output = host.get('install_output') or "text"
        if install_output == "text":
            install_output_arg = "-t"
        elif install_output == "graphical":
            install_output_arg = "-g"
        else:
            LOG.warning("install_output set to invalid value (%s)"
                        % install_output)
            install_output_arg = "-t"
        install_opts += [install_output_arg]

        # This version check MUST be present. The -u option does not exists
        # prior to v17.00. This method is also called during upgrades to
        # re-generate the host's pxe config files to the appropriate host's
        # software version. It is required specifically when we downgrade a
        # host or when we lock/unlock a host.
        if sw_version != tsc.SW_VERSION_1610:
            host_uuid = host.get('uuid')
            notify_url = \
                "http://pxecontroller:%d/v1/ihosts/%s/install_progress" % \
                (CONF.sysinv_api_port, host_uuid)
            install_opts += ['-u', notify_url]

        system = self.dbapi.isystem_get_one()

        # This version check MUST be present. The -s option
        # (security profile) does not exist 17.06 and below.
        if sw_version != tsc.SW_VERSION_1706:
            secprofile = system.security_profile
            # ensure that the securtiy profile selection is valid
            if secprofile not in [constants.SYSTEM_SECURITY_PROFILE_STANDARD,
                                  constants.SYSTEM_SECURITY_PROFILE_EXTENDED]:
                LOG.error("Security Profile (%s) not a valid selection. "
                          "Defaulting to: %s" % (secprofile,
                           constants.SYSTEM_SECURITY_PROFILE_STANDARD))
                secprofile = constants.SYSTEM_SECURITY_PROFILE_STANDARD
            install_opts += ['-s', secprofile]

        # If 'console' is not present in ihost_obj, we want to use the default.
        # If, however, it is present and is explicitly set to None or "", then
        # we don't specify the -c argument at all.
        if 'console' not in host:
            console = "ttyS0,115200"
        else:
            console = host.get('console')
        if console is not None and console != "":
            install_opts += ['-c', console]

        # If 'tboot' is present in ihost_obj, retrieve and send the value
        if 'tboot' in host:
            tboot = host.get('tboot')
            if tboot is not None and tboot != "":
                install_opts += ['-T', tboot]

        # This version check MUST be present. The -k option
        # (extra_kernel_args) does not exist 18.03 and below.
        if sw_version != tsc.SW_VERSION_1706 and \
           sw_version != tsc.SW_VERSION_1803:
            install_opts += ['-k', system.security_feature]

        base_url = "http://pxecontroller:%d" % cutils.get_http_port(self.dbapi)
        install_opts += ['-l', base_url]

        if host['mgmt_mac']:
            dashed_mac = host["mgmt_mac"].replace(":", "-")
            pxeboot_update = "/usr/sbin/pxeboot-update-%s.sh" % sw_version

            # Remove an old file if it exists
            try:
                os.remove("/pxeboot/pxelinux.cfg/01-" + dashed_mac)
            except OSError:
                pass

            try:
                os.remove("/pxeboot/pxelinux.cfg/efi-01-" + dashed_mac)
            except OSError:
                pass
            with open(os.devnull, "w") as fnull:
                try:
                    subprocess.check_call(
                        [pxeboot_update, "-i", "/pxeboot/pxelinux.cfg.files/" +
                         pxe_config, "-o", "/pxeboot/pxelinux.cfg/01-" +
                         dashed_mac] + install_opts,
                        stdout=fnull,
                        stderr=fnull)
                except subprocess.CalledProcessError:
                    raise exception.SysinvException(_(
                        "Failed to create pxelinux.cfg file"))

    def _remove_pxe_config(self, host):
        """Delete the PXE config file for this host.

        :param host: host object.
        """
        if host.mgmt_mac:
            dashed_mac = host.mgmt_mac.replace(":", "-")

            # Remove the old file if it exists
            try:
                os.remove("/pxeboot/pxelinux.cfg/01-" + dashed_mac)
            except OSError:
                pass

            try:
                os.remove("/pxeboot/pxelinux.cfg/efi-01-" + dashed_mac)
            except OSError:
                pass

    def _create_or_update_address(self, context, hostname, ip_address,
                                  iface_type, iface_id=None):
        if hostname is None or ip_address is None:
            return
        address_name = cutils.format_address_name(hostname, iface_type)
        address_family = IPNetwork(ip_address).version
        try:
            address = self.dbapi.address_get_by_address(ip_address)
            address_uuid = address['uuid']
            # If name is already set, return
            if (self.dbapi.address_get_by_name(address_name) ==
                    address_uuid and iface_id is None):
                return
        except exception.AddressNotFoundByAddress:
            address_uuid = None
        except exception.AddressNotFoundByName:
            pass
        network = self.dbapi.network_get_by_type(iface_type)
        address_pool_uuid = network.pool_uuid
        address_pool = self.dbapi.address_pool_get(address_pool_uuid)
        values = {
            'name': address_name,
            'family': address_family,
            'prefix': address_pool.prefix,
            'address': ip_address,
            'address_pool_id': address_pool.id,
        }

        if iface_id:
            values['interface_id'] = iface_id
        if address_uuid:
            address = self.dbapi.address_update(address_uuid, values)
        else:
            address = self.dbapi.address_create(values)
        self._generate_dnsmasq_hosts_file()
        return address

    def _allocate_pool_address(self, interface_id, pool_uuid, address_name):
        return address_pool.AddressPoolController.assign_address(
            interface_id, pool_uuid, address_name, dbapi=self.dbapi
        )

    def _allocate_addresses_for_host(self, context, host):
        """Allocates addresses for a given host.

        Does the following tasks:
        - Check if addresses exist for host
        - Allocate addresses for host from pools
        - Update ihost with mgmt address
        - Regenerate the dnsmasq hosts file

        :param context: request context
        :param host: host object
        """
        mgmt_ip = host.mgmt_ip
        mgmt_interfaces = self.iinterfaces_get_by_ihost_nettype(
            context, host.uuid, constants.NETWORK_TYPE_MGMT
        )
        mgmt_interface_id = None
        if mgmt_interfaces:
            mgmt_interface_id = mgmt_interfaces[0]['id']
        hostname = host.hostname
        address_name = cutils.format_address_name(hostname,
                                                  constants.NETWORK_TYPE_MGMT)
        # if ihost has mgmt_ip, make sure address in address table
        if mgmt_ip:
            self._create_or_update_address(context, hostname, mgmt_ip,
                                           constants.NETWORK_TYPE_MGMT,
                                           mgmt_interface_id)
        # if ihost has no management IP, check for static mgmt IP
        if not mgmt_ip:
            mgmt_ip = self._lookup_static_ip_address(
                hostname, constants.NETWORK_TYPE_MGMT
            )
            if mgmt_ip:
                host.mgmt_ip = mgmt_ip
                self.update_ihost(context, host)
        # if no static address, then allocate one
        if not mgmt_ip:
            mgmt_pool = self.dbapi.network_get_by_type(
                constants.NETWORK_TYPE_MGMT
            ).pool_uuid

            mgmt_ip = self._allocate_pool_address(mgmt_interface_id, mgmt_pool,
                                                  address_name).address
            if mgmt_ip:
                host.mgmt_ip = mgmt_ip
                self.update_ihost(context, host)

        self._generate_dnsmasq_hosts_file(existing_host=host)

    def get_my_host_id(self):
        if not ConductorManager.my_host_id:
            local_hostname = socket.gethostname()
            controller = self.dbapi.ihost_get(local_hostname)
            ConductorManager.my_host_id = controller['id']
        return ConductorManager.my_host_id

    def get_dhcp_server_duid(self):
        """Retrieves the server DUID from the local DHCP server lease file."""
        lease_filename = tsc.CONFIG_PATH + 'dnsmasq.leases'
        with open(lease_filename, 'r') as lease_file:
            for columns in (line.strip().split() for line in lease_file):
                if len(columns) != 2:
                    continue
                keyword, value = columns
                if keyword.lower() == "duid":
                    return value

    def _dhcp_release(self, interface, ip_address, mac_address, cid=None):
        """Release a given DHCP lease"""
        params = [interface, ip_address, mac_address]
        if cid:
            params += [cid]
        if IPAddress(ip_address).version == 6:
            params = ["--ip", ip_address,
                "--iface", interface,
                "--server-id", self.get_dhcp_server_duid(),
                "--client-id", cid,
                "--iaid", str(cutils.get_dhcp_client_iaid(mac_address))]
            LOG.warning("Invoking dhcp_release6 for {}".format(params))
            subprocess.call(["dhcp_release6"] + params)
        else:
            LOG.warning("Invoking dhcp_release for {}".format(params))
            subprocess.call(["dhcp_release"] + params)

    def _find_networktype_for_address(self, ip_address):
        for network in self.dbapi.networks_get_all():
            pool = self.dbapi.address_pool_get(network.pool_uuid)
            subnet = IPNetwork(pool.network + '/' + str(pool.prefix))
            address = IPAddress(ip_address)
            if address in subnet:
                return network.type

    def _find_local_interface_name(self, network_type):
        """Lookup the local interface name for a given network type."""
        host_id = self.get_my_host_id()
        interface_list = self.dbapi.iinterface_get_all(host_id, expunge=True)
        ifaces = dict((i['ifname'], i) for i in interface_list)
        port_list = self.dbapi.port_get_all(host_id)
        ports = dict((p['interface_id'], p) for p in port_list)
        for interface in interface_list:
            if interface.networktype == network_type:
                return cutils.get_interface_os_ifname(interface, ifaces, ports)

    def _find_local_mgmt_interface_vlan_id(self):
        """Lookup the local interface name for a given network type."""
        host_id = self.get_my_host_id()
        interface_list = self.dbapi.iinterface_get_all(host_id, expunge=True)
        for interface in interface_list:
            if interface.networktype == constants.NETWORK_TYPE_MGMT:
                if 'vlan_id' not in interface:
                    return 0
                else:
                    return interface['vlan_id']

    def _remove_leases_by_mac_address(self, mac_address):
        """Remove any leases that were added without a CID that we were not
        able to delete.  This is specifically looking for leases on the pxeboot
        network that may still be present but will also handle the unlikely
        event of deleting an old host during an upgrade.  Hosts on previous
        releases did not register a CID on the mgmt interface."""
        lease_filename = tsc.CONFIG_PATH + 'dnsmasq.leases'
        try:
            with open(lease_filename, 'r') as lease_file:
                for columns in (line.strip().split() for line in lease_file):
                    if len(columns) != 5:
                        continue
                    timestamp, address, ip_address, hostname, cid = columns
                    if address != mac_address:
                        continue
                    network_type = self._find_networktype_for_address(ip_address)
                    if not network_type:
                        # Not one of our managed networks
                        LOG.warning("Lease for unknown network found in "
                                    "dnsmasq.leases file: {}".format(columns))
                        continue
                    interface_name = self._find_local_interface_name(
                        network_type
                    )
                    self._dhcp_release(interface_name, ip_address, mac_address)
        except Exception as e:
            LOG.error("Failed to remove leases for %s: %s" % (mac_address,
                                                              str(e)))

    def _remove_lease_for_address(self, hostname, network_type):
        """Remove the lease for a given address"""
        address_name = cutils.format_address_name(hostname, network_type)
        try:
            interface_name = self._find_local_interface_name(network_type)
            if not interface_name:
                return

            address = self.dbapi.address_get_by_name(address_name)
            interface_uuid = address.interface_uuid
            ip_address = address.address

            if interface_uuid:
                interface = self.dbapi.iinterface_get(interface_uuid)
                mac_address = interface.imac
            elif network_type == constants.NETWORK_TYPE_MGMT:
                ihost = self.dbapi.ihost_get_by_hostname(hostname)
                mac_address = ihost.mgmt_mac
            else:
                return

            cid = cutils.get_dhcp_cid(hostname, network_type, mac_address)
            self._dhcp_release(interface_name, ip_address, mac_address, cid)
        except Exception as e:
            LOG.error("Failed to remove lease %s: %s" % (address_name,
                                                         str(e)))

    def _unallocate_address(self, hostname, network_type):
        """Unallocate address if it exists"""
        address_name = cutils.format_address_name(hostname, network_type)
        if network_type == constants.NETWORK_TYPE_MGMT:
            self._remove_lease_for_address(hostname, network_type)
        try:
            address_uuid = self.dbapi.address_get_by_name(address_name).uuid
            self.dbapi.address_remove_interface(address_uuid)
        except exception.AddressNotFoundByName:
            pass

    def _remove_address(self, hostname, network_type):
        """Remove address if it exists"""
        address_name = cutils.format_address_name(hostname, network_type)
        self._remove_lease_for_address(hostname, network_type)
        try:
            address_uuid = self.dbapi.address_get_by_name(address_name).uuid
            self.dbapi.address_destroy(address_uuid)
        except exception.AddressNotFoundByName:
            pass
        except exception.AddressNotFound:
            pass

    def _unallocate_addresses_for_host(self, host):
        """Unallocates management addresses for a given host.

        :param host: host object
        """
        hostname = host.hostname
        self._unallocate_address(hostname, constants.NETWORK_TYPE_MGMT)
        if host.personality == constants.CONTROLLER:
            self._unallocate_address(hostname, constants.NETWORK_TYPE_OAM)
            self._unallocate_address(hostname, constants.NETWORK_TYPE_PXEBOOT)
        self._remove_leases_by_mac_address(host.mgmt_mac)
        self._generate_dnsmasq_hosts_file(deleted_host=host)

    def _remove_addresses_for_host(self, host):
        """Removes management addresses for a given host.

        :param host: host object
        """
        hostname = host.hostname
        self._remove_address(hostname, constants.NETWORK_TYPE_MGMT)
        self._remove_leases_by_mac_address(host.mgmt_mac)
        self._generate_dnsmasq_hosts_file(deleted_host=host)

    def _configure_controller_host(self, context, host):
        """Configure a controller host with the supplied data.

        Does the following tasks:
        - Update the puppet hiera data configuration for host
        - Allocates management address if none exists
        - Set up PXE configuration to run installer
        - Update grub for AIO before initial unlock

        :param context: request context
        :param host: host object
        """
        # Only update the config if the host is running the same version as
        # the active controller.
        if self.host_load_matches_sw_version(host):
            if (host.administrative == constants.ADMIN_UNLOCKED or
                    host.action == constants.FORCE_UNLOCK_ACTION or
                    host.action == constants.UNLOCK_ACTION):

                # Update host configuration
                self._puppet.update_host_config(host)
        else:
            LOG.info("Host %s is not running active load. "
                     "Skipping manifest generation" % host.hostname)

        self._allocate_addresses_for_host(context, host)
        # Set up the PXE config file for this host so it can run the installer
        self._update_pxe_config(host)
        self._ceph_mon_create(host)

        if (os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG) and
                host.availability == constants.AVAILABILITY_ONLINE):
            # This must be the initial controller host unlock request.
            personalities = [constants.CONTROLLER]
            if not utils.is_aio_system(self.dbapi):
                # Standard system, touch the unlock ready flag
                cutils.touch(constants.UNLOCK_READY_FLAG)
            else:
                # AIO, must update grub before the unlock. Sysinv agent expects
                # this exact set of manifests in order to touch the unlock ready
                # flag after they have been applied.
                config_uuid = self._config_update_hosts(context, personalities)
                if self._config_is_reboot_required(host.config_target):
                    config_uuid = self._config_set_reboot_required(config_uuid)

                config_dict = {
                    "personalities": personalities,
                    "host_uuids": [host.uuid],
                    "classes": ['platform::compute::grub::runtime',
                                'platform::compute::config::runtime']
                }
                self._config_apply_runtime_manifest(
                    context, config_uuid, config_dict, force=True)

            # Regenerate config target uuid, node is going for reboot!
            config_uuid = self._config_update_hosts(context, personalities)
            if self._config_is_reboot_required(host.config_target):
                config_uuid = self._config_set_reboot_required(config_uuid)
            self._puppet.update_host_config(host, config_uuid)

    def _ceph_mon_create(self, host):
        if not StorageBackendConfig.has_backend(
            self.dbapi,
            constants.CINDER_BACKEND_CEPH
        ):
            return
        if not self.dbapi.ceph_mon_get_by_ihost(host.uuid):
            system = self.dbapi.isystem_get_one()
            ceph_mon_gib = None
            ceph_mons = self.dbapi.ceph_mon_get_list()
            if ceph_mons:
                ceph_mon_gib = ceph_mons[0].ceph_mon_gib
            values = {'forisystemid': system.id,
                      'forihostid': host.id,
                      'ceph_mon_gib': ceph_mon_gib,
                      'state': constants.SB_STATE_CONFIGURED,
                      'task': constants.SB_TASK_NONE}
            LOG.info("creating ceph_mon for host %s with ceph_mon_gib=%s."
                     % (host.hostname, ceph_mon_gib))
            self.dbapi.ceph_mon_create(values)

    def _remove_ceph_mon(self, host):
        if not StorageBackendConfig.has_backend(
            self.dbapi,
            constants.CINDER_BACKEND_CEPH
        ):
            return

        mon = self.dbapi.ceph_mon_get_by_ihost(host.uuid)
        if mon:
            LOG.info("Deleting ceph monitor for host %s"
                     % str(host.hostname))
            self.dbapi.ceph_mon_destroy(mon[0].uuid)
        else:
            LOG.info("No ceph monitor present for host %s. "
                     "Skipping deleting ceph monitor."
                     % str(host.hostname))

    def update_remotelogging_config(self, context):
        """Update the remotelogging configuration"""

        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": [constants.CONTROLLER],
            "classes": ['platform::sysctl::controller::runtime',
                        'platform::remotelogging::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        config_dict = {
            "personalities": [constants.WORKER, constants.STORAGE],
            "classes": ['platform::remotelogging::runtime'],
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def get_magnum_cluster_count(self, context):
        return self._openstack.get_magnum_cluster_count()

    def _configure_worker_host(self, context, host):
        """Configure a worker host with the supplied data.

        Does the following tasks:
        - Create or update entries in address table
        - Generate the configuration file for the host
        - Allocates management address if none exists
        - Set up PXE configuration to run installer

        :param context: request context
        :param host: host object
        """
        # Only update the config if the host is running the same version as
        # the active controller.
        if self.host_load_matches_sw_version(host):
            # Only generate the config files if the worker host is unlocked.
            if (host.administrative == constants.ADMIN_UNLOCKED or
                    host.action == constants.FORCE_UNLOCK_ACTION or
                    host.action == constants.UNLOCK_ACTION):
                # Generate host configuration file
                self._puppet.update_host_config(host)
        else:
            LOG.info("Host %s is not running active load. "
                     "Skipping manifest generation" % host.hostname)

        self._allocate_addresses_for_host(context, host)
        # Set up the PXE config file for this host so it can run the installer
        self._update_pxe_config(host)

    def _configure_storage_host(self, context, host):
        """Configure a storage ihost with the supplied data.

        Does the following tasks:
        - Update the puppet hiera data configuration for host
        - Allocates management address if none exists
        - Set up PXE configuration to run installer

        :param context: request context
        :param host: host object
        """

        # Update cluster and peers model
        self._ceph.update_ceph_cluster(host)

        # Only update the manifest if the host is running the same version as
        # the active controller.
        if self.host_load_matches_sw_version(host):
            # Only generate the manifest files if the storage host is unlocked.
            # At that point changes are no longer allowed to the hostname, so
            # it is OK to allow the node to boot and configure the platform
            # services.
            if (host.administrative == constants.ADMIN_UNLOCKED or
                    host.action == constants.FORCE_UNLOCK_ACTION or
                    host.action == constants.UNLOCK_ACTION):

                # TODO(CephPoolsDecouple): remove
                # Ensure the OSD pools exists. In the case of a system restore,
                # the pools must be re-created when the first storage node is
                # unlocked.
                if not utils.is_kubernetes_config(self.dbapi):
                    self._ceph.configure_osd_pools()

                # Generate host configuration files
                self._puppet.update_host_config(host)
        else:
            LOG.info("Host %s is not running active load. "
                     "Skipping manifest generation" % host.hostname)

        self._allocate_addresses_for_host(context, host)
        # Set up the PXE config file for this host so it can run the installer
        self._update_pxe_config(host)
        if host['hostname'] == constants.STORAGE_0_HOSTNAME:
            self._ceph_mon_create(host)

    # TODO(CephPoolsDecouple): remove
    def configure_osd_pools(self, context, ceph_backend=None, new_pool_size=None, new_pool_min_size=None):
        """Configure or update configuration of the OSD pools.
        If none of the optionals are provided then all pools are updated based on DB configuration.

        :param context: an admin context.
        :param ceph_backend: Optional ceph backend object of a tier
        :param new_pool_size: Optional override for replication number.
        :param new_pool_min_size: Optional override for minimum replication number.
        """
        self._ceph.configure_osd_pools(ceph_backend, new_pool_size, new_pool_min_size)

    def remove_host_config(self, context, host_uuid):
        """Remove configuration files for a host.

        :param context: an admin context.
        :param host_uuid: host uuid.
        """
        host = self.dbapi.ihost_get(host_uuid)

        self._puppet.remove_host_config(host)

    def _unconfigure_controller_host(self, host):
        """Unconfigure a controller host.

        Does the following tasks:
        - Remove the puppet hiera data configuration for host
        - Remove host entry in the dnsmasq hosts file
        - Delete PXE configuration

        :param host: a host object.
        """
        self._unallocate_addresses_for_host(host)
        self._puppet.remove_host_config(host)
        self._remove_pxe_config(host)

        # Create the simplex flag on this controller because our mate has
        # been deleted.
        cutils.touch(tsc.PLATFORM_SIMPLEX_FLAG)

        if host.hostname == constants.CONTROLLER_0_HOSTNAME:
            self.controller_0_posted = False
        elif host.hostname == constants.CONTROLLER_1_HOSTNAME:
            self.controller_1_posted = False

    def _unconfigure_worker_host(self, host, is_cpe=False):
        """Unconfigure a worker host.

        Does the following tasks:
        - Remove the puppet hiera data configuration for host
        - Remove the host entry from the dnsmasq hosts file
        - Delete PXE configuration

        :param host: a host object.
        :param is_cpe: this node is a combined node
        """
        if not is_cpe:
            self._remove_addresses_for_host(host)
        self._puppet.remove_host_config(host)
        self._remove_pxe_config(host)
        self._remove_ceph_mon(host)

    def _unconfigure_storage_host(self, host):
        """Unconfigure a storage host.

        Does the following tasks:
        - Remove the puppet hiera data configuration for host
        - Remove host entry in the dnsmasq hosts file
        - Delete PXE configuration

        :param host: a host object.
        """
        self._unallocate_addresses_for_host(host)
        self._puppet.remove_host_config(host)
        self._remove_pxe_config(host)

    def configure_ihost(self, context, host,
                        do_worker_apply=False):
        """Configure a host.

        :param context: an admin context.
        :param host: a host object.
        :param do_worker_apply: configure the worker subfunctions of the host.
        """

        LOG.debug("configure_ihost %s" % host.hostname)

        # Generate system configuration files
        # TODO(mpeters): remove this once all system reconfigurations properly
        # invoke this method
        self._puppet.update_system_config()
        self._puppet.update_secure_system_config()

        if host.personality == constants.CONTROLLER:
            self._configure_controller_host(context, host)
        elif host.personality == constants.WORKER:
            self._configure_worker_host(context, host)
        elif host.personality == constants.STORAGE:
            self._configure_storage_host(context, host)
        else:
            raise exception.SysinvException(_(
                "Invalid method call: unsupported personality: %s") %
                                            host.personality)

        if do_worker_apply:
            # Apply the manifests immediately
            puppet_common.puppet_apply_manifest(host.mgmt_ip,
                                                       constants.WORKER,
                                                       do_reboot=True)
        return host

    def unconfigure_ihost(self, context, ihost_obj):
        """Unconfigure a host.

        :param context: an admin context.
        :param ihost_obj: a host object.
        """
        LOG.debug("unconfigure_ihost %s." % ihost_obj.uuid)

        # Configuring subfunctions of the node instead
        if ihost_obj.subfunctions:
            personalities = cutils.get_personalities(ihost_obj)
            is_cpe = cutils.is_cpe(ihost_obj)
        else:
            personalities = (ihost_obj.personality,)
            is_cpe = False

        for personality in personalities:
            if personality == constants.CONTROLLER:
                self._unconfigure_controller_host(ihost_obj)
            elif personality == constants.WORKER:
                self._unconfigure_worker_host(ihost_obj, is_cpe)
            elif personality == constants.STORAGE:
                self._unconfigure_storage_host(ihost_obj)
            else:
                # allow a host with no personality to be unconfigured
                pass

    def _update_dependent_interfaces(self, interface, ihost,
                                     phy_intf, newmac, depth=1):
        """ Updates the MAC address for dependent logical interfaces.

        :param interface: interface object
        :param ihost: host object
        :param phy_intf: physical interface name
        :newmac: MAC address to be updated
        """
        if depth > 5:
            # be safe! dont loop for cyclic DB entries
            LOG.error("Looping? [{}] {}:{}".format(depth, phy_intf, newmac))
            return
        label = constants.CLONE_ISO_MAC + ihost['hostname'] + phy_intf
        if hasattr(interface, 'used_by'):
            LOG.info("clone_mac_update: {} used_by {} on {}".format(
                interface['ifname'], interface['used_by'], ihost['hostname']))
            for i in interface['used_by']:
                used_by_if = self.dbapi.iinterface_get(i, ihost['uuid'])
                if used_by_if:
                    LOG.debug("clone_mac_update: Found used_by_if: {} {} --> {} [{}]"
                              .format(used_by_if['ifname'],
                                used_by_if['imac'],
                                newmac, label))
                    if label in used_by_if['imac']:
                        updates = {'imac': newmac}
                        self.dbapi.iinterface_update(used_by_if['uuid'], updates)
                        LOG.info("clone_mac_update: MAC updated: {} {} --> {} [{}]"
                                 .format(used_by_if['ifname'],
                                    used_by_if['imac'],
                                    newmac, label))
                # look for dependent interfaces of this one.
                self._update_dependent_interfaces(used_by_if, ihost, phy_intf,
                                                  newmac, depth + 1)

    def validate_cloned_interfaces(self, ihost_uuid):
        """Check if all the cloned interfaces are reported by the host.

        :param ihost_uuid: ihost uuid unique id
        """
        LOG.info("clone_mac_update: validate_cloned_interfaces %s" % ihost_uuid)
        try:
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)
        except exc.DetachedInstanceError:
            # A rare DetachedInstanceError exception may occur, retry
            LOG.warn("Detached Instance Error,  retry "
                     "iinterface_get_by_ihost %s" % ihost_uuid)
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)
        for interface in iinterfaces:
            if constants.CLONE_ISO_MAC in interface['imac']:
                LOG.warn("Missing interface [{},{}] on the cloned host"
                         .format(interface['ifname'], interface['id']))
                raise exception.SysinvException(_(
                        "Missing interface on the cloned host"))

    def iport_update_by_ihost(self, context,
                              ihost_uuid, inic_dict_array):
        """Create iports for an ihost with the supplied data.

        This method allows records for iports for ihost to be created.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param inic_dict_array: initial values for iport objects
        :returns: pass or fail
        """

        LOG.debug("Entering iport_update_by_ihost %s %s" %
                  (ihost_uuid, inic_dict_array))
        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        try:
            hostname = socket.gethostname()
        except socket.error:
            LOG.exception("Failed to get local hostname")
            hostname = None

        try:
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)
        except exc.DetachedInstanceError:
            # A rare DetachedInstanceError exception may occur, retry
            LOG.warn("Detached Instance Error,  retry "
                     "iinterface_get_by_ihost %s" % ihost_uuid)
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)

        for i in iinterfaces:
            if i.networktype == constants.NETWORK_TYPE_MGMT:
                break

        cloning = False
        for inic in inic_dict_array:
            LOG.debug("Processing inic %s" % inic)
            interface_exists = False
            networktype = None
            ifclass = None
            bootp = None
            create_tagged_interface = False
            new_interface = None
            set_address_interface = False
            mtu = constants.DEFAULT_MTU
            port = None
            vlan_id = self._find_local_mgmt_interface_vlan_id()
            # ignore port if no MAC address present, this will
            # occur for data port after they are configured via DPDK driver
            if not inic['mac']:
                continue
            try:
                inic_dict = {'host_id': ihost['id']}
                inic_dict.update(inic)
                ifname = inic['pname']
                if cutils.is_valid_mac(inic['mac']):
                    # Is this the port that the management interface is on?
                    if inic['mac'].strip() == ihost['mgmt_mac'].strip():
                        if ihost['hostname'] != hostname:
                            # auto create management/pxeboot network for all
                            # nodes but the active controller
                            if vlan_id:
                                create_tagged_interface = True
                                networktype = constants.NETWORK_TYPE_PXEBOOT
                                ifname = 'pxeboot0'
                            else:
                                networktype = constants.NETWORK_TYPE_MGMT
                                ifname = 'mgmt0'
                            ifclass = constants.INTERFACE_CLASS_PLATFORM
                            set_address_interface = True
                        bootp = 'True'

                clone_mac_updated = False
                for interface in iinterfaces:
                    LOG.debug("Checking interface %s" % interface)
                    if interface['imac'] == inic['mac']:
                        # append to port attributes as well
                        inic_dict.update({
                            'interface_id': interface['id'], 'bootp': bootp
                        })

                        # interface already exists so don't create another
                        interface_exists = True
                        LOG.debug("interface mac match inic mac %s, inic_dict "
                                  "%s, interface_exists %s" %
                                  (interface['imac'], inic_dict,
                                   interface_exists))
                        break
                    # If there are interfaces with clone labels as MAC addresses,
                    # this is a install-from-clone scenario. Update MAC addresses.
                    elif ((constants.CLONE_ISO_MAC + ihost['hostname'] + inic['pname']) ==
                          interface['imac']):
                        # Not checking for "interface['ifname'] == ifname",
                        # as it could be data0, bond0.100
                        updates = {'imac': inic['mac']}
                        self.dbapi.iinterface_update(interface['uuid'], updates)
                        LOG.info("clone_mac_update: updated if mac {} {} --> {}"
                            .format(ifname, interface['imac'], inic['mac']))
                        ports = self.dbapi.ethernet_port_get_by_interface(
                                                              interface['uuid'])
                        for p in ports:
                            # Update the corresponding ports too
                            LOG.debug("clone_mac_update: port={} mac={} for intf: {}"
                                .format(p['id'], p['mac'], interface['uuid']))
                            if constants.CLONE_ISO_MAC in p['mac']:
                                updates = {'mac': inic['mac']}
                                self.dbapi.ethernet_port_update(p['id'], updates)
                                LOG.info("clone_mac_update: updated port: {} {}-->{}"
                                    .format(p['id'], p['mac'], inic['mac']))
                        # See if there are dependent interfaces.
                        # If yes, update them too.
                        self._update_dependent_interfaces(interface, ihost,
                                                          ifname, inic['mac'])
                        clone_mac_updated = True

                        if ((constants.CLONE_ISO_MAC + ihost['hostname'] + inic['pname'])
                                in ihost['mgmt_mac']):
                            LOG.info("clone_mac_update: mgmt_mac {}:{}"
                                     .format(ihost['mgmt_mac'], inic['mac']))
                            values = {'mgmt_mac': inic['mac']}
                            self.dbapi.ihost_update(ihost['uuid'], values)

                if clone_mac_updated:
                    # no need create any interfaces or ports for cloning scenario
                    cloning = True
                    continue

                if not interface_exists:
                    interface_dict = {'forihostid': ihost['id'],
                                      'ifname': ifname,
                                      'imac': inic['mac'],
                                      'imtu': mtu,
                                      'iftype': 'ethernet',
                                      'ifclass': ifclass,
                                      'networktype': networktype
                                      }

                    # autocreate untagged interface
                    try:
                        LOG.debug("Attempting to create new interface %s" %
                                  interface_dict)
                        new_interface = self.dbapi.iinterface_create(
                                          ihost['id'],
                                          interface_dict)
                        # append to port attributes as well
                        inic_dict.update(
                            {'interface_id': new_interface['id'],
                             'bootp': bootp
                             })
                        if networktype in [constants.NETWORK_TYPE_MGMT,
                                           constants.NETWORK_TYPE_PXEBOOT]:
                            network = self.dbapi.network_get_by_type(networktype)
                            # create interface network association
                            ifnet_dict = {
                                'interface_id': new_interface['id'],
                                'network_id': network['id']
                            }
                            try:
                                self.dbapi.interface_network_create(ifnet_dict)
                            except Exception:
                                LOG.exception(
                                    "Failed to create interface %s "
                                    "network %s association" %
                                    (new_interface['id'], network['id']))
                    except Exception:
                        LOG.exception("Failed to create new interface %s" %
                                      inic['mac'])
                        pass  # at least create the port

                    if create_tagged_interface:
                        # autocreate tagged management interface
                        interface_dict = {
                            'forihostid': ihost['id'],
                            'ifname': 'mgmt0',
                            'imac': inic['mac'],
                            'imtu': constants.DEFAULT_MTU,
                            'iftype': 'vlan',
                            'ifclass': constants.INTERFACE_CLASS_PLATFORM,
                            'networktype': constants.NETWORK_TYPE_MGMT,
                            'uses': [ifname],
                            'vlan_id': vlan_id,
                        }

                        try:
                            LOG.debug("Attempting to create new interface %s" %
                                      interface_dict)
                            new_interface = self.dbapi.iinterface_create(
                                ihost['id'], interface_dict
                            )
                            network = self.dbapi.network_get_by_type(
                                constants.NETWORK_TYPE_MGMT
                            )
                            # create interface network association
                            ifnet_dict = {
                                'interface_id': new_interface['id'],
                                'network_id': network['id']
                            }
                            try:
                                self.dbapi.interface_network_create(ifnet_dict)
                            except Exception:
                                LOG.exception(
                                    "Failed to create interface %s "
                                    "network %s association" %
                                    (new_interface['id'], network['id']))
                        except Exception:
                            LOG.exception(
                                "Failed to create new vlan interface %s" %
                                inic['mac'])
                            pass  # at least create the port

                try:
                    LOG.debug("Attempting to create new port %s on host %s" %
                              (inic_dict, ihost['id']))

                    port = self.dbapi.ethernet_port_get_by_mac(inic['mac'])

                    # update existing port with updated attributes
                    try:
                        port_dict = {
                            'sriov_totalvfs': inic['sriov_totalvfs'],
                            'sriov_numvfs': inic['sriov_numvfs'],
                            'sriov_vfs_pci_address':
                                inic['sriov_vfs_pci_address'],
                            'driver': inic['driver'],
                            'dpdksupport': inic['dpdksupport'],
                            'speed': inic['speed'],
                        }

                        LOG.info("port %s update attr: %s" %
                                 (port.uuid, port_dict))
                        self.dbapi.ethernet_port_update(port.uuid, port_dict)

                        # During WRL to CentOS upgrades the port name can
                        # change. This will update the db to reflect that
                        if port['name'] != inic['pname']:
                            self._update_port_name(port, inic['pname'])
                    except Exception:
                        LOG.exception("Failed to update port %s" % inic['mac'])
                        pass

                except Exception:
                    # adjust for field naming differences between the NIC
                    # dictionary returned by the agent and the Port model
                    port_dict = inic_dict.copy()
                    port_dict['name'] = port_dict.pop('pname', None)
                    port_dict['namedisplay'] = port_dict.pop('pnamedisplay',
                                                             None)

                    LOG.info("Attempting to create new port %s "
                             "on host %s" % (inic_dict, ihost.uuid))
                    port = self.dbapi.ethernet_port_create(ihost.uuid, port_dict)

            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid ihost_uuid: host not found: %s") %
                    ihost_uuid)

            except Exception:  # this info may have been posted previously, update ?
                pass

            # Set interface ID for management address
            if set_address_interface:
                if new_interface and 'id' in new_interface:
                    values = {'interface_id': new_interface['id']}
                    try:
                        addr_name = cutils.format_address_name(
                            ihost.hostname, new_interface['networktype'])
                        address = self.dbapi.address_get_by_name(addr_name)
                        self.dbapi.address_update(address['uuid'], values)
                    except exception.AddressNotFoundByName:
                        pass
                    # Do any potential distributed cloud config
                    # We do this here where the interface is created.
                    cutils.perform_distributed_cloud_config(self.dbapi,
                                                            new_interface['id'])
                if port:
                    values = {'interface_id': port.interface_id}
                try:
                    addr_name = cutils.format_address_name(ihost.hostname,
                                                           networktype)
                    address = self.dbapi.address_get_by_name(addr_name)
                    if address['interface_uuid'] is None:
                        self.dbapi.address_update(address['uuid'], values)
                except exception.AddressNotFoundByName:
                    pass

        if ihost.invprovision not in [constants.PROVISIONED, constants.PROVISIONING]:
            value = {'invprovision': constants.UNPROVISIONED}
            self.dbapi.ihost_update(ihost_uuid, value)

        if cloning:
            # if cloning scenario, check and log if there are lesser no:of interfaces
            # on the host being installed with a cloned image. Comparison is against
            # the DB which was backed up on the original system (used for cloning).
            self.validate_cloned_interfaces(ihost_uuid)

    def _update_port_name(self, port, updated_name):
        """
        Sets the port name based on the updated name.
        Will also set the ifname of any associated ethernet/vlan interfaces
        We do not modify any AE interfaces. The names of AE interfaces should
        not be related to any physical ports.
        :param port: the db object of the port to update
        :param updated_name: the new name
        """
        port_name = port['name']
        # Might need to update the associated interface and vlan names as well
        interface = self.dbapi.iinterface_get(port['interface_id'])
        if interface.ifname == port_name:
            LOG.info("Updating interface name: %s to %s" %
                     (interface.ifname, updated_name))
            self.dbapi.iinterface_update(interface.uuid,
                                         {'ifname': updated_name})

            used_by = interface['used_by']
            for ifname in used_by:
                vlan = self.dbapi.iinterface_get(ifname, port['forihostid'])
                if vlan.get('iftype') != constants.INTERFACE_TYPE_VLAN:
                    continue
                if vlan.ifname.startswith((port_name + ".")):
                    new_vlan_name = vlan.ifname.replace(
                        port_name, updated_name, 1)
                    LOG.info("Updating vlan interface name: %s to %s" %
                             (vlan.ifname, new_vlan_name))
                    self.dbapi.iinterface_update(vlan.uuid,
                                                 {'ifname': new_vlan_name})
        LOG.info("Updating port name: %s to %s" % (port_name, updated_name))
        self.dbapi.ethernet_port_update(port['uuid'], {'name': updated_name})

    def lldp_id_to_port(self, id, ports):
        ovs_id = re.sub(r'^{}'.format(constants.LLDP_OVS_PORT_PREFIX), '', id)
        for port in ports:
            if (port['name'] == id or
                    port['uuid'] == id or
                    port['uuid'].find(ovs_id) == 0):
                return port
        return None

    def lldp_tlv_dict(self, agent_neighbour_dict):
        tlv_dict = {}
        for k, v in agent_neighbour_dict.items():
            if v is not None and k in constants.LLDP_TLV_VALID_LIST:
                tlv_dict.update({k: v})
        return tlv_dict

    def lldp_agent_tlv_update(self, tlv_dict, agent):
        tlv_update_list = []
        tlv_create_list = []
        agent_id = agent['id']
        agent_uuid = agent['uuid']

        tlvs = self.dbapi.lldp_tlv_get_by_agent(agent_uuid)
        for k, v in tlv_dict.items():
            for tlv in tlvs:
                if tlv['type'] == k:
                    tlv_value = tlv_dict.get(tlv['type'])
                    entry = {'type': tlv['type'],
                             'value': tlv_value}
                    if tlv['value'] != tlv_value:
                        tlv_update_list.append(entry)
                    break
            else:
                tlv_create_list.append({'type': k,
                                        'value': v})

        if tlv_update_list:
            try:
                tlvs = self.dbapi.lldp_tlv_update_bulk(tlv_update_list,
                                                       agentid=agent_id)
            except Exception as e:
                LOG.exception("Error during bulk TLV update for agent %s: %s",
                    agent_id, str(e))
                raise
        if tlv_create_list:
            try:
                self.dbapi.lldp_tlv_create_bulk(tlv_create_list,
                                                agentid=agent_id)
            except Exception as e:
                LOG.exception("Error during bulk TLV create for agent %s: %s",
                    agent_id, str(e))
                raise

    def lldp_neighbour_tlv_update(self, tlv_dict, neighbour):
        tlv_update_list = []
        tlv_create_list = []
        neighbour_id = neighbour['id']
        neighbour_uuid = neighbour['uuid']

        tlvs = self.dbapi.lldp_tlv_get_by_neighbour(neighbour_uuid)
        for k, v in tlv_dict.items():
            for tlv in tlvs:
                if tlv['type'] == k:
                    tlv_value = tlv_dict.get(tlv['type'])
                    entry = {'type': tlv['type'],
                             'value': tlv_value}
                    if tlv['value'] != tlv_value:
                        tlv_update_list.append(entry)
                    break
            else:
                tlv_create_list.append({'type': k,
                                        'value': v})

        if tlv_update_list:
            try:
                tlvs = self.dbapi.lldp_tlv_update_bulk(
                    tlv_update_list,
                    neighbourid=neighbour_id)
            except Exception as e:
                LOG.exception("Error during bulk TLV update for neighbour"
                              "%s: %s", neighbour_id, str(e))
                raise
        if tlv_create_list:
            try:
                self.dbapi.lldp_tlv_create_bulk(tlv_create_list,
                                                neighbourid=neighbour_id)
            except Exception as e:
                LOG.exception("Error during bulk TLV create for neighbour"
                              "%s: %s",
                              neighbour_id, str(e))
                raise

    def lldp_agent_update_by_host(self, context,
                                  host_uuid, agent_dict_array):
        """Create or update lldp agents for an host with the supplied data.

        This method allows records for lldp agents for ihost to be created or
        updated.

        :param context: an admin context
        :param host_uuid: host uuid unique id
        :param agent_dict_array: initial values for lldp agent objects
        :returns: pass or fail
        """
        LOG.debug("Entering lldp_agent_update_by_host %s %s" %
                  (host_uuid, agent_dict_array))
        host_uuid.strip()
        try:
            db_host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            raise exception.SysinvException(_(
                "Invalid host_uuid: %s") % host_uuid)

        try:
            db_ports = self.dbapi.port_get_by_host(host_uuid)
        except Exception:
            raise exception.SysinvException(_(
                "Error getting ports for host %s") % host_uuid)

        try:
            db_agents = self.dbapi.lldp_agent_get_by_host(host_uuid)
        except Exception:
            raise exception.SysinvException(_(
                "Error getting LLDP agents for host %s") % host_uuid)

        for agent in agent_dict_array:
            db_port = self.lldp_id_to_port(agent['name_or_uuid'], db_ports)
            if not db_port:
                LOG.debug("Could not find port for agent %s",
                          agent['name_or_uuid'])
                return

            hostid = db_host['id']
            portid = db_port['id']

            agent_found = None
            for db_agent in db_agents:
                if db_agent['port_id'] == portid:
                    agent_found = db_agent
                    break

            LOG.debug("Processing agent %s" % agent)

            agent_dict = {'host_id': hostid,
                          'port_id': portid,
                          'status': agent['status']}
            update_tlv = False
            try:
                if not agent_found:
                    LOG.info("Attempting to create new LLDP agent "
                             "%s on host %s" % (agent_dict, hostid))
                    if agent['state'] != constants.LLDP_AGENT_STATE_REMOVED:
                        db_agent = self.dbapi.lldp_agent_create(portid,
                                                                hostid,
                                                                agent_dict)
                        update_tlv = True
                else:
                    # If the agent exists, try to update some of the fields
                    # or remove it
                    agent_uuid = db_agent['uuid']
                    if agent['state'] == constants.LLDP_AGENT_STATE_REMOVED:
                        db_agent = self.dbapi.lldp_agent_destroy(agent_uuid)
                    else:
                        attr = {'status': agent['status'],
                                'system_name': agent['system_name']}
                        db_agent = self.dbapi.lldp_agent_update(agent_uuid,
                                                                attr)
                        update_tlv = True

                if update_tlv:
                    tlv_dict = self.lldp_tlv_dict(agent)
                    self.lldp_agent_tlv_update(tlv_dict, db_agent)

            except exception.InvalidParameterValue:
                raise exception.SysinvException(_(
                    "Failed to update/delete non-existing"
                    "lldp agent %s") % agent_uuid)
            except exception.LLDPAgentExists:
                raise exception.SysinvException(_(
                    "Failed to add LLDP agent %s. "
                    "Already exists") % agent_uuid)
            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid host_uuid: host not found: %s") %
                    host_uuid)
            except exception.PortNotFound:
                raise exception.SysinvException(_(
                    "Invalid port id: port not found: %s") %
                    portid)
            except Exception as e:
                raise exception.SysinvException(_(
                    "Failed to update lldp agent: %s") % e)

    def lldp_neighbour_update_by_host(self, context,
                                      host_uuid, neighbour_dict_array):
        """Create or update lldp neighbours for an ihost with the supplied data.

        This method allows records for lldp neighbours for ihost to be created
        or updated.

        :param context: an admin context
        :param host_uuid: host uuid unique id
        :param neighbour_dict_array: initial values for lldp neighbour objects
        :returns: pass or fail
        """
        LOG.debug("Entering lldp_neighbour_update_by_host %s %s" %
                  (host_uuid, neighbour_dict_array))
        host_uuid.strip()
        try:
            db_host = self.dbapi.ihost_get(host_uuid)
        except Exception:
            raise exception.SysinvException(_(
                "Invalid host_uuid: %s") % host_uuid)

        try:
            db_ports = self.dbapi.port_get_by_host(host_uuid)
        except Exception:
            raise exception.SysinvException(_(
                "Error getting ports for host %s") % host_uuid)

        try:
            db_neighbours = self.dbapi.lldp_neighbour_get_by_host(host_uuid)
        except Exception:
            raise exception.SysinvException(_(
                "Error getting LLDP neighbours for host %s") % host_uuid)

        reported = set([(d['msap']) for d in neighbour_dict_array])
        stale = [d for d in db_neighbours if (d['msap']) not in reported]
        for neighbour in stale:
            db_neighbour = self.dbapi.lldp_neighbour_destroy(
                            neighbour['uuid'])

        for neighbour in neighbour_dict_array:
            db_port = self.lldp_id_to_port(neighbour['name_or_uuid'], db_ports)
            if not db_port:
                LOG.debug("Could not find port for neighbour %s",
                          neighbour['name_or_uuid'])
                return

            LOG.debug("Processing lldp neighbour %s" % neighbour)

            hostid = db_host['id']
            portid = db_port['id']
            msap = neighbour['msap']
            state = neighbour['state']

            neighbour_dict = {'host_id': hostid,
                              'port_id': portid,
                              'msap': msap}

            neighbour_found = False
            for db_neighbour in db_neighbours:
                if db_neighbour['msap'] == msap:
                    neighbour_found = db_neighbour
                    break

            update_tlv = False
            try:
                if not neighbour_found:
                    LOG.info("Attempting to create new lldp neighbour "
                             "%r on host %s" % (neighbour_dict, hostid))
                    db_neighbour = self.dbapi.lldp_neighbour_create(
                        portid, hostid, neighbour_dict)
                    update_tlv = True
                else:
                    # If the neighbour exists, remove it if requested by
                    # the agent. Otherwise, trigger a TLV update.  There
                    # are currently no neighbour attributes that need to
                    # be updated.
                    if state == constants.LLDP_NEIGHBOUR_STATE_REMOVED:
                        db_neighbour = self.dbapi.lldp_neighbour_destroy(
                            db_neighbour['uuid'])
                    else:
                        update_tlv = True
                if update_tlv:
                    tlv_dict = self.lldp_tlv_dict(neighbour)
                    self.lldp_neighbour_tlv_update(tlv_dict,
                                                   db_neighbour)
            except exception.InvalidParameterValue:
                raise exception.SysinvException(_(
                    "Failed to update/delete lldp neighbour. "
                    "Invalid parameter: %r") % tlv_dict)
            except exception.LLDPNeighbourExists:
                raise exception.SysinvException(_(
                    "Failed to add lldp neighbour %r. "
                    "Already exists") % neighbour_dict)
            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid host_uuid: host not found: %s") %
                    host_uuid)
            except exception.PortNotFound:
                raise exception.SysinvException(_(
                    "Invalid port id: port not found: %s") %
                    portid)
            except Exception as e:
                raise exception.SysinvException(_(
                    "Couldn't update LLDP neighbour: %s") % e)

    def pci_device_update_by_host(self, context,
                                  host_uuid, pci_device_dict_array):
        """Create devices for an ihost with the supplied data.

        This method allows records for devices for ihost to be created.

        :param context: an admin context
        :param host_uuid: host uuid unique id
        :param pci_device_dict_array: initial values for device objects
        :returns: pass or fail
        """
        LOG.debug("Entering device_update_by_host %s %s" %
                  (host_uuid, pci_device_dict_array))
        host_uuid.strip()
        try:
            host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid host_uuid %s" % host_uuid)
            return
        for pci_dev in pci_device_dict_array:
            LOG.debug("Processing dev %s" % pci_dev)
            try:
                pci_dev_dict = {'host_id': host['id']}
                pci_dev_dict.update(pci_dev)
                dev_found = None
                try:
                    dev = self.dbapi.pci_device_get(pci_dev['pciaddr'],
                                                    hostid=host['id'])
                    dev_found = dev
                    if not dev:
                        LOG.info("Attempting to create new device "
                                 "%s on host %s" % (pci_dev_dict, host['id']))
                        dev = self.dbapi.pci_device_create(host['id'],
                                                           pci_dev_dict)
                except Exception:
                    LOG.info("Attempting to create new device "
                             "%s on host %s" % (pci_dev_dict, host['id']))
                    dev = self.dbapi.pci_device_create(host['id'],
                                                       pci_dev_dict)

                # If the device exists, try to update some of the fields
                if dev_found:
                    try:
                        attr = {
                            'pclass_id': pci_dev['pclass_id'],
                            'pvendor_id': pci_dev['pvendor_id'],
                            'pdevice_id': pci_dev['pdevice_id'],
                            'pclass': pci_dev['pclass'],
                            'pvendor': pci_dev['pvendor'],
                            'psvendor': pci_dev['psvendor'],
                            'psdevice': pci_dev['psdevice'],
                            'sriov_totalvfs': pci_dev['sriov_totalvfs'],
                            'sriov_numvfs': pci_dev['sriov_numvfs'],
                            'sriov_vfs_pci_address':
                                pci_dev['sriov_vfs_pci_address'],
                            'driver': pci_dev['driver']}
                        LOG.info("attr: %s" % attr)
                        dev = self.dbapi.pci_device_update(dev['uuid'], attr)
                    except Exception:
                        LOG.exception("Failed to update port %s" %
                                      dev['pciaddr'])
                        pass

            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid host_uuid: host not found: %s") %
                    host_uuid)
            except Exception:
                pass

    def inumas_update_by_ihost(self, context,
                               ihost_uuid, inuma_dict_array):
        """Create inumas for an ihost with the supplied data.

        This method allows records for inumas for ihost to be created.
        Updates the port node_id once its available.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param inuma_dict_array: initial values for inuma objects
        :returns: pass or fail
        """

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        try:
            # Get host numa nodes which may already be in db
            mynumas = self.dbapi.inode_get_by_ihost(ihost_uuid)
        except exception.NodeNotFound:
            raise exception.SysinvException(_(
                "Invalid ihost_uuid: host not found: %s") % ihost_uuid)

        mynuma_nodes = [n.numa_node for n in mynumas]

        # perform update for ports
        ports = self.dbapi.ethernet_port_get_by_host(ihost_uuid)
        for i in inuma_dict_array:
            if 'numa_node' in i and i['numa_node'] in mynuma_nodes:
                LOG.info("Already in db numa_node=%s mynuma_nodes=%s" %
                         (i['numa_node'], mynuma_nodes))
                continue

            try:
                inuma_dict = {'forihostid': ihost['id']}

                inuma_dict.update(i)

                inuma = self.dbapi.inode_create(ihost['id'], inuma_dict)

                for port in ports:
                    port_node = port['numa_node']
                    if port_node == -1:
                        port_node = 0  # special handling

                    if port_node == inuma['numa_node']:
                        attr = {'node_id': inuma['id']}
                        self.dbapi.ethernet_port_update(port['uuid'], attr)

            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid ihost_uuid: host not found: %s") %
                    ihost_uuid)
            except Exception:  # this info may have been posted previously, update ?
                pass

    def _get_default_platform_cpu_count(self, ihost, node,
                                        cpu_count, hyperthreading):
        """Return the initial number of reserved logical cores for platform
        use.  This can be overridden later by the end user."""
        cpus = 0
        if cutils.host_has_function(ihost, constants.WORKER) and node == 0:
            cpus += 1 if not hyperthreading else 2
            if cutils.host_has_function(ihost, constants.CONTROLLER):
                cpus += 1 if not hyperthreading else 2
        return cpus

    def _get_default_vswitch_cpu_count(self, ihost, node,
                                       cpu_count, hyperthreading):
        """Return the initial number of reserved logical cores for vswitch
        use.  This can be overridden later by the end user."""
        if constants.VSWITCH_TYPE_NONE == cutils.get_vswitch_type(self.dbapi):
            return 0
        if cutils.host_has_function(ihost, constants.WORKER) and node == 0:
            physical_cores = (cpu_count / 2) if hyperthreading else cpu_count
            system_mode = self.dbapi.isystem_get_one().system_mode
            if system_mode == constants.SYSTEM_MODE_SIMPLEX:
                return 1 if not hyperthreading else 2
            else:
                if physical_cores > 4:
                    return 2 if not hyperthreading else 4
                elif physical_cores > 1:
                    return 1 if not hyperthreading else 2
        return 0

    def _get_default_shared_cpu_count(self, ihost, node,
                                       cpu_count, hyperthreading):
        """Return the initial number of reserved logical cores for shared
        use.  This can be overridden later by the end user."""
        return 0

    def _sort_by_socket_and_coreid(self, icpu_dict):
        """Sort a list of cpu dict objects such that lower numbered sockets
        appear first and that threads of the same core are adjacent in the
        list with the lowest thread number appearing first."""
        return (int(icpu_dict['numa_node']), int(icpu_dict['core']), int(icpu_dict['thread']))

    def _get_hyperthreading_enabled(self, cpu_list):
        """Determine if hyperthreading is enabled based on whether any threads
        exist with a threadId greater than 0"""
        for cpu in cpu_list:
            if int(cpu['thread']) > 0:
                return True
        return False

    def _get_node_cpu_count(self, cpu_list, node):
        count = 0
        for cpu in cpu_list:
            count += 1 if int(cpu['numa_node']) == node else 0
        return count

    def _get_default_cpu_functions(self, host, node, cpu_list, hyperthreading):
        """Return the default list of CPU functions to be reserved for this
        host on the specified numa node."""
        functions = []
        cpu_count = self._get_node_cpu_count(cpu_list, node)
        # Determine how many platform cpus need to be reserved
        count = self._get_default_platform_cpu_count(
            host, node, cpu_count, hyperthreading)
        for i in range(0, count):
            functions.append(constants.PLATFORM_FUNCTION)
        # Determine how many vswitch cpus need to be reserved
        count = self._get_default_vswitch_cpu_count(
            host, node, cpu_count, hyperthreading)
        for i in range(0, count):
            functions.append(constants.VSWITCH_FUNCTION)
        # Determine how many shared cpus need to be reserved
        count = self._get_default_shared_cpu_count(
            host, node, cpu_count, hyperthreading)
        for i in range(0, count):
            functions.append(constants.SHARED_FUNCTION)
        # Assign the default function to the remaining cpus
        for i in range(0, (cpu_count - len(functions))):
            functions.append(cpu_utils.get_default_function(host))
        return functions

    def print_cpu_topology(self, hostname=None, subfunctions=None,
                           reference=None,
                           sockets=None, cores=None, threads=None):
        """Print logical cpu topology table (for debug reasons).

        :param hostname: hostname
        :param subfunctions: subfunctions
        :param reference: reference label
        :param sockets: dictionary of socket_ids, sockets[cpu_id]
        :param cores:   dictionary of core_ids,   cores[cpu_id]
        :param threads: dictionary of thread_ids, threads[cpu_id]
        :returns: None
        """
        if sockets is None or cores is None or threads is None:
            LOG.error("print_cpu_topology: topology not defined. "
                      "sockets=%s, cores=%s, threads=%s"
                      % (sockets, cores, threads))
            return

        # calculate overall cpu topology stats
        n_sockets = len(set(sockets.values()))
        n_cores = len(set(cores.values()))
        n_threads = len(set(threads.values()))
        if n_sockets < 1 or n_cores < 1 or n_threads < 1:
            LOG.error("print_cpu_topology: unexpected topology. "
                      "n_sockets=%d, n_cores=%d, n_threads=%d"
                      % (n_sockets, n_cores, n_threads))
            return

        # build each line of output
        ll = ''
        s = ''
        c = ''
        t = ''
        for cpu in sorted(cores.keys()):
            ll += '%3d' % cpu
            s += '%3d' % sockets[cpu]
            c += '%3d' % cores[cpu]
            t += '%3d' % threads[cpu]

        LOG.info('Logical CPU topology: host:%s (%s), '
                 'sockets:%d, cores/socket=%d, threads/core=%d, reference:%s'
                 % (hostname, subfunctions, n_sockets, n_cores, n_threads,
                    reference))
        LOG.info('%9s : %s' % ('cpu_id', ll))
        LOG.info('%9s : %s' % ('socket_id', s))
        LOG.info('%9s : %s' % ('core_id', c))
        LOG.info('%9s : %s' % ('thread_id', t))

    def icpus_update_by_ihost(self, context,
                              ihost_uuid, icpu_dict_array,
                              force_grub_update=False):
        """Create cpus for an ihost with the supplied data.

        This method allows records for cpus for ihost to be created.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param icpu_dict_array: initial values for cpu objects
        :param force_grub_update: bool value to force grub update
        :returns: pass or fail
        """

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        forihostid = ihost['id']
        ihost_inodes = self.dbapi.inode_get_by_ihost(ihost_uuid)

        icpus = self.dbapi.icpu_get_by_ihost(ihost_uuid)

        num_cpus_dict = len(icpu_dict_array)
        num_cpus_db = len(icpus)

        # Capture 'current' topology in dictionary format
        cs = {}
        cc = {}
        ct = {}
        if num_cpus_dict > 0:
            for icpu in icpu_dict_array:
                cpu_id = icpu.get('cpu')
                cs[cpu_id] = icpu.get('numa_node')
                cc[cpu_id] = icpu.get('core')
                ct[cpu_id] = icpu.get('thread')

        # Capture 'previous' topology in dictionary format
        ps = {}
        pc = {}
        pt = {}
        if num_cpus_db > 0:
            for icpu in icpus:
                cpu_id = icpu.get('cpu')
                core_id = icpu.get('core')
                thread_id = icpu.get('thread')
                forinodeid = icpu.get('forinodeid')
                socket_id = None
                for inode in ihost_inodes:
                    if forinodeid == inode.get('id'):
                        socket_id = inode.get('numa_node')
                        break
                ps[cpu_id] = socket_id
                pc[cpu_id] = core_id
                pt[cpu_id] = thread_id

        if num_cpus_dict > 0 and num_cpus_db == 0:
            self.print_cpu_topology(hostname=ihost.get('hostname'),
                                    subfunctions=ihost.get('subfunctions'),
                                    reference='current (initial)',
                                    sockets=cs, cores=cc, threads=ct)

        if num_cpus_dict > 0 and num_cpus_db > 0:
            LOG.debug("num_cpus_dict=%d num_cpus_db= %d. "
                      "icpud_dict_array= %s icpus.as_dict= %s" %
                      (num_cpus_dict, num_cpus_db, icpu_dict_array, icpus))

            # Skip update if topology has not changed
            if ps == cs and pc == cc and pt == ct:
                self.print_cpu_topology(hostname=ihost.get('hostname'),
                                        subfunctions=ihost.get('subfunctions'),
                                        reference='current (unchanged)',
                                        sockets=cs, cores=cc, threads=ct)
                if ihost.administrative == constants.ADMIN_LOCKED:
                    self.update_cpu_config(context, ihost_uuid, force_grub_update)
                return

            self.print_cpu_topology(hostname=ihost.get('hostname'),
                                    subfunctions=ihost.get('subfunctions'),
                                    reference='previous',
                                    sockets=ps, cores=pc, threads=pt)
            self.print_cpu_topology(hostname=ihost.get('hostname'),
                                    subfunctions=ihost.get('subfunctions'),
                                    reference='current (CHANGED)',
                                    sockets=cs, cores=cc, threads=ct)

            # there has been an update.  Delete db entries and replace.
            for icpu in icpus:
                self.dbapi.icpu_destroy(icpu.uuid)

        # sort the list of cpus by socket and coreid
        cpu_list = sorted(icpu_dict_array, key=self._sort_by_socket_and_coreid)

        # determine if hyperthreading is enabled
        hyperthreading = self._get_hyperthreading_enabled(cpu_list)

        # build the list of functions to be assigned to each cpu
        functions = {}
        for n in ihost_inodes:
            numa_node = int(n.numa_node)
            functions[numa_node] = self._get_default_cpu_functions(
                ihost, numa_node, cpu_list, hyperthreading)

        for data in cpu_list:
            try:
                forinodeid = None
                for n in ihost_inodes:
                    numa_node = int(n.numa_node)
                    if numa_node == int(data['numa_node']):
                        forinodeid = n['id']
                        break

                cpu_dict = {'forihostid': forihostid,
                            'forinodeid': forinodeid,
                            'allocated_function': functions[numa_node].pop(0)}

                cpu_dict.update(data)

                self.dbapi.icpu_create(forihostid, cpu_dict)

            except exception.NodeNotFound:
                raise exception.SysinvException(_(
                    "Invalid ihost_uuid: host not found: %s") %
                    ihost_uuid)
            except Exception:
                # info may have already been posted
                pass

        # if it is the first controller wait for the initial config to
        # be completed
        if ((utils.is_host_simplex_controller(ihost) and
                (os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG) or
                 os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG))) or
                (not utils.is_host_simplex_controller(ihost) and
                 ihost.administrative == constants.ADMIN_LOCKED)):
            LOG.info("Update CPU grub config, host_uuid (%s), name (%s)"
                     % (ihost_uuid, ihost.get('hostname')))
            self.update_cpu_config(context, ihost_uuid, force_grub_update)

        return

    def _get_platform_reserved_memory(self, ihost, node):
        low_core = cutils.is_low_core_system(ihost, self.dbapi)
        reserved = cutils.get_required_platform_reserved_memory(ihost, node, low_core)
        return {'platform_reserved_mib': reserved} if reserved else {}

    def imemory_update_by_ihost(self, context,
                                ihost_uuid, imemory_dict_array,
                                force_update):
        """Create or update imemory for an ihost with the supplied data.

        This method allows records for memory for ihost to be created,
        or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param imemory_dict_array: initial values for cpu objects
        :param: force_update: force host memory update
        :returns: pass or fail
        """

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        if ihost['administrative'] == constants.ADMIN_LOCKED and \
            ihost['invprovision'] == constants.PROVISIONED and \
                not force_update:
            LOG.debug("Ignore the host memory audit after the host is locked")
            return

        forihostid = ihost['id']
        ihost_inodes = self.dbapi.inode_get_by_ihost(ihost_uuid)

        for i in imemory_dict_array:
            forinodeid = None
            inode_uuid = None
            for n in ihost_inodes:
                numa_node = int(n.numa_node)
                if numa_node == int(i['numa_node']):
                    forinodeid = n['id']
                    inode_uuid = n['uuid']
                    inode_uuid.strip()
                    break
            else:
                # not found in host_nodes, do not add memory element
                continue

            mem_dict = {'forihostid': forihostid,
                        'forinodeid': forinodeid}

            mem_dict.update(i)

            # Do not allow updates to the amounts of reserved memory.
            mem_dict.pop('platform_reserved_mib', None)

            # numa_node is not stored against imemory table
            mem_dict.pop('numa_node', None)

            # clear the pending hugepage number for unlocked nodes
            if ihost.administrative == constants.ADMIN_UNLOCKED:
                mem_dict['vm_hugepages_nr_2M_pending'] = None
                mem_dict['vm_hugepages_nr_1G_pending'] = None
                mem_dict['vswitch_hugepages_reqd'] = None

            try:
                imems = self.dbapi.imemory_get_by_ihost_inode(ihost_uuid,
                                                              inode_uuid)
                if not imems:
                    # Set the amount of memory reserved for platform use.
                    mem_dict.update(self._get_platform_reserved_memory(
                            ihost, i['numa_node']))
                    self.dbapi.imemory_create(forihostid, mem_dict)
                else:
                    for imem in imems:
                        # Include 4K pages in the displayed VM memtotal
                        if imem.vm_hugepages_nr_4K is not None:
                            vm_4K_mib = \
                                (imem.vm_hugepages_nr_4K /
                                 constants.NUM_4K_PER_MiB)
                            mem_dict['memtotal_mib'] += vm_4K_mib
                            mem_dict['memavail_mib'] += vm_4K_mib
                        self.dbapi.imemory_update(imem['uuid'],
                                                         mem_dict)
            except Exception:
                # Set the amount of memory reserved for platform use.
                mem_dict.update(self._get_platform_reserved_memory(
                        ihost, i['numa_node']))
                self.dbapi.imemory_create(forihostid, mem_dict)
                pass

        return

    def _get_disk_available_mib(self, disk, agent_disk_dict):
        partitions = self.dbapi.partition_get_by_idisk(disk['uuid'])

        if not partitions:
            LOG.debug("Disk %s has no partitions" % disk.uuid)
            return agent_disk_dict['available_mib']

        available_mib = agent_disk_dict['available_mib']
        for part in partitions:
            if (part.status in
                    [constants.PARTITION_CREATE_IN_SVC_STATUS,
                     constants.PARTITION_CREATE_ON_UNLOCK_STATUS]):
                available_mib = available_mib - part.size_mib

        LOG.debug("Disk available mib host - %s disk - %s av - %s" %
                  (disk.forihostid, disk.device_node, available_mib))
        return available_mib

    def disk_format_gpt(self, context, agent_idisk, host_id):
        rpcapi = agent_rpcapi.AgentAPI()
        try:
            ihost = self.dbapi.ihost_get(host_id)
            LOG.info("Sending sysinv-agent request to GPT format disk %s of "
                     "host %s." %
                     (agent_idisk.get('device_path'), host_id))
            # If the replaced disk is the cinder disk, we also need to remove
            # PLATFORM_CONF_PATH/.node_cinder_lvm_config_complete to enable
            # cinder provisioning on the new disk.
            is_cinder_device = False
            cinder_device, cinder_size = cutils._get_cinder_device_info(
                self.dbapi, ihost.get('id'))

            if cinder_device:
                if agent_idisk.get('device_path') in cinder_device:
                    is_cinder_device = True

            # On SX we have to wait for disk wipe confirmation
            # before updating DB otherwise user may unlock host without wipe
            # and operation won't be retried.
            # If DB was not updated, operation will be retried on reboot
            # ensuring that the disk was indeed wiped.
            system_mode = utils.get_system_mode(self.dbapi)
            if system_mode == constants.SYSTEM_MODE_SIMPLEX:
                try:
                    os.mknod(constants.DISK_WIPE_IN_PROGRESS_FLAG)
                except OSError:
                    pass

            rpcapi.disk_format_gpt(context, ihost.uuid, agent_idisk,
                                   is_cinder_device)

            if system_mode == constants.SYSTEM_MODE_SIMPLEX:
                timeout = 0
                while os.path.isfile(constants.DISK_WIPE_IN_PROGRESS_FLAG):
                    if timeout > constants.DISK_WIPE_COMPLETE_TIMEOUT:
                        # Wipe takes a few seconds. Problem is that if
                        # sysinv-agent is stuck in a long running operation,
                        # such as applying manifests, then the wipe itself
                        # will be delayed and even skipped if user unlocks
                        # the host.
                        msg = ("Wiping device: %s on %s takes too long. "
                               "Aborting! Operation will retry on next "
                               "agent inventory reporting." % (agent_idisk, ihost.uuid))
                        raise exception.SysinvException(msg)
                    time.sleep(1)
                    timeout += 1

        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_id %s" % host_id)
            return

    def host_version_match(self, host_uuid):
        """
        Returns if the host software version matches the software version of
        this node (the active controller)
        :param host_uuid: the uuid of the host
        :return:
        """
        try:
            self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # Not upgrading. We assume the host versions match
            # If they somehow don't match we've got bigger problems
            return True

        host_obj = self.dbapi.ihost_get(host_uuid)
        host_version = host_obj.software_load

        return host_version == tsc.SW_VERSION

    def idisk_update_by_ihost(self, context,
                              ihost_uuid, idisk_dict_array):
        """Create or update idisk for an ihost with the supplied data.

        This method allows records for disk for ihost to be created,
        or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param idisk_dict_array: initial values for disk objects
        :returns: pass or fail
        """

        def is_same_disk(i, idisk):
            # Upgrades R3->R4: An update from an N-1 agent will be missing the
            # persistent naming fields.
            if 'device_path' in i:
                if i.get('device_path') is not None:
                    if idisk.device_path == i.get('device_path'):
                        # Update from R4 node: Use R4 disk identification logic
                        return True
                    elif not idisk.device_path:
                        # TODO: remove R5. still need to compare device_node
                        # because not inventoried for R3 node controller-0
                        if idisk.device_node == i.get('device_node'):
                            LOG.info("host_uuid=%s idisk.device_path not"
                                     "set, match on device_node %s" %
                                     (ihost_uuid, idisk.device_node))
                            return True
                else:
                    return False
            elif idisk.device_node == i.get('device_node'):
                # Update from R3 node: Fall back to R3 disk identification
                # logic.
                return True
            return False

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        forihostid = ihost['id']

        lvm_config = StorageBackendConfig.get_configured_backend_conf(
            self.dbapi,
            constants.CINDER_BACKEND_LVM
        )

        # Ensure that we properly identify the cinder device on a
        # combo node so that we can prevent it from being used as
        # a physical volume in the nova-local volume group
        cinder_device = None
        if (cutils.host_has_function(ihost, constants.CONTROLLER) and
                cutils.host_has_function(ihost, constants.WORKER)):

            if lvm_config:
                cinder_device = cutils._get_cinder_device(self.dbapi,
                                                          ihost.get('id'))

        idisks = self.dbapi.idisk_get_by_ihost(ihost_uuid)

        for i in idisk_dict_array:
            disk_dict = {'forihostid': forihostid}
            # this could overwrite capabilities - do not overwrite device_function?
            # if not in dictionary and device_function already in capabilities

            disk_dict.update(i)

            if not idisks:
                disk = self.dbapi.idisk_create(forihostid, disk_dict)
            else:
                found = False
                for idisk in idisks:
                    LOG.debug("[DiskEnum] for - current idisk: %s - %s -%s" %
                             (idisk.uuid, idisk.device_node, idisk.device_id))

                    if is_same_disk(i, idisk):
                        found = True
                        # The disk has been replaced?
                        if idisk.serial_id != i.get('serial_id'):
                            LOG.info("Disk uuid: %s changed serial_id from %s "
                                     "to %s", idisk.uuid, idisk.serial_id,
                                     i.get('serial_id'))
                            # If the clone label is in the serial id, this is
                            # install-from-clone scenario. Skip gpt formatting.
                            if ((constants.CLONE_ISO_DISK_SID + ihost['hostname'] + i.get('device_node')) == idisk.serial_id):
                                LOG.info("Install from clone. Update disk serial"
                                         " id for disk %s. Skip gpt formatting."
                                         % idisk.uuid)
                            elif (ihost.rootfs_device == idisk.device_path or
                                    ihost.rootfs_device in idisk.device_node):
                                LOG.info("Disk uuid: %s is a root disk, "
                                         "skipping gpt formatting."
                                         % idisk.uuid)
                            else:
                                self.disk_format_gpt(context, i, forihostid)
                            # Update the associated physical volume.
                            if idisk.foripvid:
                                self._ipv_replace_disk(idisk.foripvid)
                        # The disk has been re-enumerated?
                        # Re-enumeration can occur if:
                        # 1) a new disk has been added to the host and the new
                        #    disk is attached to a port that the kernel
                        #    enumerates earlier than existing disks
                        # 2) a new disk has been added to the host and the new
                        #    disk is attached to a new disk controller that the
                        #    kernel enumerates earlier than the existing disk
                        #    controller
                        if idisk.device_node != i.get('device_node'):
                            LOG.info("Disk uuid: %s has been re-enumerated "
                                     "from %s to %s.", idisk.uuid,
                                     idisk.device_node, i.get('device_node'))
                            disk_dict.update({
                                'device_node': i.get('device_node')})

                        LOG.debug("[DiskEnum] found disk: %s - %s - %s - %s -"
                                  "%s" % (idisk.uuid, idisk.device_node,
                                   idisk.device_id, idisk.capabilities,
                                   disk_dict['capabilities']))

                        # disk = self.dbapi.idisk_update(idisk['uuid'],
                        #                                disk_dict)
                        disk_dict_capabilities = disk_dict.get('capabilities')
                        if (disk_dict_capabilities and
                                ('device_function' not in
                                    disk_dict_capabilities)):
                            dev_function = idisk.capabilities.get(
                                'device_function')
                            if dev_function:
                                disk_dict['capabilities'].update(
                                    {'device_function': dev_function})
                                LOG.debug("update disk_dict=%s" %
                                          str(disk_dict))

                        available_mib = self._get_disk_available_mib(
                            idisk, disk_dict)
                        disk_dict.update({'available_mib': available_mib})

                        LOG.debug("[DiskEnum] updating disk uuid %s with"
                                  "values: %s" %
                                  (idisk['uuid'], str(disk_dict)))
                        disk = self.dbapi.idisk_update(idisk['uuid'],
                                                       disk_dict)
                    elif not idisk.device_path:
                        if idisk.device_node == i.get('device_node'):
                            found = True
                            disk = self.dbapi.idisk_update(idisk['uuid'],
                                                           disk_dict)
                            self.dbapi.journal_update_path(disk)

                if not found:
                    disk = self.dbapi.idisk_create(forihostid, disk_dict)

                # Update the capabilities if the device is a cinder
                # disk
                if ((cinder_device is not None) and
                        (disk.device_path == cinder_device)):

                    idisk_capabilities = disk.capabilities
                    if 'device_function' not in idisk_capabilities:
                        # Only update if it's not already present
                        idisk_dict = {'device_function': 'cinder_device'}
                        idisk_capabilities.update(idisk_dict)

                        idisk_val = {'capabilities': idisk_capabilities}
                        self.dbapi.idisk_update(idisk.uuid, idisk_val)

        # Check if this is the controller or storage-0, if so, autocreate.
        # Monitor stor entry if ceph is configured.
        if ((ihost.personality == constants.STORAGE and
                ihost.hostname == constants.STORAGE_0_HOSTNAME) or
                (ihost.personality == constants.CONTROLLER)):
            if StorageBackendConfig.has_backend_configured(
                self.dbapi,
                constants.CINDER_BACKEND_CEPH
            ):
                ihost.capabilities.update({
                    constants.IHOST_STOR_FUNCTION:
                        constants.STOR_FUNCTION_MONITOR})
                self.dbapi.ihost_update(ihost_uuid,
                    {'capabilities': ihost.capabilities})

        # Check whether a disk has been removed.
        if idisks and len(idisk_dict_array) > 0:
            if len(idisks) > len(idisk_dict_array):
                # Compare tuples of device_path.
                for pre_disk in idisks:
                    found = False
                    for cur_disk in idisk_dict_array:
                        cur_device_path = cur_disk.get('device_path') or ""
                        if pre_disk.device_path == cur_device_path:
                            found = True
                            break

                    if not found:
                        # remove if not associated with storage
                        if not pre_disk.foristorid:
                            LOG.warn("Disk removed: %s dev_node=%s "
                                     "dev_path=%s serial_id=%s." %
                                     (pre_disk.uuid,
                                      pre_disk.device_node,
                                      pre_disk.device_path,
                                      pre_disk.serial_id))
                            self.dbapi.idisk_destroy(pre_disk.uuid)
                        else:
                            LOG.warn("Disk missing: %s dev_node=%s "
                                     "dev_path=%s serial_id=%s" %
                                     (pre_disk.uuid,
                                      pre_disk.device_node,
                                      pre_disk.device_path,
                                      pre_disk.serial_id))

        return

    def ilvg_update_by_ihost(self, context,
                             ihost_uuid, ilvg_dict_array):
        """Create or update ilvg for an ihost with the supplied data.

        This method allows records for local volume groups for ihost to be
        created, or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param ilvg_dict_array: initial values for local volume group objects
        :returns: pass or fail
        """

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        forihostid = ihost['id']

        ilvgs = self.dbapi.ilvg_get_by_ihost(ihost_uuid)

        # Process the response from the agent
        for i in ilvg_dict_array:

            lvg_dict = {
                'forihostid': forihostid,
            }

            lvg_dict.update(i)

            found = False
            for ilvg in ilvgs:
                if ilvg.lvm_vg_name == i['lvm_vg_name']:
                    found = True
                    if ilvg.lvm_vg_uuid != i['lvm_vg_uuid']:
                        # The volume group has been replaced.
                        LOG.info("LVG uuid: %s changed UUID from %s to %s",
                                 ilvg.uuid, ilvg.lvm_vg_uuid,
                                 i['lvm_vg_uuid'])
                        # May need to take some action => None for now

                    if ilvg.vg_state == constants.LVG_ADD:
                        lvg_dict.update({'vg_state': constants.PROVISIONED})

                    # Update the database
                    self.dbapi.ilvg_update(ilvg['uuid'], lvg_dict)
                    break

            if not found:
                lvg_dict.update({'vg_state': constants.PROVISIONED})
                try:
                    self.dbapi.ilvg_create(forihostid, lvg_dict)
                except Exception:
                    LOG.exception("Local Volume Group Creation failed")

        # Purge the database records for volume groups that have been
        # removed
        for ilvg in ilvgs:
            if ilvg.vg_state == constants.LVG_DEL:
                # Make sure that the agent hasn't reported that it is
                # still present on the host
                found = False
                for i in ilvg_dict_array:
                    if ilvg.lvm_vg_name == i['lvm_vg_name']:
                        found = True

                if not found:
                    try:
                        self.dbapi.ilvg_destroy(ilvg.id)
                    except Exception:
                        LOG.exception("Local Volume Group removal failed")

        return

    def _fill_partition_info(self, db_part, ipart):
        db_part_dict = db_part.as_dict()
        keys = ['start_mib', 'end_mib', 'size_mib', 'type_name', 'type_guid']
        values = {}
        for key in keys:
            if (key in db_part_dict and key in ipart and
                    not db_part_dict.get(key, None)):
                values.update({key: ipart.get(key)})

        # If the report from the manage-partitions script is lost
        # (although the partition was created successfully)
        # the partition goes into an error state.
        # In such a case, the agent should report the correct info,
        # so we should allow the transition from and error state
        # to a ready state.
        states = [constants.PARTITION_CREATE_IN_SVC_STATUS,
                  constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
                  constants.PARTITION_ERROR_STATUS]

        if db_part.status in states and not db_part.foripvid:
            LOG.debug("Update the state to ready for partition %s" %
                      db_part.uuid)
            values.update({'status': constants.PARTITION_READY_STATUS})

        try:
            self.dbapi.partition_update(db_part.uuid, values)
        except Exception:
            LOG.exception("Updating partition (%s) with values %s failed." %
                          (db_part.uuid, str(values)))

    def _build_device_node_path(self, idisk_uuid):
        """Builds the partition device path and device node based on last
           partition number and assigned disk.
        """
        idisk = self.dbapi.idisk_get(idisk_uuid)
        partitions = self.dbapi.partition_get_by_idisk(
            idisk_uuid, sort_key='device_path')
        if partitions:
            device_node = "%s%s" % (idisk.device_node, len(partitions) + 1)
            device_path = "%s-part%s" % (idisk.device_path, len(partitions) + 1)
        else:
            device_node = idisk.device_node + '1'
            device_path = idisk.device_path + '-part1'

        return device_node, device_path

    def _check_cgts_vg_extend(self, host, disk, pv4_name):
        """If the current R5 main cgts-vg partition is too small for the R4
           cgts-vg, create an extra partition & PV for cgts-vg.
           TODO: This function is only useful for supporting R4 -> R5 upgrades.
                 Remove in future release.
        """
        pvs = self.dbapi.ipv_get_by_ihost(host.id)
        pv_cgts_vg = next((pv for pv in pvs if pv.lvm_pv_name == pv4_name), None)
        if not pv_cgts_vg:
            raise exception.SysinvException(_("ERROR: No %s PV for Volume Group %s on host %s") %
                (pv4_name, constants.LVG_CGTS_VG, host.hostname))

        partitions = self.dbapi.partition_get_by_ihost(host.id)
        partition4 = next((p for p in partitions if p.device_node == pv4_name), None)
        part_size_mib = float(pv_cgts_vg.lvm_pv_size) / (1024**2) - int(partition4.size_mib)
        if part_size_mib > 0:
            LOG.info("%s is not enough for R4 cgts-vg" % pv4_name)
        else:
            LOG.info("%s is enough for R4 cgts-vg, returning" % pv4_name)
            return

        part_device_node, part_device_path = self._build_device_node_path(disk.uuid)
        LOG.info("Extra cgts partition size: %s device node: %s "
                 "device path: %s" %
                 (part_size_mib, part_device_node, part_device_path))

        partition_dict = {
            'idisk_id': disk.id,
            'idisk_uuid': disk.uuid,
            'size_mib': part_size_mib,
            'device_node': part_device_node,
            'device_path': part_device_path,
            'status': constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
            'type_guid': constants.USER_PARTITION_PHYSICAL_VOLUME,
            'forihostid': host.id
        }
        new_partition = self.dbapi.partition_create(host.id, partition_dict)

        pv_dict = {
            'pv_state': constants.PV_ADD,
            'pv_type': constants.PV_TYPE_PARTITION,
            'disk_or_part_uuid': new_partition.uuid,
            'disk_or_part_device_node': new_partition.device_node,
            'disk_or_part_device_path': new_partition.device_path,
            'lvm_pv_name': new_partition.device_node,
            'lvm_vg_name': constants.LVG_CGTS_VG,
            'forihostid': host.id,
            'forilvgid': pv_cgts_vg.forilvgid
        }
        new_pv = self.dbapi.ipv_create(host.id, pv_dict)

        new_partition = self.dbapi.partition_update(new_partition.uuid, {'foripvid': new_pv.id})

    def _check_pv_partition(self, pv):
        """Ensure a proper physical volume transition from R4.
           TODO: This function is only useful for supporting R4 -> R5 upgrades.
                 Remove in future release.
        """
        R4_part_number = "5"
        pv_name = pv['lvm_pv_name']
        partitions = self.dbapi.partition_get_by_ihost(pv['forihostid'])

        if not partitions:
            LOG.info("No partitions present for host %s yet, try later" % pv['forihostid'])
            return

        disk_uuid = pv['disk_or_part_uuid']
        disk = self.dbapi.idisk_get(disk_uuid)

        # Treat AIO controller differently.
        # The 5th partition becomes the 4th partition.
        host = self.dbapi.ihost_get(pv['forihostid'])

        rootfs_partition = False
        for p in partitions:
            if (host.rootfs_device in p.device_node or
                    host.rootfs_device in p.device_path):
                rootfs_partition = True
                break

        if not rootfs_partition:
            LOG.info("Host %s has no rootfs partitions, return" % host.hostname)
            return

        if (host.personality == constants.CONTROLLER and
            (host.rootfs_device in pv['disk_or_part_device_node'] or
             host.rootfs_device in pv['disk_or_part_device_path'])):
            if R4_part_number in pv_name:
                pv4_name = "%s4" % disk.device_node
                self.dbapi.ipv_update(pv['uuid'], {'lvm_pv_name': pv4_name})
                pv_name = pv4_name

                # Check if we need to extend cgts-vg to match its R4 size.
                self._check_cgts_vg_extend(host, disk, pv4_name)

        partition = next((p for p in partitions if p.device_node == pv_name), None)

        # If the PV partition exists, only update the PV info.
        if partition:
            if partition.device_node == pv_name:
                values = {
                    'disk_or_part_uuid': partition.uuid,
                    'disk_or_part_device_node': partition.device_node,
                    'disk_or_part_device_path': partition.device_path
                }
                self.dbapi.ipv_update(pv['uuid'], values)
                self.dbapi.partition_update(partition.uuid, {'foripvid': pv['id']})
                self.dbapi.idisk_update(disk_uuid, {'foripvid': None})
                return

        # If the PV partition does not exist, we need to create the DB entry for it
        # and then update the PV.

        # If the required size for the PV is larger then the available space,
        # log a warning, but use the available space for the PV partition.
        if disk.available_mib < pv['lvm_pv_size'] / (1024 ** 2):
            LOG.warning("ERROR not enough space to create the needed partition: %s < %s" %
                        (disk.available_mib, pv['lvm_pv_size']))

        part_device_node, part_device_path = self._build_device_node_path(disk_uuid)
        part_size_mib = disk.available_mib

        for part in partitions:
            if (part.status in
                    [constants.PARTITION_CREATE_IN_SVC_STATUS,
                     constants.PARTITION_CREATE_ON_UNLOCK_STATUS] and
                    part.idisk_uuid == disk.uuid):
                part_size_mib = part_size_mib - part.size_mib

        partition_dict = {
            'idisk_id': disk.id,
            'idisk_uuid': disk.uuid,
            'size_mib': part_size_mib,
            'device_node': part_device_node,
            'device_path': part_device_path,
            'foripvid': pv['id'],
            'status': constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
            'type_guid': constants.USER_PARTITION_PHYSICAL_VOLUME
        }
        new_partition = self.dbapi.partition_create(pv['forihostid'], partition_dict)

        pv_update_dict = {
            'disk_or_part_uuid': new_partition.uuid,
            'disk_or_part_device_node': part_device_node,
            'disk_or_part_device_path': part_device_path,
            'lvm_pv_name': part_device_node
        }
        self.dbapi.idisk_update(disk_uuid, {'foripvid': None})
        self.dbapi.ipv_update(pv['uuid'], pv_update_dict)

    def _prepare_for_ipv_removal(self, ipv):
        if ipv['pv_type'] == constants.PV_TYPE_DISK:
            if ipv.get('disk_or_part_uuid'):
                try:
                    self.dbapi.idisk_update(ipv['disk_or_part_uuid'],
                                            {'foripvid': None})
                except exception.DiskNotFound:
                    pass
        elif ipv['pv_type'] == constants.PV_TYPE_PARTITION:
            if not ipv.get('disk_or_part_uuid'):
                return

            try:
                ihost = self.dbapi.ihost_get(ipv.get('forihostid'))
                values = {'foripvid': None}
                if ihost['invprovision'] == constants.PROVISIONED:
                    values.update(
                        {'status': constants.PARTITION_READY_STATUS})
                self.dbapi.partition_update(ipv['disk_or_part_uuid'], values)
            except exception.DiskPartitionNotFound:
                pass

    # TODO(rchurch): Update this for cinder disk removal
    def _ipv_handle_phys_storage_removal(self, ipv, storage):
        """ Remove a PV from a missing disk or partition"""
        if ipv['lvm_pv_name'] == constants.CINDER_DRBD_DEVICE:
            # Special Case: combo node /dev/drbd4 for cinder will
            # not show up in the disk list so allow it to remain.
            return

        # For any other system type & VG the removal is done automatically
        # as users don't have the option (yet).
        try:
            self._prepare_for_ipv_removal(ipv)
            self.dbapi.ipv_destroy(ipv.id)
        except Exception:
            LOG.exception("Remove ipv for missing %s failed" % storage)

    def update_partition_config(self, context, partition):
        """Configure the partition with the supplied data.

        :param context: an admin context.
        :param partition: data about the partition
        """
        LOG.debug("PART conductor-manager partition: %s" % str(partition))
        # Get host.
        host_uuid = partition.get('ihost_uuid')
        try:
            db_host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid host_uuid %s" % host_uuid)
            return

        personalities = [db_host.personality]
        config_uuid = self._config_update_hosts(context,
                                                personalities,
                                                host_uuids=[host_uuid],
                                                reboot=False)
        config_dict = {
            "host_uuids": host_uuid,
            'personalities': personalities,
            "classes": ['platform::partitions::runtime'],
            "idisk_uuid": partition.get('idisk_uuid'),
            "partition_uuid": partition.get('uuid'),
            puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_DISK_PARTITON_CONFIG
        }

        # Currently sysinv agent does not create the needed partition during nova-local
        # configuration without the existence of the initial_config_complete flag.
        # During Ansible bootstrap, force manifest apply as the generation of this
        # file is deferred until host unlock where full controller manifest is applied.
        force_apply = False if cutils.is_initial_config_complete() else True
        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict,
                                            host_uuids=[host_uuid],
                                            force=force_apply)

    def ipartition_update_by_ihost(self, context,
                                   ihost_uuid, ipart_dict_array):
        """Update existing partition information based on information received
           from the agent."""
        LOG.debug("PART ipartition_update_by_ihost %s ihost_uuid "
                 "ipart_dict_array: %s" % (ihost_uuid, str(ipart_dict_array)))

        # Get host.
        ihost_uuid.strip()
        try:
            db_host = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        # Get the id of the host.
        forihostid = db_host['id']

        # Obtain the partitions, disks and physical volumes that are currently
        # present in the DB.
        db_parts = self.dbapi.partition_get_by_ihost(ihost_uuid)
        db_disks = self.dbapi.idisk_get_by_ihost(ihost_uuid)

        # Check that the DB partitions are in sync with the DB disks and PVs.
        for db_part in db_parts:
            if not db_part.device_path:
                # Should not happen unless pyudev gives us wrong data
                # or we have a programming error.
                LOG.error("PART ipartition_update_by_ihost: "
                          "Disk partition %s is missing its "
                          "device path, ignoring!" % db_part.uuid)
                continue

            # Obtain the disk the partition is on.
            part_disk = next((d for d in db_disks
                             if d.device_path in db_part.device_path), None)

            if not part_disk:
                # Should not happen as we only store partitions associated
                # with a disk.
                LOG.error("PART ipartition_update_by_ihost: "
                          "Disk for partition %s is not "
                          "present in database, ignoring!" % db_part.uuid)
                continue

            partition_dict = {'forihostid': forihostid}
            partition_update_needed = False

            if part_disk.uuid != db_part['idisk_uuid']:
                # TO DO: What happens when a disk is replaced
                partition_update_needed = True
                partition_dict.update({'idisk_uuid': part_disk.uuid})
                LOG.info("Disk for partition %s has changed." %
                         db_part['uuid'])

            if partition_update_needed:
                self.dbapi.partition_update(db_part['uuid'],
                                            partition_dict)
                LOG.debug("PART conductor - partition needs to be "
                          "updated.")

        # Go through the partitions reported by the agent and make needed
        # modifications.
        for ipart in ipart_dict_array:
            # Not to add ceph osd related partitions
            if (ipart['type_guid'] == constants.CEPH_DATA_PARTITION or
                   ipart['type_guid'] == constants.CEPH_JOURNAL_PARTITION):
                continue

            part_dict = {
                'forihostid': forihostid,
                'status': constants.PARTITION_IN_USE_STATUS,  # Be conservative here
            }

            part_dict.update(ipart)

            found = False

            # If the paths match, then the partition already exists in the DB.
            for db_part in db_parts:
                if ipart['device_path'] == db_part.device_path:
                    found = True

                    if ipart['device_node'] != db_part.device_node:
                        LOG.info("PART update part device node")
                        self.dbapi.partition_update(
                            db_part.uuid,
                            {'device_node': ipart['device_node']})
                    LOG.debug("PART conductor - found partition: %s" %
                              db_part.device_path)

                    self._fill_partition_info(db_part, ipart)

                    # Try to resize the underlying FS.
                    if db_part.foripvid:
                        pv = self.dbapi.ipv_get(db_part.foripvid)
                        if (pv and pv.lvm_vg_name == constants.LVG_CINDER_VOLUMES):
                            try:
                                self._resize_cinder_volumes(delayed=True)
                            except retrying.RetryError:
                                LOG.info("Cinder volumes resize failed")
                    break

            # If we've found no matching path, then this is a new partition.
            if not found:
                LOG.debug("PART conductor - partition not found, adding...")
                # Complete disk info.
                for db_disk in db_disks:
                    if db_disk.device_path in ipart['device_path']:
                        part_dict.update({'idisk_id': db_disk.id,
                                          'idisk_uuid': db_disk.uuid})
                        LOG.debug("PART conductor - disk - part_dict: %s " %
                                  str(part_dict))

                        new_part = None
                        try:
                            LOG.info("Partition create on host: %s. Details: %s" % (forihostid, part_dict))
                            new_part = self.dbapi.partition_create(
                                forihostid, part_dict)
                        except Exception as e:
                            LOG.exception("Partition creation failed on host: %s. "
                                          "Details: %s" % (forihostid, str(e)))

                        # If the partition has been successfully created, update its status.
                        if new_part:
                            if new_part.type_guid != constants.USER_PARTITION_PHYSICAL_VOLUME:
                                status = {'status': constants.PARTITION_IN_USE_STATUS}
                            else:
                                status = {'status': constants.PARTITION_READY_STATUS}
                            self.dbapi.partition_update(new_part.uuid, status)
                        break
                else:
                    # This shouldn't happen as disks are reported before partitions
                    LOG.warning("Found partition not associated with any disks, "
                                "underlying disk should be created on next inventory "
                                "reporting, ignoring for now. Details: ihost_uuid: %s "
                                "ipart_dict_array: %s" % (ihost_uuid, part_dict))

        # Check to see if partitions have been removed.
        for db_part in db_parts:
            found = False
            for ipart in ipart_dict_array:
                if db_part.device_path:
                    if ipart['device_path'] == db_part.device_path:
                        found = True
                        break

            # PART - TO DO - Maybe some extra checks will be needed here,
            # depending on the status.
            if not found:
                delete_partition = True

                # If it's still used by a PV, don't remove the partition yet.
                if db_part.foripvid:
                    delete_partition = False
                # If the partition is in creating state, don't remove it.
                elif (db_part.status ==
                        constants.PARTITION_CREATE_ON_UNLOCK_STATUS or
                      db_part.status ==
                        constants.PARTITION_CREATE_IN_SVC_STATUS):
                    delete_partition = False
                elif not cutils.is_partition_the_last(self.dbapi,
                                                      db_part.as_dict()):
                    delete_partition = False
                    LOG.debug("Partition %s(%s) is missing, but it cannot "
                              "be deleted since it's not the last "
                              "partition on disk." %
                              (db_part.uuid, db_part.device_path))

                if delete_partition:
                    LOG.info("Deleting missing partition %s - %s" %
                             (db_part.uuid, db_part.device_path))
                    self.dbapi.partition_destroy(db_part.uuid)
                else:
                    LOG.warn("Partition missing: %s - %s" %
                             (db_part.uuid, db_part.device_path))

    def ipv_update_by_ihost(self, context,
                            ihost_uuid, ipv_dict_array):
        """Create or update ipv for an ihost with the supplied data.

        This method allows records for a physical volume for ihost to be
        created, or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param ipv_dict_array: initial values for a physical volume objects
        :returns: pass or fail
        """

        def is_same_disk(idisk, ipv):
            if 'disk_or_part_device_path' in ipv:
                if ipv.get('disk_or_part_device_path') is not None:
                    if idisk.device_path == ipv.get('disk_or_part_device_path'):
                        return True
                else:
                    return False
            return False

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        forihostid = ihost['id']

        ipvs = self.dbapi.ipv_get_by_ihost(ihost_uuid)
        ilvgs = self.dbapi.ilvg_get_by_ihost(ihost_uuid)
        idisks = self.dbapi.idisk_get_by_ihost(ihost_uuid)
        partitions = self.dbapi.partition_get_by_ihost(ihost_uuid)
        # Cinder is now optional. A PV must be defined for it as part of
        # provisioning. When looking for disk re-enumerations, identify it so
        # when the DRBD device is reported by the agent we can reconcile the PV
        # entry.
        cinder_pv_id = None

        # Timeout for PV operations
        # In case of major failures (e.g. sysinv restart, system reset)
        # PVs may remain stuck in adding or removing. Semantic checks
        # will then prevent any other operation on the PVs

        # First remove any invalid timeout (i.e. PV was removed)
        ipv_uuids = [i['uuid'] for i in ipvs]
        for k in self._pv_op_timeouts.keys():
            if k not in ipv_uuids:
                del self._pv_op_timeouts[k]

        # Make sure that the Physical Volume to Disk info is still valid
        for ipv in ipvs:
            # Handle the case where the disk has been
            # removed/replaced/re-enumerated.
            pv_disk_is_present = False
            if ipv['pv_type'] == constants.PV_TYPE_DISK:
                for idisk in idisks:
                    if is_same_disk(idisk, ipv):
                        pv_disk_is_present = True
                        ipv_update_needed = False
                        pv_dict = {'forihostid': forihostid}

                        # Disk has been removed/replaced => UUID has changed.
                        if idisk.uuid != ipv['disk_or_part_uuid']:
                            ipv_update_needed = True
                            pv_dict.update({'disk_or_part_uuid': idisk.uuid})
                            LOG.info("Disk for ipv %s has changed." % ipv['uuid'])

                        # Disk has been re-enumerated.
                        if idisk.device_node != ipv['disk_or_part_device_node']:
                            ipv_update_needed = True
                            # If the PV name contained the device node, replace
                            # it accordingly.
                            new_lvm_pv_name = ipv['lvm_pv_name']
                            if ipv['disk_or_part_device_node'] in ipv['lvm_pv_name']:
                                new_lvm_pv_name = new_lvm_pv_name.replace(
                                    ipv['disk_or_part_device_node'],
                                    idisk.device_node)
                            # Update PV dictionary containing changes.
                            pv_dict.update({
                                'disk_or_part_device_node': idisk.device_node,
                                'lvm_pv_name': new_lvm_pv_name
                            })
                            # Update current PV object.
                            ipv.disk_or_part_device_node = idisk.device_node
                            ipv.lvm_pv_name = new_lvm_pv_name
                            LOG.info("Disk for ipv %s has been re-enumerated." %
                                     ipv['uuid'])

                        if ipv_update_needed:
                            try:
                                self.dbapi.ipv_update(ipv['uuid'], pv_dict)
                            except Exception:
                                LOG.exception("Update ipv for changed idisk "
                                              "details failed.")
                            break
                    elif not ipv['disk_or_part_device_path']:
                        # Device path is provided for the first time, update pv
                        # entry.
                        if idisk.device_node == ipv['disk_or_part_device_node']:
                            pv_disk_is_present = True
                            self._update_ipv_device_path(idisk, ipv)

                if not pv_disk_is_present:
                    self._ipv_handle_phys_storage_removal(ipv, 'idisk')

            elif ipv['pv_type'] == constants.PV_TYPE_PARTITION and ipv['disk_or_part_uuid']:
                try:
                    partition = self.dbapi.partition_get(
                        ipv['disk_or_part_uuid'])

                    # Disk on which the partition was created was re-enumerated.
                    # This assumes that the partition information is correctly updated
                    # for re-enumeration before we update the PVs
                    if (ipv['disk_or_part_device_node'] != partition['device_node']):
                        pv_dict = {'forihostid': forihostid,
                                   'disk_or_part_device_node': partition['device_node']}
                        ipv.disk_or_part_device_node = partition['device_node']

                        # the lvm_pv_name for cinder volumes is always /dev/drbd4
                        if ipv['lvm_pv_name'] != constants.CINDER_DRBD_DEVICE:
                            pv_dict.update({'lvm_pv_name': partition['device_node']})
                            ipv.lvm_pv_name = partition['device_node']

                        LOG.info("Disk information for PV %s has been changed "
                                 "due to disk re-enumeration." % ipv['uuid'])

                        try:
                            self.dbapi.ipv_update(ipv['uuid'], pv_dict)
                        except Exception:
                            LOG.exception("Update ipv for changed partition "
                                           "details failed.")

                    if (ipv['pv_state'] == constants.PROVISIONED and
                        partition.status not in
                        [constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
                         constants.PARTITION_CREATE_IN_SVC_STATUS,
                         constants.PARTITION_IN_USE_STATUS]):
                        self.dbapi.partition_update(
                            partition.uuid,
                            {'status': constants.PARTITION_IN_USE_STATUS})
                except exception.DiskPartitionNotFound:
                    if ipv['lvm_vg_name'] != constants.LVG_CINDER_VOLUMES:
                        self._check_pv_partition(ipv)

                # Save the physical PV associated with cinder volumes for use later
                if ipv['lvm_vg_name'] == constants.LVG_CINDER_VOLUMES:
                        cinder_pv_id = ipv['id']

        # Some of the PVs may have been updated, so get them again.
        ipvs = self.dbapi.ipv_get_by_ihost(ihost_uuid)

        # Process the response from the agent
        regex = re.compile("^/dev/.*[a-z][1-9][0-9]?$")
        for i in ipv_dict_array:
            # Between a disk being wiped and the PV recreated, PVs are reported
            # as unknown. These values must not reach the DB.
            if constants.PV_NAME_UNKNOWN in i['lvm_pv_name']:
                LOG.info("Unknown PV on host %s: %s" %
                         (forihostid, i['lvm_pv_uuid']))
                continue

            pv_dict = {
                'forihostid': forihostid,
            }
            pv_dict.update(i)

            # get the LVG info
            for ilvg in ilvgs:
                if ilvg.lvm_vg_name == i['lvm_vg_name']:
                    pv_dict['forilvgid'] = ilvg.id
                    pv_dict['lvm_vg_name'] = ilvg.lvm_vg_name

            # Search the current pv to see if this one exists
            found = False
            for ipv in ipvs:
                if ipv.lvm_pv_name == i['lvm_pv_name']:
                    found = True
                    if ipv.lvm_pv_uuid != i['lvm_pv_uuid']:
                        # The physical volume has been replaced.
                        LOG.info("PV uuid: %s changed UUID from %s to %s",
                                 ipv.uuid, ipv.lvm_pv_uuid,
                                 i['lvm_pv_uuid'])
                        # May need to take some action => None for now

                    system_mode = self.dbapi.isystem_get_one().system_mode
                    if (ipv.pv_state == constants.PV_ADD and not
                        (system_mode == constants.SYSTEM_MODE_SIMPLEX and
                            pv_dict['lvm_vg_name'] == constants.LVG_CINDER_VOLUMES)):
                        pv_dict.update({'pv_state': constants.PROVISIONED})

                    # Update the database
                    try:
                        self.dbapi.ipv_update(ipv['uuid'], pv_dict)
                        if ipv['pv_type'] == constants.PV_TYPE_PARTITION:
                            self.dbapi.partition_update(
                                ipv['disk_or_part_uuid'],
                                {'status': constants.PARTITION_IN_USE_STATUS})
                    except Exception:
                        LOG.exception("Update ipv with latest info failed")

                    if ipv['pv_type'] == constants.PV_TYPE_PARTITION:
                        continue

                    # Handle the case where the disk has been removed/replaced
                    idisk = self.dbapi.idisk_get_by_ihost(ihost_uuid)
                    pv_disk_is_present = False
                    for d in idisk:
                        if ((d.device_node in ipv['lvm_pv_name']) or
                            ((i['lvm_pv_name'] ==
                                constants.CINDER_DRBD_DEVICE) and
                             ((ipv['disk_or_part_device_node'] and
                               (d.device_node in
                                ipv['disk_or_part_device_node']))))):
                            pv_disk_is_present = True
                            if d.uuid != ipv['disk_or_part_uuid']:
                                # UUID has changed
                                pv_dict.update({'disk_or_part_uuid': d.uuid})
                                try:
                                    self.dbapi.ipv_update(ipv['uuid'], pv_dict)
                                except Exception:
                                    LOG.exception("Update ipv for changed "
                                                  "idisk uuid failed")
                            break
                    if not pv_disk_is_present:
                        self._ipv_handle_phys_storage_removal(ipv, 'idisk')
                    break

            # Special Case: DRBD has provisioned the cinder partition. Update the existing PV partition
            if not found and i['lvm_pv_name'] == constants.CINDER_DRBD_DEVICE:
                if cinder_pv_id:
                    cinder_pv = self.dbapi.ipv_get(cinder_pv_id)
                    if cinder_pv.pv_state == constants.PV_ADD:
                        self.dbapi.ipv_update(
                            cinder_pv.uuid,
                            {'lvm_pv_name': i['lvm_pv_name'],
                             'lvm_pe_alloced': i['lvm_pe_alloced'],
                             'lvm_pe_total': i['lvm_pe_total'],
                             'lvm_pv_uuid': i['lvm_pv_uuid'],
                             'lvm_pv_size': i['lvm_pv_size'],
                             'pv_state': constants.PROVISIONED})

                        self.dbapi.partition_update(
                            cinder_pv.disk_or_part_uuid,
                            {'status': constants.PARTITION_IN_USE_STATUS})

                        mate_hostname = cutils.get_mate_controller_hostname()
                        try:
                            standby_controller = self.dbapi.ihost_get_by_hostname(
                                mate_hostname)
                            standby_ipvs = self.dbapi.ipv_get_by_ihost(
                                standby_controller['uuid'])
                            for pv in standby_ipvs:
                                if pv.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
                                    self.dbapi.ipv_update(
                                        pv.uuid,
                                        {'pv_state': constants.PROVISIONED,
                                         'lvm_pv_name': constants.CINDER_DRBD_DEVICE})
                                    self.dbapi.ilvg_update(
                                        pv.forilvgid,
                                        {'vg_state': constants.PROVISIONED})
                                    self.dbapi.partition_update(
                                        pv.disk_or_part_uuid,
                                        {'status': constants.PARTITION_IN_USE_STATUS})
                        except exception.NodeNotFound:
                            # We don't have a mate, standby, controller
                            pass
                        except Exception as e:
                            LOG.exception("Updating mate cinder PV/LVG state failed: %s", str(e))

                    found = True
                else:
                    LOG.error("Agent reports a DRBD cinder device, but no physical device found in the inventory.")
                    # Do not create an unaffiliated DRBD PV, go to the next agent reported PV
                    continue

            # Create the physical volume if it doesn't currently exist but only
            # if it's associated with an existing volume group. A physical
            # volume without a volume group should not happen, but we want to
            # avoid creating an orphaned physical volume because semantic
            # checks will prevent if from being removed.
            if ((not found) and ('forilvgid' in pv_dict) and
                    (pv_dict['lvm_vg_name'] in constants.LVG_ALLOWED_VGS)):
                # Determine the volume type => look for a partition number.
                if regex.match(i['lvm_pv_name']):
                    pv_dict['pv_type'] = constants.PV_TYPE_PARTITION
                else:
                    pv_dict['pv_type'] = constants.PV_TYPE_DISK

                # Lookup the uuid of the disk
                pv_dict['disk_or_part_uuid'] = None
                pv_dict['disk_or_part_device_node'] = None

                idisk = self.dbapi.idisk_get_by_ihost(ihost_uuid)
                for d in idisk:
                    if d.device_node in i['lvm_pv_name']:
                        if pv_dict['pv_type'] == constants.PV_TYPE_DISK:
                            pv_dict['disk_or_part_uuid'] = d.uuid
                            pv_dict['disk_or_part_device_node'] = d.device_node
                            pv_dict['disk_or_part_device_path'] = d.device_path
                        elif pv_dict['pv_type'] == constants.PV_TYPE_PARTITION:
                            partitions = self.dbapi.partition_get_by_idisk(d.uuid)
                            for p in partitions:
                                partition_number = (
                                    re.match('.*?([0-9]+)$',
                                             i['lvm_pv_name']).group(1))
                                if '-part' + partition_number in p.device_path:
                                    pv_dict['disk_or_part_uuid'] = p.uuid
                                    pv_dict['disk_or_part_device_node'] = i['lvm_pv_name']
                                    pv_dict['disk_or_part_device_path'] = p.device_path

                pv_dict['pv_state'] = constants.PROVISIONED

                # Create the Physical Volume
                pv = None
                try:
                    pv = self.dbapi.ipv_create(forihostid, pv_dict)
                except Exception:
                    LOG.exception("PV Volume Creation failed")

                if pv.get('pv_type') == constants.PV_TYPE_PARTITION:
                    try:
                        self.dbapi.partition_update(
                            pv.disk_or_part_uuid,
                            {'foripvid': pv.id,
                             'status': constants.PARTITION_IN_USE_STATUS})
                    except Exception:
                        LOG.exception("Updating partition (%s) for ipv id "
                                      "failed (%s)" % (pv.disk_or_part_uuid,
                                                       pv.uuid))
                elif pv.get('pv_type') == constants.PV_TYPE_DISK:
                    try:
                        self.dbapi.idisk_update(pv.disk_or_part_uuid,
                                                {'foripvid': pv.id})
                    except Exception:
                        LOG.exception("Updating idisk (%s) for ipv id "
                                      "failed (%s)" % (pv.disk_or_part_uuid,
                                                       pv.uuid))
            else:
                if not found:
                    # TODO(rchurch): Eval the restriction on requiring a valid LVG
                    # name. We may have scenarios where a PV is in transition and
                    # needs to be added so that the global filter is set correctly
                    # by a followup manifest application.
                    LOG.info("Inconsistent Data: Not adding PV: %s" % pv_dict)

        # Some of the PVs may have been updated, so get them again.
        ipvs = self.dbapi.ipv_get_by_ihost(ihost_uuid)

        # Purge the records that have been requested to be removed and
        # update the failed ones
        for ipv in ipvs:
            # Make sure that the agent hasn't reported that it is
            # still present on the host
            found = False
            for ipv_in_agent in ipv_dict_array:
                if ipv.lvm_pv_name == ipv_in_agent['lvm_pv_name']:
                    found = True
                    break

            update = {}
            if not found:
                LOG.info("PV not found in Agent. uuid: %(ipv)s current state: "
                         "%(st)s" % {'ipv': ipv['uuid'],
                                     'st': ipv['pv_state']})
                if ipv.pv_state in [constants.PV_DEL, constants.PV_ERR]:
                    try:
                        #
                        # Simplex should not be a special case anymore.
                        #
                        # system_mode = self.dbapi.isystem_get_one().system_mode
                        # if not (system_mode == constants.SYSTEM_MODE_SIMPLEX and
                        #         ipv['lvm_vg_name'] == constants.LVG_CINDER_VOLUMES):
                        #     # Make sure the disk or partition is free of this
                        #     # PV before removal.
                        self._prepare_for_ipv_removal(ipv)
                        self.dbapi.ipv_destroy(ipv.id)
                    except Exception:
                        LOG.exception("Physical Volume removal failed")
                else:
                    if ipv.pv_state == constants.PROVISIONED:
                        # Our drive may have issues (e.g. toast or wiped)
                        if 'drbd' in ipv.lvm_pv_name:
                            # TODO(rchurch): Can't destroy the standby PV (even
                            # though it disappears) or we lose the physical PV
                            # mapping in the DB. Use a different PV state for
                            # standby controller
                            continue
            else:
                if (ipv.pv_state == constants.PV_ERR and
                        ipv.lvm_vg_name == ipv_in_agent['lvm_vg_name']):
                    # PV is back!
                    update = {'pv_state': constants.PROVISIONED}

            if update:
                try:
                    self.dbapi.ipv_update(ipv['uuid'], update)
                except Exception:
                    LOG.exception("Updating ipv id %s "
                                  "failed" % ipv['uuid'])

        return

    @periodic_task.periodic_task(spacing=CONF.conductor.audit_interval)
    def _agent_update_request(self, context):
        """
        Check DB  for inventory objects with an inconsistent state and
        request an update from sysinv agent.
        Currently requesting updates for:
        - ipv:  if state is not 'provisioned'
        - ilvg: if state is not 'provisioned'
        """
        LOG.debug("Calling _agent_update_request")
        update_hosts = {}

        # Check if the LVM backend is in flux. If so, skip the audit as we know
        # VG/PV states are going to be transitory. Otherwise, maintain the
        # audit for nova storage.
        skip_lvm_audit = False
        lvm_backend = StorageBackendConfig.get_backend(self.dbapi, constants.SB_TYPE_LVM)
        if lvm_backend and lvm_backend.state != constants.SB_STATE_CONFIGURED:
            skip_lvm_audit = True

        if not skip_lvm_audit:
            ipvs = self.dbapi.ipv_get_all()
            ilvgs = self.dbapi.ilvg_get_all()

            def update_hosts_dict(host_id, val):
                if host_id not in update_hosts:
                    update_hosts[host_id] = set()
                update_hosts[host_id].add(val)

            # Check LVGs
            for ilvg in ilvgs:
                if ilvg['vg_state'] != constants.PROVISIONED:
                    host_id = ilvg['forihostid']
                    update_hosts_dict(host_id, constants.LVG_AUDIT_REQUEST)

            # Check PVs
            for ipv in ipvs:
                if ipv['pv_state'] != constants.PROVISIONED:
                    host_id = ipv['forihostid']
                    update_hosts_dict(host_id, constants.PV_AUDIT_REQUEST)

            # Make sure we get at least one good report for PVs & LVGs
            hosts = self.dbapi.ihost_get_list()
            for host in hosts:
                if host.availability != constants.AVAILABILITY_OFFLINE:
                    idisks = self.dbapi.idisk_get_by_ihost(host.uuid)
                    if not idisks:
                        update_hosts_dict(host.id, constants.DISK_AUDIT_REQUEST)
                    ipvs = self.dbapi.ipv_get_by_ihost(host.uuid)
                    if not ipvs:
                        update_hosts_dict(host.id, constants.PARTITION_AUDIT_REQUEST)
                        update_hosts_dict(host.id, constants.PV_AUDIT_REQUEST)
                    ilvgs = self.dbapi.ilvg_get_by_ihost(host.uuid)
                    if not ilvgs:
                        update_hosts_dict(host.id, constants.LVG_AUDIT_REQUEST)

        # Check partitions.
        partitions = self.dbapi.partition_get_all()
        # Transitory partition states.
        states = [constants.PARTITION_CREATE_IN_SVC_STATUS,
                  constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
                  constants.PARTITION_DELETING_STATUS,
                  constants.PARTITION_MODIFYING_STATUS]
        for part in partitions:
            # TODO (rchurch):These mib checks cover an R4->R5 upgrade
            # scenario.Remove after R5.
            if ((part.status in states) or
                    (not part.get('start_mib') or
                     not part.get('end_mib'))):
                host_id = part['forihostid']
                update_hosts_dict(host_id, constants.PARTITION_AUDIT_REQUEST)

        # Send update request if required
        if update_hosts:
            rpcapi = agent_rpcapi.AgentAPI()
            for host_id, update_set in update_hosts.items():

                ihost = self.dbapi.ihost_get(host_id)
                if (ihost.invprovision != constants.PROVISIONED and
                        tsc.system_type != constants.TIS_AIO_BUILD):
                    continue
                if ihost:
                    LOG.info("Sending agent update request for host %s "
                             "to update (%s)" %
                             (host_id, (', '.join(update_set))))

                    # Get the cinder device to force detection even
                    # when filtered by LVM's global_filter.
                    ipvs = self.dbapi.ipv_get_by_ihost(ihost['uuid'])
                    cinder_device = None
                    for ipv in ipvs:
                        if ipv['lvm_vg_name'] == constants.LVG_CINDER_VOLUMES:
                            cinder_device = ipv.get('disk_or_part_device_path')

                    rpcapi.agent_update(context, ihost['uuid'],
                                        list(update_set), cinder_device)
                else:
                    LOG.error("Host: %s not found in database" % host_id)

    def _clear_ceph_stor_state(self, ihost_uuid):
        """ Once a node starts, clear status of OSD storage devices

        On reboot storage devices are expected to be 'configured', even if they
        were in 'configuration-failed'.
        This code will not be reached if manifests fail.
        Also, realtime status of Ceph's OSD is queried by pmon/sm, no need to do
        it in sysinv.
        """
        stors = self.dbapi.istor_get_by_ihost(ihost_uuid)
        for stor in stors:
            if stor.state != constants.SB_STATE_CONFIGURED:
                LOG.info("State of stor: '%s' is '%s', resetting to '%s'." %
                         (stor.uuid, stor.state,
                          constants.SB_STATE_CONFIGURED))
                values = {'state': constants.SB_STATE_CONFIGURED}
                self.dbapi.istor_update(stor.uuid, values)

    def iplatform_update_by_ihost(self, context,
                                  ihost_uuid, imsg_dict):
        """Update node data when sysinv-agent is started after a boot.

        This method is invoked on initialization and allows
        updates that need to happen once, when a node is started.
        Note, swact also results in restart of services, but not
        of sysinv-agent.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param imsg_dict:  inventory message
        :returns: pass or fail
        """
        ihost_uuid.strip()
        LOG.info("Updating platform data for host: %s "
                 "with: %s" % (ihost_uuid, imsg_dict))
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        availability = imsg_dict.get('availability')

        val = {}

        action_state = imsg_dict.get(constants.HOST_ACTION_STATE)
        if action_state and action_state != ihost.action_state:
            LOG.info("%s updating action_state=%s" % (ihost.hostname, action_state))
            val[constants.HOST_ACTION_STATE] = action_state

        iscsi_initiator_name = imsg_dict.get('iscsi_initiator_name')
        if (iscsi_initiator_name and
                ihost.iscsi_initiator_name is None):
            LOG.info("%s updating iscsi initiator=%s" %
                        (ihost.hostname, iscsi_initiator_name))
            val['iscsi_initiator_name'] = iscsi_initiator_name

        if val:
            ihost = self.dbapi.ihost_update(ihost_uuid, val)

        if not availability:
            return

        kubernetes_config = utils.is_kubernetes_config(self.dbapi)

        if (cutils.host_has_function(ihost, constants.WORKER) and not
                kubernetes_config):
            if availability == constants.VIM_SERVICES_ENABLED:
                # report to nova the host aggregate groupings now that
                # the worker node is available
                LOG.info("AGG iplatform available for ihost= %s imsg= %s" %
                         (ihost_uuid, imsg_dict))
                # AGG10 noted 13secs in vbox between nova manifests applied and
                # reported by inv to conductor and available signal to
                # nova conductor
                for attempts in range(1, 10):
                    try:
                        if self._openstack.nova_host_available(ihost_uuid):
                            break
                        else:
                            LOG.error(
                                "AGG iplatform attempt failed for ihost= %s imsg= %s" % (
                                    ihost_uuid, imsg_dict))
                    except Exception:
                        LOG.exception("nova_host_available exception, continuing!")

                    time.sleep(2)

            elif availability == constants.AVAILABILITY_OFFLINE:
                LOG.debug("AGG iplatform not available for ihost= %s imsg= %s" % (ihost_uuid, imsg_dict))
                self._openstack.nova_host_offline(ihost_uuid)

        if ((ihost.personality == constants.STORAGE and
                ihost.hostname == constants.STORAGE_0_HOSTNAME) or
                (ihost.personality == constants.CONTROLLER)):

            # monitor stor entry if ceph is configured initially or
            # 1st pair of storage nodes are provisioned (so that controller
            # node can be locked/unlocked)
            ceph_backend = StorageBackendConfig.get_backend(
                self.dbapi,
                constants.CINDER_BACKEND_CEPH
            )

            if ceph_backend and ceph_backend.task != \
                    constants.SB_TASK_PROVISION_STORAGE:
                ihost.capabilities.update({
                    constants.IHOST_STOR_FUNCTION:
                        constants.STOR_FUNCTION_MONITOR})
                self.dbapi.ihost_update(ihost_uuid,
                    {'capabilities': ihost.capabilities})

            storage_lvm = StorageBackendConfig.get_configured_backend_conf(
                self.dbapi,
                constants.CINDER_BACKEND_LVM
            )

            if (storage_lvm and ihost.personality == constants.CONTROLLER and
                    not kubernetes_config):
                LOG.debug("iplatform monitor check system has lvm backend")
                cinder_device = cutils._get_cinder_device(self.dbapi, ihost.id)
                idisks = self.dbapi.idisk_get_by_ihost(ihost_uuid)
                for idisk in idisks:
                    LOG.debug("checking for cinder disk device_path=%s "
                              "cinder_device=%s" %
                              (idisk.device_path, cinder_device))
                    if ((idisk.device_path and
                        idisk.device_path == cinder_device) or
                        (idisk.device_node and
                           idisk.device_node == cinder_device)):
                        idisk_capabilities = idisk.capabilities
                        idisk_dict = {'device_function': 'cinder_device'}
                        idisk_capabilities.update(idisk_dict)

                        idisk_val = {'capabilities': idisk_capabilities}
                        LOG.info("SYS_I MATCH host %s device_node %s cinder_device %s idisk.uuid %s val %s" %
                             (ihost.hostname,
                              idisk.device_node,
                              cinder_device,
                              idisk.uuid,
                              idisk_val))

                        self.dbapi.idisk_update(idisk.uuid, idisk_val)

                if availability == constants.VIM_SERVICES_ENABLED:
                    self._resize_cinder_volumes()

        if availability == constants.AVAILABILITY_AVAILABLE:
            if imsg_dict.get(constants.SYSINV_AGENT_FIRST_REPORT):
                # This should be run once after a node boot
                self._clear_ceph_stor_state(ihost_uuid)
                cceph.fix_crushmap(self.dbapi)
            config_uuid = imsg_dict['config_applied']
            self._update_host_config_applied(context, ihost, config_uuid)

    def iconfig_update_by_ihost(self, context,
                                ihost_uuid, imsg_dict):
        """Update applied iconfig for an ihost with the supplied data.

        This method allows records for iconfig for ihost to be updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param imsg_dict: inventory message dict
        :returns: pass or fail
        """

        ihost_uuid.strip()
        try:
            ihost = self.dbapi.ihost_get(ihost_uuid)
        except exception.ServerNotFound:
            LOG.exception("Invalid ihost_uuid %s" % ihost_uuid)
            return

        config_uuid = imsg_dict['config_applied']
        self._update_host_config_applied(context, ihost, config_uuid)

    def subfunctions_update_by_ihost(self, context,
                                ihost_uuid, subfunctions):
        """Update subfunctions for a host.

        This method allows records for subfunctions to be updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param subfunctions: subfunctions provided by the ihost
        :returns: pass or fail
        """
        ihost_uuid.strip()
        ihost_val = {'subfunctions': subfunctions}
        self.dbapi.ihost_update(ihost_uuid, ihost_val)

    def get_ihost_by_macs(self, context, ihost_macs):
        """Finds ihost db entry based upon the mac list

        This method returns an ihost if it matches a mac

        :param context: an admin context
        :param ihost_macs: list of mac addresses
        :returns: ihost object, including all fields.
        """

        ihosts = self.dbapi.ihost_get_list()

        LOG.debug("Checking ihost db for macs: %s" % ihost_macs)
        for mac in ihost_macs:
            try:
                mac = mac.rstrip()
                mac = cutils.validate_and_normalize_mac(mac)
            except Exception:
                LOG.warn("get_ihost_by_macs invalid mac: %s" % mac)
                continue

            for host in ihosts:
                if host.mgmt_mac == mac:
                    LOG.info("Host found ihost db for macs: %s" % host.hostname)
                    return host
        LOG.debug("RPC get_ihost_by_macs called but found no ihost.")

    def get_ihost_by_hostname(self, context, ihost_hostname):
        """Finds ihost db entry based upon the ihost hostname

        This method returns an ihost if it matches the ihost
        hostname.

        :param context: an admin context
        :param ihost_hostname: ihost hostname
        :returns: ihost object, including all fields.
        """

        try:
            ihost = self.dbapi.ihost_get_by_hostname(ihost_hostname)

            return ihost

        except exception.NodeNotFound:
            pass

        LOG.debug("RPC ihost_get_by_hostname called but found no ihost.")

    @staticmethod
    def _controller_config_active_check():
        """Determine whether the active configuration has been finalized"""

        if not os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG):
            return False

        # Defer running the manifest apply if backup/restore operations are
        # in progress.
        if (os.path.isfile(tsc.BACKUP_IN_PROGRESS_FLAG) or
                os.path.isfile(tsc.RESTORE_IN_PROGRESS_FLAG)):
            return False

        if not os.path.isfile(CONFIG_CONTROLLER_FINI_FLAG):
            return True

        return False

    def _controller_config_active_apply(self, context):
        """Check whether target config has been applied to active
           controller to run postprocessing"""

        # check whether target config may be finished based upon whether
        # the active controller has the active config target
        if not self._controller_config_active_check():
            return  # already finalized on this active controller

        try:
            hostname = socket.gethostname()
            controller_hosts =\
                self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        except Exception as e:
            LOG.warn("Failed to get local host object: %s", str(e))
            return

        active_host = None
        standby_host = None
        for controller_host in controller_hosts:
            if controller_host.hostname == hostname:
                active_host = controller_host
            else:
                standby_host = controller_host

        if (active_host and active_host.config_target and
           active_host.config_applied == active_host.config_target):
            # active controller has applied target, apply pending config

            if not os.path.isfile(CONFIG_CONTROLLER_ACTIVATE_FLAG):
                cutils.touch(CONFIG_CONTROLLER_ACTIVATE_FLAG)
                # apply keystone changes to current active controller
                personalities = [constants.CONTROLLER]
                config_uuid = self._config_update_hosts(context, personalities,
                                                        host_uuids=[active_host.uuid])
                config_dict = {
                    "personalities": personalities,
                    "host_uuids": active_host.uuid,
                    "classes": ['openstack::keystone::endpoint::runtime',
                                'platform::firewall::runtime',
                                'platform::sysinv::runtime']
                }
                self._config_apply_runtime_manifest(
                    context, config_uuid, config_dict, host_uuids=[active_host.uuid])

            # apply filesystem config changes if all controllers at target
            standby_config_target_flipped = None
            if standby_host and standby_host.config_target:
                standby_config_target_flipped = self._config_flip_reboot_required(standby_host.config_target)
            if not standby_host or (standby_host and
               (standby_host.config_applied == standby_host.config_target or
               standby_host.config_applied == standby_config_target_flipped)):

                LOG.info("_controller_config_active_apply about to resize the filesystem")

                if self._config_resize_filesystems(context, standby_host):
                    cutils.touch(CONFIG_CONTROLLER_FINI_FLAG)

                    controller_fs_list = self.dbapi.controller_fs_get_list()
                    for fs in controller_fs_list:
                        if (fs.get('state') !=
                                constants.CONTROLLER_FS_AVAILABLE):
                            self.dbapi.controller_fs_update(
                                fs.uuid,
                                {'state': constants.CONTROLLER_FS_AVAILABLE})

                    self._update_alarm_status(context, active_host)
                    if standby_host and standby_host.config_applied == standby_host.config_target:
                        self._update_alarm_status(context, standby_host)

        else:
            # Ignore the reboot required bit for active controller when doing the comparison
            active_config_target_flipped = None
            if active_host and active_host.config_target:
                active_config_target_flipped = self._config_flip_reboot_required(active_host.config_target)
            standby_config_target_flipped = None
            if standby_host and standby_host.config_target:
                standby_config_target_flipped = self._config_flip_reboot_required(standby_host.config_target)
            if active_host and active_config_target_flipped and \
               active_host.config_applied == active_config_target_flipped:
                # apply filesystem config changes if all controllers at target
                # Ignore the reboot required bit
                if not standby_host or (standby_host and
                   (standby_host.config_applied == standby_host.config_target or
                   standby_host.config_applied == standby_config_target_flipped)):

                    LOG.info(
                        "_controller_config_active_apply about to resize the filesystem")
                    if self._config_resize_filesystems(context, standby_host):
                        cutils.touch(CONFIG_CONTROLLER_FINI_FLAG)

                        controller_fs_list = \
                            self.dbapi.controller_fs_get_list()
                        for fs in controller_fs_list:
                            if (fs.get('state') !=
                                    constants.CONTROLLER_FS_AVAILABLE):
                                self.dbapi.controller_fs_update(
                                    fs.uuid,
                                    {'state':
                                        constants.CONTROLLER_FS_AVAILABLE})

                        if standby_host and standby_host.config_applied == standby_host.config_target:
                            self._update_alarm_status(context, standby_host)

    def _audit_ihost_action(self, ihost):
        """Audit whether the ihost_action needs to be terminated or escalated.
        """

        if ihost.administrative == constants.ADMIN_UNLOCKED:
            ihost_action_str = ihost.ihost_action or ""

            if (ihost_action_str.startswith(constants.FORCE_LOCK_ACTION) or
                    ihost_action_str.startswith(constants.LOCK_ACTION)):

                task_str = ihost.task or ""
                if (('--' in ihost_action_str and
                      ihost_action_str.startswith(
                           constants.FORCE_LOCK_ACTION)) or
                      ('----------' in ihost_action_str and
                      ihost_action_str.startswith(constants.LOCK_ACTION))):

                    ihost_mtc = ihost.as_dict()
                    keepkeys = ['ihost_action', 'vim_progress_status']
                    ihost_mtc = cutils.removekeys_nonmtce(ihost_mtc,
                                                          keepkeys)

                    if ihost_action_str.startswith(constants.FORCE_LOCK_ACTION):
                        timeout_in_secs = 6
                        ihost_mtc['operation'] = 'modify'
                        ihost_mtc['action'] = constants.FORCE_LOCK_ACTION
                        ihost_mtc['task'] = constants.FORCE_LOCKING
                        LOG.warn("ihost_action override %s" %
                                 ihost_mtc)
                        mtce_api.host_modify(
                            self._api_token, self._mtc_address, self._mtc_port,
                            ihost_mtc, timeout_in_secs)

                    # need time for FORCE_LOCK mtce to clear
                    if ('----' in ihost_action_str):
                        ihost_action_str = ""
                    else:
                        ihost_action_str += "-"

                    if (task_str.startswith(constants.FORCE_LOCKING) or
                       task_str.startswith(constants.LOCKING)):
                        val = {'task': "",
                               'ihost_action': ihost_action_str,
                               'vim_progress_status': ""}
                    else:
                        val = {'ihost_action': ihost_action_str,
                               'vim_progress_status': ""}
                else:
                    ihost_action_str += "-"
                    if (task_str.startswith(constants.FORCE_LOCKING) or
                       task_str.startswith(constants.LOCKING)):
                        task_str += "-"
                        val = {'task': task_str,
                               'ihost_action': ihost_action_str}
                    else:
                        val = {'ihost_action': ihost_action_str}

                self.dbapi.ihost_update(ihost.uuid, val)
        else:  # Administrative locked already
            task_str = ihost.task or ""
            if (task_str.startswith(constants.FORCE_LOCKING) or
               task_str.startswith(constants.LOCKING)):
                val = {'task': ""}
                self.dbapi.ihost_update(ihost.uuid, val)

        vim_progress_status_str = ihost.get('vim_progress_status') or ""
        if (vim_progress_status_str and
           (vim_progress_status_str != constants.VIM_SERVICES_ENABLED) and
           (vim_progress_status_str != constants.VIM_SERVICES_DISABLED)):
            if ('..' in vim_progress_status_str):
                LOG.info("Audit clearing vim_progress_status=%s" %
                         vim_progress_status_str)
                vim_progress_status_str = ""
            else:
                vim_progress_status_str += ".."

            val = {'vim_progress_status': vim_progress_status_str}
            self.dbapi.ihost_update(ihost.uuid, val)

    def _audit_upgrade_status(self):
        """Audit upgrade related status"""
        try:
            upgrade = self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # Not upgrading. No need to update status
            return

        if upgrade.state == constants.UPGRADE_ACTIVATING:
            personalities = [constants.CONTROLLER, constants.WORKER]

            all_manifests_applied = True
            hosts = self.dbapi.ihost_get_list()
            for host in hosts:
                if host.personality in personalities and \
                        host.config_target != host.config_applied:
                    all_manifests_applied = False
                    break
            if all_manifests_applied:
                self.dbapi.software_upgrade_update(
                    upgrade.uuid,
                    {'state': constants.UPGRADE_ACTIVATION_COMPLETE})

        elif upgrade.state == constants.UPGRADE_DATA_MIGRATION:
            # Progress upgrade state if necessary...
            if os.path.isfile(tsc.CONTROLLER_UPGRADE_COMPLETE_FLAG):
                self.dbapi.software_upgrade_update(
                    upgrade.uuid,
                    {'state': constants.UPGRADE_DATA_MIGRATION_COMPLETE})
            elif os.path.isfile(tsc.CONTROLLER_UPGRADE_FAIL_FLAG):
                self.dbapi.software_upgrade_update(
                    upgrade.uuid,
                    {'state': constants.UPGRADE_DATA_MIGRATION_FAILED})

        elif upgrade.state == constants.UPGRADE_UPGRADING_CONTROLLERS:
            # In CPE upgrades, after swacting to controller-1, we need to clear
            # the VIM upgrade flag on Controller-0 to allow VMs to be migrated
            # to controller-1.
            if constants.WORKER in tsc.subfunctions:
                try:
                    controller_0 = self.dbapi.ihost_get_by_hostname(
                        constants.CONTROLLER_0_HOSTNAME)
                    if not utils.is_host_active_controller(controller_0):
                        vim_api.set_vim_upgrade_state(controller_0, False)
                except Exception:
                    LOG.exception("Unable to set VIM upgrade state to False")

    def _audit_install_states(self, hosts):
        # A node could shutdown during it's installation and the install_state
        # for example could get stuck at the value "installing". To avoid
        # this situation we audit the sanity of the states by appending the
        # character '+' to the states in the database. After 15 minutes of the
        # states not changing, set the install_state to failed.

        # The audit's interval is 60sec
        MAX_COUNT = 15

        # Allow longer duration for booting phase
        MAX_COUNT_BOOTING = 40

        for host in hosts:
            LOG.debug("Auditing %s, install_state is %s",
                      host.hostname, host.install_state)
            LOG.debug("Auditing %s, availability is %s",
                      host.hostname, host.availability)

            if (host.administrative == constants.ADMIN_LOCKED and
                    host.install_state is not None):

                install_state = host.install_state.rstrip('+')

                if host.install_state != constants.INSTALL_STATE_FAILED:
                    if (install_state == constants.INSTALL_STATE_BOOTING and
                            host.availability !=
                            constants.AVAILABILITY_OFFLINE):
                        host.install_state = constants.INSTALL_STATE_COMPLETED

                    if (install_state != constants.INSTALL_STATE_INSTALLED and
                            install_state !=
                            constants.INSTALL_STATE_COMPLETED):
                        if (install_state ==
                                constants.INSTALL_STATE_INSTALLING and
                                host.install_state_info is not None):
                            if host.install_state_info.count('+') >= MAX_COUNT:
                                LOG.info(
                                    "Auditing %s, install_state changed from "
                                    "'%s' to '%s'", host.hostname,
                                    host.install_state,
                                    constants.INSTALL_STATE_FAILED)
                                host.install_state = \
                                    constants.INSTALL_STATE_FAILED
                            else:
                                host.install_state_info += "+"
                        else:
                            if install_state == constants.INSTALL_STATE_BOOTING:
                                max_count = MAX_COUNT_BOOTING
                            else:
                                max_count = MAX_COUNT
                            if host.install_state.count('+') >= max_count:
                                LOG.info(
                                    "Auditing %s, install_state changed from "
                                    "'%s' to '%s'", host.hostname,
                                    host.install_state,
                                    constants.INSTALL_STATE_FAILED)
                                host.install_state = \
                                    constants.INSTALL_STATE_FAILED
                            else:
                                host.install_state += "+"

                # It is possible we get stuck in an installed failed state. For
                # example if a node gets powered down during an install booting
                # state and then powered on again. Clear it if the node is
                # online.
                elif (host.availability == constants.AVAILABILITY_ONLINE and
                        host.install_state == constants.INSTALL_STATE_FAILED):
                    host.install_state = constants.INSTALL_STATE_COMPLETED

                self.dbapi.ihost_update(host.uuid,
                                        {'install_state': host.install_state,
                                         'install_state_info':
                                             host.install_state_info})

    def _audit_cinder_state(self):
        """
         Complete disabling the EMC by removing it from the list of cinder
         services.
         """
        emc_state_param = self._get_emc_state()
        current_emc_state = emc_state_param.value

        if (current_emc_state !=
                constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_DISABLING):
            return

        LOG.info("Running cinder state audit")
        try:
            hostname = socket.gethostname()
            active_host = \
                self.dbapi.ihost_get_by_hostname(hostname)
        except Exception as e:
            LOG.error(
                "Failed to get local host object during cinder audit: %s",
                str(e))
            return

        if (active_host and active_host.config_target and
                active_host.config_applied == active_host.config_target):
            # The manifest has been applied on the active controller
            # Now check that the emc service has gone down
            emc_service_removed = False
            emc_service_found = False
            cinder_services = self._openstack.get_cinder_services()
            for cinder_service in cinder_services:
                if '@emc' in cinder_service.host:
                    emc_service_found = True

                    if cinder_service.state == 'down':
                        command_args = [
                            '/usr/bin/cinder-manage',
                            'service',
                            'remove',
                            'cinder-volume',
                            cinder_service.host
                        ]
                        with open(os.devnull, "w") as fnull:
                            LOG.info("Removing emc cinder-volume service")
                            try:
                                subprocess.check_call(
                                    command_args, stdout=fnull, stderr=fnull)
                                emc_service_removed = True
                            except subprocess.CalledProcessError as e:
                                LOG.exception(e)

            if emc_service_removed or not emc_service_found:
                LOG.info("Setting EMC state to disabled")
                new_state = constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_DISABLED
                self.dbapi.service_parameter_update(
                    emc_state_param.uuid,
                    {'value': new_state}
                )

    def _hpe_audit_cinder_state(self):
        """
         Complete disabling the hpe drivers by removing them from the list
         of cinder services.
         """

        # Only run audit if any one of the backends is enabled

        hpe3par_enabled = False
        try:
            param = self.dbapi.service_parameter_get_one(constants.SERVICE_TYPE_CINDER,
                constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR,
                constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED)
            hpe3par_enabled = param.value.lower() == 'true'
        except exception.NotFound:
            pass
        if not hpe3par_enabled:
            for i in range(2, constants.SERVICE_PARAM_MAX_HPE3PAR + 1):
                section = "{0}{1}".format(constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR, i)
                try:
                    param = self.dbapi.service_parameter_get_one(constants.SERVICE_TYPE_CINDER,
                        section,
                        constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED)
                    hpe3par_enabled = param.value.lower() == 'true'
                except exception.NotFound:
                    pass
                if hpe3par_enabled:
                    break
        try:
            param = self.dbapi.service_parameter_get_one(constants.SERVICE_TYPE_CINDER,
                constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND,
                constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED)
            hpelefthand_enabled = param.value.lower() == 'true'
        except exception.NotFound:
            hpelefthand_enabled = False

        if not (hpe3par_enabled or hpelefthand_enabled):
            return

        # Start audit

        try:
            hostname = socket.gethostname()
            active_host = \
                self.dbapi.ihost_get_by_hostname(hostname)
        except Exception as e:
            LOG.error(
                "Failed to get local host object during cinder audit: %s",
                str(e))
            return

        if (not (active_host and active_host.config_target and
                active_host.config_applied == active_host.config_target)):
            return

        #
        # The manifest has been applied on the active controller. Now, ensure
        # that the hpe services are down.
        #

        hosts = [constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR,
                 constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND]

        services = self._openstack.get_cinder_services()

        for host in hosts:
            status = self._hpe_get_state(host)
            if status.value != "disabling":
                continue

            found = False
            removed = False

            LOG.info("Running hpe cinder state audit for %s", host)

            for cinder_service in services:
                if "@" + host in cinder_service.host:
                    found = True
                    if cinder_service.state == 'down':
                        command_args = [
                            '/usr/bin/cinder-manage',
                            'service',
                            'remove',
                            'cinder-volume',
                            cinder_service.host
                        ]
                        with open(os.devnull, "w") as fnull:
                            LOG.info("Removing cinder-volume service %s" % host)
                            try:
                                subprocess.check_call(
                                    command_args, stdout=fnull, stderr=fnull)
                                removed = True
                            except subprocess.CalledProcessError as e:
                                LOG.exception(e)
                    break

                if removed or not found:
                    LOG.info("Setting %s state to disabled", host)
                    self.dbapi.service_parameter_update(status.uuid,
                                                        {"value": "disabled"})

    @periodic_task.periodic_task(spacing=CONF.conductor.audit_interval)
    def _conductor_audit(self, context):
        # periodically, perform audit of inventory
        LOG.debug("Sysinv Conductor running periodic audit task.")

        # check whether we may have just become active with target config
        self._controller_config_active_apply(context)

        # Audit upgrade status
        self._audit_upgrade_status()

        self._audit_cinder_state()

        self._hpe_audit_cinder_state()

        hosts = self.dbapi.ihost_get_list()

        # Audit install states
        self._audit_install_states(hosts)

        # Audit kubernetes node labels
        self._audit_kubernetes_labels(hosts)

        for host in hosts:
            # only audit configured hosts
            if not host.personality:
                continue
            self._audit_ihost_action(host)

    def _audit_kubernetes_labels(self, hosts):
        if (not utils.is_kubernetes_config(self.dbapi) or
                not cutils.is_initial_config_complete()):
            LOG.debug("_audit_kubernetes_labels skip")
            return

        LOG.debug("Starting kubernetes label audit")
        sysinv_labels = self.dbapi.label_get_all()
        nodes = self._kube.kube_get_nodes()

        for host in hosts:
            try:
                for node in nodes:
                    if host.hostname == node.metadata.name:
                        node_labels = node.metadata.labels
                        host_labels = [l for l in sysinv_labels if l.host_id == host.id]
                        for host_label in host_labels:
                            if host_label.label_key not in node_labels.keys():
                                LOG.info("Label audit: creating %s=%s on node %s"
                                         % (host_label.label_key,
                                            host_label.label_value, host.hostname))
                                body = {
                                    'metadata': {
                                        'labels': {host_label.label_key: host_label.label_value}
                                    }
                                }
                                self._kube.kube_patch_node(host.hostname, body)
            except Exception as e:
                LOG.warning("Failed to sync kubernetes label to host %s: %s" %
                            (host.hostname, e))

    # TODO(CephPoolsDecouple): remove
    @periodic_task.periodic_task(spacing=60)
    def _osd_pool_audit(self, context):
        if utils.is_kubernetes_config(self.dbapi):
            LOG.debug("_osd_pool_audit skip")
            return

        # Only do the audit if ceph is configured.
        if not StorageBackendConfig.has_backend(
            self.dbapi,
            constants.CINDER_BACKEND_CEPH
        ):
            return

        LOG.debug("_osd_pool_audit")

        # Only run the pool audit task if we have at least one storage node
        # available. Pools are created with initial PG num values and quotas
        # when the first OSD is added. This is done with only controller-0
        # and controller-1 forming a quorum in the cluster. Trigger the code
        # that will look to scale the PG num values and validate pool quotas
        # once a storage host becomes available.
        if self._ceph.get_ceph_cluster_info_availability():
            # periodically, perform audit of OSD pool
            LOG.debug("Sysinv Conductor running periodic OSD pool audit task.")
            self._ceph.audit_osd_pools_by_tier()

    def set_backend_to_err(self, backend):
        """Set backend state to error"""

        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(backend.uuid, values)

        # Raise alarm
        reason = "Backend %s configuration timed out." % backend.backend
        self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_SET,
                                           backend.backend,
                                           reason)

    @periodic_task.periodic_task(spacing=CONF.conductor.audit_interval)
    def _storage_backend_failure_audit(self, context):
        """Check if storage backend is stuck in 'configuring'"""

        backend_list = self.dbapi.storage_backend_get_list()
        for bk in backend_list:
            # TODO(oponcea): Update when sm supports in-service config reload.
            if (bk.state == constants.SB_STATE_CONFIGURING and
                    constants.SB_TASK_APPLY_MANIFESTS in str(bk.task)):
                if bk.backend not in self._stor_bck_op_timeouts:
                    self._stor_bck_op_timeouts[bk.backend] = int(time.time())
                else:
                    d = int(time.time()) - self._stor_bck_op_timeouts[bk.backend]
                    if d >= constants.SB_CONFIGURATION_TIMEOUT:
                        LOG.error("Storage backend %(name)s configuration "
                                  "timed out at: %(task)s. Raising alarm!" %
                                  {'name': bk.backend, 'task': bk.task})
                        self.set_backend_to_err(bk)
            elif bk.backend in self._stor_bck_op_timeouts:
                del self._stor_bck_op_timeouts[bk.backend]

    @periodic_task.periodic_task(spacing=CONF.conductor.audit_interval,
                                 run_immediately=True)
    def _k8s_application_audit(self, context):
        """Make sure that the required k8s applications are running"""

        AppTarBall = namedtuple(
            'AppTarBall',
            "tarball_name app_name app_version manifest_name manifest_file")

        def _check_tarfile(app_name):
            tarfiles = []
            for f in os.listdir(constants.HELM_APP_ISO_INSTALL_PATH):
                if fnmatch.fnmatch(f, '{}-*'.format(app_name)):
                    tarfiles.append(f)

            if not tarfiles:
                LOG.error("Failed to find an application tarball for {}.".format(app_name))
                return AppTarBall(None, None, None, None, None)
            elif len(tarfiles) > 1:
                LOG.error("Found multiple application tarballs for {}.".format(app_name))
                return AppTarBall(None, None, None, None, None)

            tarball_name = '{}/{}'.format(
                constants.HELM_APP_ISO_INSTALL_PATH, tarfiles[0])

            with kube_api.TempDirectory() as app_path:
                if not cutils.extract_tarfile(app_path, tarball_name):
                    LOG.error("Failed to extract tar file {}.".format(
                        os.path.basename(tarball_name)))
                    return AppTarBall(tarball_name, None, None, None, None)

                # If checksum file is included in the tarball, verify its contents.
                if not cutils.verify_checksum(app_path):
                    LOG.error("Checksum validation failed for %s." % app_name)
                    return AppTarBall(tarball_name, None, None, None, None)

                try:
                    name, version, patches = \
                        self._kube_app_helper._verify_metadata_file(
                            app_path, app_name, None)
                    manifest_name, manifest_file = \
                        self._kube_app_helper._find_manifest_file(app_path)
                    self._kube_app_helper._extract_helm_charts(app_path)
                except exception.SysinvException as e:
                    LOG.error("Extracting tarfile for %s failed: %s." % (
                        app_name, str(e)))
                    return AppTarBall(tarball_name, None, None, None, None)

                LOG.debug("Tar file of application %s verified." % app_name)
                return AppTarBall(tarball_name, name, version,
                                  manifest_name, manifest_file)

        def _patching_operation_is_occurring():
            # Makes sure a patching operation is not currently underway. We want
            # all hosts to be patch-current before taking any application
            # actions
            #
            # Execute this check in a function as the rest_api has info logs on
            # the request/response. Call this only when an action will occur and
            # not on in every audit cycle
            try:
                self._kube_app_helper._check_patching_operation()
                return False
            except exception.SysinvException as e:
                LOG.info("{}. Patching operations are in progress. Suspending "
                         "actions on platform managed application until patching is "
                         "completed.".format(e))
            except Exception as e:
                LOG.error("{}. Communication Error with patching subsystem. "
                          "Preventing managed application actions.".format(e))
            return True

        def _met_app_apply_prerequisites(app_name):
            prereqs_met = False
            if app_name == constants.HELM_APP_PLATFORM:
                # make sure for the ceph related apps that we have ceph access
                # and the crushmap is applied to correctly set up related k8s
                # resources.
                crushmap_flag_file = os.path.join(constants.SYSINV_CONFIG_PATH,
                    constants.CEPH_CRUSH_MAP_APPLIED)
                if (os.path.isfile(crushmap_flag_file) and
                        self._ceph.have_ceph_monitor_access()):
                    prereqs_met = True
            return prereqs_met

        LOG.debug("Periodic Task: _k8s_application_audit: Starting")
        # Make sure that the active controller is unlocked/enabled. Only
        # install an application if the controller has been provisioned.
        active_ctrl = utils.HostHelper.get_active_controller(self.dbapi)

        if (active_ctrl is None or
                ((active_ctrl.administrative != constants.ADMIN_UNLOCKED) or
                 (active_ctrl.operational != constants.OPERATIONAL_ENABLED))):
            return

        # Check the application state and take the approprate action
        for app_name in constants.HELM_APPS_PLATFORM_MANAGED:

            # Handle initial loading states
            try:
                app = kubeapp_obj.get_by_name(context, app_name)
                status = app.status
            except exception.KubeAppNotFound:
                status = constants.APP_NOT_PRESENT

            LOG.debug("Platform managed application %s: %s" % (app_name, status))
            if status == constants.APP_NOT_PRESENT:

                LOG.info("Platform managed application %s: Creating..." % app_name)
                app_data = {'name': app_name,
                            'app_version': constants.APP_VERSION_PLACEHOLDER,
                            'manifest_name': constants.APP_MANIFEST_NAME_PLACEHOLDER,
                            'manifest_file': constants.APP_TARFILE_NAME_PLACEHOLDER,
                            'status': constants.APP_UPLOAD_IN_PROGRESS}
                try:
                    self.dbapi.kube_app_create(app_data)
                    app = kubeapp_obj.get_by_name(context, app_name)
                except exception.KubeAppAlreadyExists as e:
                    LOG.exception(e)
                    continue
                except exception.KubeAppNotFound as e:
                    LOG.exception(e)
                    continue

                tarball = _check_tarfile(app_name)
                if ((tarball.manifest_name is None) or
                        (tarball.manifest_file is None)):
                    app.status = constants.APP_UPLOAD_FAILURE
                    app.save()
                    continue

                app.name = tarball.app_name
                app.app_version = tarball.app_version
                app.manifest_name = tarball.manifest_name
                app.manifest_file = os.path.basename(tarball.manifest_file)
                app.save()

                if _patching_operation_is_occurring():
                    continue

                # Action: Upload.
                # Do not block this audit task or any other periodic task. This
                # could be long running. The next audit cycle will pick up the
                # latest status.
                LOG.info("Platform managed application %s: "
                         "Uploading..." % app_name)
                greenthread.spawn(self._app.perform_app_upload, app,
                                  tarball.tarball_name)
            elif status == constants.APP_UPLOAD_IN_PROGRESS:
                # Action: do nothing
                pass
            elif status == constants.APP_UPLOAD_FAILURE:
                # Action: Raise alarm?
                pass
            elif status == constants.APP_UPLOAD_SUCCESS:
                if not _met_app_apply_prerequisites(app_name):
                    LOG.info("Platform managed application %s: Prerequisites "
                             "not met." % app_name)
                    continue

                if _patching_operation_is_occurring():
                    continue

                try:
                    app = kubeapp_obj.get_by_name(context, app_name)
                    app.status = constants.APP_APPLY_IN_PROGRESS
                except exception.KubeAppNotFound as e:
                    LOG.exception(e)
                    continue

                # Action: Apply the application
                # Do not block this audit task or any other periodic task. This
                # could be long running. The next audit cycle will pick up the
                # latest status.
                LOG.info("Platform managed application %s: "
                         "Applying..." % app_name)
                greenthread.spawn(self._app.perform_app_apply, app, None)
                pass
            elif status == constants.APP_APPLY_IN_PROGRESS:
                # Action: do nothing
                pass
            elif status == constants.APP_APPLY_FAILURE:
                # Action: Raise alarm?
                pass
            elif status == constants.APP_APPLY_SUCCESS:
                # Action: do nothing -> done

                # TODO(rchurch): Check to see if an existing application needs
                # upgrading. Wait for the proper application versioning
                # support to the determine proper action.

                pass

        LOG.debug("Periodic Task: _k8s_application_audit: Finished")

    def get_k8s_namespaces(self, context):
        """ Get Kubernetes namespaces
        :returns: list of namespaces
        """
        try:
            cmd = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf',
                   'get', 'namespaces', '-o',
                   'go-template=\'{{range .items}}{{.metadata.name}}\'{{end}}\'']
            stdout, stderr = cutils.execute(*cmd, run_as_root=False)
            namespaces = [n for n in stdout.split("\'") if n]
            return namespaces
        except exception.ProcessExecutionError as e:
            raise exception.SysinvException(
                _("Error getting Kubernetes list of namespaces, "
                  "Details: %s") % str(e))

    def configure_isystemname(self, context, systemname):
        """Configure the systemname with the supplied data.

        :param context: an admin context.
        :param systemname: the systemname
        """

        LOG.debug("configure_isystemname: sending systemname to agent(s)")
        rpcapi = agent_rpcapi.AgentAPI()
        rpcapi.configure_isystemname(context, systemname=systemname)

        return

    def get_ceph_primary_tier_size(self, context):
        """Get the usage information for the primary ceph tier."""

        if not StorageBackendConfig.has_backend_configured(
                self.dbapi,
                constants.CINDER_BACKEND_CEPH):
            return 0

        if not self._ceph.get_ceph_cluster_info_availability():
            return 0

        return int(self._ceph.get_ceph_primary_tier_size())

    def get_ceph_tier_size(self, context, tier_name):
        """Get the usage information for a specific ceph tier."""

        if not StorageBackendConfig.has_backend_configured(
                self.dbapi,
                constants.CINDER_BACKEND_CEPH):
            return 0

        if not self._ceph.get_ceph_cluster_info_availability():
            return 0

        tiers_dict = self._ceph.get_ceph_tiers_size()
        tier_root = tier_name + constants.CEPH_CRUSH_TIER_SUFFIX
        return tiers_dict.get(tier_root, 0)

    def get_ceph_pools_df_stats(self, context):
        """Get the usage information for the ceph pools."""
        if not StorageBackendConfig.has_backend_configured(
                self.dbapi,
                constants.CINDER_BACKEND_CEPH):
            return

        if not self._ceph.get_ceph_cluster_info_availability():
            return

        return self._ceph.get_pools_df_stats()

    def get_ceph_cluster_df_stats(self, context):
        """Get the usage information for the ceph pools."""
        if not StorageBackendConfig.has_backend_configured(
               self.dbapi,
               constants.CINDER_BACKEND_CEPH):
            return

        if not self._ceph.get_ceph_cluster_info_availability():
            return

        return self._ceph.get_cluster_df_stats()

    def get_cinder_lvm_usage(self, context):
        """Get the usage information for the LVM pools."""

        if StorageBackendConfig.has_backend_configured(
                self.dbapi, constants.SB_TYPE_LVM):
            pools = self._openstack.get_cinder_pools()
            for pool in pools:
                if (getattr(pool, 'volume_backend_name', '') ==
                        constants.CINDER_BACKEND_LVM):
                    return pool.to_dict()

        return None

    def get_cinder_volume_type_names(self, context):
        """Get the names of all currently defined cinder volume types."""

        volume_types_list = self._openstack.get_cinder_volume_types()
        return [t.name for t in volume_types_list]

    def _ipv_replace_disk(self, pv_id):
        """Handle replacement of the disk this physical volume is attached to.
        """
        # Not sure yet what the proper response is here
        pass

    def restore_ceph_config(self, context, after_storage_enabled=False):
        """Restore Ceph configuration during Backup and Restore process.

        :param context: request context.
        :returns: return True if restore is successful or no need to restore
        """
        return self._ceph.restore_ceph_config(
            after_storage_enabled=after_storage_enabled)

    def get_ceph_pool_replication(self, context, ceph_backend=None):
        """Get ceph storage backend pool replication parameters

        :param context: request context.
        :param ceph_backend: ceph backend object type
        :returns: tuple with (replication, min_replication)
        """
        return StorageBackendConfig.get_ceph_pool_replication(self.dbapi, ceph_backend)

    def delete_osd_pool(self, context, pool_name):
        """delete an OSD pool

        :param context: request context
        :parm pool_name: pool to delete
        """

        response = self._ceph.delete_osd_pool(pool_name)

        return response

    def list_osd_pools(self, context):
        """list all OSD pools

        :param context: request context
        :returns: a list of ceph pools
        """

        response = self._ceph.list_osd_pools()

        return response

    def get_osd_pool_quota(self, context, pool_name):
        """Get the quota for an OSD pool"""

        response = self._ceph.osd_get_pool_quota(pool_name)

        return response

    def set_osd_pool_quota(self, context, pool, max_bytes, max_objects):
        """Set the quota for an OSD pool

           Setting max_bytes or max_objects to 0 will disable that quota param
        """

        self._ceph.set_osd_pool_quota(pool, max_bytes, max_objects)

    def unconfigure_osd_istor(self, context, istor_obj):
        """Synchronously, have a conductor unconfigure an OSD istor.

        Does the following tasks:
        - Removes the OSD from the crush map.
        - Deletes the OSD's auth key.
        - Deletes the OSD.

        :param context: request context.
        :param istor_obj: an istor object.
        """

        if istor_obj['osdid'] is None:
            LOG.info("OSD not assigned - nothing to do")
            return

        LOG.info("About to delete OSD with osdid:%s", str(istor_obj['osdid']))

        # Mark the OSD down in case it is still up
        self._ceph.mark_osd_down(istor_obj['osdid'])

        # Remove the OSD from the crush map
        self._ceph.osd_remove_crush_auth(istor_obj['osdid'])

        # Remove the OSD
        response, body = self._ceph_osd_remove(
            istor_obj['osdid'], body='json')
        if not response.ok:
            LOG.error("OSD remove failed for OSD %s: %s",
                      "osd." + str(istor_obj['osdid']), response.reason)
            response.raise_for_status()

    # @staticmethod can't be used with @retry decorator below because
    # it raises a "'staticmethod' object is not callable" exception
    def _osd_must_be_down(result):
        response, body = result
        if not response.ok:
            LOG.error("OSD remove failed: {}".format(body))
        if (response.status_code == httplib.BAD_REQUEST and
            isinstance(body, dict) and
            body.get('status', '').endswith(
                    "({})".format(-errno.EBUSY))):
            LOG.info("Retry OSD remove")
            return True
        else:
            return False

    @retry(retry_on_result=_osd_must_be_down,
           stop_max_attempt_number=CONF.conductor.osd_remove_retry_count,
           wait_fixed=(CONF.conductor.osd_remove_retry_interval * 1000))
    def _ceph_osd_remove(self, *args, **kwargs):
        return self._ceph.osd_remove(*args, **kwargs)

    def kill_ceph_storage_monitor(self, context):
        """Stop the ceph storage monitor.
        pmon will not restart it. This should only be used in an
        upgrade/rollback

        :param context: request context.
        """
        try:
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(["mv", "/etc/pmon.d/ceph.conf",
                                      "/etc/pmond.ceph.conf.bak"],
                                      stdout=fnull, stderr=fnull)

                subprocess.check_call(["systemctl", "restart", "pmon"],
                                      stdout=fnull, stderr=fnull)

                subprocess.check_call(["/etc/init.d/ceph", "stop", "mon"],
                                      stdout=fnull, stderr=fnull)

                subprocess.check_call(["mv", "/etc/services.d/controller/ceph.sh",
                                       "/etc/services.d.controller.ceph.sh"],
                                      stdout=fnull, stderr=fnull)
        except subprocess.CalledProcessError as e:
            LOG.exception(e)
            raise exception.SysinvException(
                _("Unable to shut down ceph storage monitor."))

    def update_dns_config(self, context):
        """Update the DNS configuration"""
        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)
        self._update_resolv_file(context, config_uuid, personalities)

    def update_ntp_config(self, context, service_change=False):
        """Update the NTP configuration"""
        if service_change:
            personalities = [constants.CONTROLLER,
                             constants.WORKER,
                             constants.STORAGE]
        else:
            personalities = [constants.CONTROLLER]
        self._config_update_hosts(context, personalities, reboot=True)

    def update_ptp_config(self, context):
        """Update the PTP configuration"""
        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        self._config_update_hosts(context, personalities)

    def update_system_mode_config(self, context):
        """Update the system mode configuration"""
        personalities = [constants.CONTROLLER]
        self._config_update_hosts(context, personalities, reboot=True)

    def configure_system_timezone(self, context):
        """Configure the system_timezone with the supplied data.

        :param context: an admin context.
        """

        # update manifest files and notify agents to apply timezone files
        personalities = [constants.WORKER,
                         constants.STORAGE]
        config_uuid = self._config_update_hosts(context, personalities)

        # NOTE: no specific classes need to be specified since the default
        # platform::config will be applied that will configure the timezone
        config_dict = {"personalities": personalities}

        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        # for controller nodes, we also update the horizon interface
        # so that it can see the new timezone setting
        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            "personalities": personalities,
            "classes": ['openstack::horizon::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_route_config(self, context):
        """add or remove a static route

        :param context: an admin context.
        """

        # update manifest files and notifiy agents to apply them
        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": 'platform::network::runtime'
        }

        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_sriov_config(self, context, host_uuid):
        """update sriov configuration for a host

        :param context: an admin context
        :param host_uuid: the host uuid
        """

        # update manifest files and notify agent to apply them
        personalities = [constants.CONTROLLER,
                         constants.WORKER]
        config_uuid = self._config_update_hosts(context, personalities,
                                                host_uuids=[host_uuid])

        config_dict = {
            "personalities": personalities,
            'host_uuids': host_uuid,
            "classes": 'platform::network::runtime',
            puppet_common.REPORT_INVENTORY_UPDATE:
                puppet_common.REPORT_PCI_SRIOV_CONFIG,
        }

        self._config_apply_runtime_manifest(
            context, config_uuid, config_dict, force=True)

    def configure_system_https(self, context):
        """Update the system https configuration.

        :param context: an admin context.
        """
        personalities = [constants.CONTROLLER]
        system = self.dbapi.isystem_get_one()

        if system.capabilities.get('https_enabled', False):
            self._config_selfsigned_certificate(context)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::haproxy::runtime',
                        'openstack::keystone::endpoint::runtime',
                        'openstack::horizon::runtime',
                        'platform::firewall::runtime']
        }

        config_uuid = self._config_update_hosts(context, personalities)
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        if not system.capabilities.get('https_enabled', False):
            self._destroy_tpm_config(context)
            self._destroy_certificates(context)

    def update_oam_config(self, context):
        """Update the OAM network configuration"""

        self._config_update_hosts(context, [constants.CONTROLLER], reboot=True)

        config_uuid = self._config_update_hosts(context, [constants.WORKER],
                                                reboot=False)

        extoam = self.dbapi.iextoam_get_one()

        self._update_hosts_file('oamcontroller', extoam.oam_floating_ip,
                                active=False)

        # make changes to the workers
        config_dict = {
            "personalities": [constants.WORKER],
            "classes": ['openstack::nova::compute::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_user_config(self, context):
        """Update the user configuration"""
        LOG.info("update_user_config")

        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::users::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_storage_config(self, context,
                              update_storage=False,
                              reinstall_required=False,
                              reboot_required=True,
                              filesystem_list=None):

        """Update the storage configuration"""
        if update_storage:
            personalities = [constants.CONTROLLER, constants.STORAGE]
        else:
            personalities = [constants.CONTROLLER]

        if reinstall_required:
            self._config_reinstall_hosts(context, personalities)
        else:
            config_uuid = self._config_update_hosts(context,
                                                    personalities,
                                                    reboot=reboot_required)

            if not reboot_required and filesystem_list:
                # apply the manifest at runtime, otherwise a reboot is required
                if os.path.isfile(CONFIG_CONTROLLER_FINI_FLAG):
                    os.remove(CONFIG_CONTROLLER_FINI_FLAG)

                if os.path.isfile(CFS_DRBDADM_RECONFIGURED):
                    os.remove(CFS_DRBDADM_RECONFIGURED)

                # map the updated file system to the runtime puppet class
                classmap = {
                    constants.FILESYSTEM_NAME_BACKUP:
                        'platform::filesystem::backup::runtime',
                    constants.FILESYSTEM_NAME_SCRATCH:
                        'platform::filesystem::scratch::runtime',
                    constants.FILESYSTEM_NAME_DOCKER:
                        'platform::filesystem::docker::runtime',
                    constants.FILESYSTEM_NAME_DOCKER_DISTRIBUTION:
                        'platform::drbd::dockerdistribution::runtime',
                    constants.FILESYSTEM_NAME_DATABASE:
                        'platform::drbd::pgsql::runtime',
                    constants.FILESYSTEM_NAME_CGCS:
                        'platform::drbd::cgcs::runtime',
                    constants.FILESYSTEM_NAME_EXTENSION:
                        'platform::drbd::extension::runtime',
                    constants.FILESYSTEM_NAME_PATCH_VAULT:
                        'platform::drbd::patch_vault::runtime',
                    constants.FILESYSTEM_NAME_ETCD:
                        'platform::drbd::etcd::runtime',
                }

                puppet_class = None
                if filesystem_list:
                    puppet_class = [classmap.get(fs) for fs in filesystem_list]
                config_dict = {
                    "personalities": personalities,
                    "classes": puppet_class
                }

                LOG.info("update_storage_config: %s" % config_dict)

                self._config_apply_runtime_manifest(context,
                                                    config_uuid,
                                                    config_dict)

    def update_lvm_config(self, context):
        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::lvm::controller::runtime']
        }

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def update_drbd_config(self, context):
        """Update the drbd configuration"""
        LOG.info("update_drbd_config")

        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::drbd::runtime',
                        'openstack::cinder::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_external_cinder_config(self, context):
        """Update the manifests for Cinder External(shared) backend"""
        personalities = [constants.CONTROLLER]

        # Retrieve cinder endpoints from primary region
        endpoint_list = self._openstack._get_cinder_endpoints()

        # Update service table
        self.update_service_table_for_cinder(endpoint_list, external=True)

        classes = ['openstack::cinder::endpoint::runtime']

        config_dict = {
            "personalities": personalities,
            "classes": classes,
            puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_EXTERNAL_BACKEND_CONFIG,
        }

        config_uuid = self._config_update_hosts(context,
                                                personalities,
                                                reboot=False)

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def update_lvm_cinder_config(self, context):
        """Update the manifests and network config for Cinder LVM backend"""
        personalities = [constants.CONTROLLER]

        # Get active hosts
        # TODO (rchurch): ensure all applicable unlocked hosts have the
        # _config_update_hosts() updated.
        ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        valid_ctrls = [ctrl for ctrl in ctrls if
                       (ctrl.administrative == constants.ADMIN_LOCKED and
                        ctrl.availability == constants.AVAILABILITY_ONLINE) or
                       (ctrl.administrative == constants.ADMIN_UNLOCKED and
                        ctrl.operational == constants.OPERATIONAL_ENABLED)]

        # Create Cinder MGMT ip address, if needed
        self.reserve_ip_for_cinder(context)

        # Update service table
        self.update_service_table_for_cinder()

        classes = ['platform::partitions::runtime',
                   'platform::lvm::controller::runtime',
                   'platform::haproxy::runtime',
                   'platform::drbd::runtime',
                   'openstack::cinder::runtime',
                   'platform::sm::norestart::runtime']

        config_dict = {
            "personalities": personalities,
            "classes": classes,
            "host_uuids": [ctrl.uuid for ctrl in valid_ctrls],
            puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_LVM_BACKEND_CONFIG
        }

        # TODO(oponcea) once sm supports in-service config reload always
        # set reboot=False
        active_controller = utils.HostHelper.get_active_controller(self.dbapi)
        if utils.is_host_simplex_controller(active_controller):
            reboot = False
        else:
            reboot = True

        # Set config out-of-date for controllers
        self._config_update_hosts(context, personalities, reboot=reboot)

        # TODO(oponcea): Set config_uuid to a random value to keep Config out-of-date.
        # Once sm supports in-service config reload set config_uuid=config_uuid.
        self._config_apply_runtime_manifest(context,
                                            str(uuid.uuid4()),
                                            config_dict)

        # Update initial task states
        storage_backends = self.dbapi.storage_backend_get_list()
        for sb in storage_backends:
            if sb.backend == constants.SB_TYPE_LVM:
                tasks = {}
                for ctrl in valid_ctrls:
                    tasks[ctrl.hostname] = constants.SB_STATE_CONFIGURING
                values = {'state': constants.SB_STATE_CONFIGURING,
                          'task': str(tasks)}
                self.dbapi.storage_backend_update(sb.uuid, values)

    def update_service_table_for_cinder(self, endpoints=None, external=False):
        """ Update service table for region name """
        system = self.dbapi.isystem_get_one()
        if system and system.capabilities.get('region_config'):
            cinder_service = self.dbapi.service_get(constants.SERVICE_TYPE_CINDER)
            capabilities = {'service_name': constants.SERVICE_TYPE_CINDER,
                            'service_type': constants.SERVICE_TYPE_VOLUME,
                            'user_name': constants.SERVICE_TYPE_CINDER}
            if endpoints:
                for ep in endpoints:
                    if ep.url.find('/v1/') != -1:
                        if ep.interface == constants.OS_INTERFACE_PUBLIC:
                            capabilities.update({'cinder_public_uri_v1': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_INTERNAL:
                            capabilities.update({'cinder_internal_uri_v1': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_ADMIN:
                            capabilities.update({'cinder_admin_uri_v1': ep.url})
                    elif ep.url.find('/v2/') != -1:
                        if ep.interface == constants.OS_INTERFACE_PUBLIC:
                            capabilities.update({'cinder_public_uri_v2': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_INTERNAL:
                            capabilities.update({'cinder_internal_uri_v2': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_ADMIN:
                            capabilities.update({'cinder_admin_uri_v2': ep.url})
                    elif ep.url.find('/v3/') != -1:
                        if ep.interface == constants.OS_INTERFACE_PUBLIC:
                            capabilities.update({'cinder_public_uri_v3': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_INTERNAL:
                            capabilities.update({'cinder_internal_uri_v3': ep.url})
                        elif ep.interface == constants.OS_INTERFACE_ADMIN:
                            capabilities.update({'cinder_admin_uri_v3': ep.url})

            if external:
                region_name = openstack.get_region_name('region_1_name')
                if region_name is None:
                    region_name = constants.REGION_ONE_NAME
            else:
                region_name = system.region_name

            values = {'enabled': True,
                      'region_name': region_name,
                      'capabilities': capabilities}
            self.dbapi.service_update(cinder_service.name, values)

    def update_install_uuid(self, context, host_uuid, install_uuid):
        """ Update install_uuid on the specified host """

        LOG.info("update_install_uuid host_uuid=%s install_uuid=%s "
                 % (host_uuid, install_uuid))
        rpcapi = agent_rpcapi.AgentAPI()
        rpcapi.iconfig_update_install_uuid(context, host_uuid, install_uuid)

    def update_ceph_config(self, context, sb_uuid, services):
        """Update the manifests for Ceph backend and services"""

        personalities = [constants.CONTROLLER]

        # Update service table
        self.update_service_table_for_cinder()

        ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        valid_ctrls = [ctrl for ctrl in ctrls if
                       ctrl.administrative == constants.ADMIN_UNLOCKED and
                       ctrl.availability == constants.AVAILABILITY_AVAILABLE]
        classes = ['platform::partitions::runtime',
                   'platform::lvm::controller::runtime',
                   'platform::haproxy::runtime',
                   'openstack::keystone::endpoint::runtime',
                   'platform::ceph::runtime_base',
                   ]

        if utils.is_aio_duplex_system(self.dbapi):
            # On 2 node systems we have a floating Ceph monitor.
            classes.append('platform::drbd::cephmon::runtime')
            classes.append('platform::drbd::runtime')

        if constants.SB_SVC_GLANCE in services:
            classes.append('openstack::glance::api::runtime')
        if constants.SB_SVC_CINDER in services:
            classes.append('openstack::cinder::runtime')
        classes.append('platform::sm::norestart::runtime')
        config_dict = {"personalities": personalities,
                       # "host_uuids": host.uuid,
                       "host_uuids": [ctrl.uuid for ctrl in valid_ctrls],
                       "classes": classes,
                       puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_CEPH_BACKEND_CONFIG,
                       }

        # TODO(oponcea) once sm supports in-service config reload always
        # set reboot=False
        active_controller = utils.HostHelper.get_active_controller(self.dbapi)
        if utils.is_host_simplex_controller(active_controller):
            reboot = False
        else:
            reboot = True

        # Set config out-of-date for controllers
        config_uuid = self._config_update_hosts(context,
                                                personalities,
                                                reboot=reboot)

        # TODO(oponcea): Set config_uuid to a random value to keep Config out-of-date.
        # Once sm supports in-service config reload, allways set config_uuid=config_uuid
        # in _config_apply_runtime_manifest and remove code bellow.
        active_controller = utils.HostHelper.get_active_controller(self.dbapi)
        if utils.is_host_simplex_controller(active_controller):
            new_uuid = config_uuid
        else:
            new_uuid = str(uuid.uuid4())

        self._config_apply_runtime_manifest(context,
                                            config_uuid=new_uuid,
                                            config_dict=config_dict)

        tasks = {}
        for ctrl in valid_ctrls:
            tasks[ctrl.hostname] = constants.SB_TASK_APPLY_MANIFESTS

        # Update initial task states
        values = {'state': constants.SB_STATE_CONFIGURING,
                  'task': str(tasks)}
        self.dbapi.storage_ceph_update(sb_uuid, values)

    def update_ceph_base_config(self, context, personalities):
        """ Update Ceph configuration, monitors and ceph.conf only"""
        config_uuid = self._config_update_hosts(context, personalities)

        valid_nodes = []
        for personality in personalities:
            nodes = self.dbapi.ihost_get_by_personality(personality)
            valid_nodes += [
                node for node in nodes if
                (node.administrative == constants.ADMIN_UNLOCKED and
                 node.operational == constants.OPERATIONAL_ENABLED)]

        config_dict = {
            "personalities": personalities,
            "host_uuids": [node.uuid for node in valid_nodes],
            "classes": ['platform::ceph::runtime_base'],
            puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_CEPH_MONITOR_CONFIG
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_ceph_osd_config(self, context, host, stor_uuid, runtime_manifests=True):
        """ Update Ceph OSD configuration at runtime"""
        personalities = [host.personality]
        config_uuid = self._config_update_hosts(context, personalities, [host.uuid],
                                                reboot=not runtime_manifests)

        if runtime_manifests:
            # Make sure that we have the correct CRUSH map before applying
            # the manifests.
            cceph.fix_crushmap(self.dbapi)

            config_dict = {
                "personalities": host.personality,
                "host_uuids": host.uuid,
                "stor_uuid": stor_uuid,
                "classes": ['platform::ceph::runtime_osds'],
                puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_CEPH_OSD_CONFIG
            }
            self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def config_update_nova_local_backed_hosts(self, context, instance_backing):
        hosts_uuid = self.hosts_with_nova_local(instance_backing)
        if hosts_uuid:
            personalities = [constants.CONTROLLER, constants.WORKER]
            self._config_update_hosts(context,
                                      personalities,
                                      host_uuids=hosts_uuid,
                                      reboot=True)

    def hosts_with_nova_local(self, backing_type):
        """Returns a list of hosts with certain backing type of nova_local"""
        hosts_uuid = []
        hosts = self.dbapi.ihost_get_list()
        for host in hosts:
            if ((host.personality and host.personality == constants.WORKER) or
                    (host.subfunctions and constants.WORKER in host.subfunctions)):
                ilvgs = self.dbapi.ilvg_get_by_ihost(host['uuid'])
                for lvg in ilvgs:
                    if (lvg['lvm_vg_name'] == constants.LVG_NOVA_LOCAL and
                          lvg['capabilities'].get(constants.LVG_NOVA_PARAM_BACKING) ==
                          backing_type):
                        hosts_uuid.append(host['uuid'])
        return hosts_uuid

    def update_ceph_external_config(self, context, sb_uuid, services):
        """Update the manifests for Cinder/Glance External Ceph backend"""

        if (constants.SB_SVC_CINDER in services or
                constants.SB_SVC_GLANCE in services):
            personalities = [constants.CONTROLLER]

            # Update service table
            self.update_service_table_for_cinder()

            ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
            valid_ctrls = [ctrl for ctrl in ctrls if
                           (ctrl.administrative == constants.ADMIN_LOCKED and
                            ctrl.availability == constants.AVAILABILITY_ONLINE) or
                           (ctrl.administrative == constants.ADMIN_UNLOCKED and
                            ctrl.operational == constants.OPERATIONAL_ENABLED)]

            classes = ['platform::partitions::runtime',
                       'platform::lvm::controller::runtime',
                       'platform::haproxy::runtime',
                       'openstack::keystone::endpoint::runtime',
                       ]

            if constants.SB_SVC_GLANCE in services:
                classes.append('openstack::glance::api::runtime')
            if constants.SB_SVC_CINDER in services:
                classes.append('openstack::cinder::runtime')
            classes.append('platform::sm::norestart::runtime')

            report_config = puppet_common.REPORT_CEPH_EXTERNAL_BACKEND_CONFIG

            config_dict = {"personalities": personalities,
                           "host_uuids": [ctrl.uuid for ctrl in valid_ctrls],
                           "classes": classes,
                           puppet_common.REPORT_STATUS_CFG: report_config, }

            # TODO(oponcea) once sm supports in-service config reload always
            # set reboot=False
            active_controller = utils.HostHelper.get_active_controller(self.dbapi)
            if utils.is_host_simplex_controller(active_controller):
                reboot = False
            else:
                if constants.SB_SVC_CINDER in services:
                    # If it is the first time to start cinder service and it
                    # is not a simplex configuration, then set reboot to false
                    if StorageBackendConfig.is_service_enabled(
                            self.dbapi,
                            constants.SB_SVC_CINDER,
                            filter_unconfigured=True,
                            filter_shared=True):
                        reboot = False
                    else:
                        reboot = True
                else:
                    reboot = False

            # Set config out-of-date for controllers
            config_uuid = self._config_update_hosts(context,
                                                    personalities,
                                                    reboot=reboot)

            tasks = {}
            for ctrl in valid_ctrls:
                tasks[ctrl.hostname] = constants.SB_TASK_APPLY_MANIFESTS

            # Update initial task states
            values = {'state': constants.SB_STATE_CONFIGURING,
                      'task': str(tasks)}

            self.dbapi.storage_ceph_external_update(sb_uuid, values)

            # TODO(oponcea): Set config_uuid to a random value to keep Config out-of-date.
            # Once sm supports in-service config reload, allways set config_uuid=config_uuid
            # in _config_apply_runtime_manifest and remove code bellow.
            if reboot:
                new_uuid = str(uuid.uuid4())
            else:
                new_uuid = config_uuid

            self._config_apply_runtime_manifest(context,
                                                config_uuid=new_uuid,
                                                config_dict=config_dict)
        else:
            values = {'state': constants.SB_STATE_CONFIGURED,
                      'task': None}
            self.dbapi.storage_ceph_external_update(sb_uuid, values)

        if constants.SB_SVC_NOVA in services:
            self.config_update_nova_local_backed_hosts(
                context, constants.LVG_NOVA_BACKING_REMOTE)

    def _update_storage_backend_alarm(self, alarm_state, backend, reason_text=None):
        """ Update storage backend configuration alarm"""
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_STORAGE_BACKEND,
                                        backend)
        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_STORAGE_BACKEND_FAILED,
            alarm_state=alarm_state,
            entity_type_id=fm_constants.FM_ENTITY_TYPE_STORAGE_BACKEND,
            entity_instance_id=entity_instance_id,
            severity=fm_constants.FM_ALARM_SEVERITY_CRITICAL,
            reason_text=reason_text,
            alarm_type=fm_constants.FM_ALARM_TYPE_4,
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_7,
            proposed_repair_action=_("Update storage backend configuration to retry. "
                                     "Consult the System Administration Manual "
                                     "for more details. If problem persists, "
                                     "contact next level of support."),
            service_affecting=True)
        if alarm_state == fm_constants.FM_ALARM_STATE_SET:
            self.fm_api.set_fault(fault)
        else:
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_STORAGE_BACKEND_FAILED,
                                    entity_instance_id)

    def report_config_status(self, context, iconfig, status, error=None):
        """ Callback from Sysinv Agent on manifest apply success or failure

        Finalize configuration after manifest apply successfully or perform
        cleanup, log errors and raise alarms in case of failure.

        :param context: request context
        :param iconfig: configuration context
        :param status: operation status
        :param error: err content as a dict of type:
                error = {
                        'class': str(ex.__class__.__name__),
                        'module': str(ex.__class__.__module__),
                        'message': six.text_type(ex),
                        'tb': traceback.format_exception(*ex),
                        'args': ex.args,
                        'kwargs': ex.kwargs
                        }

        The iconfig context is expected to contain a valid REPORT_STATUS_CFG
        key, so that we can correctly identify the set of pupet clasees executed.
        """
        reported_cfg = iconfig.get(puppet_common.REPORT_STATUS_CFG)
        if not reported_cfg:
            LOG.error("Function report_config_status was called without"
                      " a reported configuration! iconfig: %s" % iconfig)
            return

        # Identify the executed set of manifests executed
        if reported_cfg == puppet_common.REPORT_DISK_PARTITON_CONFIG:
            partition_uuid = iconfig['partition_uuid']
            host_uuid = iconfig['host_uuid']
            idisk_uuid = iconfig['idisk_uuid']
            if status == puppet_common.REPORT_SUCCESS:
                # Configuration was successful
                self.report_partition_mgmt_success(host_uuid, idisk_uuid,
                                                   partition_uuid)
            elif status == puppet_common.REPORT_FAILURE:
                # Configuration has failed
                self.report_partition_mgmt_failure(host_uuid, idisk_uuid,
                                                   partition_uuid, error)
        elif reported_cfg == puppet_common.REPORT_LVM_BACKEND_CONFIG:
            host_uuid = iconfig['host_uuid']
            if status == puppet_common.REPORT_SUCCESS:
                # Configuration was successful
                self.report_lvm_cinder_config_success(context, host_uuid)
            elif status == puppet_common.REPORT_FAILURE:
                # Configuration has failed
                self.report_lvm_cinder_config_failure(host_uuid, error)
            else:
                args = {'cfg': reported_cfg, 'status': status, 'iconfig': iconfig}
                LOG.error("No match for sysinv-agent manifest application reported! "
                          "reported_cfg: %(cfg)s status: %(status)s "
                          "iconfig: %(iconfig)s" % args)
        elif reported_cfg == puppet_common.REPORT_CEPH_BACKEND_CONFIG:
            host_uuid = iconfig['host_uuid']
            if status == puppet_common.REPORT_SUCCESS:
                # Configuration was successful
                self.report_ceph_config_success(context, host_uuid)
            elif status == puppet_common.REPORT_FAILURE:
                # Configuration has failed
                self.report_ceph_config_failure(host_uuid, error)
            else:
                args = {'cfg': reported_cfg, 'status': status, 'iconfig': iconfig}
                LOG.error("No match for sysinv-agent manifest application reported! "
                          "reported_cfg: %(cfg)s status: %(status)s "
                          "iconfig: %(iconfig)s" % args)
        elif reported_cfg == puppet_common.REPORT_CEPH_EXTERNAL_BACKEND_CONFIG:
            host_uuid = iconfig['host_uuid']
            if status == puppet_common.REPORT_SUCCESS:
                # Configuration was successful
                self.report_ceph_external_config_success(context, host_uuid)
            elif status == puppet_common.REPORT_FAILURE:
                # Configuration has failed
                self.report_ceph_external_config_failure(host_uuid, error)
            else:
                args = {'cfg': reported_cfg, 'status': status, 'iconfig': iconfig}
                LOG.error("No match for sysinv-agent manifest application reported! "
                          "reported_cfg: %(cfg)s status: %(status)s "
                          "iconfig: %(iconfig)s" % args)
        elif reported_cfg == puppet_common.REPORT_EXTERNAL_BACKEND_CONFIG:
            host_uuid = iconfig['host_uuid']
            if status == puppet_common.REPORT_SUCCESS:
                # Configuration was successful
                self.report_external_config_success(host_uuid)
            elif status == puppet_common.REPORT_FAILURE:
                # Configuration has failed
                self.report_external_config_failure(host_uuid, error)
            else:
                args = {'cfg': reported_cfg, 'status': status, 'iconfig': iconfig}
                LOG.error("No match for sysinv-agent manifest application reported! "
                          "reported_cfg: %(cfg)s status: %(status)s "
                          "iconfig: %(iconfig)s" % args)
        elif reported_cfg == puppet_common.REPORT_CEPH_SERVICES_CONFIG:
            host_uuid = iconfig['host_uuid']
            if status == puppet_common.REPORT_SUCCESS:
                # Configuration was successful
                self.report_ceph_services_config_success(host_uuid)
            elif status == puppet_common.REPORT_FAILURE:
                # Configuration has failed
                self.report_ceph_services_config_failure(host_uuid, error)
            else:
                args = {'cfg': reported_cfg, 'status': status, 'iconfig': iconfig}
                LOG.error("No match for sysinv-agent manifest application reported! "
                          "reported_cfg: %(cfg)s status: %(status)s "
                          "iconfig: %(iconfig)s" % args)
        elif reported_cfg == puppet_common.REPORT_CEPH_MONITOR_CONFIG:
            host_uuid = iconfig['host_uuid']
            if status == puppet_common.REPORT_SUCCESS:
                # Configuration was successful
                self.report_ceph_base_config_success(host_uuid)
            elif status == puppet_common.REPORT_FAILURE:
                # Configuration has failed
                self.report_ceph_base_config_failure(host_uuid, error)
            else:
                args = {'cfg': reported_cfg, 'status': status, 'iconfig': iconfig}
                LOG.error("No match for sysinv-agent manifest application reported! "
                          "reported_cfg: %(cfg)s status: %(status)s "
                          "iconfig: %(iconfig)s" % args)
        elif reported_cfg == puppet_common.REPORT_CEPH_OSD_CONFIG:
            host_uuid = iconfig['host_uuid']
            stor_uuid = iconfig['stor_uuid']
            if status == puppet_common.REPORT_SUCCESS:
                # Configuration was successful
                self.report_ceph_osd_config_success(host_uuid, stor_uuid)
            elif status == puppet_common.REPORT_FAILURE:
                # Configuration has failed
                self.report_ceph_osd_config_failure(host_uuid, stor_uuid, error)
            else:
                args = {'cfg': reported_cfg, 'status': status, 'iconfig': iconfig}
                LOG.error("No match for sysinv-agent manifest application reported! "
                          "reported_cfg: %(cfg)s status: %(status)s "
                          "iconfig: %(iconfig)s" % args)
        else:
            LOG.error("Reported configuration '%(cfg)s' is not handled by"
                      " report_config_status! iconfig: %(iconfig)s" %
                      {'iconfig': iconfig, 'cfg': reported_cfg})

    def report_partition_mgmt_success(self, host_uuid, idisk_uuid,
                                      partition_uuid):
        """ Disk partition management success callback for Sysinv Agent

        Finalize the successful operation performed on a host disk partition.
        The Agent calls this if manifests are applied correctly.
        """
        try:
            partition = self.dbapi.partition_get(partition_uuid)
        except exception.DiskPartitionNotFound:
            # A parition was succesfully deleted by the manifest
            LOG.info("PART manifest application for partition %s on host %s"
                     "was successful" % (partition_uuid, host_uuid))
            return

        # A partition was successfully created or modified...
        states = [constants.PARTITION_CREATE_IN_SVC_STATUS,
                  constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
                  constants.PARTITION_DELETING_STATUS,
                  constants.PARTITION_MODIFYING_STATUS]

        if partition.status not in states:
            LOG.info("PART manifest application for partition %s on host %s "
                     "was successful" % (partition_uuid, host_uuid))
        else:
            LOG.warning("PART manifest application for partition %s on host "
                        "%s was successful, but the partition remained in a "
                        "transitional state." % (partition_uuid, host_uuid))
            updates = {'status': constants.PARTITION_ERROR_STATUS}
            self.dbapi.partition_update(partition.uuid, updates)

    def report_partition_mgmt_failure(self, host_uuid, idisk_uuid,
                                      partition_uuid, error):
        """ Disk partition management failure callback for Sysinv Agent

        Finalize the failed operation performed on a host disk partition.
        The Agent calls this if manifests are applied correctly.
        """
        LOG.info("PART manifest application for partition %s on host %s "
                 "failed" % (partition_uuid, host_uuid))

        partition = self.dbapi.partition_get(partition_uuid)

        if partition.status < constants.PARTITION_ERROR_STATUS:
            updates = {'status': constants.PARTITION_ERROR_STATUS_INTERNAL}
            self.dbapi.partition_update(partition.uuid, updates)

        reason = jsonutils.loads(str(error)).get('message', "")
        LOG.error("Error handling partition on disk %(idisk_uuid)s, host "
                  "%(host_uuid)s: %(reason)s." %
                  {'idisk_uuid': idisk_uuid, 'host_uuid': host_uuid,
                   'reason': reason})

    def update_partition_information(self, context, partition_data):
        """ Synchronously, have the conductor update partition information.

        Partition information as changed on a given host. Update the inventory
        database with the new partition information provided.
        """
        LOG.info("PART updating information for partition %s on host %s was "
                 "successful: %s" % (partition_data['uuid'],
                                     partition_data['ihost_uuid'],
                                     partition_data))
        partition_status = partition_data.get('status')

        part_updates = {'status': partition_status}
        if partition_status == constants.PARTITION_READY_STATUS:
            part_updates.update({
                'start_mib': partition_data.get('start_mib', None),
                'end_mib': partition_data.get('end_mib', None),
                'size_mib': partition_data.get('size_mib', None),
                'device_path': partition_data.get('device_path', None),
                'type_name': partition_data.get('type_name', None)
            })
            disk_updates = {
                'available_mib': partition_data.get('available_mib')}

            # Update the disk usage info
            partition = self.dbapi.partition_get(partition_data['uuid'])
            self.dbapi.idisk_update(partition.idisk_uuid, disk_updates)

            # Update the partition info
            self.dbapi.partition_update(partition_data['uuid'], part_updates)

            # TODO(oponcea) Uncomment this once sysinv-conductor RPCAPI supports eventlets
            # Currently we wait for the partition update sent by the Agent.
            # If this is the cinder-volumes partition, then resize its PV and thinpools
            # pv = self.dbapi.ipv_get(partition.foripvid)
            # if (pv and pv.lvm_vg_name == constants.LVG_CINDER_VOLUMES):
            #    self._resize_cinder_volumes(delayed=True)

        elif partition_status == constants.PARTITION_DELETED_STATUS:
            disk_updates = {
                'available_mib': partition_data.get('available_mib')}

            # Update the disk usage info
            partition = self.dbapi.partition_get(partition_data['uuid'])
            self.dbapi.idisk_update(partition.idisk_uuid, disk_updates)

            # Delete the partition
            self.dbapi.partition_destroy(partition_data['uuid'])

        elif partition_status >= constants.PARTITION_ERROR_STATUS:
            LOG.error("PART Unexpected Error.")
            self.dbapi.partition_update(partition_data['uuid'], part_updates)

    def _update_vim_config(self, context):
        """ Update the VIM's configuration. """
        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::nfv::runtime']
        }

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def _update_pciirqaffinity_config(self, context):
        """ Update the PciIrqAffinity's configuration. """
        personalities = [constants.WORKER]

        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::pciirqaffinity::runtime']
        }

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def _config_sm_stx_openstack(self, context):
        """ provision dbmon """
        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::sm::stx_openstack::runtime']
        }

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def _update_config_for_stx_openstack(self, context):
        """ Update the runtime configurations that are required
            for stx-openstack application
        """
        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::nfv::runtime',
                        'platform::sm::stx_openstack::runtime']
        }

        self._config_apply_runtime_manifest(context,
                                            config_uuid,
                                            config_dict)

    def report_lvm_cinder_config_success(self, context, host_uuid):
        """ Callback for Sysinv Agent

        Configuring LVM backend was successful, finalize operation.
        The Agent calls this if LVM manifests are applied correctly.
        Both controllers have to get their manifests applied before accepting
        the entire operation as successful.
        """
        LOG.debug("LVM manifests success on host: %s" % host_uuid)
        lvm_conf = StorageBackendConfig.get_backend(self.dbapi,
                                                    constants.CINDER_BACKEND_LVM)
        ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)

        # Note that even if nodes are degraded we still accept the answer.
        valid_ctrls = [ctrl for ctrl in ctrls if
                       (ctrl.administrative == constants.ADMIN_LOCKED and
                        ctrl.availability == constants.AVAILABILITY_ONLINE) or
                       (ctrl.administrative == constants.ADMIN_UNLOCKED and
                        ctrl.operational == constants.OPERATIONAL_ENABLED)]

        # Set state for current node
        for host in valid_ctrls:
            if host.uuid == host_uuid:
                break
        else:
            LOG.error("Host %(host) is not in the required state!" % host_uuid)
            host = self.dbapi.ihost_get(host_uuid)
            if not host:
                LOG.error("Host %s is invalid!" % host_uuid)
                return
        tasks = eval(lvm_conf.get('task', '{}'))
        if tasks:
            tasks[host.hostname] = constants.SB_STATE_CONFIGURED
        else:
            tasks = {host.hostname: constants.SB_STATE_CONFIGURED}

        # Check if all hosts configurations have applied correctly
        # and mark config cuccess
        config_success = True
        for host in valid_ctrls:
            if tasks.get(host.hostname, '') != constants.SB_STATE_CONFIGURED:
                config_success = False

        values = None
        if lvm_conf.state != constants.SB_STATE_CONFIG_ERR:
            if config_success:
                # All hosts have completed configuration
                values = {'state': constants.SB_STATE_CONFIGURED, 'task': None}
                # Clear alarm, if any
                self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
                                                   constants.CINDER_BACKEND_LVM)
                # The VIM needs to know when a cinder backend was added.
                self._update_vim_config(context)
            else:
                # This host_uuid has completed configuration
                values = {'task': str(tasks)}
        if values:
            self.dbapi.storage_backend_update(lvm_conf.uuid, values)

    def report_lvm_cinder_config_failure(self, host_uuid, error):
        """ Callback for Sysinv Agent

        Configuring LVM backend failed, set backend to err and raise alarm
        The agent calls this if LVM manifests failed to apply
        """
        args = {'host': host_uuid, 'error': error}
        LOG.error("LVM manifests failed on host: %(host)s. Error: %(error)s" % args)

        # Set lvm backend to error state
        lvm_conf = StorageBackendConfig.get_backend(self.dbapi,
                                                    constants.CINDER_BACKEND_LVM)
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(lvm_conf.uuid, values)

        # Raise alarm
        reason = "LVM configuration failed to apply on host: %(host)s" % args
        self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_SET,
                                           constants.CINDER_BACKEND_LVM,
                                           reason)

    def report_external_config_success(self, host_uuid):
        """
           Callback for Sysinv Agent
        """
        LOG.info("external manifests success on host: %s" % host_uuid)
        conf = StorageBackendConfig.get_backend(self.dbapi,
                                                constants.SB_TYPE_EXTERNAL)
        values = {'state': constants.SB_STATE_CONFIGURED, 'task': None}
        self.dbapi.storage_backend_update(conf.uuid, values)

        # Clear alarm, if any
        # self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
        #                                   constants.SB_TYPE_EXTERNAL)

    def report_exernal_config_failure(self, host_uuid, error):
        """
           Callback for Sysinv Agent

        """
        args = {'host': host_uuid, 'error': error}
        LOG.error("External manifests failed on host: %(host)s. Error: %(error)s" % args)

        # Set external backend to error state
        conf = StorageBackendConfig.get_backend(self.dbapi,
                                                constants.SB_TYPE_EXTERNAL)
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(conf.uuid, values)

        # Raise alarm
        # reason = "Share cinder configuration failed to apply on host: %(host)s" % args
        # self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_SET,
        #                                   constants.SB_TYPE_EXTERNAL,
        #                                   reason)

    def report_ceph_external_config_success(self, context, host_uuid):
        """ Callback for Sysinv Agent

        Configuring Ceph External was successful, finalize operation.
        The Agent calls this if Ceph manifests are applied correctly.
        Both controllers have to get their manifests applied before accepting
        the entire operation as successful.
        """
        LOG.info("Ceph manifests success on host: %s" % host_uuid)

        # As we can have multiple external_ceph backends, need to find the one
        # that is in configuring state.
        ceph_conf = StorageBackendConfig.get_configuring_target_backend(
            self.dbapi, target=constants.SB_TYPE_CEPH_EXTERNAL)

        if ceph_conf:
            # For NOVA, if nova.conf needs to be updated on worker nodes, the
            # task should be set to what? constants.SB_TASK_RECONFIG_WORKER?

            config_done = True
            active_controller = utils.HostHelper.get_active_controller(self.dbapi)
            if not utils.is_host_simplex_controller(active_controller):
                ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
                for host in ctrls:
                    if host.uuid == host_uuid:
                        break
                else:
                    LOG.error("Host %s is not a controller?" % host_uuid)
                    return
                tasks = eval(ceph_conf.get('task', '{}'))
                if tasks:
                    tasks[host.hostname] = None
                else:
                    tasks = {host.hostname: None}

                for h in ctrls:
                    if tasks[h.hostname]:
                        config_done = False
                        break

            if config_done:
                values = {'state': constants.SB_STATE_CONFIGURED,
                          'task': None}
                # The VIM needs to know when a cinder backend was added.
                services = utils.SBApiHelper.getListFromServices(ceph_conf.as_dict())
                if constants.SB_SVC_CINDER in services:
                    self._update_vim_config(context)

                # Clear alarm, if any
                self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
                                                   constants.CINDER_BACKEND_CEPH)
            else:
                values = {'task': str(tasks)}

            self.dbapi.storage_backend_update(ceph_conf.uuid, values)

    def report_ceph_external_config_failure(self, host_uuid, error):
        """ Callback for Sysinv Agent

        Configuring External Ceph backend failed, set backend to err and raise alarm
        The agent calls this if Ceph manifests failed to apply
        """

        args = {'host': host_uuid, 'error': error}
        LOG.error("Ceph external manifests failed on host: %(host)s. Error: %(error)s" % args)

        # As we can have multiple external_ceph backends, need to find the one
        # that is in configuring state.
        ceph_conf = StorageBackendConfig.get_configuring_target_backend(
            self.dbapi, target=constants.SB_TYPE_CEPH_EXTERNAL)

        # Set ceph backend to error state
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(ceph_conf.uuid, values)

        # Raise alarm
        reason = "Ceph external configuration failed to apply on host: %(host)s" % args
        self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_SET,
                                           constants.CINDER_BACKEND_CEPH,
                                           reason)

    def report_ceph_config_success(self, context, host_uuid):
        """ Callback for Sysinv Agent

        Configuring Ceph was successful, finalize operation.
        The Agent calls this if Ceph manifests are applied correctly.
        Both controllers have to get their manifests applied before accepting
        the entire operation as successful.
        """
        LOG.info("Ceph manifests success on host: %s" % host_uuid)
        ceph_conf = StorageBackendConfig.get_backend(self.dbapi,
                                                     constants.CINDER_BACKEND_CEPH)

        # Only update the state/task if the backend hasn't been previously
        # configured. Subsequent re-applies of the runtime manifest that need to
        # have the controllers rebooted should be handled by SB_TASK changes
        # (i.e adding object GW)
        if ceph_conf.state != constants.SB_STATE_CONFIGURED:
            active_controller = utils.HostHelper.get_active_controller(self.dbapi)
            if utils.is_host_simplex_controller(active_controller):
                state = constants.SB_STATE_CONFIGURED
                if utils.is_aio_system(self.dbapi):
                    task = None
                    cceph.fix_crushmap(self.dbapi)
                else:
                    task = constants.SB_TASK_PROVISION_STORAGE
                values = {'state': state,
                          'task': task}
            else:
                # TODO(oponcea): Remove when sm supports in-service config reload
                # and any logic dealing with constants.SB_TASK_RECONFIG_CONTROLLER.
                ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
                # Note that even if nodes are degraded we still accept the answer.
                valid_ctrls = [ctrl for ctrl in ctrls if
                               (ctrl.administrative == constants.ADMIN_LOCKED and
                                ctrl.availability == constants.AVAILABILITY_ONLINE) or
                               (ctrl.administrative == constants.ADMIN_UNLOCKED and
                                ctrl.operational == constants.OPERATIONAL_ENABLED)]

                # Set state for current node
                for host in valid_ctrls:
                    if host.uuid == host_uuid:
                        break
                else:
                    LOG.error("Host %(host) is not in the required state!" % host_uuid)
                    host = self.dbapi.ihost_get(host_uuid)
                    if not host:
                        LOG.error("Host %s is invalid!" % host_uuid)
                        return

                tasks = eval(ceph_conf.get('task', '{}'))
                if tasks:
                    tasks[host.hostname] = constants.SB_STATE_CONFIGURED
                else:
                    tasks = {host.hostname: constants.SB_STATE_CONFIGURED}

                config_success = True
                for host in valid_ctrls:
                    if tasks.get(host.hostname, '') != constants.SB_STATE_CONFIGURED:
                        config_success = False

                if ceph_conf.state != constants.SB_STATE_CONFIG_ERR:
                    if config_success:
                        values = {'task': constants.SB_TASK_RECONFIG_CONTROLLER}
                    else:
                        values = {'task': str(tasks)}
            self.dbapi.storage_backend_update(ceph_conf.uuid, values)

            # The VIM needs to know when a cinder backend was added.
            services = utils.SBApiHelper.getListFromServices(ceph_conf.as_dict())
            if constants.SB_SVC_CINDER in services:
                self._update_vim_config(context)

        # Clear alarm, if any
        self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_CLEAR,
                                           constants.CINDER_BACKEND_CEPH)

    def report_ceph_config_failure(self, host_uuid, error):
        """ Callback for Sysinv Agent

        Configuring Ceph backend failed, set ackend to err and raise alarm
        The agent calls this if LVM manifests failed to apply
        """
        args = {'host': host_uuid, 'error': error}
        LOG.error("Ceph manifests failed on host: %(host)s. Error: %(error)s" % args)

        # Set ceph backend to error state
        ceph_conf = StorageBackendConfig.get_backend(self.dbapi,
                                                     constants.CINDER_BACKEND_CEPH)
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(ceph_conf.uuid, values)

        # Raise alarm
        reason = "Ceph configuration failed to apply on host: %(host)s" % args
        self._update_storage_backend_alarm(fm_constants.FM_ALARM_STATE_SET,
                                           constants.CINDER_BACKEND_CEPH,
                                           reason)

    def report_ceph_services_config_success(self, host_uuid):
        """
           Callback for Sysinv Agent
        """

        LOG.info("Ceph service update succeeded on host: %s" % host_uuid)

        # Get the backend that is configuring
        backend_list = self.dbapi.storage_ceph_get_list()
        backend = None
        for b in backend_list:
            if b.state == constants.SB_STATE_CONFIGURING:
                backend = b
                break

        ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        # Note that even if nodes are degraded we still accept the answer.
        valid_ctrls = [ctrl for ctrl in ctrls if
                       (ctrl.administrative == constants.ADMIN_LOCKED and
                        ctrl.availability == constants.AVAILABILITY_ONLINE) or
                       (ctrl.administrative == constants.ADMIN_UNLOCKED and
                        ctrl.operational == constants.OPERATIONAL_ENABLED)]

        # Set state for current node
        for host in valid_ctrls:
            if host.uuid == host_uuid:
                break
        else:
            LOG.error("Host %(host) is not in the required state!" % host_uuid)
            host = self.dbapi.ihost_get(host_uuid)
            if not host:
                LOG.error("Host %s is invalid!" % host_uuid)
                return
        tasks = eval(backend.get('task', '{}'))
        if tasks:
            tasks[host.hostname] = constants.SB_STATE_CONFIGURED
        else:
            tasks = {host.hostname: constants.SB_STATE_CONFIGURED}

        # Check if all hosts configurations have applied correctly
        # and mark config cuccess
        config_success = True
        for host in valid_ctrls:
            if tasks.get(host.hostname, '') != constants.SB_STATE_CONFIGURED:
                config_success = False

        values = None
        if backend.state != constants.SB_STATE_CONFIG_ERR:
            if config_success:
                # All hosts have completed configuration
                values = {'state': constants.SB_STATE_CONFIGURED, 'task': None}
            else:
                # This host_uuid has completed configuration
                values = {'task': str(tasks)}
        if values:
            self.dbapi.storage_backend_update(backend.uuid, values)

    def report_ceph_services_config_failure(self, host_uuid, error):
        """
           Callback for Sysinv Agent

        """
        LOG.error("Ceph service update failed on host: %(host)s. Error: "
                  "%(error)s" % {'host': host_uuid, 'error': error})

        backend_list = self.dbapi.storage_ceph_get_list()
        backend = None
        for b in backend_list:
            if b.state == constants.SB_STATE_CONFIGURING:
                backend = b
                break

        # Set external backend to error state
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.storage_backend_update(backend.uuid, values)

    def report_ceph_base_config_success(self, host_uuid):
        """
           Callback for Sysinv Agent
        """

        LOG.info("Ceph monitor update succeeded on host: %s" % host_uuid)

        # Get the monitor that is configuring
        monitor_list = self.dbapi.ceph_mon_get_list()
        monitor = None
        for mon in monitor_list:
            if mon.state == constants.SB_STATE_CONFIGURING:
                monitor = mon
                break

        ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        # Note that even if nodes are degraded we still accept the answer.
        valid_ctrls = [ctrl for ctrl in ctrls if
                       (ctrl.administrative == constants.ADMIN_LOCKED and
                        ctrl.availability == constants.AVAILABILITY_ONLINE) or
                       (ctrl.administrative == constants.ADMIN_UNLOCKED and
                        ctrl.operational == constants.OPERATIONAL_ENABLED)]

        # Set state for current node
        for host in valid_ctrls:
            if host.uuid == host_uuid:
                break
        else:
            LOG.error("Host %(host) is not in the required state!" % host_uuid)
            host = self.dbapi.ihost_get(host_uuid)
            if not host:
                LOG.error("Host %s is invalid!" % host_uuid)
                return
            elif host.personality == constants.WORKER:
                LOG.info("Ignoring report from worker hosts")
                return
        tasks = eval(monitor.get('task', '{}'))
        if tasks:
            tasks[host.hostname] = constants.SB_STATE_CONFIGURED
        else:
            tasks = {host.hostname: constants.SB_STATE_CONFIGURED}

        # Check if all hosts configurations have applied correctly
        # and mark config success
        config_success = True
        for host in valid_ctrls:
            if tasks.get(host.hostname, '') != constants.SB_STATE_CONFIGURED:
                config_success = False

        values = None
        if monitor.state != constants.SB_STATE_CONFIG_ERR:
            if config_success:
                # All hosts have completed configuration
                values = {'state': constants.SB_STATE_CONFIGURED, 'task': None}
            else:
                # This host_uuid has completed configuration
                values = {'task': str(tasks)}
        if values:
            self.dbapi.ceph_mon_update(monitor.uuid, values)

    def report_ceph_base_config_failure(self, host_uuid, error):
        """
           Callback for Sysinv Agent
        """
        LOG.error("Ceph monitor update failed on host: %(host)s. Error: "
                  "%(error)s" % {'host': host_uuid, 'error': error})

        host = self.dbapi.ihost_get(host_uuid)
        if host and host.personality == constants.WORKER:
            # Ignoring report from worker
            return

        monitor_list = self.dbapi.ceph_mon_get_list()
        monitor = None
        for mon in monitor_list:
            if mon.state == constants.SB_STATE_CONFIGURING:
                monitor = mon
                break

        # Set monitor to error state
        values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
        self.dbapi.ceph_mon_update(monitor.uuid, values)

    def report_ceph_osd_config_success(self, host_uuid, stor_uuid):
        """
           Callback for Sysinv Agent on ceph OSD config success
        """

        LOG.info("Ceph OSD stor '%s' update succeeded on host: %s" % (stor_uuid, host_uuid))

        values = {'state': constants.SB_STATE_CONFIGURED}
        self.dbapi.istor_update(stor_uuid, values)

    def report_ceph_osd_config_failure(self, host_uuid, stor_uuid, error):
        """
           Callback for Sysinv Agent on ceph OSD config failure
        """
        LOG.error("Ceph OSD stor '%(stor)s' update failed on host: %(host)s. Error: "
                  "%(error)s" % {'stor': stor_uuid, 'host': host_uuid, 'error': error})

        # Set OSD to error state
        values = {'state': constants.SB_STATE_CONFIG_ERR}
        self.dbapi.istor_update(stor_uuid, values)

    def create_controller_filesystems(self, context, rootfs_device):
        """ Create the storage config based on disk size for
            database, image, backup, img-conversion

            :param context: an admin context.
            :param rootfs_device: the root disk device
        """
        database_storage = 0
        cgcs_lv_size = 0
        backup_lv_size = 0

        # Add the extension storage
        extension_lv_size = constants.DEFAULT_EXTENSION_STOR_SIZE
        scratch_lv_size = cutils.get_controller_fs_scratch_size()

        system = self.dbapi.isystem_get_one()
        system_dc_role = system.get('distributed_cloud_role', None)
        kubernetes_config = system.capabilities.get('kubernetes_enabled', False)

        LOG.info("Local  Region Name: %s" % system.region_name)

        disk_size = cutils.get_disk_capacity_mib(rootfs_device)
        disk_size = int(disk_size / 1024)

        if disk_size > constants.DEFAULT_SMALL_DISK_SIZE:

            LOG.info("Disk size : %s ... large disk defaults" % disk_size)

            # Defaults: 500G root disk
            #
            # Min size of the cgts-vg PV is:
            #   202.0 G - PV for cgts-vg (specified in the kickstart)
            # or
            #   210.0 G - (for DCSC non-AIO)
            #          8 G - /var/log (reserved in kickstart)
            #          8 G - /scratch (reserved in kickstart)
            #          2 G - cgcs_lv (DRBD bootstrap manifest)
            #          2 G - pgsql_lv (DRBD bootstrap manifest)
            #          2 G - rabbit_lv (DRBD bootstrap manifest)
            #          2 G - platform_lv (DRBD bootstrap manifest)
            #          1 G - extension_lv (DRBD bootstrap manifest)
            #        -----
            #         25 G - cgts-vg contents when we get to these checks
            #
            #
            #       Final defaults view after controller manifests
            #          8 G - /var/log (reserved in kickstart)
            #          8 G - /scratch (reserved in kickstart)
            #         20 G - /opt/cgcs
            #         40 G - /var/lib/postgresql
            #          2 G - /var/lib/rabbitmq
            #          2 G - /opt/platform
            #          1 G - /opt/extension
            #         50 G - /opt/backup
            #         30 G - /var/lib/docker (--kubernetes)
            #         16 G - /var/lib/docker-distribution (--kubernetes)
            #          5 G - /opt/etcd (--kubernetes)
            #         20 G - /var/lib/ceph/mon (--kubernetes)
            #          8 G - /opt/patch-vault (DRBD ctlr manifest for
            #                   Distributed Cloud System Controller non-AIO only)
            #        -----
            #        210 G (for DCSC non-AIO) or 202
            #
            #  The absolute minimum disk size for these default settings:
            #      0.5 G - /boot
            #     20.0 G - /
            #    202.0 G - cgts-vg PV
            # or 210.0 G - (DCSC non-AIO)
            #   -------
            #    222.5 G => ~223G min size disk
            # or
            #    230.5 G => ~231G min size disk
            #
            # If required disk is size 500G:
            #   1) Standard controller - will use all free space for the PV
            #       0.5 G - /boot
            #      20.0 G - /
            #     479.5 G - cgts-vg PV
            #
            #   2) AIO - will leave unused space for further partitioning
            #       0.5 G - /boot
            #      20.0 G - /
            #     202.0 G - cgts-vg PV
            #     277.5 G - unpartitioned free space
            #
            database_storage = constants.DEFAULT_DATABASE_STOR_SIZE

            cgcs_lv_size = constants.DEFAULT_CGCS_STOR_SIZE
            backup_lv_size = database_storage + \
                cgcs_lv_size + constants.BACKUP_OVERHEAD

        elif disk_size >= constants.MINIMUM_DISK_SIZE:

            LOG.info("Disk size : %s ... small disk defaults" % disk_size)

            # Small disk: under 240G root disk
            #
            # Min size of the cgts-vg PV is:
            #   170.0 G - PV for cgts-vg (specified in the kickstart)
            # or
            #   162.0 G - (for DCSC non-AIO)
            #          8 G - /var/log (reserved in kickstart)
            #          8 G - /scratch (reserved in kickstart)
            #          2 G - cgcs_lv (DRBD bootstrap manifest)
            #          2 G - pgsql_lv (DRBD bootstrap manifest)
            #          2 G - rabbit_lv (DRBD bootstrap manifest)
            #          2 G - platform_lv (DRBD bootstrap manifest)
            #          1 G - extension_lv (DRBD bootstrap manifest)
            #        -----
            #         25 G - cgts-vg contents when we get to these checks
            #
            #
            #       Final defaults view after controller manifests
            #          8 G - /var/log (reserved in kickstart)
            #          8 G - /scratch (reserved in kickstart)
            #         10 G - /opt/cgcs
            #         20 G - /var/lib/postgresql
            #          2 G - /var/lib/rabbitmq
            #          2 G - /opt/platform
            #          1 G - /opt/extension
            #         40 G - /opt/backup
            #         30 G - /var/lib/docker (--kubernetes)
            #         16 G - /var/lib/docker-distribution (--kubernetes)
            #         20 G - /var/lib/ceph/mon (--kubernetes)
            #          5 G - /opt/etcd (--kubernetes)
            #          8 G - /opt/patch-vault (DRBD ctlr manifest for DCSC non-AIO only)
            #        -----
            #        170 G (for DCSC non-AIO) or 162 G
            #
            #  The absolute minimum disk size for these default settings:
            #     0.5 G - /boot
            #    20.0 G - /
            #   162.0 G - cgts-vg PV
            # or
            #   170.0 G - (for DCSC non-AIO)
            #   -------
            #   182.5 G => ~183G min size disk
            # or
            #   190.5 G => ~191G min size disk
            #
            # If required disk is size 240G:
            #   1) Standard controller - will use all free space for the PV
            #       0.5 G - /boot
            #      20.0 G - /
            #     219.5 G - cgts-vg PV
            #   2) AIO - will leave unused space for further partitioning
            #       0.5 G - /boot
            #      20.0 G - /
            #     162.0 G - cgts-vg PV
            #      57.5 G - unpartitioned free space
            #
            database_storage = \
                constants.DEFAULT_SMALL_DATABASE_STOR_SIZE

            cgcs_lv_size = constants.DEFAULT_SMALL_CGCS_STOR_SIZE
            # Due to the small size of the disk we can't provide the
            # proper amount of backup space which is (database + cgcs_lv
            # + BACKUP_OVERHEAD) so we are using a smaller default.
            backup_lv_size = constants.DEFAULT_SMALL_BACKUP_STOR_SIZE
        else:
            LOG.info("Disk size : %s ... disk too small" % disk_size)
            raise exception.SysinvException("Disk size requirements not met.")

        data = {
            'name': constants.FILESYSTEM_NAME_BACKUP,
            'size': backup_lv_size,
            'logical_volume': constants.FILESYSTEM_LV_DICT[
                constants.FILESYSTEM_NAME_BACKUP],
            'replicated': False,
        }
        LOG.info("Creating FS:%s:%s %d" % (
            data['name'], data['logical_volume'], data['size']))
        self.dbapi.controller_fs_create(data)

        data = {
            'name': constants.FILESYSTEM_NAME_CGCS,
            'size': cgcs_lv_size,
            'logical_volume': constants.FILESYSTEM_LV_DICT[
                constants.FILESYSTEM_NAME_CGCS],
            'replicated': True,
        }
        LOG.info("Creating FS:%s:%s %d" % (
            data['name'], data['logical_volume'], data['size']))
        self.dbapi.controller_fs_create(data)

        data = {
            'name': constants.FILESYSTEM_NAME_DATABASE,
            'size': database_storage,
            'logical_volume': constants.FILESYSTEM_LV_DICT[
                constants.FILESYSTEM_NAME_DATABASE],
            'replicated': True,
        }
        LOG.info("Creating FS:%s:%s %d" % (
            data['name'], data['logical_volume'], data['size']))
        self.dbapi.controller_fs_create(data)

        data = {
            'name': constants.FILESYSTEM_NAME_SCRATCH,
            'size': scratch_lv_size,
            'logical_volume': constants.FILESYSTEM_LV_DICT[
                constants.FILESYSTEM_NAME_SCRATCH],
            'replicated': False,
        }
        LOG.info("Creating FS:%s:%s %d" % (
            data['name'], data['logical_volume'], data['size']))
        self.dbapi.controller_fs_create(data)

        data = {
            'name': constants.FILESYSTEM_NAME_EXTENSION,
            'size': extension_lv_size,
            'logical_volume': constants.FILESYSTEM_LV_DICT[
                constants.FILESYSTEM_NAME_EXTENSION],
            'replicated': True,
        }
        LOG.info("Creating FS:%s:%s %d" % (
            data['name'], data['logical_volume'], data['size']))
        self.dbapi.controller_fs_create(data)

        if kubernetes_config:
            docker_lv_size = constants.KUBERNETES_DOCKER_STOR_SIZE

            data = {
                'name': constants.FILESYSTEM_NAME_DOCKER,
                'size': docker_lv_size,
                'logical_volume': constants.FILESYSTEM_LV_DICT[
                    constants.FILESYSTEM_NAME_DOCKER],
                'replicated': False,
            }
            LOG.info("Creating FS:%s:%s %d" % (
                data['name'], data['logical_volume'], data['size']))
            self.dbapi.controller_fs_create(data)

            # ETCD fs added to cgts-lv
            etcd_lv_size = constants.ETCD_STOR_SIZE

            data_etcd = {
                    'name': constants.FILESYSTEM_NAME_ETCD,
                    'size': etcd_lv_size,
                    'logical_volume': constants.FILESYSTEM_LV_DICT[
                        constants.FILESYSTEM_NAME_ETCD],
                    'replicated': True,
            }
            LOG.info("Creating FS:%s:%s %d" % (
                data_etcd['name'], data_etcd['logical_volume'], data_etcd['size']))
            self.dbapi.controller_fs_create(data_etcd)

            data = {
                'name': constants.FILESYSTEM_NAME_DOCKER_DISTRIBUTION,
                'size': constants.DOCKER_DISTRIBUTION_STOR_SIZE,
                'logical_volume': constants.FILESYSTEM_LV_DICT[
                    constants.FILESYSTEM_NAME_DOCKER_DISTRIBUTION],
                'replicated': True,
            }
            LOG.info("Creating FS:%s:%s %d" % (
                data['name'], data['logical_volume'], data['size']))
            self.dbapi.controller_fs_create(data)

        if (system_dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER and
                tsc.system_type != constants.TIS_AIO_BUILD):
            data = {
                'name': constants.FILESYSTEM_NAME_PATCH_VAULT,
                'size': constants.DEFAULT_PATCH_VAULT_STOR_SIZE,
                'logical_volume': constants.FILESYSTEM_LV_DICT[
                    constants.FILESYSTEM_NAME_PATCH_VAULT],
                'replicated': True,
            }
            LOG.info("Creating FS:%s:%s %d" % (
                data['name'], data['logical_volume'], data['size']))
            self.dbapi.controller_fs_create(data)

        else:
            values = {
                'services': constants.SB_SVC_GLANCE,
                'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_EXTERNAL],
                'state': constants.SB_STATE_CONFIGURED,
                'backend': constants.SB_TYPE_EXTERNAL,
                'task': constants.SB_TASK_NONE,
                'capabilities': {},
                'forsystemid': system.id
            }
            self.dbapi.storage_external_create(values)

    def update_service_config(self, context, service=None, do_apply=False):
        """Update the service parameter configuration"""

        LOG.info("Updating parameters configuration for service: %s" % service)

        if service == constants.SERVICE_TYPE_CEPH:
            return self._ceph.update_service_config(do_apply)

        # On service parameter add just update the host profile
        # for personalities pertinent to that service
        if service == constants.SERVICE_TYPE_NETWORK:
            if tsc.system_type == constants.TIS_AIO_BUILD:
                personalities = [constants.CONTROLLER]
                # AIO hosts must be rebooted following service reconfig
                config_uuid = self._config_update_hosts(context, personalities,
                                                        reboot=True)
            else:
                # worker hosts must be rebooted following service reconfig
                self._config_update_hosts(context, [constants.WORKER],
                                          reboot=True)
                # controller hosts will actively apply the manifests
                config_uuid = self._config_update_hosts(context,
                                                        [constants.CONTROLLER])
        elif service == constants.SERVICE_TYPE_MURANO:
            config_uuid = self._config_update_hosts(context,
                                                    [constants.CONTROLLER],
                                                    reboot=True)
        elif service == constants.SERVICE_TYPE_MAGNUM:
            config_uuid = self._config_update_hosts(context,
                                                    [constants.CONTROLLER],
                                                    reboot=True)

        elif service == constants.SERVICE_TYPE_IRONIC:
            config_uuid = self._config_update_hosts(context,
                                                    [constants.CONTROLLER],
                                                    reboot=True)
        elif service == constants.SERVICE_TYPE_NOVA:
            config_uuid = self._config_update_hosts(context,
                                                    [constants.CONTROLLER,
                                                     constants.WORKER])
        elif service == constants.SERVICE_TYPE_HTTP:
            config_uuid = self._config_update_hosts(context,
                                                    [constants.CONTROLLER,
                                                     constants.WORKER,
                                                     constants.STORAGE])
        elif service == constants.SERVICE_TYPE_OPENSTACK:
            # Do nothing. Does not need to update target config of any hosts
            pass
        else:
            # All other services
            personalities = [constants.CONTROLLER]
            config_uuid = self._config_update_hosts(context, personalities)

        if do_apply:
            if service == constants.SERVICE_TYPE_IDENTITY:
                config_dict = {
                    "personalities": personalities,
                    "classes": ['platform::haproxy::runtime',
                                'openstack::keystone::server::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_HORIZON:
                config_dict = {
                    "personalities": personalities,
                    "classes": ['openstack::horizon::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_NETWORK:
                if not self._config_is_reboot_required(config_uuid):
                    personalities = [constants.CONTROLLER]
                    config_dict = {
                        "personalities": personalities,
                        "classes": ['openstack::neutron::server::runtime']
                    }
                    self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_CINDER:
                self._update_emc_state()

                self._hpe_update_state(constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR)
                self._hpe_update_state(constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND)

                # service params need to be applied to controllers that have cinder provisioned
                # TODO(rchurch) make sure that we can't apply without a cinder backend.
                ctrls = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
                valid_ctrls = [ctrl for ctrl in ctrls if
                               (utils.is_host_active_controller(ctrl) and
                                ctrl.administrative == constants.ADMIN_LOCKED and
                                ctrl.availability == constants.AVAILABILITY_ONLINE) or
                               (ctrl.administrative == constants.ADMIN_UNLOCKED and
                                ctrl.operational == constants.OPERATIONAL_ENABLED)]

                config_dict = {
                    "personalities": personalities,
                    "classes": ['openstack::cinder::service_param::runtime'],
                    "host_uuids": [ctrl.uuid for ctrl in valid_ctrls],
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

                multipath_state_changed = self._multipath_update_state()
                if multipath_state_changed:
                    self._config_update_hosts(context,
                        [constants.CONTROLLER, constants.WORKER],
                        reboot=True)

            elif service == constants.SERVICE_TYPE_PLATFORM:
                config_dict = {
                    "personalities": personalities,
                    "classes": ['platform::mtce::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_NOVA:
                personalities = [constants.CONTROLLER]
                config_uuid = self._config_update_hosts(context, personalities)
                config_dict = {
                    "personalities": personalities,
                    "classes": ['openstack::nova::controller::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

                personalities = [constants.WORKER]
                config_uuid = self._config_update_hosts(context, personalities)
                config_dict = {
                    "personalities": personalities,
                    "classes": ['openstack::nova::compute::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_SWIFT:
                personalities = [constants.CONTROLLER]
                config_dict = {
                    "personalities": personalities,
                    "classes": ['openstack::swift::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_BARBICAN:
                personalities = [constants.CONTROLLER]
                config_dict = {
                    "personalities": personalities,
                    "classes": ['openstack::barbican::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid, config_dict)

            elif service == constants.SERVICE_TYPE_HTTP:
                # the platform::config class will be applied that will
                # configure the http port
                personalities = [constants.WORKER, constants.STORAGE]
                config_dict = {
                    "personalities": personalities,
                    "classes": ['platform::patching::runtime']}
                self._config_apply_runtime_manifest(context, config_uuid,
                                                    config_dict)

                # the runtime classes on controllers will be applied
                personalities = [constants.CONTROLLER]
                config_dict = {
                    "personalities": personalities,
                    "classes": ['openstack::lighttpd::runtime',
                                'platform::helm::runtime',
                                'platform::firewall::runtime',
                                'platform::patching::runtime']
                }
                self._config_apply_runtime_manifest(context, config_uuid,
                                                    config_dict)

    def update_security_feature_config(self, context):
        """Update the kernel options configuration"""
        personalities = constants.PERSONALITIES
        config_uuid = self._config_update_hosts(context, personalities, reboot=True)

        config_dict = {
            'personalities': personalities,
            'classes': ['platform::grub::runtime']
        }

        self._config_apply_runtime_manifest(context, config_uuid, config_dict, force=True)

    def _update_emc_state(self):
        emc_state_param = self._get_emc_state()
        current_state = emc_state_param.value

        enabled_param = self.dbapi.service_parameter_get_one(
            constants.SERVICE_TYPE_CINDER,
            constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX,
            constants.SERVICE_PARAM_CINDER_EMC_VNX_ENABLED
        )
        requested_state = (enabled_param.value.lower() == 'true')

        if (requested_state and current_state ==
                constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_DISABLED):
            new_state = constants.SERVICE_PARAM_CINDER_EMC_VNX_ENABLED
            LOG.info("Updating EMC state to %s" % new_state)
            self.dbapi.service_parameter_update(
                emc_state_param.uuid,
                {'value': new_state}
            )
        elif (not requested_state and current_state ==
                constants.SERVICE_PARAM_CINDER_EMC_VNX_ENABLED):
            new_state = constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_DISABLING
            LOG.info("Updating EMC state to %s" % new_state)
            self.dbapi.service_parameter_update(
                emc_state_param.uuid,
                {'value': new_state}
            )

    def _get_emc_state(self):
        try:
            state = self.dbapi.service_parameter_get_one(
                constants.SERVICE_TYPE_CINDER,
                constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX_STATE,
                constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS
            )
        except exception.NotFound:
            LOG.info("EMC state not found, setting to disabled")
            values = {
                'service': constants.SERVICE_TYPE_CINDER,
                'section': constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX_STATE,
                'name': constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS,
                'value': constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_DISABLED
            }
            state = self.dbapi.service_parameter_create(values)
        return state

    def _hpe_get_state(self, name):
        section = name + '.state'
        try:
            parm = self.dbapi.service_parameter_get_one(
                constants.SERVICE_TYPE_CINDER, section,
                constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS
            )

        except exception.NotFound:
            raise exception.SysinvException(_("Hpe section %s not "
                                              "found" % section))
        return parm

    def _hpe_update_state(self, name):

        do_update = False
        status_param = self._hpe_get_state(name)
        status = status_param.value

        enabled = False
        try:
            enabled_param = self.dbapi.service_parameter_get_one(
                constants.SERVICE_TYPE_CINDER, name,
                constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED
            )
            enabled = (enabled_param.value.lower() == 'true')
        except exception.NotFound:
            pass
        if not enabled and name == constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR:
            for i in range(2, constants.SERVICE_PARAM_MAX_HPE3PAR + 1):
                section = "{0}{1}".format(name, i)
                try:
                    enabled_param = self.dbapi.service_parameter_get_one(
                        constants.SERVICE_TYPE_CINDER, section,
                        constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED
                    )
                    enabled = (enabled_param.value.lower() == 'true')
                except exception.NotFound:
                    pass
                if enabled:
                    break
        if enabled and status == constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_DISABLED:
            do_update = True
            new_state = constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED
        elif not enabled and status == constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED:
            do_update = True
            new_state = constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_DISABLING

        if do_update:
            LOG.info("Updating %s to %s" % (name, new_state))
            self.dbapi.service_parameter_update(status_param.uuid, {'value': new_state})

    def _multipath_get_state(self):
        try:
            state = self.dbapi.service_parameter_get_one(
                constants.SERVICE_TYPE_CINDER,
                constants.SERVICE_PARAM_SECTION_CINDER_DEFAULT,
                constants.SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH_STATE
            )
        except exception.NotFound:
            state = self.dbapi.service_parameter_create({
                'service': constants.SERVICE_TYPE_CINDER,
                'section': constants.SERVICE_PARAM_SECTION_CINDER_DEFAULT,
                'name': constants.SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH_STATE,
                'value': constants.SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH_STATE_DISABLED
            })
        return state

    def _multipath_update_state(self):
        """Update multipath service parameter state

        :return True if multipath state changed, False otherwise
        """
        state_param = self._multipath_get_state()
        current_state = state_param.value
        try:
            state = self.dbapi.service_parameter_get_one(
                constants.SERVICE_TYPE_CINDER,
                constants.SERVICE_PARAM_SECTION_CINDER_DEFAULT,
                constants.SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH
            ).value
        except exception.NotFound:
            state = constants.SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH_STATE_DISABLED
        if current_state != state:
            self.dbapi.service_parameter_update(
                state_param.uuid, dict(value=state))
            return True
        return False

    def update_sdn_controller_config(self, context):
        """Update the SDN controller configuration"""
        LOG.info("update_sdn_controller_config")

        # Apply Neutron manifest on Controller(this
        # will update the SNAT rules for the SDN controllers)
        self._config_update_hosts(context, [constants.WORKER], reboot=True)

        config_uuid = self._config_update_hosts(context,
                                               [constants.CONTROLLER])
        config_dict = {
            "personalities": [constants.CONTROLLER],
            "classes": ['openstack::neutron::server::runtime'],
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def update_sdn_enabled(self, context):
        """Update the sdn enabled flag.

        :param context: an admin context.
        """
        LOG.info("update_sdn_enabled")

        personalities = [constants.CONTROLLER]
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::sysctl::controller::runtime',
                        'openstack::neutron::server::runtime']
        }
        config_uuid = self._config_update_hosts(context, personalities)
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        personalities = [constants.WORKER]
        self._config_update_hosts(context, personalities, reboot=True)

    def update_vswitch_type(self, context):
        """Update the system vswitch type.

        :param context: an admin context.
        """
        LOG.info("update_vswitch_type")

        personalities = [constants.CONTROLLER]
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::sysctl::controller::runtime',
                        'platform::nfv::runtime']
        }
        config_uuid = self._config_update_hosts(context, personalities)
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        if tsc.system_type == constants.TIS_AIO_BUILD:
            personalities = [constants.CONTROLLER]
        else:
            personalities = [constants.WORKER]

        self._config_update_hosts(context, personalities, reboot=True)

    def _update_hosts_file(self, hostname, address, active=True):
        """Update or add an entry to the /etc/hosts configuration file

        :param hostname: The hostname to update or add
        :param address: The address to update or add
        :param active: Flag indicating whether to update the active hosts file
        """
        hosts_file = '/etc/hosts'
        hosts_file_temp = hosts_file + '.temp'

        with open(hosts_file, 'r') as f_in:
            with open(hosts_file_temp, 'w') as f_out:
                for line in f_in:
                    # copy all entries except for the updated host
                    if hostname not in line:
                        f_out.write(line)
                f_out.write("%s %s\n" % (address, hostname))

        # Copy the updated file to shared storage
        shutil.copy2(hosts_file_temp, tsc.CONFIG_PATH + 'hosts')

        if active:
            # Atomically replace the active hosts file
            os.rename(hosts_file_temp, hosts_file)
        else:
            # discard temporary file
            os.remove(hosts_file_temp)

    def update_cpu_config(self, context, host_uuid, force_grub_update=False):
        """Update the cpu assignment configuration on a host"""

        # only apply the manifest on the host that has worker sub function
        host = self.dbapi.ihost_get(host_uuid)
        if constants.WORKER in host.subfunctions:
            force = (not utils.is_host_simplex_controller(host) or
                     force_grub_update)
            LOG.info("update_cpu_config, host uuid: (%s), force: (%s)",
                     host_uuid, str(force))
            personalities = [constants.CONTROLLER, constants.WORKER]
            config_uuid = self._config_update_hosts(context,
                                                    personalities,
                                                    host_uuids=[host_uuid])
            config_dict = {
                "personalities": personalities,
                "host_uuids": [host_uuid],
                "classes": ['platform::compute::grub::runtime',
                            'platform::compute::config::runtime']
            }
            self._config_apply_runtime_manifest(context, config_uuid,
                                                config_dict,
                                                force=force,
                                                host_uuids=[host_uuid])

    def _update_resolv_file(self, context, config_uuid, personalities):
        """Generate and update the resolv.conf files on the system"""

        # get default name server which is the controller floating IP address
        servers = [cutils.gethostbyname(constants.CONTROLLER_HOSTNAME)]

        # add configured dns entries (if any)
        dns = self.dbapi.idns_get_one()
        if dns.nameservers:
            servers += dns.nameservers.split(',')

        # generate the formatted file content based on configured servers
        file_content = ''
        for server in servers:
            file_content += "nameserver %s\n" % server

        # Write contents to master resolv.conf in the platform config
        resolv_file = os.path.join(tsc.CONFIG_PATH, 'resolv.conf')
        resolv_file_temp = resolv_file + '.temp'

        with open(resolv_file_temp, 'w') as f:
            f.write(file_content)

        # Atomically replace the updated file
        os.rename(resolv_file_temp, resolv_file)

        config_dict = {
            'personalities': personalities,
            'file_names': ['/etc/resolv.conf'],
            'file_content': file_content,
        }

        self._config_update_file(context, config_uuid, config_dict)

    def _drbd_connected(self):
        connected = False

        output = subprocess.check_output("drbd-overview",
                                         stderr=subprocess.STDOUT)
        output = [_f for _f in output.split('\n') if _f]

        for row in output:
            if "Connected" in row:
                connected = True
            else:
                connected = False
                break

        return connected

    def _drbd_fs_sync(self):
        output = subprocess.check_output("drbd-overview",
                                         stderr=subprocess.STDOUT)
        output = [_f for _f in output.split('\n') if _f]

        fs = []
        for row in output:
            # Check PausedSyncS as well as drbd sync is changed to serial
            if "drbd-pgsql" in row and ("SyncSource" in row or "PausedSyncS" in row):
                fs.append(constants.DRBD_PGSQL)
            if "drbd-cgcs" in row and ("SyncSource" in row or "PausedSyncS" in row):
                fs.append(constants.DRBD_CGCS)
            if "drbd-extension" in row and ("SyncSource" in row or "PausedSyncS" in row):
                fs.append(constants.DRBD_EXTENSION)
            if "drbd-patch-vault" in row and ("SyncSource" in row or "PausedSyncS" in row):
                fs.append(constants.DRBD_PATCH_VAULT)
            if "drbd-etcd" in row and ("SyncSource" in row or "PausedSyncS" in row):
                fs.append(constants.DRBD_ETCD)
            if "drbd-dockerdistribution" in row and ("SyncSource" in row or "PausedSyncS" in row):
                fs.append(constants.DRBD_DOCKER_DISTRIBUTION)
        return fs

    def _drbd_fs_updated(self, context):
        drbd_dict = subprocess.check_output("drbd-overview",
                                            stderr=subprocess.STDOUT)
        drbd_dict = [_f for _f in drbd_dict.split('\n') if _f]

        drbd_patch_size = 0
        patch_lv_size = 0
        dockerdistribution_size = 0
        dockerdistribution_lv_size = 0
        drbd_etcd_size = 0
        etcd_lv_size = 0

        for row in drbd_dict:
            if "sync\'ed" not in row:
                try:
                    size = ([_f for _f in row.split(' ') if _f])[8]
                except IndexError:
                    LOG.error("Skipping unexpected drbd-overview output: %s" % row)
                    continue
                unit = size[-1]
                size = float(size[:-1])

                # drbd-overview can display the units in M or G
                if unit == 'M':
                    size = size / 1024
                elif unit == 'T':
                    size = size * 1024

                if 'drbd-pgsql' in row:
                    drbd_pgsql_size = size
                if 'drbd-cgcs' in row:
                    drbd_cgcs_size = size
                if 'drbd-extension' in row:
                    drbd_extension_size = size
                if 'drbd-patch-vault' in row:
                    drbd_patch_size = size
                if 'drbd-etcd' in row:
                    drbd_etcd_size = size
                if 'drbd-dockerdistribution' in row:
                    dockerdistribution_size = size

        lvdisplay_dict = self.get_controllerfs_lv_sizes(context)
        if lvdisplay_dict.get('pgsql-lv', None):
            pgsql_lv_size = float(lvdisplay_dict['pgsql-lv'])
        if lvdisplay_dict.get('cgcs-lv', None):
            cgcs_lv_size = float(lvdisplay_dict['cgcs-lv'])
        if lvdisplay_dict.get('extension-lv', None):
            extension_lv_size = float(lvdisplay_dict['extension-lv'])
        if lvdisplay_dict.get('patch-vault-lv', None):
            patch_lv_size = float(lvdisplay_dict['patch-vault-lv'])
        if lvdisplay_dict.get('etcd-lv', None):
            etcd_lv_size = float(lvdisplay_dict['etcd-lv'])
        if lvdisplay_dict.get('dockerdistribution-lv', None):
            dockerdistribution_lv_size = float(lvdisplay_dict['dockerdistribution-lv'])

        LOG.info("drbd-overview: pgsql-%s, cgcs-%s, extension-%s, patch-vault-%s, etcd-%s, dockerdistribution-%s", drbd_pgsql_size, drbd_cgcs_size, drbd_extension_size, drbd_patch_size, drbd_etcd_size, dockerdistribution_size)
        LOG.info("lvdisplay: pgsql-%s, cgcs-%s, extension-%s, patch-vault-%s, etcd-%s, dockerdistribution-%s", pgsql_lv_size, cgcs_lv_size, extension_lv_size, patch_lv_size, etcd_lv_size, dockerdistribution_lv_size)

        drbd_fs_updated = []
        if math.ceil(drbd_pgsql_size) < math.ceil(pgsql_lv_size):
            drbd_fs_updated.append(constants.DRBD_PGSQL)
        if math.ceil(drbd_cgcs_size) < math.ceil(cgcs_lv_size):
            drbd_fs_updated.append(constants.DRBD_CGCS)
        if math.ceil(drbd_extension_size) < math.ceil(extension_lv_size):
            drbd_fs_updated.append(constants.DRBD_EXTENSION)
        if math.ceil(drbd_patch_size) < math.ceil(patch_lv_size):
            drbd_fs_updated.append(constants.DRBD_PATCH_VAULT)
        if math.ceil(drbd_etcd_size) < math.ceil(etcd_lv_size):
            drbd_fs_updated.append(constants.DRBD_ETCD)
        if math.ceil(dockerdistribution_size) < math.ceil(dockerdistribution_lv_size):
            drbd_fs_updated.append(constants.DRBD_DOCKER_DISTRIBUTION)

        return drbd_fs_updated

    def _config_resize_filesystems(self, context, standby_host):
        """Resize the filesystems upon completion of storage config.
           Retry in case of errors or racing issues when resizing fails."""

        LOG.warn("resizing filesystems")

        progress = ""
        retry_attempts = 3
        rc = False
        with open(os.devnull, "w"):
            try:
                if standby_host:
                    if not self._drbd_connected():
                        LOG.info("resizing filesystems WAIT for drbd connected")
                        return rc
                    else:
                        LOG.info("resizing filesystems drbd connected")

                if not os.path.isfile(CFS_DRBDADM_RECONFIGURED):
                    progress = "drbdadm resize all"
                    if standby_host:
                        cmd = ["drbdadm", "resize", "all"]
                    else:
                        cmd = ["drbdadm", "--", "--assume-peer-has-space", "resize", "all"]
                    stdout, __ = cutils.execute(*cmd, attempts=retry_attempts, run_as_root=True)
                    LOG.info("Performed %s" % progress)
                    cutils.touch(CFS_DRBDADM_RECONFIGURED)

                pgsql_resized = False
                cgcs_resized = False
                extension_resized = False
                patch_resized = False
                etcd_resized = False
                dockerdistribution_resized = False
                loop_timeout = 0
                drbd_fs_updated = self._drbd_fs_updated(context)
                if not drbd_fs_updated:
                    rc = True
                else:
                    while(loop_timeout <= 5):
                        if constants.DRBD_PGSQL in drbd_fs_updated:
                            if (not pgsql_resized and
                                (not standby_host or (standby_host and
                                 constants.DRBD_PGSQL in self._drbd_fs_sync()))):
                                # database_gib /var/lib/postgresql
                                progress = "resize2fs drbd0"
                                cmd = ["resize2fs", "/dev/drbd0"]
                                stdout, __ = cutils.execute(*cmd, attempts=retry_attempts, run_as_root=True)
                                LOG.info("Performed %s" % progress)
                                pgsql_resized = True

                        if constants.DRBD_CGCS in drbd_fs_updated:
                            if (not cgcs_resized and
                                (not standby_host or (standby_host and
                                 constants.DRBD_CGCS in self._drbd_fs_sync()))):
                                # cgcs_gib /opt/cgcs
                                progress = "resize2fs drbd3"
                                cmd = ["resize2fs", "/dev/drbd3"]
                                stdout, __ = cutils.execute(*cmd, attempts=retry_attempts, run_as_root=True)
                                LOG.info("Performed %s" % progress)
                                cgcs_resized = True

                        if constants.DRBD_EXTENSION in drbd_fs_updated:
                            if (not extension_resized and
                                (not standby_host or (standby_host and
                                 constants.DRBD_EXTENSION in self._drbd_fs_sync()))):
                                # extension_gib /opt/extension
                                progress = "resize2fs drbd5"
                                cmd = ["resize2fs", "/dev/drbd5"]
                                stdout, __ = cutils.execute(*cmd, attempts=retry_attempts, run_as_root=True)
                                LOG.info("Performed %s" % progress)
                                extension_resized = True

                        if constants.DRBD_PATCH_VAULT in drbd_fs_updated:
                            if (not patch_resized and
                                (not standby_host or (standby_host and
                                 constants.DRBD_PATCH_VAULT in self._drbd_fs_sync()))):
                                # patch_gib /opt/patch-vault
                                progress = "resize2fs drbd6"
                                cmd = ["resize2fs", "/dev/drbd6"]
                                stdout, __ = cutils.execute(*cmd, attempts=retry_attempts, run_as_root=True)
                                LOG.info("Performed %s" % progress)
                                patch_resized = True

                        if constants.DRBD_ETCD in drbd_fs_updated:
                            if (not etcd_resized and
                                (not standby_host or (standby_host and
                                 constants.DRBD_ETCD in self._drbd_fs_sync()))):
                                # patch_gib /opt/etcd
                                progress = "resize2fs drbd7"
                                cmd = ["resize2fs", "/dev/drbd7"]
                                stdout, __ = cutils.execute(*cmd, attempts=retry_attempts, run_as_root=True)
                                LOG.info("Performed %s" % progress)
                                etcd_resized = True

                        if constants.DRBD_DOCKER_DISTRIBUTION in drbd_fs_updated:
                            if (not dockerdistribution_resized and
                                (not standby_host or (standby_host and
                                 constants.DRBD_DOCKER_DISTRIBUTION in self._drbd_fs_sync()))):
                                # patch_gib /var/lib/docker-distribution
                                progress = "resize2fs drbd8"
                                cmd = ["resize2fs", "/dev/drbd8"]
                                stdout, __ = cutils.execute(*cmd, attempts=retry_attempts, run_as_root=True)
                                LOG.info("Performed %s" % progress)
                                dockerdistribution_resized = True

                        if not standby_host:
                            rc = True
                            break

                        all_resized = True
                        for drbd in drbd_fs_updated:
                            if drbd == constants.DRBD_PGSQL and not pgsql_resized:
                                all_resized = False
                            elif drbd == constants.DRBD_CGCS and not cgcs_resized:
                                all_resized = False
                            elif drbd == constants.DRBD_EXTENSION and not extension_resized:
                                all_resized = False
                            elif drbd == constants.DRBD_PATCH_VAULT and not patch_resized:
                                all_resized = False
                            elif drbd == constants.DRBD_ETCD and not etcd_resized:
                                all_resized = False
                            elif drbd == constants.DRBD_DOCKER_DISTRIBUTION and not dockerdistribution_resized:
                                all_resized = False

                        if all_resized:
                            LOG.info("resizing filesystems completed")
                            rc = True
                            break

                        loop_timeout += 1
                        time.sleep(1)
                    else:
                        LOG.warn("resizing filesystems not completed")

            except exception.ProcessExecutionError as ex:
                LOG.warn("Failed to perform storage resizing (cmd: '%(cmd)s', "
                         "return code: %(rc)s, stdout: '%(stdout)s).', "
                         "stderr: '%(stderr)s'" %
                         {"cmd": " ".join(cmd), "stdout": ex.stdout,
                          "stderr": ex.stderr, "rc": ex.exit_code})

        return rc

    # Retrying a few times and waiting between each retry should provide
    # enough protection in the unlikely case LVM's own locking mechanism
    # is unreliable.
    @retry(stop_max_attempt_number=5, wait_fixed=1000,
           retry_on_result=(lambda x: True if x == constants.CINDER_RESIZE_FAILURE else False))
    def _resize_cinder_volumes(self, delayed=False):
        """Resize cinder-volumes drbd-backed PV and cinder-volumes-pool LV to
        match the new (increased) size"""

        if not StorageBackendConfig.has_backend_configured(
            self.dbapi,
            constants.CINDER_BACKEND_LVM
        ):
            return

        cmd = []
        try:
            if delayed:
                cmd = ["drbdadm", "cstate", constants.CINDER_LVM_DRBD_RESOURCE]
                stdout, __ = cutils.execute(*cmd, run_as_root=True)
                if utils.get_system_mode(self.dbapi) != constants.SYSTEM_MODE_SIMPLEX:
                    # Wait for drbd connect.
                    # It is possible that drbd is already in sync state
                    # (e.g. When the disk partition for the cinder-volumes is
                    # increased on the newly standby controller after controller
                    # swact), so we check for drbd "Connected" and "SyncSource".
                    # It is also possible that drbd is in "PausedSyncS" if we are
                    # doing serial syncing and another FS is syncing.
                    if ("Connected" not in stdout and
                            "SyncSource" not in stdout and
                            "PausedSyncS" not in stdout):
                        return constants.CINDER_RESIZE_FAILURE
                else:
                    # For simplex we just need to have drbd up
                    if "WFConnection" not in stdout:
                        return constants.CINDER_RESIZE_FAILURE

            # Force a drbd resize on AIO SX as peer is not configured.
            # DRBD resize is automatic when both peers are connected.
            if utils.get_system_mode(self.dbapi) == constants.SYSTEM_MODE_SIMPLEX:
                # get the commands executed by 'drbdadm resize' and append some options
                cmd = ["drbdadm", "--dry-run", "resize", constants.CINDER_LVM_DRBD_RESOURCE]
                stdout, __ = cutils.execute(*cmd, run_as_root=True)
                for line in stdout.splitlines():
                    if 'drbdsetup resize' in line:
                        cmd = line.split()
                        cmd = cmd + ['--assume-peer-has-space=yes']
                    else:
                        cmd = line.split()
                    __, __ = cutils.execute(*cmd, run_as_root=True)

            # Resize the pv
            cmd = ["pvresize", "/dev/drbd/by-res/%s/0" % constants.CINDER_LVM_DRBD_RESOURCE]
            stdout, __ = cutils.execute(*cmd, run_as_root=True)
            LOG.info("Resized %s PV" % constants.CINDER_LVM_DRBD_RESOURCE)

            # Resize the Thin pool LV. Abort if pool doesn't exist, it may not be configured at all
            data_lv = "%s/%s" % (constants.LVG_CINDER_VOLUMES, constants.CINDER_LVM_POOL_LV)
            metadata_lv = "%s/%s" % (constants.LVG_CINDER_VOLUMES, constants.CINDER_LVM_POOL_META_LV)
            cmd = ["lvs", "-o", "vg_name,lv_name", "--noheadings", "--separator", "/", data_lv]
            stdout, __ = cutils.trycmd(*cmd, attempts=3, run_as_root=True)
            if data_lv in stdout:
                # Extend metadata portion of the thinpool to be at least 1 GiB
                cmd = ["lvextend", "-L1g", metadata_lv]
                # It's ok if it returns 0 or 5 (ECMD_FAILED in lvm cmds), it most likely
                # means that the size is equal or greater than what we intend to configure.
                # But we have to retry in case it gets ECMD_PROCESSED which seems to happen
                # randomly and rarely yet is important not to fail the operation.
                stdout, __ = cutils.execute(*cmd, check_exit_code=[0, 5],
                                            run_as_root=True, attempts=3)

                # Get the VG size and VG free
                cmd = ['vgs', 'cinder-volumes', '-o', 'vg_size,vg_free',
                       '--noheadings', '--units', 'm', '--nosuffix']
                stdout, __ = cutils.execute(*cmd, run_as_root=True, attempts=3)
                vg_size_str, vg_free_str = stdout.split()
                vg_size = float(vg_size_str)
                vg_free = float(vg_free_str)

                # Leave ~1% in VG for metadata expansion and recovery,
                # result rounded to multiple of block size (4MiB)
                extend_lv_by = (vg_free - vg_size * 0.01) // 4 * 4

                LOG.info("Cinder-volumes VG size: %(size)sMiB free: %(free)sMiB, "
                         "cinder volumes pool delta to desired 99%% of VG: %(delta)sMiB" %
                         {"size": vg_size, "free": vg_free, "delta": extend_lv_by})

                if extend_lv_by > 0:
                    # Get current size of the data LV for logging
                    cmd = ['lvs', '-o', 'lv_size', '--noheadings',
                           '--units', 'm', '--nosuffix', data_lv]
                    stdout, __ = cutils.execute(*cmd, run_as_root=True, attempts=3)
                    data_old_size = float(stdout)

                    # Extend the data part of the thinpool
                    cmd = ["lvextend", "-L+%.2fm" % extend_lv_by, data_lv]
                    cutils.execute(*cmd, check_exit_code=[0, 5],
                                   run_as_root=True, attempts=3)

                    # Get new size of the data LV for logging
                    cmd = ['lvs', '-o', 'lv_size', '--noheadings',
                           '--units', 'm', '--nosuffix', data_lv]
                    stdout, __ = cutils.execute(*cmd, run_as_root=True, attempts=3)
                    data_new_size = float(stdout)

                    LOG.info(_("Resized %(name)s thinpool LV from %(old)sMiB to %(new)sMiB") %
                             {"name": constants.CINDER_LVM_POOL_LV,
                              "old": data_old_size,
                              "new": data_new_size})
                else:
                    LOG.info("Cinder %s already uses 99%% or more of "
                             "available space" % constants.CINDER_LVM_POOL_LV)
        except exception.ProcessExecutionError as ex:
            LOG.warn("Failed to resize cinder volumes (cmd: '%(cmd)s', "
                     "return code: %(rc)s, stdout: '%(stdout)s).', "
                     "stderr: '%(stderr)s'" %
                     {"cmd": " ".join(cmd), "stdout": ex.stdout,
                      "stderr": ex.stderr, "rc": ex.exit_code})
            # We avoid re-raising this as it may brake critical operations after this one
            return constants.CINDER_RESIZE_FAILURE

    def _config_out_of_date(self, ihost_obj):
        target = ihost_obj.config_target
        applied = ihost_obj.config_applied
        hostname = ihost_obj.hostname

        if not hostname:
            hostname = ihost_obj.get('uuid') or ""

        if not target:
            LOG.warn("%s: iconfig no target, but config %s applied" %
                     (hostname, applied))
            return False
        elif target == applied:
            if ihost_obj.personality == constants.CONTROLLER:

                controller_fs_list = self.dbapi.controller_fs_get_list()
                for controller_fs in controller_fs_list:
                    if controller_fs['replicated']:
                        if (controller_fs.get('state') ==
                           constants.CONTROLLER_FS_RESIZING_IN_PROGRESS):
                            LOG.info("%s: drbd resize config pending. "
                                     "manifests up to date: "
                                     "target %s, applied %s " %
                                     (hostname, target, applied))
                            return True
            else:
                LOG.info("%s: iconfig up to date: target %s, applied %s " %
                         (hostname, target, applied))
                return False
        else:
            LOG.warn("%s: iconfig out of date: target %s, applied %s " %
                     (hostname, target, applied))
            return True

    @staticmethod
    def _get_fm_entity_instance_id(ihost_obj):
        """
        Create 'entity_instance_id' from ihost_obj data
        """

        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                        ihost_obj.hostname)
        return entity_instance_id

    def _log_host_create(self, host, reason=None):
        """
        Create host discovery event customer log.
        """
        if host.hostname:
            hostid = host.hostname
        else:
            hostid = host.mgmt_mac

        if reason is not None:
            reason_text = ("%s has been 'discovered' on the network. (%s)" %
                (hostid, reason))
        else:
            reason_text = ("%s has been 'discovered'." % hostid)

        # action event -> FM_ALARM_TYPE_4 = 'equipment'
        # FM_ALARM_SEVERITY_CLEAR to be consistent with 200.x series Info
        log_data = {'hostid': hostid,
                    'event_id': fm_constants.FM_LOG_ID_HOST_DISCOVERED,
                    'entity_type': fm_constants.FM_ENTITY_TYPE_HOST,
                    'entity': 'host=%s.event=discovered' % hostid,
                    'fm_severity': fm_constants.FM_ALARM_SEVERITY_CLEAR,
                    'fm_event_type': fm_constants.FM_ALARM_TYPE_4,
                    'reason_text': reason_text,
                    }
        self.fm_log.customer_log(log_data)

    def _update_alarm_status(self, context, ihost_obj):
        self._do_update_alarm_status(
            context,
            ihost_obj,
            constants.CONFIG_STATUS_OUT_OF_DATE
        )

    def _do_update_alarm_status(self, context, ihost_obj, status):
        """Check config and update FM alarm"""

        entity_instance_id = self._get_fm_entity_instance_id(ihost_obj)

        save_required = False
        if self._config_out_of_date(ihost_obj) or \
                status == constants.CONFIG_STATUS_REINSTALL:
            LOG.warn("SYS_I Raise system config alarm: host %s "
                     "config applied: %s  vs. target: %s." %
                     (ihost_obj.hostname,
                      ihost_obj.config_applied,
                      ihost_obj.config_target))

            fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_SYSCONFIG_OUT_OF_DATE,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
                reason_text=(_("%s Configuration is out-of-date.") %
                               ihost_obj.hostname),
                alarm_type=fm_constants.FM_ALARM_TYPE_7,  # operational
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_75,
                proposed_repair_action=_(
                    "Lock and unlock host %s to update config." %
                    ihost_obj.hostname),
                service_affecting=True)

            self.fm_api.set_fault(fault)

            if not ihost_obj.config_status:
                ihost_obj.config_status = status
                save_required = True
            elif (status != ihost_obj.config_status and
               status == constants.CONFIG_STATUS_REINSTALL):
                ihost_obj.config_status = status
                save_required = True

            if save_required:
                ihost_obj.save(context)

        else:
            # better to clear since a GET may block
            LOG.info("SYS_I Clear system config alarm: %s target config %s" %
                     (ihost_obj.hostname, ihost_obj.config_target))

            self.fm_api.clear_fault(
                fm_constants.FM_ALARM_ID_SYSCONFIG_OUT_OF_DATE,
                entity_instance_id)

            # Do not clear the config status if there is a reinstall pending.
            if (ihost_obj.config_status != constants.CONFIG_STATUS_REINSTALL):
                ihost_obj.config_status = None
                ihost_obj.save(context)

    @staticmethod
    def _config_is_reboot_required(config_uuid):
        """Check if the supplied config_uuid has the reboot required flag

        :param config_uuid UUID object or UUID string
        :return True if reboot is required, False otherwise
        """
        return int(uuid.UUID(config_uuid)) & CONFIG_REBOOT_REQUIRED

    @staticmethod
    def _config_set_reboot_required(config_uuid):
        """Set the reboot required flag for the supplied UUID

        :param config_uuid UUID object or UUID string
        :return The modified UUID as a string
        :rtype str
        """
        uuid_str = str(config_uuid)
        uuid_int = int(uuid.UUID(uuid_str)) | CONFIG_REBOOT_REQUIRED
        return str(uuid.UUID(int=uuid_int))

    @staticmethod
    def _config_clear_reboot_required(config_uuid):
        """Clear the reboot required flag for the supplied UUID

        :param config_uuid UUID object or UUID string
        :return The modified UUID as a string
        :rtype str
        """
        uuid_str = str(config_uuid)
        uuid_int = int(uuid.UUID(uuid_str)) & ~CONFIG_REBOOT_REQUIRED
        return str(uuid.UUID(int=uuid_int))

    @staticmethod
    def _config_flip_reboot_required(config_uuid):
        """flip the reboot required flag for the supplied UUID

        :param config_uuid UUID object or UUID string
        :return The modified UUID as a string
        :rtype str
        """
        uuid_str = str(config_uuid)
        uuid_int = int(uuid.UUID(uuid_str)) ^ CONFIG_REBOOT_REQUIRED
        return str(uuid.UUID(int=uuid_int))

    def _update_host_config_reinstall(self, context, ihost_obj):
        """ update the host to be 'reinstall required'
        """
        self._do_update_alarm_status(
            context,
            ihost_obj,
            constants.CONFIG_STATUS_REINSTALL
        )

    def _update_host_config_target(self, context, ihost_obj, config_uuid):
        """Based upon config update, update config status."""

        lock_name = LOCK_NAME_UPDATE_CONFIG + ihost_obj.uuid

        @cutils.synchronized(lock_name, external=False)
        def _sync_update_host_config_target(self,
                                            context, ihost_obj, config_uuid):
            if ihost_obj.config_target != config_uuid:
                # promote the current config to reboot required if a pending
                # reboot required is still present
                if (ihost_obj.config_target and
                        ihost_obj.config_applied != ihost_obj.config_target):
                    if self._config_is_reboot_required(ihost_obj.config_target):
                        config_uuid = self._config_set_reboot_required(config_uuid)
                ihost_obj.config_target = config_uuid
                ihost_obj.save(context)
            if cutils.is_initial_config_complete():
                self._update_alarm_status(context, ihost_obj)

        _sync_update_host_config_target(self, context, ihost_obj, config_uuid)

    def _update_host_config_applied(self, context, ihost_obj, config_uuid):
        """Based upon agent update, update config status."""

        lock_name = LOCK_NAME_UPDATE_CONFIG + ihost_obj.uuid

        @cutils.synchronized(lock_name, external=False)
        def _sync_update_host_config_applied(self,
                                             context, ihost_obj, config_uuid):
            if ihost_obj.config_applied != config_uuid:
                ihost_obj.config_applied = config_uuid
                ihost_obj.save(context)
            if cutils.is_initial_config_complete():
                self._update_alarm_status(context, ihost_obj)

        _sync_update_host_config_applied(self, context, ihost_obj, config_uuid)

    def _update_subfunctions(self, context, ihost_obj):
        """Update subfunctions."""

        ihost_obj.invprovision = constants.PROVISIONED
        ihost_obj.save(context)

    def _config_reinstall_hosts(self, context, personalities):
        """ update the hosts configuration status for all host to be "
            reinstall is required.
        """
        hosts = self.dbapi.ihost_get_list()
        for host in hosts:
            if host.personality and host.personality in personalities:
                self._update_host_config_reinstall(context, host)

    def _config_update_hosts(self, context, personalities, host_uuids=None,
                             reboot=False):
        """"Update the hosts configuration status for all hosts affected
        :param context: request context.
        :param personalities: list of affected host personalities
        :parm host_uuids (optional): hosts whose config_target will be updated
        :param reboot (optional): indicates if a reboot is required to apply
        :                         update
        :return The UUID of the configuration generation
        """

        # generate a new configuration identifier for this update
        config_uuid = uuid.uuid4()

        # Scope the UUID according to the reboot requirement of the update.
        # This is done to prevent dynamic updates from overriding the reboot
        # requirement of a previous update that required the host to be locked
        # and unlocked in order to apply the full set of updates.
        if reboot:
            config_uuid = self._config_set_reboot_required(config_uuid)
        else:
            config_uuid = self._config_clear_reboot_required(config_uuid)

        if not host_uuids:
            hosts = self.dbapi.ihost_get_list()
        else:
            hosts = [self.dbapi.ihost_get(host_uuid) for host_uuid in host_uuids]

        for host in hosts:
            if host.personality and host.personality in personalities:
                self._update_host_config_target(context, host, config_uuid)

        LOG.info("_config_update_hosts config_uuid=%s" % config_uuid)
        return config_uuid

    def _config_update_puppet(self, config_uuid, config_dict, force=False,
                              host_uuids=None):
        """Regenerate puppet hiera data files for each affected host that is
           provisioned. If host_uuid is provided, only that host's puppet
           hiera data file will be regenerated.
        """
        host_updated = False

        personalities = config_dict['personalities']
        if not host_uuids:
            hosts = self.dbapi.ihost_get_list()
        else:
            hosts = [self.dbapi.ihost_get(host_uuid) for host_uuid in host_uuids]

        for host in hosts:
            if host.personality in personalities:
                # We will allow controller nodes to re-generate manifests
                # when in an "provisioning" state. This will allow for
                # example the ntp configuration to be changed on an CPE
                # node before the "worker_config_complete" has been
                # executed.
                if (force or
                    host.invprovision == constants.PROVISIONED or
                    (host.invprovision == constants.PROVISIONING and
                     host.personality == constants.CONTROLLER)):
                    self._puppet.update_host_config(host, config_uuid)
                    host_updated = True
                else:
                    LOG.info(
                        "Cannot regenerate the configuration for %s, "
                        "the node is not ready. invprovision=%s" %
                        (host.hostname, host.invprovision))

        # ensure the system configuration is also updated if hosts require
        # a reconfiguration
        if host_updated:
            self._puppet.update_system_config()
            self._puppet.update_secure_system_config()

    def _config_update_file(self,
                            context,
                            config_uuid,
                            config_dict):

        """Apply the file on all hosts affected by supplied personalities.

        :param context: request context.
        :param config_uuid: configuration uuid
        :param config_dict: dictionary of attributes, such as:
        :          {personalities: list of host personalities
        :           file_names: list of full path file names
        :           file_content: file contents
        :           action: put(full replacement), patch
        :           action_key: match key (for patch only)
        :          }
        """
        # Ensure hiera data is updated prior to active apply.
        self._config_update_puppet(config_uuid, config_dict)

        rpcapi = agent_rpcapi.AgentAPI()
        try:
            rpcapi.iconfig_update_file(context,
                                       iconfig_uuid=config_uuid,
                                       iconfig_dict=config_dict)
        except Exception as e:
            LOG.info("Error: %s" % str(e))

    def _config_apply_runtime_manifest(self,
                                       context,
                                       config_uuid,
                                       config_dict,
                                       host_uuids=None,
                                       force=False):

        """Apply manifests on all hosts affected by the supplied personalities.
           If host_uuid is set, only update hiera data for that host
        """
        if "classes" in config_dict:
            LOG.info("applying runtime manifest config_uuid=%s, classes: %s" % (
                config_uuid, config_dict["classes"]))
        else:
            LOG.info("applying runtime manifest config_uuid=%s" % config_uuid)

        # Update hiera data for all hosts prior to runtime apply if host_uuid
        # is not set. If host_uuid is set only update hiera data for that host
        self._config_update_puppet(config_uuid,
                                   config_dict,
                                   host_uuids=host_uuids,
                                   force=force)

        config_dict.update({'force': force})
        rpcapi = agent_rpcapi.AgentAPI()
        rpcapi.config_apply_runtime_manifest(context,
                                             config_uuid=config_uuid,
                                             config_dict=config_dict)

    def _update_ipv_device_path(self, idisk, ipv):
        if not idisk.device_path:
            return
        pv_dict = {'disk_or_part_device_path': idisk.device_path}
        self.dbapi.ipv_update(ipv['uuid'], pv_dict)

    def iinterface_get_providernets(self, context, pn_names=None):
        """
        Gets names and MTUs for providernets in neutron

        If param 'pn_names' is provided, returns dict for
        only specified providernets, else: returns all
        providernets in neutron

        """
        return self._openstack.get_providernetworksdict(pn_names)

    def iinterfaces_get_by_ihost_nettype(self,
                                         context,
                                         ihost_uuid,
                                         nettype=None):
        """
        Gets iinterfaces list by ihost and network type.

        If param 'nettype' is provided, returns list for
        only specified nettype, else: returns all
        iinterfaces in the host.

        """
        try:
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)
        except exc.DetachedInstanceError:
            # A rare DetachedInstanceError exception may occur, retry
            LOG.warn("Detached Instance Error,  retry "
                     "iinterface_get_by_ihost %s" % ihost_uuid)
            iinterfaces = self.dbapi.iinterface_get_by_ihost(ihost_uuid,
                                                             expunge=True)

        if nettype:
            iinterfaces[:] = [i for i in iinterfaces if
                              i.networktype == nettype]
        return iinterfaces

    def mgmt_ip_set_by_ihost(self,
                             context,
                             ihost_uuid,
                             interface_id,
                             mgmt_ip):
        """Call sysinv to update host mgmt_ip
           (removes previous entry if necessary)

        :param context: an admin context
        :param ihost_uuid: ihost uuid
        :param interface_id: interface id value
        :param mgmt_ip: mgmt_ip to set, None for removal
        :returns: Address
        """

        LOG.debug("Calling mgmt ip set for ihost %s, ip %s" % (ihost_uuid,
            mgmt_ip))

        # Check for and remove existing addrs on mgmt subnet & host
        ihost = self.dbapi.ihost_get(ihost_uuid)

        for address in self.dbapi.addresses_get_by_interface(interface_id):
            if address['address'] == mgmt_ip:
                # Address already exists, can return early
                return address
            if not address['name']:
                self.dbapi.address_destroy(address['uuid'])

        try:
            if ihost.get('hostname'):
                self._generate_dnsmasq_hosts_file()
        except Exception:
            LOG.warning("Failed to remove mgmt ip from dnsmasq.hosts")

        if mgmt_ip is None:
            # Remove DHCP lease when removing mgmt interface
            self._unallocate_address(ihost.hostname,
                                     constants.NETWORK_TYPE_MGMT)
            self._generate_dnsmasq_hosts_file()
            # Just doing a remove, return early
            return

        # Check for IPv4 or IPv6
        if not cutils.is_valid_ipv4(mgmt_ip):
            if not cutils.is_valid_ipv6(mgmt_ip):
                LOG.error("Invalid mgmt_ip=%s" % mgmt_ip)
                return False
        address = self._create_or_update_address(context, ihost.hostname,
                                                 mgmt_ip,
                                                 constants.NETWORK_TYPE_MGMT,
                                                 interface_id)
        return address

    def neutron_extension_list(self, context):
        """
        Send a request to neutron to query the supported extension list.
        """
        response = self._openstack.neutron_extension_list(context)
        return response

    def neutron_bind_interface(self, context, host_uuid, interface_uuid,
                               network_type, providernets, mtu,
                               vlans=None, test=False):
        """
        Send a request to neutron to bind an interface to a set of provider
        networks, and inform neutron of some key attributes of the interface
        for semantic checking purposes.
        """
        response = self._openstack.bind_interface(
            context, host_uuid, interface_uuid, network_type,
            providernets, mtu, vlans=vlans, test=test)
        return response

    def neutron_unbind_interface(self, context, host_uuid, interface_uuid):
        """
        Send a request to neutron to unbind an interface from a set of
        provider networks.
        """
        response = self._openstack.unbind_interface(
            context, host_uuid, interface_uuid)
        return response

    def vim_host_add(self, context, api_token, ihost_uuid,
                     hostname, subfunctions, administrative,
                     operational, availability,
                     subfunction_oper, subfunction_avail,
                     timeout_in_secs):
        """
        Asynchronously, notify VIM of host add
        """

        vim_resp = vim_api.vim_host_add(api_token,
                                        ihost_uuid,
                                        hostname,
                                        subfunctions,
                                        administrative,
                                        operational,
                                        availability,
                                        subfunction_oper,
                                        subfunction_avail,
                                        timeout_in_secs)
        LOG.info("vim_host_add resp=%s" % vim_resp)
        return vim_resp

    def mtc_host_add(self, context, mtc_address, mtc_port, ihost_mtc_dict):
        """
        Asynchronously, notify mtc of host add
        """
        mtc_response_dict = cutils.notify_mtc_and_recv(mtc_address,
                                                       mtc_port,
                                                       ihost_mtc_dict)

        if (mtc_response_dict['status'] != 'pass'):
            LOG.error("Failed mtc_host_add=%s" % ihost_mtc_dict)

        return

    def notify_subfunctions_config(self, context, ihost_uuid, ihost_notify_dict):
        """
        Notify sysinv of host subfunctions configuration status
        """

        subfunctions_configured = ihost_notify_dict.get(
            'subfunctions_configured') or ""
        try:
            ihost_obj = self.dbapi.ihost_get(ihost_uuid)
        except Exception as e:
            LOG.exception("notify_subfunctions_config e=%s "
                          "ihost=%s subfunctions=%s" %
                          (e, ihost_uuid, subfunctions_configured))
            return False

        if not subfunctions_configured:
            self._update_subfunctions(context, ihost_obj)

    def ilvg_get_nova_ilvg_by_ihost(self,
                                    context,
                                    ihost_uuid):
        """
        Gets the nova ilvg by ihost.

        returns the nova ilvg if added to the host else returns empty
        list

        """
        ilvgs = self.dbapi.ilvg_get_by_ihost(ihost_uuid)

        ilvgs[:] = [i for i in ilvgs if
                    (i.lvm_vg_name == constants.LVG_NOVA_LOCAL)]

        return ilvgs

    def _add_port_to_list(self, interface_id, networktype, port_list):
        info = {}
        ports = self.dbapi.port_get_all(interfaceid=interface_id)
        if ports:
            info['name'] = ports[0]['name']
            info['numa_node'] = ports[0]['numa_node']
            info['networktype'] = networktype
            if info not in port_list:
                port_list.append(info)
        return port_list

    def platform_interfaces(self, context, ihost_id):
        """
        Gets the platform interfaces and associated numa nodes
        """
        info_list = []
        interface_list = self.dbapi.iinterface_get_all(ihost_id, expunge=True)
        for interface in interface_list:
            ntype = interface['networktype']
            if (ntype == constants.NETWORK_TYPE_CLUSTER_HOST or
                    ntype == constants.NETWORK_TYPE_MGMT):
                if interface['iftype'] == 'vlan' or \
                                interface['iftype'] == 'ae':
                    for uses_if in interface['uses']:
                        for i in interface_list:
                            if i['ifname'] == str(uses_if):
                                if i['iftype'] == 'ethernet':
                                    info_list = self._add_port_to_list(i['id'],
                                                                       ntype,
                                                                       info_list)
                                elif i['iftype'] == 'ae':
                                    for uses in i['uses']:
                                        for a in interface_list:
                                            if a['ifname'] == str(uses) and \
                                                    a['iftype'] == 'ethernet':
                                                info_list = self._add_port_to_list(
                                                                    a['id'],
                                                                    ntype,
                                                                    info_list)
                elif interface['iftype'] == 'ethernet':
                    info_list = self._add_port_to_list(interface['id'],
                                                       ntype,
                                                       info_list)

        LOG.info("platform_interfaces host_id=%s info_list=%s" %
                 (ihost_id, info_list))
        return info_list

    def ibm_deprovision_by_ihost(self, context, ihost_uuid, ibm_msg_dict):
        """Update ihost upon notification of board management controller
           deprovisioning.

        This method also allows a dictionary of values to be passed in to
        affort additional controls, if and as needed.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param ibm_msg_dict: values for additional controls or changes
        :returns: pass or fail
        """
        LOG.info("ibm_deprovision_by_ihost=%s msg=%s" %
                 (ihost_uuid, ibm_msg_dict))

        isensorgroups = self.dbapi.isensorgroup_get_by_ihost(ihost_uuid)

        for isensorgroup in isensorgroups:
            isensors = self.dbapi.isensor_get_by_sensorgroup(isensorgroup.uuid)
            for isensor in isensors:
                self.dbapi.isensor_destroy(isensor.uuid)

            self.dbapi.isensorgroup_destroy(isensorgroup.uuid)

        isensors = self.dbapi.isensor_get_by_ihost(ihost_uuid)
        if isensors:
            LOG.info("ibm_deprovision_by_ihost=%s Non-group sensors=%s" %
                     (ihost_uuid, isensors))
            for isensor in isensors:
                self.dbapi.isensor_destroy(isensor.uuid)

        isensors = self.dbapi.isensor_get_by_ihost(ihost_uuid)

        return True

    def configure_ttys_dcd(self, context, uuid, ttys_dcd):
        """Notify agent to configure the dcd with the supplied data.

        :param context: an admin context.
        :param uuid: the host uuid
        :param ttys_dcd: the flag to enable/disable dcd
        """

        LOG.debug("ConductorManager.configure_ttys_dcd: sending dcd update %s "
                  "%s to agents" % (ttys_dcd, uuid))
        rpcapi = agent_rpcapi.AgentAPI()
        rpcapi.configure_ttys_dcd(context, uuid=uuid, ttys_dcd=ttys_dcd)

    def get_host_ttys_dcd(self, context, ihost_id):
        """
        Retrieve the serial line carrier detect state for a given host
        """
        ihost = self.dbapi.ihost_get(ihost_id)
        if ihost:
            return ihost.ttys_dcd
        else:
            LOG.error("Host: %s not found in database" % ihost_id)
            return None

    def _import_load_error(self, new_load):
        """
        Update the load state to 'error' in the database
        """
        patch = {'state': constants.ERROR_LOAD_STATE}
        try:
            self.dbapi.load_update(new_load['id'], patch)

        except exception.SysinvException as e:
            LOG.exception(e)
            raise exception.SysinvException(_("Error updating load in "
                                              "database for load id: %s")
                                            % new_load['id'])

    def start_import_load(self, context, path_to_iso, path_to_sig):
        """
        Mount the ISO and validate the load for import
        """
        loads = self.dbapi.load_get_list()

        active_load = cutils.get_active_load(loads)

        cutils.validate_loads_for_import(loads)

        current_version = active_load.software_version

        if not os.path.exists(path_to_iso):
            raise exception.SysinvException(_("Specified path not found %s") %
                                            path_to_iso)
        if not os.path.exists(path_to_sig):
            raise exception.SysinvException(_("Specified path not found %s") %
                                            path_to_sig)

        if not verify_files([path_to_iso], path_to_sig):
            raise exception.SysinvException(_("Signature %s could not be verified") %
                                            path_to_sig)

        mounted_iso = None
        mntdir = tempfile.mkdtemp(dir='/tmp')
        # Attempt to mount iso
        try:
            mounted_iso = cutils.ISO(path_to_iso, mntdir)
            # Note: iso will be unmounted when object goes out of scope

        except subprocess.CalledProcessError:
            raise exception.SysinvException(_(
                "Unable to mount iso"))

        metadata_file_path = mntdir + '/upgrades/metadata.xml'
        if not os.path.exists(metadata_file_path):
            raise exception.SysinvException(_("Metadata file not found"))

        # Read in the metadata file
        try:
            metadata_file = open(metadata_file_path, 'r')
            root = ElementTree.fromstring(metadata_file.read())
            metadata_file.close()

        except Exception:
            raise exception.SysinvException(_(
                "Unable to read metadata file"))

        # unmount iso

        # We need to sleep here because the mount/umount is happening too
        # fast and cause the following kernel logs
        #   Buffer I/O error on device loopxxx, logical block x
        # We sleep 1 sec to give time for the mount to finish processing
        # properly.
        time.sleep(1)
        mounted_iso._umount_iso()
        shutil.rmtree(mntdir)

        new_version = root.findtext('version')

        if new_version == current_version:
            raise exception.SysinvException(
                _("Active version and import version match (%s)")
                % current_version)

        supported_upgrades_elm = root.find('supported_upgrades')
        if not supported_upgrades_elm:
            raise exception.SysinvException(
                _("Invalid Metadata XML"))

        path_found = False
        upgrade_path = None
        upgrade_paths = supported_upgrades_elm.findall('upgrade')

        for upgrade_element in upgrade_paths:
            valid_from_version = upgrade_element.findtext('version')
            if valid_from_version == current_version:
                path_found = True
                upgrade_path = upgrade_element
                break

        if not path_found:
            raise exception.SysinvException(
                _("No valid upgrade path found"))

        # Create a patch with the values from the metadata
        patch = dict()

        patch['state'] = constants.IMPORTING_LOAD_STATE
        patch['software_version'] = new_version
        patch['compatible_version'] = current_version

        required_patches = []
        patch_elements = upgrade_path.findall('required_patch')
        for patch_element in patch_elements:
            required_patches.append(patch_element.text)
        patch['required_patches'] = "\n".join(required_patches)

        # create the new imported load in the database
        new_load = self.dbapi.load_create(patch)

        return new_load

    def import_load(self, context, path_to_iso, new_load):
        """
        Run the import script and add the load to the database
        """
        loads = self.dbapi.load_get_list()

        cutils.validate_loads_for_import(loads)

        if new_load is None:
            raise exception.SysinvException(
                _("Error importing load. Load not found"))

        if not os.path.exists(path_to_iso):
            self._import_load_error(new_load)
            raise exception.SysinvException(_("Specified path not found %s") %
                                            path_to_iso)
        mounted_iso = None

        mntdir = tempfile.mkdtemp(dir='/tmp')
        # Attempt to mount iso
        try:
            mounted_iso = cutils.ISO(path_to_iso, mntdir)
            # Note: iso will be unmounted when object goes out of scope

        except subprocess.CalledProcessError:
            self._import_load_error(new_load)
            raise exception.SysinvException(_(
                "Unable to mount iso"))

        # Run the upgrade script
        with open(os.devnull, "w") as fnull:
            try:
                subprocess.check_call(mntdir +
                                      '/upgrades/import.sh',
                                      stdout=fnull, stderr=fnull)
            except subprocess.CalledProcessError:
                self._import_load_error(new_load)
                raise exception.SysinvException(_(
                    "Failure during import script"))

        # unmount iso
        mounted_iso._umount_iso()
        shutil.rmtree(mntdir)

        # Update the load status in the database
        try:
            self.dbapi.load_update(new_load['id'],
                                   {'state': constants.IMPORTED_LOAD_STATE})

        except exception.SysinvException as e:
            LOG.exception(e)
            raise exception.SysinvException(_("Error updating load in "
                                              "database for load id: %s")
                                            % new_load['id'])

        # Run the sw-patch init-release commands
        with open(os.devnull, "w") as fnull:
            try:
                subprocess.check_call(["/usr/sbin/sw-patch",
                                       "init-release",
                                       new_load['software_version']],
                                      stdout=fnull, stderr=fnull)
            except subprocess.CalledProcessError:
                self._import_load_error(new_load)
                raise exception.SysinvException(_(
                    "Failure during sw-patch init-release"))

        return True

    def delete_load(self, context, load_id):
        """
        Cleanup a load and remove it from the database
        """
        load = self.dbapi.load_get(load_id)

        cutils.validate_load_for_delete(load)

        # We allow this command to be run again if the delete fails
        if load.state != constants.DELETING_LOAD_STATE:
            # Here we run the cleanup script locally
            self._cleanup_load(load)
            self.dbapi.load_update(
                load_id, {'state': constants.DELETING_LOAD_STATE})

        mate_hostname = cutils.get_mate_controller_hostname()

        try:
            standby_controller = self.dbapi.ihost_get_by_hostname(
                mate_hostname)
            rpcapi = agent_rpcapi.AgentAPI()
            rpcapi.delete_load(
                context, standby_controller['uuid'], load.software_version)
        except exception.NodeNotFound:
            # The mate controller has not been configured so complete the
            # deletion of the load now.
            self.finalize_delete_load(context)

    def _cleanup_load(self, load):
        # Run the sw-patch del-release commands
        with open(os.devnull, "w") as fnull:
            try:
                subprocess.check_call(["/usr/sbin/sw-patch",
                                       "del-release",
                                       load.software_version],
                                      stdout=fnull, stderr=fnull)
            except subprocess.CalledProcessError:
                raise exception.SysinvException(_(
                    "Failure during sw-patch del-release"))

        # delete the central patch vault if it exists
        patch_vault = '/opt/patch-vault/' + load.software_version
        if os.path.exists(patch_vault):
            shutil.rmtree(patch_vault)

        cleanup_script = constants.DELETE_LOAD_SCRIPT
        if os.path.isfile(cleanup_script):
            with open(os.devnull, "w") as fnull:
                try:
                    subprocess.check_call(
                        [cleanup_script, load.software_version],
                        stdout=fnull, stderr=fnull)
                except subprocess.CalledProcessError:
                    raise exception.SysinvException(_(
                        "Failure during cleanup script"))
        else:
            raise exception.SysinvException(_(
                "Cleanup script %s does not exist.") % cleanup_script)

    def finalize_delete_load(self, context):
        loads = self.dbapi.load_get_list()
        for load in loads:
            if load.state == constants.DELETING_LOAD_STATE:
                self.dbapi.load_destroy(load.id)

    def upgrade_ihost_pxe_config(self, context, host, load):
        """Upgrade a host.

        Does the following tasks:
        - Updates the host's pxelinux.cfg file to the specified load

        :param host: a host object.
        :param load: a load object.
        """
        self._update_pxe_config(host, load)

    def load_update_by_host(self, context, ihost_id, sw_version):
        """Update the host_upgrade table with the running SW_VERSION

        Does the following:
           - Raises an alarm if host_upgrade software and target do not match
           - Clears an alarm if host_upgrade software and target do match
           - Updates upgrade state once data migration is complete
           - Clears VIM upgrade flag once controller-0 has been upgraded

        :param ihost_id: the host id
        :param sw_version: the SW_VERSION from the host
        """
        host_load = self.dbapi.load_get_by_version(sw_version)

        host = self.dbapi.ihost_get(ihost_id)

        host_upgrade = self.dbapi.host_upgrade_get_by_host(host.id)

        check_for_alarm = host_upgrade.software_load != host_upgrade.target_load

        if host_upgrade.software_load != host_load.id:
            host_upgrade.software_load = host_load.id
            host_upgrade.save(context)

        if host_upgrade.software_load != host_upgrade.target_load:
            entity_instance_id = self._get_fm_entity_instance_id(host)
            fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_HOST_VERSION_MISMATCH,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
                reason_text=(_("Incorrect software load on %s.") %
                             host.hostname),
                alarm_type=fm_constants.FM_ALARM_TYPE_7,  # operational
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_7,
                # configuration error
                proposed_repair_action=_(
                    "Reinstall %s to update applied load." %
                    host.hostname),
                service_affecting=True)

            self.fm_api.set_fault(fault)
        elif check_for_alarm:
            entity_instance_id = self._get_fm_entity_instance_id(host)
            self.fm_api.clear_fault(
                fm_constants.FM_ALARM_ID_HOST_VERSION_MISMATCH,
                entity_instance_id)

        # Check if there is an upgrade in progress
        try:
            upgrade = self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            # No upgrade in progress
            pass
        else:
            # Check if controller-1 has finished its data migration
            if (host.hostname == constants.CONTROLLER_1_HOSTNAME and
                    host_upgrade.software_load == upgrade.to_load and
                    upgrade.state == constants.UPGRADE_DATA_MIGRATION_COMPLETE):
                LOG.info("Finished upgrade of %s" %
                         constants.CONTROLLER_1_HOSTNAME)
                # Update upgrade state
                upgrade_update = {
                    'state': constants.UPGRADE_UPGRADING_CONTROLLERS}
                self.dbapi.software_upgrade_update(upgrade.uuid,
                                                   upgrade_update)

            if (host.hostname == constants.CONTROLLER_0_HOSTNAME and
                    host_upgrade.software_load == upgrade.to_load):
                # Clear VIM upgrade flag once controller_0 has been upgraded
                # This allows VM management
                try:
                    vim_api.set_vim_upgrade_state(host, False)
                except Exception as e:
                    LOG.exception(e)
                    raise exception.SysinvException(_(
                        "Failure clearing VIM host upgrade state"))

                # If we are in the upgrading controllers state and controller-0
                # is running the new release, update the upgrade state
                if upgrade.state == constants.UPGRADE_UPGRADING_CONTROLLERS:
                    upgrade_update = {
                        'state': constants.UPGRADE_UPGRADING_HOSTS}
                    self.dbapi.software_upgrade_update(upgrade.uuid,
                                                       upgrade_update)

    def start_upgrade(self, context, upgrade):
        """ Start the upgrade"""

        from_load = self.dbapi.load_get(upgrade.from_load)
        from_version = from_load.software_version
        to_load = self.dbapi.load_get(upgrade.to_load)
        to_version = to_load.software_version

        controller_0 = self.dbapi.ihost_get_by_hostname(
            constants.CONTROLLER_0_HOSTNAME)

        # Prepare for upgrade
        LOG.info("Preparing for upgrade from release: %s to release: %s" %
                 (from_version, to_version))

        try:
            # Extract N+1 packages necessary for installation of controller-1
            # (ie. installer images, kickstarts)
            subprocess.check_call(['/usr/sbin/upgrade-start-pkg-extract',
                                   '-r', to_version])

            if tsc.system_mode == constants.SYSTEM_MODE_SIMPLEX:
                LOG.info("Generating agent request to create simplex upgrade "
                         "data")
                software_upgrade = self.dbapi.software_upgrade_get_one()
                rpcapi = agent_rpcapi.AgentAPI()
                rpcapi.create_simplex_backup(context, software_upgrade)
                return
            else:
                i_system = self.dbapi.isystem_get_one()
                upgrades_management.prepare_upgrade(
                    from_version, to_version, i_system)

            LOG.info("Finished upgrade preparation")
        except Exception:
            LOG.exception("Upgrade preparation failed")
            with excutils.save_and_reraise_exception():
                if tsc.system_mode != constants.SYSTEM_MODE_SIMPLEX:
                    vim_api.set_vim_upgrade_state(controller_0, False)
                upgrades_management.abort_upgrade(from_version, to_version,
                                                  upgrade)
                # Delete upgrade record
                self.dbapi.software_upgrade_destroy(upgrade.uuid)

        # Raise alarm to show an upgrade is in progress
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                        constants.CONTROLLER_HOSTNAME)
        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_UPGRADE_IN_PROGRESS,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
            entity_instance_id=entity_instance_id,
            severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
            reason_text="System Upgrade in progress.",
            # operational
            alarm_type=fm_constants.FM_ALARM_TYPE_7,
            # congestion
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_8,
            proposed_repair_action="No action required.",
            service_affecting=False)
        fm_api.FaultAPIs().set_fault(fault)

        self.dbapi.software_upgrade_update(
            upgrade.uuid, {'state': constants.UPGRADE_STARTED})

    def activate_upgrade(self, context, upgrade):
        """Activate the upgrade. Generate and apply new manifests.

        """
        # TODO Move upgrade methods to another file
        from_load = self.dbapi.load_get(upgrade.from_load)
        from_version = from_load.software_version
        to_load = self.dbapi.load_get(upgrade.to_load)
        to_version = to_load.software_version

        personalities = [constants.CONTROLLER, constants.WORKER]
        config_uuid = self._config_update_hosts(context, personalities)

        self.dbapi.software_upgrade_update(
            upgrade.uuid, {'state': constants.UPGRADE_ACTIVATING})

        # Ask upgrade management to activate the upgrade
        try:
            i_system = self.dbapi.isystem_get_one()
            upgrades_management.activate_upgrade(from_version,
                                                 to_version, i_system)
            LOG.info("Finished upgrade activation")
        except Exception:
            LOG.exception("Upgrade activation failed")
            with excutils.save_and_reraise_exception():
                # mark the activation as failed. The intention
                # is for the user to retry activation once they
                # have resolved the cause for failure
                self.dbapi.software_upgrade_update(
                    upgrade.uuid,
                    {'state': constants.UPGRADE_ACTIVATION_FAILED})

        config_dict = {
            "personalities": [constants.CONTROLLER],
            "classes": ['openstack::nova::controller::runtime',
                        'openstack::neutron::server::runtime'],
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

        config_dict = {
            "personalities": [constants.WORKER],
            "classes": ['openstack::nova::compute::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def complete_upgrade(self, context, upgrade, state):
        """ Complete the upgrade"""

        from_load = self.dbapi.load_get(upgrade.from_load)
        from_version = from_load.software_version
        to_load = self.dbapi.load_get(upgrade.to_load)
        to_version = to_load.software_version

        controller_0 = self.dbapi.ihost_get_by_hostname(
            constants.CONTROLLER_0_HOSTNAME)

        # TODO: This code is only useful for supporting R5 to R6 upgrades.
        #       Remove in future release.
        # update crushmap and remove cache-tier on upgrade
        if from_version == tsc.SW_VERSION_1803:
            ceph_backend = StorageBackendConfig.get_backend(self.dbapi, constants.CINDER_BACKEND_CEPH)
            if ceph_backend and ceph_backend.state == constants.SB_STATE_CONFIGURED:
                try:
                    response, body = self._ceph_api.osd_crush_rule_rm("cache_tier_ruleset",
                                                                      body='json')
                    if response.ok:
                        LOG.info("Successfully removed cache_tier_ruleset "
                                 "[ceph osd crush rule rm cache_tier_ruleset]")
                        try:
                            response, body = self._ceph_api.osd_crush_remove("cache-tier",
                                                                             body='json')
                            if response.ok:
                                LOG.info("Successfully removed cache_tier "
                                         "[ceph osd crush remove cache-tier]")
                        except exception.CephFailure:
                            LOG.warn("Failed to remove bucket cache-tier from crushmap")
                            pass
                except exception.CephFailure:
                    LOG.warn("Failed to remove rule cache-tier from crushmap")
                    pass

        if state in [constants.UPGRADE_ABORTING,
                constants.UPGRADE_ABORTING_ROLLBACK]:
            if upgrade.state != constants.UPGRADE_ABORT_COMPLETING:
                raise exception.SysinvException(
                    _("Unable to complete upgrade-abort: Upgrade not in %s "
                      "state.") % constants.UPGRADE_ABORT_COMPLETING)
            LOG.info(
                "Completing upgrade abort from release: %s to release: %s" %
                (from_version, to_version))
            upgrades_management.abort_upgrade(from_version, to_version, upgrade)

            if (tsc.system_type == constants.SYSTEM_MODE_DUPLEX and
                    tsc.system_type == constants.TIS_AIO_BUILD and
                        state == constants.UPGRADE_ABORTING_ROLLBACK):

                # For AIO Case, VM goes into no state when Controller-0 becomes active
                # after swact. nova clean up will fail the instance and restart
                # nova-compute service
                LOG.info("Calling nova cleanup")
                with open(os.devnull, "w") as fnull:
                    try:
                        subprocess.check_call(["systemctl", "start", "nova-cleanup"],
                                              stdout=fnull,
                                              stderr=fnull)
                    except subprocess.CalledProcessError:
                        raise exception.SysinvException(_(
                            "Failed to call nova cleanup during AIO abort"))

            try:
                vim_api.set_vim_upgrade_state(controller_0, False)
            except Exception:
                LOG.exception()
                raise exception.SysinvException(_(
                    "upgrade-abort rejected: unable to reset VIM upgrade "
                    "state"))
            LOG.info("Finished upgrade abort")
        else:
            if upgrade.state != constants.UPGRADE_COMPLETING:
                raise exception.SysinvException(
                    _("Unable to complete upgrade: Upgrade not in %s state.")
                    % constants.UPGRADE_COMPLETING)
            # Force all host_upgrade entries to use the new load
            # In particular we may have host profiles created in the from load
            # that we need to update before we can delete the load.
            hosts = self.dbapi.host_upgrade_get_list()
            for host_upgrade in hosts:
                if (host_upgrade.target_load == from_load.id or
                        host_upgrade.software_load == from_load.id):
                    LOG.info(_("Updating host id: %s to use load id: %s")
                             % (host_upgrade.forihostid, upgrade.to_load))
                    self.dbapi.host_upgrade_update(
                        host_upgrade.id,
                        {"software_load": upgrade.to_load,
                         "target_load": upgrade.to_load})

            # Complete the upgrade
            LOG.info("Completing upgrade from release: %s to release: %s" %
                     (from_version, to_version))
            upgrades_management.complete_upgrade(from_version, to_version)
            LOG.info("Finished completing upgrade")

        # Delete upgrade record
        self.dbapi.software_upgrade_destroy(upgrade.uuid)

        # Clear upgrades alarm
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                        constants.CONTROLLER_HOSTNAME)
        fm_api.FaultAPIs().clear_fault(
            fm_constants.FM_ALARM_ID_UPGRADE_IN_PROGRESS,
            entity_instance_id)

    def abort_upgrade(self, context, upgrade):
        """ Abort the upgrade"""
        from_load = self.dbapi.load_get(upgrade.from_load)
        from_version = from_load.software_version
        to_load = self.dbapi.load_get(upgrade.to_load)
        to_version = to_load.software_version
        LOG.info("Aborted upgrade from release: %s to release: %s" %
                 (from_version, to_version))

        updates = {'state': constants.UPGRADE_ABORTING}

        controller_0 = self.dbapi.ihost_get_by_hostname(
            constants.CONTROLLER_0_HOSTNAME)
        host_upgrade = self.dbapi.host_upgrade_get_by_host(
            controller_0.id)

        if host_upgrade.target_load == to_load.id:
            updates['state'] = constants.UPGRADE_ABORTING_ROLLBACK

        rpc_upgrade = self.dbapi.software_upgrade_update(
            upgrade.uuid, updates)
        # make sure the to/from loads are in the correct state
        self.dbapi.set_upgrade_loads_state(
            upgrade,
            constants.IMPORTED_LOAD_STATE,
            constants.ACTIVE_LOAD_STATE)

        self._puppet.update_system_config()
        self._puppet.update_secure_system_config()

        # When we abort from controller-1 while controller-0 is running
        # the previous release, controller-0 will not be aware of the abort.
        # We set the following flag so controller-0 will know we're
        # aborting the upgrade and can set it's database accordingly
        if tsc.system_mode != constants.SYSTEM_MODE_SIMPLEX:
            if updates['state'] == constants.UPGRADE_ABORTING:
                controller_1 = self.dbapi.ihost_get_by_hostname(
                    constants.CONTROLLER_1_HOSTNAME)
                c1_host_upgrade = self.dbapi.host_upgrade_get_by_host(
                    controller_1.id)
                if utils.is_host_active_controller(controller_1) and \
                        c1_host_upgrade.target_load == to_load.id:
                    abort_flag = os.path.join(
                        tsc.PLATFORM_PATH, 'config', from_version,
                        tsc.UPGRADE_ABORT_FILE)
                    open(abort_flag, "w").close()

        return rpc_upgrade

    def complete_simplex_backup(self, context, success):
        """Complete the simplex upgrade start process

        :param context: request context.
        :param success: If the create_simplex_backup call completed
        """
        try:
            upgrade = self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            LOG.error("Software upgrade record not found")
            return

        from_version = upgrade.from_release
        to_version = upgrade.to_release

        if not success:
            # The upgrade start data collection failed, stop the upgrade
            upgrades_management.abort_upgrade(from_version, to_version,
                                              upgrade)
            # Delete upgrade record
            self.dbapi.software_upgrade_destroy(upgrade.uuid)
            LOG.info("Simplex upgrade start failed")
        else:
            LOG.info("Simplex upgrade start completed")
            # Raise alarm to show an upgrade is in progress
            entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                            constants.CONTROLLER_HOSTNAME)
            fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_UPGRADE_IN_PROGRESS,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
                reason_text="System Upgrade in progress.",
                # operational
                alarm_type=fm_constants.FM_ALARM_TYPE_7,
                # congestion
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_8,
                proposed_repair_action="No action required.",
                service_affecting=False)
            fm_api.FaultAPIs().set_fault(fault)

            self.dbapi.software_upgrade_update(
                upgrade.uuid, {'state': constants.UPGRADE_STARTED})

        return

    def get_system_health(self, context, force=False, upgrade=False):
        """
        Performs a system health check.

        :param context: request context.
        :param force: set to true to ignore minor and warning alarms
        :param upgrade: set to true to perform an upgrade health check
        """
        health_util = health.Health(self.dbapi)

        if upgrade is True:
            return health_util.get_system_health_upgrade(context=context,
                                                         force=force)
        else:
            return health_util.get_system_health(context=context,
                                                 force=force)

    def _get_cinder_address_name(self, network_type):
        ADDRESS_FORMAT_ARGS = (constants.CONTROLLER_HOSTNAME,
                               network_type)
        return "%s-cinder-%s" % ADDRESS_FORMAT_ARGS

    def reserve_ip_for_first_storage_node(self, context):
        """
        Reserve ip address for the first storage node for Ceph monitor
        when installing Ceph as a second backend

        :param context: request context.
        """
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        address_name = cutils.format_address_name(
            constants.STORAGE_0_HOSTNAME, constants.NETWORK_TYPE_MGMT)

        try:
            self.dbapi.address_get_by_name(address_name)
            LOG.debug("Addres %s already reserved, continuing." % address_name)
        except exception.AddressNotFoundByName:
            LOG.debug("Reserving address for %s." % address_name)
            self._allocate_pool_address(None, network.pool_uuid,
                                        address_name)
            self._generate_dnsmasq_hosts_file()

    def reserve_ip_for_cinder(self, context):
        """
        Reserve ip address for Cinder's services

        :param context: request context.
        """
        lvm_backend = StorageBackendConfig.has_backend(
            self.dbapi,
            constants.CINDER_BACKEND_LVM
        )
        if not lvm_backend:
            # Cinder's IP address is only valid if LVM backend exists
            return

        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        network_type = constants.NETWORK_TYPE_MGMT

        # Reserve new ip address, if not present
        try:
            self.dbapi.address_get_by_name(
                self._get_cinder_address_name(network_type)
            )
        except exception.NotFound:
            self._allocate_pool_address(None, network.pool_uuid,
                                        self._get_cinder_address_name(network_type))

        self._generate_dnsmasq_hosts_file()

    def host_load_matches_sw_version(self, host):
        """
        Checks if the host is running the same load as the active controller
        :param host: a host object
        :return: true if host target load matches active sw_version
        """
        host_upgrade = self.dbapi.host_upgrade_get_by_host(host.id)
        target_load = self.dbapi.load_get(host_upgrade.target_load)
        return target_load.software_version == tsc.SW_VERSION

    def create_barbican_secret(self, context, name, payload):
        """Calls Barbican API to create a secret

        :param context: request context.
        :param name: secret name
        :param payload: secret payload
        """
        self._openstack.create_barbican_secret(context=context,
                                               name=name, payload=payload)

    def delete_barbican_secret(self, context, name):
        """Calls Barbican API to delete a secret

        :param context: request context.
        :param name: secret name
        """
        self._openstack.delete_barbican_secret(context=context, name=name)

    def update_snmp_config(self, context):
        """Update the snmpd configuration"""
        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::snmp::runtime',
                        'platform::fm::runtime'],
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def get_ceph_pools_config(self, context):
        return self._ceph.get_pools_config()

    def get_controllerfs_lv_sizes(self, context):
        system = self.dbapi.isystem_get_one()
        system_dc_role = system.get('distributed_cloud_role', None)

        lvdisplay_command = 'lvdisplay --columns --options lv_size,lv_name ' \
                            '--units g --noheading --nosuffix ' \
                            '/dev/cgts-vg/pgsql-lv /dev/cgts-vg/backup-lv ' \
                            '/dev/cgts-vg/cgcs-lv ' \
                            '/dev/cgts-vg/scratch-lv ' \
                            '/dev/cgts-vg/extension-lv ' \
                            '/dev/cgts-vg/docker-lv ' \
                            '/dev/cgts-vg/etcd-lv ' \
                            '/dev/cgts-vg/dockerdistribution-lv '

        if (system_dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER and
                tsc.system_type != constants.TIS_AIO_BUILD):
            lvdisplay_command = lvdisplay_command + '/dev/cgts-vg/patch-vault-lv '

        lvdisplay_dict = {}
        # Execute the command.
        try:
            lvdisplay_process = subprocess.Popen(lvdisplay_command,
                                                 stdout=subprocess.PIPE,
                                                 shell=True)
        except Exception as e:
            LOG.error("Could not retrieve lvdisplay information: %s" % e)
            return lvdisplay_dict

        lvdisplay_output = lvdisplay_process.communicate()[0]
        lvdisplay_dict = cutils.output_to_dict(lvdisplay_output)
        LOG.debug("get_controllerfs_lv_sizes lvdisplay_output %s" % lvdisplay_output)

        return lvdisplay_dict

    def get_cinder_gib_pv_sizes(self, context):
        pvs_command = 'pvs --options pv_size,vg_name --units g --noheading ' \
                      '--nosuffix | grep cinder-volumes'

        pvs_dict = {}
        # Execute the command.
        try:
            pvs_process = subprocess.Popen(pvs_command,
                                           stdout=subprocess.PIPE,
                                           shell=True)
        except Exception as e:
            LOG.error("Could not retrieve pvs information: %s" % e)
            return pvs_dict

        pvs_output = pvs_process.communicate()[0]
        pvs_dict = cutils.output_to_dict(pvs_output)

        return pvs_dict

    def cinder_has_external_backend(self, context):
        """
        Check if cinder has loosely coupled external backends.
        These are the possible backends: emc_vnx, hpe3par, hpelefthand
        """

        pools = self._openstack.get_cinder_pools()
        if pools is not None:
            for pool in pools:
                volume_backend = getattr(pool, 'volume_backend_name', '')
                if volume_backend and volume_backend != constants.CINDER_BACKEND_LVM and \
                   volume_backend != constants.CINDER_BACKEND_CEPH:
                    return True

        return False

    def get_ceph_object_pool_name(self, context):
        """
        Get Rados Gateway object data pool name
        """
        return self._ceph.get_ceph_object_pool_name()

    def get_partition_size(self, context, partition):
        # Use the 'blockdev' command for obtaining the size of the partition.
        get_size_command = '{0} {1}'.format('blockdev --getsize64',
                                            partition)

        partition_size = None
        try:
            get_size_process = subprocess.Popen(get_size_command,
                                                stdout=subprocess.PIPE,
                                                shell=True)
        except Exception as e:
            LOG.error("Could not retrieve device information: %s" % e)
            return partition_size

        partition_size = get_size_process.communicate()[0]

        partition_size = partition_size if partition_size else None

        if partition_size:
            # We also need to add the size of the partition table.
            partition_size = int(partition_size) +\
                                 constants.PARTITION_TABLE_SIZE

            # Convert bytes to GiB and round to be sure.
            partition_size = int(round(
                                 cutils.bytes_to_GiB(partition_size)))

        return partition_size

    def get_cinder_partition_size(self, context):
        # Obtain the active controller.
        active_controller = None
        hosts = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
        for h in hosts:
            if utils.is_host_active_controller(h):
                active_controller = h

        if not active_controller:
            raise exception.SysinvException(_("Unable to obtain active "
                                              "controller."))

        # Obtain the cinder disk.
        cinder_device = cutils._get_cinder_device(self.dbapi,
                                                  active_controller.id)

        # Raise exception in case we couldn't get the cinder disk.
        if not cinder_device:
            raise exception.SysinvException(_(
                "Unable to determine the current value of cinder_device for "
                "host %s " % active_controller.hostname))

        # The partition for cinder volumes is always the first.
        cinder_device_partition = '{}{}'.format(cinder_device, '-part1')
        cinder_size = self.get_partition_size(context, cinder_device_partition)

        return cinder_size

    def validate_emc_removal(self, context):
        """
        Check that it is safe to remove the EMC SAN
        Ensure there are no volumes using the EMC endpoint
        """
        emc_volume_found = False

        for volume in self._openstack.get_cinder_volumes():
            end_point = getattr(volume, 'os-vol-host-attr:host', '')
            if end_point and '@emc_vnx' in end_point:
                emc_volume_found = True
                break

        return not emc_volume_found

    def validate_hpe3par_removal(self, context, backend):
        """
        Check that it is safe to remove the HPE3PAR SAN
        Ensure there are no volumes using the HPE3PAR endpoint
        """
        volume_found = False

        for volume in self._openstack.get_cinder_volumes():
            end_point = getattr(volume, 'os-vol-host-attr:host', '')
            if end_point and '@' + backend + '#' in end_point:
                volume_found = True
                break

        return not volume_found

    def validate_hpelefthand_removal(self, context):
        """
        Check that it is safe to remove the HPELEFTHAND SAN
        Ensure there are no volumes using the HPELEFTHAND endpoint
        """
        volume_found = False

        volumes = self._openstack.get_cinder_volumes()
        for volume in volumes:
            end_point = getattr(volume, 'os-vol-host-attr:host', '')
            if end_point and '@hpelefthand' in end_point:
                volume_found = True
                break

        return not volume_found

    def region_has_ceph_backend(self, context):
        """
        Send a request to the primary region to see if ceph is configured
        """
        return self._openstack.region_has_ceph_backend()

    def get_system_tpmconfig(self, context):
        """
        Retrieve the system tpmconfig object
        """
        try:
            tpmconfig = self.dbapi.tpmconfig_get_one()
            if tpmconfig:
                return tpmconfig.as_dict()
        except exception.NotFound:
            # No TPM configuration found
            return None

    def get_tpmdevice_by_host(self, context, host_id):
        """
        Retrieve the tpmdevice object for this host
        """
        try:
            tpmdevice = self.dbapi.tpmdevice_get_by_host(host_id)
            if tpmdevice and len(tpmdevice) == 1:
                return tpmdevice[0].as_dict()
        except exception.NotFound:
            # No TPM device found
            return None

    def update_tpm_config(self, context, tpm_context, update_file_required=True):
        """Notify agent to configure TPM with the supplied data.

        :param context: an admin context.
        :param tpm_context: the tpm object context
        :param update_file_required: boolean, whether file needs to be updated
        """

        LOG.debug("ConductorManager.update_tpm_config: sending TPM update %s "
                  "to agents" % tpm_context)
        rpcapi = agent_rpcapi.AgentAPI()
        personalities = [constants.CONTROLLER]

        # the original key from which TPM context will be derived
        # needs to be present on all agent nodes, as well as
        # the public cert
        if update_file_required:
            for fp in ['cert_path', 'public_path']:
                file_name = tpm_context[fp]
                with open(file_name, 'r') as content_file:
                    file_content = content_file.read()

                config_dict = {
                    'personalities': personalities,
                    'file_names': [file_name],
                    'file_content': file_content,
                }

                # TODO(jkung): update public key info
                config_uuid = self._config_update_hosts(context, personalities)
                rpcapi.iconfig_update_file(context,
                                           iconfig_uuid=config_uuid,
                                           iconfig_dict=config_dict)

        rpcapi.apply_tpm_config(context,
                                tpm_context=tpm_context)

    def update_tpm_config_manifests(self, context, delete_tpm_file=None):
        """Apply TPM related runtime manifest changes. """
        LOG.info("update_tpm_config_manifests")

        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)

        if delete_tpm_file:
            # Delete the TPM file from the controllers
            rpcapi = agent_rpcapi.AgentAPI()
            command = ['rm', '-f', delete_tpm_file]
            hosts = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
            for host in hosts:
                rpcapi.execute_command(context, host.uuid, command)

        config_dict = {
            "personalities": personalities,
            "classes": ['platform::haproxy::runtime',
                        'openstack::horizon::runtime']
        }
        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def _set_tpm_config_state(self,
                              ihost, response_dict):
        """Update tpm configuration state. """
        try:
            existing_tpmdevice = \
                self.dbapi.tpmdevice_get_by_host(ihost.uuid)
            if (len(existing_tpmdevice) > 1):
                LOG.error("Multiple tpmdevice entries found for host %s" %
                          ihost.uuid)
                return
            elif not existing_tpmdevice:
                LOG.debug("TPM Audit: No tpmdevice entry found while TPM "
                          "configuration exists.")
                return
            existing_tpmdevice = existing_tpmdevice[0]
        except exception.NotFound:
            # No TPM configuration. No need to update status
            return

        updated_state = None
        if response_dict['is_configured']:
            updated_state = constants.TPMCONFIG_APPLIED
        else:
            updated_state = constants.TPMCONFIG_FAILED

        if (updated_state and updated_state != existing_tpmdevice.state):
            self.dbapi.tpmdevice_update(existing_tpmdevice.uuid,
                                        {'state': updated_state})

    def tpm_config_update_by_host(self, context,
                                  host_uuid, response_dict):
        """Get TPM configuration status from Agent host.

        This method allows for alarms to be raised for hosts if TPM
        is not configured properly.

        :param context: an admin context
        :param host_uuid: host unique id
        :param response_dict: configuration status
        :returns: pass or fail
        """
        LOG.debug("Entering tpm_config_update_by_host %s %s" %
                  (host_uuid, response_dict))
        host_uuid.strip()
        try:
            tpm_host = self.dbapi.ihost_get(host_uuid)
            entity_instance_id = ("%s=%s" %
                                  (fm_constants.FM_ENTITY_TYPE_HOST,
                                   tpm_host.hostname))
            alarm_id = fm_constants.FM_ALARM_ID_TPM_INIT

            if response_dict['is_configured']:
                tpmdevice = self.get_tpmdevice_by_host(context, host_uuid)
                # apply config manifest for tpm create/update
                if (tpmdevice and
                            tpmdevice['state'] ==
                            constants.TPMCONFIG_APPLYING):
                    self.update_tpm_config_manifests(context)
                # update the system configuration state
                self._set_tpm_config_state(tpm_host, response_dict)
                # do a blind clear on any TPM alarm
                # for this host.
                self.fm_api.clear_fault(alarm_id,
                                        entity_instance_id)
            else:
                # update the system configuration state
                self._set_tpm_config_state(tpm_host, response_dict)
                # set an alarm for this host and tell
                # mtce to degrade this node
                if not self.fm_api.get_fault(alarm_id, entity_instance_id):
                    fault = fm_api.Fault(
                        alarm_id=alarm_id,
                        alarm_state=fm_constants.FM_ALARM_STATE_SET,
                        entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                        entity_instance_id=entity_instance_id,
                        severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
                        reason_text="TPM configuration failed "
                                    "or device not found.",
                        # equipment
                        alarm_type=fm_constants.FM_ALARM_TYPE_4,
                        # procedural-error
                        probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_64,
                        proposed_repair_action="reinstall HTTPS certificate; "
                                               "if problem persists",
                        service_affecting=False)
                    self.fm_api.set_fault(fault)

        except Exception:
            raise exception.SysinvException(_(
                "Invalid host_uuid: %s") % host_uuid)

    def tpm_device_update_by_host(self, context,
                                  host_uuid, tpmdevice_dict):
        """Synchronously, have the conductor create or update
        a tpmdevice per host.

        :param context: request context.
        :param host_uuid: uuid or id of the host
        :param tpmdevice_dict: a dicitionary of tpm device attributes

        :returns tpmdevice object
        """
        try:
            tpm_host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            LOG.error("Cannot find host by id %s" % host_uuid)
            return

        tpm_devices = self.dbapi.tpmdevice_get_by_host(tpm_host.id)
        if tpm_devices:
            tpmdevice = self.dbapi.tpmdevice_update(tpm_devices[0].uuid,
                                                    tpmdevice_dict)
            # update table tpmconfig updated_at as its visible from tpmconfig-show
            try:
                tpm_obj = self.dbapi.tpmconfig_get_one()
                updated_at = timeutils.utcnow()
                self.dbapi.tpmconfig_update(tpm_obj.uuid,
                                            {'updated_at': updated_at})
                LOG.info("TPM config updated at: %s" % updated_at)
            except exception.NotFound:
                LOG.error("tpm_device_update_by_host tpmconfig NotFound")
        else:
            try:
                # create new tpmdevice
                tpmdevice_dict.update({'host_uuid': tpm_host['uuid']})
                tpmdevice = self.dbapi.tpmdevice_create(tpm_host['id'],
                                                        tpmdevice_dict)
            except Exception:
                LOG.exception("Cannot create TPM device for host %s" % host_uuid)
                return

        return tpmdevice

    def cinder_prepare_db_for_volume_restore(self, context):
        """
        Send a request to cinder to remove all volume snapshots and set all
        volumes to error state in preparation for restoring all volumes.

        This is needed for cinder disk replacement.
        """
        response = self._openstack.cinder_prepare_db_for_volume_restore(context)
        return response

    def get_software_upgrade_status(self, context):
        """
        Software upgrade status is needed by ceph-manager to take ceph specific
        upgrade actions
        """
        upgrade = {
            'from_version': None,
            'to_version': None,
            'state': None}
        try:
            row = self.dbapi.software_upgrade_get_one()
            upgrade['from_version'] = row.from_release
            upgrade['to_version'] = row.to_release
            upgrade['state'] = row.state
        except exception.NotFound:
            # No upgrade in progress
            pass
        return upgrade

    def distribute_ceph_external_config(self, context, ceph_conf_filename):
        """Notify agent to distribute Ceph configuration file for external
           cluster.
        """
        LOG.debug("ceph_conf_file: %s" % ceph_conf_filename)

        # Retriving the ceph config file that is stored in the /opt/platform/config
        # during the file upload stage.
        opt_ceph_conf_file = os.path.join(tsc.PLATFORM_CEPH_CONF_PATH,
                                          ceph_conf_filename)
        if not os.path.exists(opt_ceph_conf_file):
            raise exception.SysinvException(
                _("Could not find the uploaded ceph config file %s in %s")
                % (ceph_conf_filename, tsc.PLATFORM_CEPH_CONF_PATH))

        try:
            f = open(opt_ceph_conf_file, "r")
            f.seek(0, os.SEEK_SET)
            contents = f.read()
        except IOError:
            msg = _("Failed to read ceph config file from %s " %
                    tsc.PLATFORM_CEPH_CONF_PATH)
            raise exception.SysinvException(msg)

        ceph_conf_file = os.path.join(constants.CEPH_CONF_PATH,
                                      ceph_conf_filename)

        personalities = [constants.CONTROLLER, constants.WORKER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            'personalities': personalities,
            'file_names': [ceph_conf_file],
            'file_content': contents,
        }
        self._config_update_file(context, config_uuid, config_dict)

    def store_ceph_external_config(self, context, contents, ceph_conf_filename):
        """Store the uploaded external ceph config file in /opt/platform/config
        """
        # Once this directory is created at installation time, we can
        # remove this code.
        if not os.path.exists(tsc.PLATFORM_CEPH_CONF_PATH):
            os.makedirs(tsc.PLATFORM_CEPH_CONF_PATH)
        opt_ceph_conf_file = os.path.join(tsc.PLATFORM_CEPH_CONF_PATH,
                                          ceph_conf_filename)

        # Because user needs root permission to manually delete ceph config file
        # from /opt/platform/config/version/ceph-config directory if the file
        # already exists, we will allow ceph config file to be overwritten.
        # Thus, we won't raise an exception if the file already exists.
        if os.path.exists(opt_ceph_conf_file):
            LOG.info("Overwriting file %s in %s " %
                     (ceph_conf_filename, tsc.PLATFORM_CEPH_CONF_PATH))

        try:
            with open(opt_ceph_conf_file, 'w+') as f:
                f.write(contents)
        except IOError:
            msg = _("Failed to write ceph config file in %s " %
                    tsc.PLATFORM_CEPH_CONF_PATH)
            raise exception.SysinvException(msg)

    def install_license_file(self, context, contents):
        """Notify agent to install license file with the supplied data.

        :param context: request context.
        :param contents: contents of license file.
        """

        LOG.info("Install license file.")
        license_file = os.path.join(tsc.PLATFORM_CONF_PATH,
                                    constants.LICENSE_FILE)
        temp_license_file = license_file + '.temp'
        with open(temp_license_file, 'w') as f:
            f.write(contents)
            f.close()

        # Verify license
        try:
            license.verify_license(temp_license_file)
        except Exception as e:
            raise exception.SysinvException(str(e))

        os.rename(temp_license_file, license_file)

        try:
            subprocess.check_output(["cp", license_file,
                os.path.join(tsc.CONFIG_PATH, constants.LICENSE_FILE)])
        except subprocess.CalledProcessError as e:
            LOG.error("Fail to install license to redundant "
                      "storage, output: %s" % e.output)
            os.remove(license_file)
            raise exception.SysinvException(_(
                "ERROR: Failed to install license to redundant storage."))

        hostname = subprocess.check_output(["hostname"]).rstrip()
        validHostnames = [constants.CONTROLLER_0_HOSTNAME,
                            constants.CONTROLLER_1_HOSTNAME]
        if hostname == 'localhost':
            raise exception.SysinvException(_(
                "ERROR: Host undefined. Unable to install license"))
        elif hostname not in validHostnames:
            raise exception.SysinvException(_(
                "ERROR: Invalid hostname for controller node: %s") % hostname)

        personalities = [constants.CONTROLLER]
        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            'personalities': personalities,
            'file_names': [license_file],
            'file_content': contents,
        }
        self._config_update_file(context, config_uuid, config_dict)

    def update_distributed_cloud_role(self, context):
        """Configure the distributed cloud role.

        :param context: an admin context.
        """

        # update manifest files and nofity agents to apply the change.
        # Should only be applicable to the single controller that is up
        # when the dc role is configured, but add personalities anyway.
        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        config_uuid = self._config_update_hosts(context, personalities)

        # NOTE: no specific classes need to be specified since the default
        # platform::config will be applied that will configure the platform.conf
        config_dict = {"personalities": personalities}

        self._config_apply_runtime_manifest(context, config_uuid, config_dict)

    def _destroy_certificates(self, context):
        """Delete certificates."""
        LOG.info("_destroy_certificates clear ssl/tpm certificates")

        certificates = self.dbapi.certificate_get_list()
        for certificate in certificates:
            if certificate.certtype in [constants.CERT_MODE_SSL,
                                        constants.CERT_MODE_TPM,
                                        constants.CERT_MODE_OPENSTACK]:
                self.dbapi.certificate_destroy(certificate.uuid)

        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)
        config_dict = {
            'personalities': personalities,
            'file_names': [constants.SSL_PEM_FILE],
            'file_content': None,
            'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            'nobackup': True,
        }
        self._config_update_file(context, config_uuid, config_dict)

    def _destroy_tpm_config(self, context, tpm_obj=None):
        """Delete a tpmconfig."""

        if not tpm_obj:
            tpm_obj = None
            try:
                tpm_obj = self.dbapi.tpmconfig_get_one()
            except exception.NotFound:
                return

        tpm_file = tpm_obj.tpm_path
        tpmdevices = self.dbapi.tpmdevice_get_list()
        for device in tpmdevices:
            self.dbapi.tpmdevice_destroy(device.uuid)
        self.dbapi.tpmconfig_destroy(tpm_obj.uuid)
        self.update_tpm_config_manifests(context,
                                         delete_tpm_file=tpm_file)

        alarms = self.fm_api.get_faults_by_id(
            fm_constants.FM_ALARM_ID_TPM_INIT)
        if alarms:
            for alarm in alarms:
                self.fm_api.clear_fault(
                    fm_constants.FM_ALARM_ID_TPM_INIT,
                    alarm.entity_instance_id)

    @staticmethod
    def _extract_keys_from_pem(mode, pem_contents, cert_format,
                               passphrase=None):
        """Extract keys from the pem contents

        :param mode: mode one of: ssl, tpm_mode, murano, murano_ca,
                     docker_registry
        :param pem_contents: pem_contents
        :param cert_format: serialization.PrivateFormat
        :param passphrase: passphrase for PEM file

        :returns: private_bytes, public_bytes, signature
        """

        temp_pem_file = constants.SSL_PEM_FILE + '.temp'
        with os.fdopen(os.open(temp_pem_file, os.O_CREAT | os.O_WRONLY,
                               constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                               'w') as f:
            f.write(pem_contents)

        if passphrase:
            passphrase = str(passphrase)

        private_bytes = None
        private_mode = False
        if mode in [constants.CERT_MODE_SSL,
                    constants.CERT_MODE_TPM,
                    constants.CERT_MODE_MURANO,
                    constants.CERT_MODE_DOCKER_REGISTRY,
                    constants.CERT_MODE_OPENSTACK,
                    ]:
            private_mode = True

        with open(temp_pem_file, "r") as key_file:
            if private_mode:
                # extract private_key with passphrase
                try:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=passphrase,
                        backend=default_backend())
                except Exception as e:
                    raise exception.SysinvException(_("Error decrypting PEM "
                        "file: %s" % e))
                key_file.seek(0)
            # extract the certificate from the pem file
            cert = x509.load_pem_x509_certificate(key_file.read(),
                                                  default_backend())
        os.remove(temp_pem_file)

        if private_mode:
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise exception.SysinvException(_("Only RSA encryption based "
                    "Private Keys are supported."))

            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=cert_format,
                encryption_algorithm=serialization.NoEncryption())

        signature = mode + '_' + str(cert.serial_number)
        if len(signature) > 255:
            LOG.info("Truncating certificate serial no %s" % signature)
            signature = signature[:255]
        LOG.info("config_certificate signature=%s" % signature)

        # format=serialization.PrivateFormat.TraditionalOpenSSL,
        public_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)

        return private_bytes, public_bytes, signature

    def _perform_config_certificate_tpm_mode(self, context,
                                             tpm, private_bytes, public_bytes):

        personalities = [constants.CONTROLLER]

        os_tpmdevices = glob.glob('/dev/tpm*')
        if not os_tpmdevices:
            msg = "TPM device does not exist on active controller"
            LOG.warn(msg)
            raise exception.SysinvException(_(msg))
        config_uuid = self._config_update_hosts(context, personalities)

        cert_path = constants.SSL_CERT_DIR + 'key.pem'
        public_path = constants.SSL_CERT_DIR + 'cert.pem'

        config_dict = {
            'personalities': personalities,
            'file_names': [cert_path, public_path],
            'file_content': {cert_path: private_bytes,
                             public_path: public_bytes},
            'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
        }
        self._config_update_file(context, config_uuid, config_dict)

        tpmconfig_dict = {'tpm_path': constants.SSL_CERT_DIR + 'object.tpm'}
        if not tpm:
            self.dbapi.tpmconfig_create(tpmconfig_dict)

        tpmconfig_dict.update(
            {'cert_path': constants.SSL_CERT_DIR + 'key.pem',
             'public_path': constants.SSL_CERT_DIR + 'cert.pem'})

        self.update_tpm_config(context,
                               tpmconfig_dict,
                               update_file_required=False)

    @staticmethod
    def _remove_certificate_file(mode, certificate_file):
        if certificate_file:
            try:
                LOG.info("config_certificate mode=%s remove %s" %
                         (mode, certificate_file))
                os.remove(certificate_file)
            except OSError:
                pass

    def _get_registry_floating_address(self):
        """gets the registry floating address. Currently this is mgmt
        """
        registry_network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)
        registry_network_addr_pool = self.dbapi.address_pool_get(
            registry_network.pool_uuid)
        addr = registry_network_addr_pool.floating_address
        return addr

    def config_certificate(self, context, pem_contents, config_dict):
        """Configure certificate with the supplied data.

        :param context: an admin context.
        :param pem_contents: contents of certificate in pem format.
        :param config_dict: dictionary of certificate config attributes.

        In regular mode, the SSL certificate is crafted from the
            isolated private and public keys.

        In tpm_mode, this is done by tpmconfig
        """

        passphrase = config_dict.get('passphrase', None)
        mode = config_dict.get('mode', None)
        certificate_file = config_dict.get('certificate_file', None)

        LOG.info("config_certificate mode=%s file=%s" % (mode, certificate_file))

        private_bytes, public_bytes, signature = \
            self._extract_keys_from_pem(mode, pem_contents,
                                        serialization.PrivateFormat.PKCS8,
                                        passphrase)

        personalities = [constants.CONTROLLER]
        tpm = None
        try:
            tpm = self.dbapi.tpmconfig_get_one()
        except exception.NotFound:
            pass

        if mode == constants.CERT_MODE_TPM:
            self._perform_config_certificate_tpm_mode(
                context, tpm, private_bytes, public_bytes)

            file_content = public_bytes
            # copy the certificate to shared directory
            with os.fdopen(os.open(constants.SSL_PEM_FILE_SHARED,
                                   os.O_CREAT | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(file_content)

            self._remove_certificate_file(mode, certificate_file)

        elif mode == constants.CERT_MODE_SSL:
            config_uuid = self._config_update_hosts(context, personalities)
            file_content = private_bytes + public_bytes
            config_dict = {
                'personalities': personalities,
                'file_names': [constants.SSL_PEM_FILE],
                'file_content': file_content,
                'nobackup': True,
                'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            }
            self._config_update_file(context, config_uuid, config_dict)

            # copy the certificate to shared directory
            with os.fdopen(os.open(constants.SSL_PEM_FILE_SHARED,
                                   os.O_CREAT | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(file_content)

            if tpm:
                LOG.info("tpm_mode not requested; destroy tpmconfig=%s" %
                         tpm.uuid)
                self._destroy_tpm_config(context, tpm_obj=tpm)

            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::haproxy::runtime',
                            'openstack::horizon::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict)

            self._remove_certificate_file(mode, certificate_file)
        elif mode == constants.CERT_MODE_SSL_CA:
            config_uuid = self._config_update_hosts(context, personalities)
            file_content = public_bytes
            config_dict = {
                'personalities': personalities,
                'file_names': [constants.SSL_CERT_CA_FILE],
                'file_content': file_content,
                'permissions': constants.CONFIG_FILE_PERMISSION_DEFAULT,
            }
            self._config_update_file(context, config_uuid, config_dict)

            # copy the certificate to shared directory
            with os.fdopen(os.open(constants.SSL_CERT_CA_FILE_SHARED,
                                   os.O_CREAT | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_DEFAULT),
                                   'wb') as f:
                f.write(file_content)

            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::haproxy::runtime',
                            'openstack::horizon::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict)
        elif mode == constants.CERT_MODE_MURANO:
            LOG.info("Murano certificate install")
            config_uuid = self._config_update_hosts(context, personalities,
                                                    reboot=True)
            key_path = constants.MURANO_CERT_KEY_FILE
            cert_path = constants.MURANO_CERT_FILE
            config_dict = {
                'personalities': personalities,
                'file_names': [key_path, cert_path],
                'file_content': {key_path: private_bytes,
                                 cert_path: public_bytes},
                'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            }
            self._config_update_file(context, config_uuid, config_dict)
            self._remove_certificate_file(mode, certificate_file)
        elif mode == constants.CERT_MODE_MURANO_CA:
            LOG.info("Murano CA certificate install")
            config_uuid = self._config_update_hosts(context, personalities,
                                                    reboot=True)
            config_dict = {
                'personalities': personalities,
                'file_names': [constants.MURANO_CERT_CA_FILE],
                'file_content': public_bytes,
                'permissions': constants.CONFIG_FILE_PERMISSION_DEFAULT,
            }
            self._config_update_file(context, config_uuid, config_dict)
        elif mode == constants.CERT_MODE_DOCKER_REGISTRY:
            LOG.info("Docker registry certificate install")
            # docker registry requires a PKCS1 key for the token server
            pkcs1_private_bytes, pkcs1_public_bytes, pkcs1_signature = \
                self._extract_keys_from_pem(mode, pem_contents,
                                            serialization.PrivateFormat
                                            .TraditionalOpenSSL, passphrase)

            # install certificate, key, and pkcs1 key to controllers
            config_uuid = self._config_update_hosts(context, personalities)
            key_path = constants.DOCKER_REGISTRY_KEY_FILE
            cert_path = constants.DOCKER_REGISTRY_CERT_FILE
            pkcs1_key_path = constants.DOCKER_REGISTRY_PKCS1_KEY_FILE

            config_dict = {
                'personalities': personalities,
                'file_names': [key_path, cert_path, pkcs1_key_path],
                'file_content': {key_path: private_bytes,
                                 cert_path: public_bytes,
                                 pkcs1_key_path: pkcs1_private_bytes},
                'nobackup': True,
                'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            }
            self._config_update_file(context, config_uuid, config_dict)

            # copy certificate to shared directory
            with os.fdopen(os.open(constants.DOCKER_REGISTRY_CERT_FILE_SHARED,
                                   os.O_CREAT | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(public_bytes)
            with os.fdopen(os.open(constants.DOCKER_REGISTRY_KEY_FILE_SHARED,
                                   os.O_CREAT | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(private_bytes)
            with os.fdopen(os.open(constants.DOCKER_REGISTRY_PKCS1_KEY_FILE_SHARED,
                                   os.O_CREAT | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(pkcs1_private_bytes)

            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['platform::dockerdistribution::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict)

            self._remove_certificate_file(mode, certificate_file)

            # install docker certificate on controllers and workers
            registry_full_address = self._get_registry_floating_address() + ":" + helm_common.REGISTRY_PORT
            docker_cert_path = os.path.join("/etc/docker/certs.d",
                                            registry_full_address,
                                            "registry-cert.crt")

            personalities = [constants.CONTROLLER,
                             constants.WORKER]
            config_uuid = self._config_update_hosts(context,
                                                    personalities)
            config_dict = {
                'personalities': personalities,
                'file_names': [docker_cert_path],
                'file_content': public_bytes,
                'nobackup': True,
                'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            }
            self._config_update_file(context, config_uuid, config_dict)
        elif mode == constants.CERT_MODE_OPENSTACK:
            config_uuid = self._config_update_hosts(context, personalities)
            key_path = constants.OPENSTACK_CERT_KEY_FILE
            cert_path = constants.OPENSTACK_CERT_FILE
            config_dict = {
                'personalities': personalities,
                'file_names': [key_path, cert_path],
                'file_content': {key_path: private_bytes,
                                 cert_path: public_bytes},
                'nobackup': True,
                'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            }
            self._config_update_file(context, config_uuid, config_dict)

            if not os.path.exists(constants.CERT_OPENSTACK_SHARED_DIR):
                os.makedirs(constants.CERT_OPENSTACK_SHARED_DIR)
            # copy the certificate to shared directory
            with os.fdopen(os.open(constants.OPENSTACK_CERT_FILE_SHARED,
                                   os.O_CREAT | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(public_bytes)
            with os.fdopen(os.open(constants.OPENSTACK_CERT_KEY_FILE_SHARED,
                                   os.O_CREAT | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                                   'wb') as f:
                f.write(private_bytes)

            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['openstack::keystone::endpoint::runtime',
                            'openstack::horizon::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict)

            self._remove_certificate_file(mode, certificate_file)

        elif mode == constants.CERT_MODE_OPENSTACK_CA:
            config_uuid = self._config_update_hosts(context, personalities)
            file_content = public_bytes
            config_dict = {
                'personalities': personalities,
                'file_names': [constants.OPENSTACK_CERT_CA_FILE],
                'file_content': file_content,
                'permissions': constants.CONFIG_FILE_PERMISSION_DEFAULT,
            }
            self._config_update_file(context, config_uuid, config_dict)

            # copy the certificate to shared directory
            with os.fdopen(os.open(constants.OPENSTACK_CERT_CA_FILE_SHARED,
                                   os.O_CREAT | os.O_WRONLY,
                                   constants.CONFIG_FILE_PERMISSION_DEFAULT),
                                   'wb') as f:
                f.write(file_content)

            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "classes": ['openstack::keystone::endpoint::runtime',
                            'openstack::horizon::runtime']
            }
            self._config_apply_runtime_manifest(context,
                                                config_uuid,
                                                config_dict)
        else:
            msg = "config_certificate unexpected mode=%s" % mode
            LOG.warn(msg)
            raise exception.SysinvException(_(msg))

        return signature

    def _config_selfsigned_certificate(self, context):
        """
        This code is invoked when https is enabled
        to install a self signed certificate to get started

        :param context: an admin context.

        """

        mode = constants.CERT_MODE_SSL
        passphrase = None
        certificate_file = constants.SSL_PEM_SS_FILE

        with open(certificate_file) as pemfile:
            pem_contents = pemfile.read()

        LOG.info("_config_selfsigned_certificate mode=%s file=%s" % (mode, certificate_file))

        private_bytes, public_bytes, signature = \
            self._extract_keys_from_pem(mode, pem_contents,
                                        serialization.PrivateFormat.PKCS8,
                                        passphrase)

        personalities = [constants.CONTROLLER]

        config_uuid = self._config_update_hosts(context, personalities)
        file_content = private_bytes + public_bytes
        config_dict = {
            'personalities': personalities,
            'file_names': [constants.SSL_PEM_FILE],
            'file_content': file_content,
            'permissions': constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY,
            'nobackup': True,
        }
        self._config_update_file(context, config_uuid, config_dict)

        # copy the certificate to shared directory
        with os.fdopen(os.open(constants.SSL_PEM_FILE_SHARED,
                               os.O_CREAT | os.O_WRONLY,
                               constants.CONFIG_FILE_PERMISSION_ROOT_READ_ONLY),
                               'wb') as f:
            f.write(file_content)

        return signature

    def get_helm_chart_namespaces(self, context, chart_name):
        """Get supported chart namespaces.

        This method retrieves the namespace supported by a given chart.

        :param context: request context.
        :param chart_name: name of the chart
        :returns: list of supported namespaces that associated overrides may be
                  provided.
        """
        return self._helm.get_helm_chart_namespaces(chart_name)

    def get_helm_chart_overrides(self, context, chart_name, cnamespace=None):
        """Get the overrides for a supported chart.

        This method retrieves overrides for a supported chart. Overrides for
        all supported namespaces will be returned unless a specific namespace
        is requested.

        :param context: request context.
        :param chart_name: name of a supported chart
        :param cnamespace: (optional) namespace
        :returns: dict of overrides.

        Example Without a cnamespace parameter:
        {
            'kube-system': {
                'deployment': {
                    'mode': 'cluster',
                    'type': 'DaemonSet'
                },
            },
            'openstack': {
                'pod': {
                    'replicas': {
                        'server': 1
                    }
                }
            }
        }

        Example with a cnamespace parameter: cnamespace='kube-system'
        {
            'deployment': {
                'mode': 'cluster',
                'type': 'DaemonSet'
            }
        }
        """
        return self._helm.get_helm_chart_overrides(chart_name,
                                                   cnamespace)

    def get_helm_application_namespaces(self, context, app_name):
        """Get supported application namespaces.

        This method retrieves a dict of charts and their supported namespaces
        for an application.

        :param app_name: name of the bundle of charts required to support an
                         application
        :returns: dict of charts and supported namespaces that associated
                  overrides may be provided.
        """
        return self._helm.get_helm_application_namespaces(app_name)

    def get_helm_application_overrides(self, context, app_name, cnamespace):
        """Get the overrides for a supported set of charts.

        This method retrieves overrides for a set of supported charts that
        comprise an application. Overrides for all charts and all supported
        namespaces will be returned unless a specific namespace is requested.

        If a specific namespace is requested, then only charts that support
        that specified namespace will be returned.

        :param context: request context.
        :param app_name: name of a supported application (set of charts)
        :param cnamespace: (optional) namespace
        :returns: dict of overrides.

        Example:
        {
            'ingress': {
                'kube-system': {
                    'deployment': {
                        'mode': 'cluster',
                        'type': 'DaemonSet'
                    },
                },
                'openstack': {
                    'pod': {
                        'replicas': {
                            'server': 1
                        }
                    }
                }
            },
            'glance': {
                'openstack': {
                    'pod': {
                        'replicas': {
                            'server': 1
                        }
                    }
                }
             }
        }
        """
        return self._helm.get_helm_application_overrides(app_name, cnamespace)

    def merge_overrides(self, context, file_overrides=[], set_overrides=[]):
        """Merge the file and set overrides into a single chart overrides.

        :param context: request context.
        :param file_overrides: (optional) list of overrides from files
        :param set_overrides: (optional) list of parameter overrides
        :returns: merged overrides string

        """
        return self._helm.merge_overrides(file_overrides, set_overrides)

    def update_kubernetes_label(self, context,
                                host_uuid, label_dict):
        """Synchronously, have the conductor update kubernetes label
        per host.

        :param context: request context.
        :param host_uuid: uuid or id of the host
        :param label_dict: a dictionary of host label attributes

        """
        LOG.info("update_kubernetes_label: label_dict=%s" % label_dict)
        try:
            host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            LOG.error("Cannot find host by id %s" % host_uuid)
            return
        body = {
            'metadata': {
                'labels': {}
            }
        }
        body['metadata']['labels'].update(label_dict)
        try:
            self._kube.kube_patch_node(host.hostname, body)
        except exception.K8sNodeNotFound:
            LOG.info("Host %s does not exist in kubernetes yet, label will "
                     "be added after node's unlock by audit" % host.hostname)

    def update_host_memory(self, context, host_uuid):
        try:
            host = self.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            LOG.error("Cannot find host by id %s" % host_uuid)
            return

        rpcapi = agent_rpcapi.AgentAPI()
        rpcapi.update_host_memory(context, host.uuid)

    def update_fernet_repo(self, context, keys=None):
        """Update the fernet repo with the new keys.

          :param context: request context.
          :param keys: a list of keys
          :returns: nothing
          """

        if keys:
            self._fernet.update_fernet_keys(keys)
        else:
            self._fernet.reset_fernet_keys()

    def get_fernet_keys(self, context, key_id=None):
        """Get the keys from the fernet repo.

          :param context: request context.
          :param key_id: Optionally, it can be used to retrieve a specified key
          :returns: a list of keys
          """
        return self._fernet.get_fernet_keys(key_id)

    def perform_app_upload(self, context, rpc_app, tarfile):
        """Handling of application upload request (via AppOperator)

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param tarfile: location of the application tarfile to be exracted

        """
        self._app.perform_app_upload(rpc_app, tarfile)

    def perform_app_apply(self, context, rpc_app, mode):
        """Handling of application install request (via AppOperator)

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param mode: mode to control how to apply application manifest
        """
        was_applied = self._app.is_app_active(rpc_app)
        app_applied = self._app.perform_app_apply(rpc_app, mode)
        appname = self._app.get_appname(rpc_app)
        if constants.HELM_APP_OPENSTACK == appname and app_applied \
                and not was_applied:
            # apply any runtime configurations that are needed for
            # stx_openstack application
            self._update_config_for_stx_openstack(context)
            self._update_pciirqaffinity_config(context)

        return app_applied

    def perform_app_remove(self, context, rpc_app):
        """Handling of application removal request (via AppOperator)

        :param context: request context.
        :param rpc_app: data object provided in the rpc request

        """
        # deactivate the app
        self._app.deactivate(rpc_app)
        appname = self._app.get_appname(rpc_app)
        # need to update sm stx_openstack runtime manifest first
        # to deprovision dbmon service prior to removing the
        # stx-openstack application
        if constants.HELM_APP_OPENSTACK == appname:
            self._config_sm_stx_openstack(context)

        app_removed = self._app.perform_app_remove(rpc_app)
        if constants.HELM_APP_OPENSTACK == appname and app_removed:
            # Update the VIM and PciIrqAffinity configuration.
            self._update_vim_config(context)
            self._update_pciirqaffinity_config(context)
        return app_removed

    def perform_app_delete(self, context, rpc_app):
        """Handling of application delete request (via AppOperator)

        :param context: request context.
        :param rpc_app: data object provided in the rpc request

        """
        return self._app.perform_app_delete(rpc_app)

    def reconfigure_service_endpoints(self, context, host):
        """Reconfigure the service endpoints upon the creation of initial
        controller host and management/oam network change during bootstrap
        playbook play and replay.

        :param context: request context.
        :param host: an ihost object

        """
        if (os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG) and
                host.hostname == constants.CONTROLLER_0_HOSTNAME):

            controller_0_address = self.dbapi.address_get_by_name(
                constants.CONTROLLER_0_MGMT)
            if controller_0_address.address != host.mgmt_ip:
                self.dbapi.ihost_update(host.uuid,
                                        {'mgmt_ip': controller_0_address.address})

            personalities = [constants.CONTROLLER]
            config_uuid = self._config_update_hosts(context, personalities)
            config_dict = {
                "personalities": personalities,
                "host_uuids": [host.uuid],
                "classes": ['openstack::keystone::endpoint::runtime']
            }
            self._config_apply_runtime_manifest(
                context, config_uuid, config_dict, force=True)
        else:
            LOG.error("Received a request to reconfigure service endpoints "
                      "for host %s under the wrong condition." % host.hostname)

    def mgmt_mac_set_by_ihost(self, context, host, mgmt_mac):
        """Update the management mac address upon management interface
        during bootstrap.

        :param context: request context
        :param host: an ihost object
        :param mgmt_mac: mac address of management interface
        """
        if (os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG) and
                host.hostname == constants.CONTROLLER_0_HOSTNAME):

            self.dbapi.ihost_update(host.uuid,
                                    {'mgmt_mac': mgmt_mac})
        else:
            LOG.error("Received a request to update management mac for host "
                      "%s under the wrong condition." % host.hostname)
