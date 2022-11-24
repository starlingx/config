#
# Copyright (c) 2018-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from __future__ import division
from distutils.version import LooseVersion
from eventlet.green import subprocess
import json
import os

from oslo_log import log
from sysinv._i18n import _
from sysinv.common import ceph
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils
from sysinv.common.fm import fmclient
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.api.controllers.v1 import patch_api
from sysinv.api.controllers.v1 import vim_api

import tsconfig.tsconfig as tsc

import cgcs_patch.constants as patch_constants

LOG = log.getLogger(__name__)


class Health(object):

    SUCCESS_MSG = _('OK')
    FAIL_MSG = _('Fail')

    def __init__(self, dbapi):
        self._dbapi = dbapi
        self._ceph = ceph.CephApiOperator()
        self._kube_operator = kubernetes.KubeOperator()

    def _check_hosts_provisioned(self, hosts):
        """Checks that each host is provisioned"""
        provisioned_hosts = []
        unprovisioned_hosts = 0
        for host in hosts:
            if host['invprovision'] != constants.PROVISIONED or \
                    host['hostname'] is None:
                unprovisioned_hosts = unprovisioned_hosts + 1
            else:
                provisioned_hosts.append(host)

        return unprovisioned_hosts, provisioned_hosts

    def _check_hosts_enabled(self, hosts):
        """Checks that each host is enabled and unlocked"""
        offline_host_list = []
        for host in hosts:
            if host['administrative'] != constants.ADMIN_UNLOCKED or \
                    host['operational'] != constants.OPERATIONAL_ENABLED:
                offline_host_list.append(host.hostname)

        success = not offline_host_list
        return success, offline_host_list

    def _check_hosts_config(self, hosts):
        """Checks that the applied and target config match for each host"""
        config_host_list = []
        for host in hosts:
            if (host.config_target and
                    host.config_applied != host.config_target):
                config_host_list.append(host.hostname)

        success = not config_host_list
        return success, config_host_list

    def _check_patch_current(self, hosts):
        """Checks that each host is patch current"""
        system = self._dbapi.isystem_get_one()
        response = patch_api.patch_query_hosts(token=None, timeout=60,
                                               region_name=system.region_name)
        patch_hosts = response['data']
        not_patch_current_hosts = []
        hostnames = []
        for host in hosts:
            hostnames.append(host['hostname'])

        for host in patch_hosts:
            # There may be instances where the patching db returns
            # hosts that have been recently deleted. We will continue if a host
            # is the patching db but not sysinv
            try:
                hostnames.remove(host['hostname'])
            except ValueError:
                LOG.info('Host %s found in patching but not in sysinv. '
                         'Continuing' % host['hostname'])
            else:
                if not host['patch_current']:
                    not_patch_current_hosts.append(host['hostname'])

        success = not not_patch_current_hosts and not hostnames
        return success, not_patch_current_hosts, hostnames

    def _check_alarms(self, context, force=False, alarm_ignore_list=None):
        """Checks that no alarms are active"""
        if alarm_ignore_list is None:
            alarm_ignore_list = []

        alarms = fmclient(context).alarm.list(include_suppress=True)

        success = True
        allowed = 0
        affecting = 0
        # Separate alarms that are mgmt affecting
        for alarm in alarms:
            if alarm.alarm_id not in alarm_ignore_list:
                mgmt_affecting = alarm.mgmt_affecting == "True"
                if not mgmt_affecting:
                    allowed += 1
                    if not force:
                        success = False
                else:
                    affecting += 1
                    success = False

        return success, allowed, affecting

    def _check_active_is_controller_0(self):
        """Checks that active controller is controller-0"""
        return utils.get_local_controller_hostname() == constants.CONTROLLER_0_HOSTNAME

    def get_alarms_degrade(self, context, alarm_ignore_list=None,
            entity_instance_id_filter=""):
        """Return all the alarms that cause the degrade"""
        alarms = fmclient(context).alarm.list(include_suppress=True)
        degrade_alarms = []
        if alarm_ignore_list is None:
            alarm_ignore_list = []

        for alarm in alarms:
            degrade_affecting = alarm.degrade_affecting
            # Ignore alarms that are part of the ignore list sent as parameter
            # and also filter the alarms bases on entity instance id.
            # If multiple alarms with the same ID exist, we only return the ID
            # one time.
            if degrade_affecting == 'True':
                if (entity_instance_id_filter in alarm.entity_instance_id and
                        alarm.alarm_id not in alarm_ignore_list and
                        alarm.alarm_id not in degrade_alarms):
                    degrade_alarms.append(alarm.alarm_id)
        return degrade_alarms

    def _check_ceph(self):
        """Checks the ceph health status"""
        return self._ceph.ceph_status_ok()

    def _check_license(self, version):
        """Validates the current license is valid for the specified version"""
        check_binary = "/usr/bin/verify-license"
        license_file = '/etc/platform/.license'

        with open(os.devnull, "w") as fnull:
            try:
                subprocess.check_call([check_binary, license_file, version],  # pylint: disable=not-callable
                                      stdout=fnull, stderr=fnull)
            except subprocess.CalledProcessError:
                return False

        return True

    def _check_required_patches_are_applied(self, patches=None):
        """Validates that each patch provided is applied on the system"""
        if patches is None:
            patches = []
        try:
            system = self._dbapi.isystem_get_one()
            response = patch_api.patch_query(
                token=None,
                timeout=constants.PATCH_DEFAULT_TIMEOUT_IN_SECS,
                region_name=system.region_name
            )
        except Exception as e:
            LOG.error(e)
            raise exception.SysinvException(_(
                "Error while querying sw-patch-controller for the "
                "state of the patch(es)."))
        query_patches = response['pd']
        applied_patches = []
        for patch_key in query_patches:
            patch = query_patches[patch_key]
            patchstate = patch.get('patchstate', None)
            if patchstate == patch_constants.APPLIED or \
                    patchstate == patch_constants.COMMITTED:
                applied_patches.append(patch_key)

        missing_patches = []
        for required_patch in patches:
            if required_patch not in applied_patches:
                missing_patches.append(required_patch)

        success = not missing_patches
        return success, missing_patches

    def _check_running_instances(self, host):
        """Checks that no instances are running on the host"""

        vim_resp = vim_api.vim_host_get_instances(
            None,
            host['uuid'],
            host['hostname'],
            constants.VIM_DEFAULT_TIMEOUT_IN_SECS)
        running_instances = vim_resp['instances']

        success = running_instances == 0
        return success, running_instances

    def _check_kube_nodes_ready(self):
        """Checks that each kubernetes node is ready"""
        fail_node_list = []

        nodes = self._kube_operator.kube_get_nodes()
        for node in nodes:
            for condition in node.status.conditions:
                if condition.type == "Ready" and condition.status != "True":
                    # This node is not ready
                    fail_node_list.append(node.metadata.name)

        success = not fail_node_list
        return success, fail_node_list

    def _check_kube_control_plane_pods(self):
        """Checks that each kubernetes control plane pod is ready"""
        fail_pod_list = []

        pod_ready_status = self._kube_operator.\
            kube_get_control_plane_pod_ready_status()

        for pod_name, ready_status in pod_ready_status.items():
            if ready_status != "True":
                # This pod is not ready
                fail_pod_list.append(pod_name)

        success = not fail_pod_list
        return success, fail_pod_list

    def _check_kube_applications(self):
        """Checks that each kubernetes application is in a valid state"""

        fail_app_list = []
        apps = self._dbapi.kube_app_get_all()

        for app in apps:
            # The following states are valid during kubernetes upgrade
            if app.status not in [constants.APP_UPLOAD_SUCCESS,
                                  constants.APP_APPLY_SUCCESS,
                                  constants.APP_INACTIVE_STATE]:
                fail_app_list.append(app.name)

        success = not fail_app_list
        return success, fail_app_list

    def _check_platform_backup_partition(self):
        """Check that the platform-backup partition is the correct size/type"""

        args = ['/usr/bin/validate-platform-backup.sh']
        try:
            subprocess.check_output(args, stderr=subprocess.STDOUT)  # pylint: disable=not-callable
        except subprocess.CalledProcessError as exc:
            LOG.error("Call to %s returned %s and %s" % (args, exc.returncode, exc.output))
            return False

        return True

    def _check_trident_compatibility(self):
        """Checks that the running Trident service has been
        upgraded and is compatible with all possible k8s
        upgrade versions."""

        latest_trident_version = '22.01'

        try:
            output = subprocess.check_output(  # pylint: disable=not-callable
                'export KUBECONFIG=/etc/kubernetes/admin.conf && \
                tridentctl -n trident version -o json',
                shell=True, stderr=subprocess.STDOUT).decode('utf-8')
            if output:
                json_output = json.loads(output)
                if 'server' in json_output.keys():
                    if LooseVersion(latest_trident_version) > \
                            LooseVersion(json_output['server']['version']):
                        return False
                else:
                    return True
        except Exception as e:
            # the exception signifies that the trident driver is not installed.
            # we can continue with the k8s upgrade in this case.
            LOG.info("Exception %s occured when trying to get trident version" % e)
            return True

        return True

    def get_system_health(self, context, force=False, alarm_ignore_list=None):
        """Returns the general health of the system

        Checks the following:
        - All hosts are provisioned
        - All hosts are patch current
        - All hosts are unlocked/enabled
        - All hosts having matching configs
        - No management affecting alarms
        - For ceph systems: The storage cluster is healthy
        - All kubernetes nodes are ready
        - All kubernetes control plane pods are ready

        :param context: request context.
        :param force: set to true to ignore minor and warning alarms
        :param alarm_ignore_list: list of alarm ids to ignore when performing
                                  a health check
        """
        hosts = utils.get_upgradable_hosts(self._dbapi)
        output = _('System Health:\n')
        health_ok = True

        unprovisioned_hosts, provisioned_hosts = \
            self._check_hosts_provisioned(hosts)
        success = unprovisioned_hosts == 0
        output += (_('All hosts are provisioned: [%s]\n')
                   % (Health.SUCCESS_MSG if success else Health.FAIL_MSG))
        if not success:
            output += _('%s Unprovisioned hosts\n') % unprovisioned_hosts
            # Set the hosts to the provisioned_hosts. This will allow the other
            # checks to continue
            hosts = provisioned_hosts

        health_ok = health_ok and success

        success, error_hosts = self._check_hosts_enabled(hosts)
        output += _('All hosts are unlocked/enabled: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            output += _('Locked or disabled hosts: %s\n') \
                % ', '.join(error_hosts)

        health_ok = health_ok and success

        success, error_hosts = self._check_hosts_config(hosts)
        output += _('All hosts have current configurations: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            output += _('Hosts with out of date configurations: %s\n') \
                % ', '.join(error_hosts)

        health_ok = health_ok and success

        success, error_hosts, missing_hosts = self._check_patch_current(hosts)
        output += _('All hosts are patch current: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            if error_hosts:
                output += _('Hosts not patch current: %s\n') \
                    % ', '.join(error_hosts)
            if missing_hosts:
                output += _('Hosts without patch data: %s\n') \
                    % ', '.join(missing_hosts)

        health_ok = health_ok and success

        if StorageBackendConfig.has_backend(
                self._dbapi,
                constants.CINDER_BACKEND_CEPH):
            success = self._check_ceph()
            output += _('Ceph Storage Healthy: [%s]\n') \
                % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)

        health_ok = health_ok and success

        success, allowed, affecting = self._check_alarms(
            context,
            force=force,
            alarm_ignore_list=alarm_ignore_list)
        output += _('No alarms: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            output += _('[%s] alarms found, [%s] of which are management '
                        'affecting\n') % (allowed + affecting, affecting)

        health_ok = health_ok and success

        success, error_nodes = self._check_kube_nodes_ready()
        output += _('All kubernetes nodes are ready: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            output += _('Kubernetes nodes not ready: %s\n') \
                % ', '.join(error_nodes)

        health_ok = health_ok and success

        success, error_nodes = self._check_kube_control_plane_pods()
        output += _('All kubernetes control plane pods are ready: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            output += _('Kubernetes control plane pods not ready: %s\n') \
                % ', '.join(error_nodes)

        health_ok = health_ok and success

        return health_ok, output

    def _check_disk_space_on_host(self, host, hostname, min_space_needed, check_free_space):
        if check_free_space:
            available_gib = utils.get_available_gib_in_disk(host, host.rootfs_device, self._dbapi)
            msg = _("Insufficient unallocated disk space on rootdisk for %s. Current\n"
                    "partitions have allocated disk space such that only %.2fGiB is "
                    "available\nbut %.2fGiB unallocated disk space is needed.\n") % (hostname,
                                                                                     available_gib,
                                                                                     min_space_needed)
        else:
            available_gib = utils.get_size_gib_in_disk(host, host.rootfs_device, self._dbapi)
            msg = _("Insufficient total disk space on rootdisk for %s, %.2fGiB needed, "
                    "%.2fGiB available.\n") % (hostname,
                                               min_space_needed,
                                               available_gib)
        if available_gib < min_space_needed:
            return msg

    def _check_free_space_for_upgrade(self):
        output = ""
        success = True
        for ihost in self._dbapi.ihost_get_list():
            min_space_needed = 0
            check_free_space = False
            host = self._dbapi.ihost_get_by_hostname(ihost.hostname)
            host_subfunctions = host.subfunctions.split(",")
            if constants.WORKER in host_subfunctions:
                min_space_needed = constants.WORKER_UPGRADE_FREE_SPACE_NEEDED_IN_GIB
                check_free_space = True
            elif constants.STORAGE in host_subfunctions:
                min_space_needed = constants.STORAGE_UPGRADE_SPACE_NEEDED_IN_GIB
            elif constants.CONTROLLER in host_subfunctions:
                min_space_needed = constants.CONTROLLER_UPGRADE_SPACE_NEEDED_IN_GIB
            msg = self._check_disk_space_on_host(
                host, ihost.hostname, min_space_needed, check_free_space)
            if msg:
                output += msg
                success = False
        return output, success

    def get_system_health_upgrade(self,
                                  context,
                                  force=False,
                                  alarm_ignore_list=None):
        """
        Ensures the system is in a valid state for an upgrade

        :param context: request context.
        :param force: set to true to ignore minor and warning alarms
        :param alarm_ignore_list: list of alarm ids to ignore when performing
                                  a health check
        """
        # Does a general health check then does the following:
        # A load is imported
        # The load patch requirements are met
        # The license is valid for the N+1 load
        # All kubernetes applications are in a stable state
        # Package metadata criteria are met
        system_mode = self._dbapi.isystem_get_one().system_mode
        simplex = (system_mode == constants.SYSTEM_MODE_SIMPLEX)

        health_ok, output = self.get_system_health(
            context,
            force=force,
            alarm_ignore_list=alarm_ignore_list)
        loads = self._dbapi.load_get_list()
        try:
            imported_load = utils.get_imported_load(loads)
        except Exception as e:
            LOG.exception(e)
            output += _('No imported load found. Unable to test further\n')
            return health_ok, output

        upgrade_version = imported_load.software_version
        if imported_load.required_patches:
            patches = imported_load.required_patches.split('\n')
        else:
            patches = []

        success, missing_patches = \
            self._check_required_patches_are_applied(patches)
        output += _('Required patches are applied: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            output += _('Patches not applied: %s\n') \
                % ', '.join(missing_patches)

        health_ok = health_ok and success

        success = self._check_license(upgrade_version)
        output += _('License valid for upgrade: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)

        health_ok = health_ok and success

        if not simplex:
            controller_1 = self._dbapi.ihost_get_by_hostname(
                constants.CONTROLLER_1_HOSTNAME)

            # If we are running on CPE we don't want any instances running
            # on controller-1 before we start the upgrade, otherwise the
            # databases will be out of sync after we lock controller-1
            if constants.WORKER in controller_1.subfunctions:
                success, running_instances = self._check_running_instances(
                    controller_1)
                output += \
                    _('No instances running on controller-1: [%s]\n') \
                    % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
                if not success:
                    output += _('Number of instances on controller-1: %s\n') \
                              % (running_instances)

            health_ok = health_ok and success
        else:
            success = self._check_platform_backup_partition()
            output += _('Valid platform-backup partition: [%s]\n') \
                % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)

            health_ok = health_ok and success

        success, apps_not_valid = self._check_kube_applications()
        output += _(
            'All kubernetes applications are in a valid state: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            output += _('Kubernetes applications not in a valid state: %s\n') \
                % ', '.join(apps_not_valid)

        health_ok = health_ok and success

        # The load is only imported to controller-0. An upgrade can only
        # be started when controller-0 is active.
        is_controller_0 = self._check_active_is_controller_0()
        success = is_controller_0
        output += \
            _('Active controller is controller-0: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)

        health_ok = health_ok and success
        # TODO (luisbonatti): remove when CentOS to Debian upgrade is deprecated
        if upgrade_version == tsc.SW_VERSION_22_12:
            msg, success = self._check_free_space_for_upgrade()
            output += \
                _('Disk space requirement: [%s]\n') \
                % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
            if not success:
                output += msg
            health_ok = health_ok and success

        return health_ok, output

    def get_system_health_kube_upgrade(self,
                                       context,
                                       force=False,
                                       alarm_ignore_list=None):
        """
        Ensures the system is in a valid state for a kubernetes upgrade

        Does a general health check then does the following:
        - All kubernetes applications are in a stable state

        :param context: request context.
        :param force: set to true to ignore minor and warning alarms
        :param alarm_ignore_list: list of alarm ids to ignore when performing
                                  a health check
        """
        health_ok, output = self.get_system_health(
            context,
            force=force,
            alarm_ignore_list=alarm_ignore_list)

        success, apps_not_valid = self._check_kube_applications()

        if not self._check_trident_compatibility():
            apps_not_valid.append("NetApp Trident Driver")
            success = False

        output += _(
            'All kubernetes applications are in a valid state: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            output += _('Kubernetes applications not in a valid state: %s\n') \
                % ', '.join(apps_not_valid)

        health_ok = health_ok and success

        return health_ok, output
