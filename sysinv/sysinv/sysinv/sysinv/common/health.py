#
# Copyright (c) 2018-2024 Wind River Systems, Inc.
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
from sysinv.common import usm_service
from sysinv.common.fm import fmclient
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.cert_alarm.audit import CertAlarmAudit
from sysinv.api.controllers.v1 import patch_api
from sysinv.api.controllers.v1 import vim_api

import cgcs_patch.constants as patch_constants

LOG = log.getLogger(__name__)


class Health(object):

    SUCCESS_MSG = _('OK')
    FAIL_MSG = _('Fail')

    def __init__(self, dbapi):
        self._dbapi = dbapi
        self._ceph = ceph.CephApiOperator()
        self._kube_operator = kubernetes.KubeOperator()
        self._cert_alarm_manager = CertAlarmAudit()

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

    def _check_patch_current(self):
        """Checks if hosts are patch current"""
        success = True
        from_release = None
        to_release = None

        # from stx-11 onwards patching is handled by USM, so the system
        # is patch current if there is no deployment in progress in USM
        # TODO(heitormatsui): change the logic when there is a USM endpoint
        #  to return data per-host
        try:
            deploy_in_progress = usm_service.get_platform_upgrade(self._dbapi)
        except exception.NotFound:
            # no upgrade in progress
            pass
        else:
            success = False
            from_release = deploy_in_progress.from_load
            to_release = deploy_in_progress.to_load

        return success, from_release, to_release

    def _check_alarms(self, context, force=False, alarm_ignore_list=None):
        """Checks that no alarms are active"""
        if alarm_ignore_list is None:
            alarm_ignore_list = []

        self._cert_alarm_manager.run_full_audit()

        alarms = fmclient(context).alarm.list(include_suppress=True)

        success = True
        allowed = 0
        affecting = 0
        cert_alarm = 0

        # Separate alarms that are mgmt affecting
        for alarm in alarms:
            if alarm.alarm_id not in alarm_ignore_list:
                mgmt_affecting = alarm.mgmt_affecting == "True"
                if alarm.alarm_id in constants.CERT_ALARM_IDS:
                    cert_alarm += 1
                    if not force:
                        success = False
                elif not mgmt_affecting:
                    allowed += 1
                    if not force:
                        success = False
                else:
                    affecting += 1
                    success = False

        return success, allowed, affecting, cert_alarm

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

    def _check_kube_all_pods_are_healthy(self):
        """Checks that all kubernetes pod are healthy

        A healthy pod is in ready or completed status.
        """
        fail_pod_list = []
        pod_list = self._kube_operator.kube_get_all_pods()

        for pod in pod_list:
            if pod.status.phase not in ['Pending', 'Running', 'Succeeded']:
                # Add it to the failed list as it's not ready/completed/pending
                fail_pod_list.append((pod.metadata.name, pod.metadata.namespace))
            elif pod.status.phase == 'Running':
                for container_status in pod.status.container_statuses:
                    if container_status.ready is not True:
                        # Pod has running status but it's not ready
                        fail_pod_list.append((pod.metadata.name,
                                              pod.metadata.namespace))
                        break
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

    def _check_kube_version(self):
        """Checks if kubernetes version is the latest supported version"""
        success = False

        latest_supported_version = \
                kubernetes.get_latest_supported_version()

        active_kube_version = self._kube_operator.kube_get_kubernetes_version()
        if active_kube_version:
            if active_kube_version == latest_supported_version:
                success = True
        return success, active_kube_version, latest_supported_version

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

    def _check_bootdevice(self):
        def _format_message(hostname, device_type, device, rootdisk):
            not_found = "%s (%s) for %s does not match root disk %s\n"
            not_assigned = "%s for %s is not assigned\n"
            if device:
                return not_found % (device_type, device, hostname, rootdisk)
            else:
                return not_assigned % (device_type, hostname)

        def is_rootdisk(idisk):
            # root disk has capabilities:{'stor_function': 'rootfs'}
            c = idisk.capabilities
            if "stor_function" in c and c["stor_function"] == "rootfs":
                return True
            return False

        success = True
        message = ""

        ihosts = self._dbapi.ihost_get_list()
        for ihost in ihosts:
            idisks = self._dbapi.idisk_get_by_ihost(ihost.uuid)
            for idisk in idisks:
                if is_rootdisk(idisk):
                    if ihost.boot_device not in [idisk.device_node, idisk.device_path]:
                        success = False
                        message += _format_message(ihost.hostname, "boot_device", ihost.boot_device,
                                                   idisk.device_node)
                    if ihost.rootfs_device not in [idisk.device_node, idisk.device_path]:
                        success = False
                        message += _format_message(ihost.hostname, "rootfs_device", ihost.rootfs_device,
                                                   idisk.device_node)
                    break
            else:
                success = False
                message += "Cannot determine the root disk for %s\n" % ihost.hostname
                continue
        return success, message

    def _check_psp_policies(self):
        """ Checks for any existing PodSecurityPolicies on the system """
        psp_list = []
        active_kube_version = self._kube_operator.kube_get_kubernetes_version()

        # check for policies only if version is less than v1.25
        if LooseVersion(active_kube_version) >= LooseVersion('v1.25.0'):
            return True, psp_list

        psp_policies = self._kube_operator.get_psp_resource()
        if psp_policies:
            for item in psp_policies:
                psp_list.append(item.metadata.name)
            return False, psp_list
        else:
            return True, psp_list

    def _check_local_issuer_clusterIssuer(self):
        err_msg = ''
        local_ca_issuer = self._kube_operator.get_clusterwide_custom_resource(
            kubernetes.CERT_MANAGER_GROUP,
            kubernetes.CERT_MANAGER_VERSION,
            'clusterissuers',
            constants.LOCAL_CA_SECRET_NAME)

        if local_ca_issuer:
            if not utils.check_k8s_resource_ready(local_ca_issuer):
                err_msg += 'Local ClusterIssuer is not Ready.\n'
        else:
            err_msg += 'Local ClusterIssuer could not be found.\n'

        return err_msg

    def _check_local_issuer_secret_data(self):
        err_msg = ''
        ca_secret = self._kube_operator.kube_get_secret(constants.LOCAL_CA_SECRET_NAME,
                                                        constants.CERT_NAMESPACE_PLATFORM_CA_CERTS)

        if not ca_secret or not hasattr(ca_secret, 'data') or not hasattr(ca_secret, 'type'):
            err_msg += 'Platform Issuer (system-local-ca) secret data could not be retrieved.\n'
        else:
            if ca_secret.type != constants.K8S_SECRET_TYPE_TLS:
                err_msg += 'Platform Issuer (system-local-ca) secret data type is invalid.\n'
            else:
                data = ca_secret.data
                if ('ca.crt' not in data or 'tls.crt' not in data or 'tls.key' not in data):
                    err_msg += 'Missing field in Platform Issuer (system-local-ca) secret data.\n'

        certs_list = self._kube_operator.list_namespaced_custom_resources(
            kubernetes.CERT_MANAGER_GROUP,
            kubernetes.CERT_MANAGER_VERSION,
            constants.CERT_NAMESPACE_PLATFORM_CA_CERTS,
            'certificates')
        if certs_list:
            for cert_obj in certs_list:
                if cert_obj.get('spec').get('secretName') == constants.LOCAL_CA_SECRET_NAME:
                    err_msg += 'Platform Issuer (system-local-ca) secret data is in an invalid state.\n'
                    LOG.error('%s is not expected to be owned by a Certificate.'
                              % constants.LOCAL_CA_SECRET_NAME)

        return err_msg

    def _check_local_issuer_CA_cert_chain(self):
        err_msg = tls_crt = tls_key = ca_crt = ''
        try:
            tls_crt, tls_key, ca_crt = utils.get_certificate_from_secret(
                constants.LOCAL_CA_SECRET_NAME,
                constants.CERT_NAMESPACE_PLATFORM_CA_CERTS)
        except Exception as e:
            LOG.exception(e)
            err_msg += 'Platform Issuer CA data could not be retrieved.\n'
            return err_msg

        if not bool(tls_crt) or not bool(tls_key):
            err_msg += 'Platform Issuer CA certificate and/or key data is empty.\n'
            return err_msg

        # RCA
        if utils.verify_self_signed_ca_cert(tls_crt):
            if not utils.verify_cert_chain_trusted(tls_crt):
                err_msg += 'Platform Issuer Root CA certificate is not trusted by the platform.\n'
                return err_msg
            elif bool(ca_crt) and ca_crt != tls_crt:
                err_msg += 'Platform Issuer CA certificate chain is incorrect.\n'
                return err_msg
        # ICA
        else:
            if ca_crt != tls_crt:
                if bool(ca_crt):
                    if not utils.verify_cert_chain_trusted(ca_crt):
                        err_msg += 'Platform Issuer Root CA certificate is not trusted by the platform.\n'
                        return err_msg
                    if not utils.verify_cert_issuer(tls_crt, ca_crt):
                        err_msg += 'Platform Issuer Intermediate CA certificate chain is incorrect.\n'
                        return err_msg
                else:
                    if not utils.verify_cert_chain_trusted(tls_crt):
                        err_msg += 'Platform Issuer Root CA certificate is not trusted by the platform.\n'
                        return err_msg
            else:
                err_msg += 'Platform Issuer CA certificate chain is incorrect.\n'
                return err_msg

        return err_msg

    def _check_leaf_certificate_chain(self, cert_name, cert_namespace):
        err_msg = tls_crt = tls_key = ''
        try:
            tls_crt, tls_key, _ = utils.get_certificate_from_secret(cert_name, cert_namespace)
        except Exception as e:
            LOG.exception(e)
            err_msg += ('Certificate - %s - data could not be retrieved.\n' % cert_name)
            return err_msg

        if not bool(tls_crt) or not bool(tls_key):
            err_msg += ('Certificate - %s - cert and/or key data is empty.\n' % cert_name)
        elif not utils.verify_cert_chain_trusted(tls_crt):
            err_msg += ('Certificate - %s - chain cannot be verified as trusted.\n' % cert_name)

        return err_msg

    def _check_expected_platform_certs(self):
        err_msg = ''

        expected_certs = [constants.RESTAPI_CERT_SECRET_NAME,
                          constants.REGISTRY_CERT_SECRET_NAME]
        system = self._dbapi.isystem_get_one()
        if system.distributed_cloud_role != constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            expected_certs.append(constants.OPENLDAP_CERT_SECRET_NAME)

        for cert in expected_certs:
            cert_data = self._kube_operator.get_custom_resource(
                kubernetes.CERT_MANAGER_GROUP,
                kubernetes.CERT_MANAGER_VERSION,
                kubernetes.NAMESPACE_DEPLOYMENT,
                'certificates',
                cert)
            if cert_data:
                if not utils.check_k8s_resource_ready(cert_data):
                    err_msg += ('Expected Certificate - %s - is not Ready.\n' % cert)
                elif cert_data.get('spec').get('issuerRef').get('name') != constants.LOCAL_CA_SECRET_NAME:
                    err_msg += ('Expected Certificate - %s - was not issued by the Platform Issuer.\n' % cert)
                elif cert_data.get('spec').get('secretName') != cert:
                    err_msg += ('Expected Certificate - %s - secret name is different from expected.\n' % cert)
                else:
                    err_msg += self._check_leaf_certificate_chain(cert, kubernetes.NAMESPACE_DEPLOYMENT)
            else:
                err_msg += ('Expected Certificate - %s - could not be found.\n' % cert)

        return err_msg

    def _check_system_local_ca_flags(self):
        err_msg = ''
        if not utils.is_system_local_ca_data_from_user() and not utils.platform_certificates_upgraded():
            err_msg += 'Platform Issuer CA data was auto generated (not provided by user).\n'
        return err_msg

    def _check_local_issuer_health(self):
        err_msg = ''
        update_ca_warning = (
            "* \n"
            "* Warning: User is expected to convert Platform certificates (e.g. System REST API / GUI and \n"
            "* Local Docker Registry) to use cert-manager and be issued by system-local-ca ClusterIssuer, \n"
            "* before upgrading.\n"
            "* If you haven\'t yet, this might be the cause of the issues detected. Please perform the\n"
            "* \'Update system-local-ca or Migrate Platform Certificates to use Cert Manager\' procedure\n"
            "* before continuing.\n"
            "* \n"
        )

        check_methods = [self._check_system_local_ca_flags(),
                         self._check_local_issuer_secret_data(),
                         self._check_local_issuer_CA_cert_chain(),
                         self._check_local_issuer_clusterIssuer(),
                         self._check_expected_platform_certs()]

        try:
            for method in check_methods:
                if err_msg == '':
                    err_msg += method
        except Exception as e:
            LOG.exception(e)
            err_msg += "Could not finish Platform Issuer (system-local-ca) health verification.\n"

        if bool(err_msg):
            err_msg += update_ca_warning

        return not bool(err_msg), err_msg

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
        - All PodSecurityPolicies are removed

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

        if context._user_id != "usm":
            success, from_release, to_release = self._check_patch_current()
            output += _('All hosts are patch current: [%s]\n') \
                % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
            if not success:
                output += _('Deployment in progress: %s to %s\n' % (from_release, to_release))

            health_ok = health_ok and success

        if StorageBackendConfig.has_backend(
                self._dbapi,
                constants.CINDER_BACKEND_CEPH):
            success = self._check_ceph()
            output += _('Ceph Storage Healthy: [%s]\n') \
                % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)

        health_ok = health_ok and success

        success, allowed, affecting, cert_alarm = self._check_alarms(
            context,
            force=force,
            alarm_ignore_list=alarm_ignore_list)
        output += _('No alarms: [%s]\n') \
            % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            output += _('[%s] alarms found, [%s] of which are management affecting '
                        'and [%s] are certificate expiration alarms. '
                        'Use "fm alarm-list" for details\n') % (allowed + affecting + cert_alarm,
                                                                           affecting, cert_alarm)

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

        success, psp_list = self._check_psp_policies()
        output += ('All PodSecurityPolicies are removed: [%s]\n') \
                % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            output += _('PSP policies exists, please remove them before upgrade: %s\n') \
                    % ', '.join(psp_list)

        health_ok = health_ok and success

        return health_ok, output

    def _check_disk_space_on_host(self, host, hostname, min_space_needed, check_free_space):
        if check_free_space:
            available_gib = utils.get_available_gib_in_disk(host, host.boot_device, self._dbapi)
            msg = _("Insufficient unallocated disk space on rootdisk for %s. Current\n"
                    "partitions have allocated disk space such that only %.2fGiB is "
                    "available\nbut %.2fGiB unallocated disk space is needed.\n") % (hostname,
                                                                                     available_gib,
                                                                                     min_space_needed)
        else:
            available_gib = utils.get_size_gib_in_disk(host, host.boot_device, self._dbapi)
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
        # The platform issuer (system-local-ca) and certs are healthy
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

        success, active_version, latest_version = self._check_kube_version()
        output += _('Active kubernetes version is the latest supported '
                    'version: [%s]\n') \
                        % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        if not success:
            if active_version:
                output += _('Upgrade kubernetes to the latest version: [%s]. '
                            'See "system kube-version-list"\n') \
                                % (latest_version)
            else:
                output += _('Failed to get version info. Upgrade kubernetes to'
                            ' the latest version (%s) and ensure that the '
                            'kubernetes  version information is available in '
                            ' the kubeadm configmap.\n'
                            'Also see "system kube-version-list"\n') \
                                % (latest_version)

        health_ok = health_ok and success

        # Check the platform issuer ('system-local-ca') and platform certificates
        success, msg = self._check_local_issuer_health()
        output += _('Platform Issuer and expected certificates are healthy: [%s]\n') \
                    % (Health.SUCCESS_MSG if success else Health.FAIL_MSG)
        output += msg
        health_ok = health_ok and success

        success, message = self._check_bootdevice()
        if not success:
            # Make this an invisible check for the bootdevice and rootfs device.
            # unless it is invalid, it is invisible to the user.
            output += _('Boot Device and Root file system Device: [%s]\n') \
                    % Health.FAIL_MSG
            output += message

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

        return health_ok, output

    def get_system_health_kube_upgrade(self,
                                       context,
                                       force=False,
                                       alarm_ignore_list=None,
                                       kube_rootca_update=False):
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

        if kube_rootca_update:
            pods_healthy, fail_pod_list = self._check_kube_all_pods_are_healthy()
            output += _(
                'All kubernetes pods are in a valid state: [%s]\n') \
                % (Health.SUCCESS_MSG if pods_healthy else Health.FAIL_MSG)
            if not pods_healthy:
                formatted_fail_pod_list = ['{} (namespace: {})'.format(name, namespace)
                                           for name, namespace in fail_pod_list]
                output += _('Kubernetes pods not in a valid state: %s\n') \
                    % ', '.join(formatted_fail_pod_list)

        health_ok = health_ok and success and \
            (pods_healthy if kube_rootca_update else True)

        return health_ok, output
