# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" Storage Utilities and helper functions."""

from kubernetes.client.rest import ApiException

from sysinv._i18n import _
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils

from sysinv.common.storage_backend_conf import StorageBackendConfig

from oslo_log import log

LOG = log.getLogger(__name__)


class StorageRookUtils(object):
    def __init__(self, dbapi):
        self.dbapi = dbapi
        self._storage_backend = None

    @property
    def storage_backend(self):
        return StorageBackendConfig.get_backend(self.dbapi, constants.SB_TYPE_CEPH_ROOK)

    def get_deployment_model(self):
        deployment_model = None
        if self.storage_backend:
            deployment_model = self.storage_backend.capabilities.get(constants.CEPH_ROOK_BACKEND_DEPLOYMENT_CAP, None)
            if not deployment_model:
                raise exception.SysinvException(
                    '{} missing from storage backend {}'.format(
                        constants.CEPH_ROOK_BACKEND_DEPLOYMENT_CAP,
                        self.storage_backend.name))

        return deployment_model

    def get_services(self):
        services_list = []

        if self.storage_backend:
            services_list = self.storage_backend.services.split(',')

        return services_list

    def is_service_enabled(self, service):
        services = self.get_services()
        if services and service in services:
            return True
        return False

    def get_tiers(self, exclude_deleting=False):
        tiers = [
            t for t in self.dbapi.storage_tier_get_all()
            if t.type == constants.SB_TIER_TYPE_CEPH
            and t.status == constants.SB_TIER_STATUS_IN_USE
        ]
        if exclude_deleting:
            valid_tiers = []
            for tier in tiers:
                stors = [
                    s for s in self.dbapi.istor_get_by_tier(tier['id'])
                    if s.state not in [
                        constants.SB_STATE_DELETING_WITH_APP,
                        constants.SB_STATE_FORCE_DELETING_WITH_APP
                    ]
                ]
                if len(stors) > 0:
                    valid_tiers.append(tier)
            return valid_tiers
        else:
            return tiers

    def get_failure_domain(self):
        # based on deployment model and installation type
        if utils.is_aio_simplex_system(self.dbapi):
            return constants.CEPH_ROOK_CLUSTER_OSD_FAIL_DOMAIN
        elif self.get_deployment_model() in [constants.CEPH_ROOK_DEPLOYMENT_CONTROLLER,
                                             constants.CEPH_ROOK_DEPLOYMENT_DEDICATED]:
            return constants.CEPH_ROOK_CLUSTER_HOST_FAIL_DOMAIN
        else:
            return constants.CEPH_ROOK_CLUSTER_OSD_FAIL_DOMAIN

    def get_replication_factor(self):
        if not self.storage_backend:
            if utils.is_aio_simplex_system(self.dbapi):
                replication = constants.AIO_SX_CEPH_REPLICATION_FACTOR_DEFAULT
            else:
                replication = constants.CEPH_REPLICATION_FACTOR_DEFAULT
            min_replication = constants.CEPH_REPLICATION_MAP_DEFAULT[replication]

            return replication, min_replication

        replication = self.storage_backend.capabilities.get(constants.CEPH_BACKEND_REPLICATION_CAP, None)
        if not replication:
            raise exception.SysinvException(
                '{} missing from storage backend {}.'.format(
                    constants.CEPH_BACKEND_REPLICATION_CAP,
                    self.storage_backend.name))

        try:
            replication = int(replication)
        except ValueError:
            raise exception.SysinvException(
                '{} from storage backend {} must be a integer.'.format(
                    constants.CEPH_BACKEND_REPLICATION_CAP,
                    self.storage_backend.name))

        min_replication = self.storage_backend.capabilities.get(constants.CEPH_BACKEND_MIN_REPLICATION_CAP, None)
        if not min_replication:
            raise exception.SysinvException(
                '{} missing from storage backend {}.'.format(
                    constants.CEPH_BACKEND_MIN_REPLICATION_CAP,
                    self.storage_backend.name))

        try:
            min_replication = int(min_replication)
        except ValueError:
            raise exception.SysinvException(
                '{} from storage backend {} must be a integer.'.format(
                    constants.CEPH_BACKEND_MIN_REPLICATION_CAP,
                    self.storage_backend.name))

        return replication, min_replication

    def get_hosts_by_deployment_model(self):
        hosts = []

        if self.storage_backend:
            deployment_model = self.storage_backend.get('capabilities', {}).get('deployment_model', '')
            if deployment_model == constants.CEPH_ROOK_DEPLOYMENT_CONTROLLER:
                hosts = self.dbapi.ihost_get_by_personality(constants.CONTROLLER)
            elif deployment_model == constants.CEPH_ROOK_DEPLOYMENT_DEDICATED:
                hosts = self.dbapi.ihost_get_by_personality(constants.WORKER)

        if not hosts:
            # TODO(rchurch): should exclude STORAGE personality (just in case one is deployed)
            hosts = self.dbapi.ihost_get_list()

        LOG.debug(f"hosts: {hosts}")
        return hosts

    def get_hosts_with_rook(self):
        hosts = self.dbapi.ihost_get_list()
        hosts_rook = []
        for host in hosts:
            try:
                host_fs = self.dbapi.host_fs_get_by_name_ihost(
                                host.uuid, constants.FILESYSTEM_NAME_CEPH)
                functions = host_fs['capabilities']['functions']
                if (constants.FILESYSTEM_CEPH_FUNCTION_MONITOR in functions or
                        constants.FILESYSTEM_CEPH_FUNCTION_OSD in functions):
                    hosts_rook.append(host)
            except exception.HostFSNameNotFound:
                LOG.warn(f"Host {host.uuid} does not have host-fs ceph")
        LOG.debug(f"hosts_rook: {hosts_rook}")
        return hosts_rook

    def floating_monitor_is_installed(self):
        _kube_operator = kubernetes.KubeOperator()
        _kube_client_custom_objects = _kube_operator._get_kubernetesclient_custom_objects()

        release_name = "rook-ceph-floating-monitor"
        float_is_installed = False

        try:
            release = _kube_client_custom_objects.get_namespaced_custom_object(
                group="helm.toolkit.fluxcd.io",
                version="v2",
                namespace="rook-ceph",
                plural="helmreleases",
                name=release_name,
            )
            conditions = release.get("status", {}).get("conditions", [])
            ready_status = next(
                (c.get("status") for c in conditions if c.get("type") == "Ready"),
                None
            )
            if ready_status == "True":
                float_is_installed = True
        except ApiException as e:
            if e.status != 404:
                msg = _("Failed to get the %s helm release. "
                         "When checking if floating monitor is installed." % release_name)
                LOG.exception(msg)

        return float_is_installed

    def get_osd_count(self, stor_to_remove=None):
        tiers = self.dbapi.storage_tier_get_all()
        ceph_tiers = [
            t for t in tiers
            if t.type == constants.SB_TIER_TYPE_CEPH
            and t.status == constants.SB_TIER_STATUS_IN_USE
        ]

        hosts_by_deployment_model = self.get_hosts_by_deployment_model()

        count_per_tier = []

        host_with_osds_count = 0
        osds_count = 0

        for tier in ceph_tiers:

            host_with_osds_count_by_tier = 0
            osds_count_by_tier = 0

            for host in hosts_by_deployment_model:
                istors = self.dbapi.istor_get_by_ihost(host.uuid)
                has_osd = False
                for stor in istors:
                    if (stor.function == constants.STOR_FUNCTION_OSD and
                            stor.state in constants.ISTOR_ACTIVE_STATES and
                            stor.tier_name == tier.name):
                        if stor_to_remove is None or stor_to_remove.uuid != stor.uuid:
                            has_osd = True
                            osds_count_by_tier += 1
                if has_osd:
                    host_with_osds_count_by_tier += 1

            host_with_osds_count += host_with_osds_count_by_tier
            osds_count += osds_count_by_tier

            count_per_tier.append({"per_host": host_with_osds_count_by_tier,
                                   "per_osd": osds_count_by_tier,
                                   "tier": tier})

        return host_with_osds_count, osds_count, count_per_tier
