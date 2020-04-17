# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System Inventory Storage Backend Utilities and helper functions."""


import ast
import pecan

from oslo_log import log
from sysinv.common import constants
from sysinv.common import exception

LOG = log.getLogger(__name__)


class StorageBackendConfig(object):

    @staticmethod
    def get_backend(api, target):
        """Get the primary backend. """
        backend_list = api.storage_backend_get_list()
        for backend in backend_list:
            if backend.backend == target and \
                   backend.name == constants.SB_DEFAULT_NAMES[target]:
                return backend

    @staticmethod
    def get_backend_conf(api, target):
        """Get the polymorphic primary backend. """

        if target == constants.SB_TYPE_FILE:
            # Only support a single file backend
            storage_files = api.storage_file_get_list()
            if storage_files:
                return storage_files[0]
        elif target == constants.SB_TYPE_LVM:
            # Only support a single LVM backend
            storage_lvms = api.storage_lvm_get_list()
            if storage_lvms:
                return storage_lvms[0]
        elif target == constants.SB_TYPE_CEPH:
            # Support multiple ceph backends
            storage_cephs = api.storage_ceph_get_list()
            primary_backends = [b for b in storage_cephs if b['name'] == constants.SB_DEFAULT_NAMES[
                    constants.SB_TYPE_CEPH]]
            if primary_backends:
                return primary_backends[0]
        elif target == constants.SB_TYPE_EXTERNAL:
            # Only support a single external backend
            storage_externals = api.storage_external_get_list()
            if storage_externals:
                return storage_externals[0]
        elif target == constants.SB_TYPE_CEPH_EXTERNAL:
            # Support multiple ceph external backends
            storage_ceph_externals = api.storage_ceph_external_get_list()
            if storage_ceph_externals:
                return storage_ceph_externals[0]
        elif target == constants.SB_TYPE_CEPH_ROOK:
            # Support multiple ceph rook backends
            storage_ceph_rook = api.storage_ceph_rook_get_list()
            if storage_ceph_rook:
                return storage_ceph_rook[0]

        return None

    @staticmethod
    def get_configured_backend_conf(api, target):
        """Return the configured polymorphic primary backend of a given type."""

        backend_list = api.storage_backend_get_list()
        for backend in backend_list:
            if backend.state == constants.SB_STATE_CONFIGURED and \
               backend.backend == target and \
               backend.name == constants.SB_DEFAULT_NAMES[target]:
                return StorageBackendConfig.get_backend_conf(api, target)
        return None

    @staticmethod
    def get_configured_backend_list(api):
        """Get the list of all configured backends. """

        backends = []
        try:
            backend_list = api.storage_backend_get_list()
        except Exception:
            backend_list = []

        for backend in backend_list:
            if backend.state == constants.SB_STATE_CONFIGURED:
                backends.append(backend.backend)
        return backends

    @staticmethod
    def get_configured_backend(api, target):
        """Return the configured primary backend of a given type."""

        backend_list = api.storage_backend_get_list()
        for backend in backend_list:
            if backend.state == constants.SB_STATE_CONFIGURED and \
                    backend.backend == target and \
                    backend.name == constants.SB_DEFAULT_NAMES[target]:
                return backend
        return None

    @staticmethod
    def get_configuring_backend(api):
        """Get the primary backend that is configuring. """

        backend_list = api.storage_backend_get_list()
        for backend in backend_list:
            if backend.state == constants.SB_STATE_CONFIGURING and \
                   backend.name == constants.SB_DEFAULT_NAMES[backend.backend]:
                # At this point we can have but only max 1 configuring backend
                # at any moment
                return backend

        # it is normal there isn't one being configured
        return None

    @staticmethod
    def get_configuring_target_backend(api, target):
        """Get the primary backend that is configuring. """

        backend_list = api.storage_backend_get_list()
        for backend in backend_list:
            if backend.state == constants.SB_STATE_CONFIGURING and \
                   backend.backend == target:
                # At this point we can have but only max 1 configuring backend
                # at any moment
                return backend

        # it is normal there isn't one being configured
        return None

    @staticmethod
    def has_backend_configured(dbapi, target, service=None,
                               check_only_defaults=True, rpcapi=None):
        """ Check if a backend is configured. """
        # If cinder is a shared service on another region and
        # we want to know if the ceph backend is configured,
        # send a rpc to conductor which sends a query to the primary
        system = dbapi.isystem_get_one()
        shared_services = system.capabilities.get('shared_services', None)
        if (shared_services is not None and
                constants.SERVICE_TYPE_VOLUME in shared_services and
                target == constants.SB_TYPE_CEPH and
                rpcapi is not None):
            return rpcapi.region_has_ceph_backend(
                pecan.request.context)
        else:
            backend_list = dbapi.storage_backend_get_list()
            for backend in backend_list:
                if backend.state == constants.SB_STATE_CONFIGURED and \
                       backend.backend == target:

                    # Check if the backend name matches the default name
                    if check_only_defaults and \
                            backend.name != constants.SB_DEFAULT_NAMES[target]:
                        continue

                    # Check if a specific service is configured on the
                    # backend.
                    if service and service not in backend.services:
                        continue

                    return True

            return False

    @staticmethod
    def has_backend(api, target):
        backend_list = api.storage_backend_get_list()
        for backend in backend_list:
            if backend.backend == target:
                return True
        return False

    @staticmethod
    def update_backend_states(api, target, state=None, task='N/A'):
        """Update primary backend state. """

        values = dict()
        if state:
            values['state'] = state
        if task != 'N/A':
            values['task'] = task
        backend = StorageBackendConfig.get_backend(api, target)
        if backend:
            api.storage_backend_update(backend.uuid, values)
        else:
            raise exception.InvalidStorageBackend(backend=target)

    @staticmethod
    def get_ceph_mon_ip_addresses(dbapi):
        # map hostname to ceph-mon ip placeholder
        host2ph = {
            constants.CONTROLLER_HOSTNAME: constants.CEPH_FLOATING_MON,
            constants.CONTROLLER_0_HOSTNAME: constants.CEPH_MON_0,
            constants.CONTROLLER_1_HOSTNAME: constants.CEPH_MON_1,
        }
        # find 3rd ceph-mon host name (if any)
        for mon in dbapi.ceph_mon_get_list():
            host = mon['hostname']
            if host not in host2ph:
                host2ph[host] = constants.CEPH_MON_2
        # map host interface to ceph-mon ip placeholder
        hostif2ph = {}
        for host, ph in host2ph.items():
            hostif = '%s-%s' % (host, constants.NETWORK_TYPE_MGMT)
            hostif2ph[hostif] = ph
        # map placeholder to ceph-mon ip address
        ph2ipaddr = {}
        for addr in dbapi.addresses_get_all():
            if addr.name in hostif2ph:
                ph = hostif2ph[addr.name]
                ph2ipaddr[ph] = addr.address
        return ph2ipaddr

    @staticmethod
    def is_ceph_backend_ready(api):
        """
        check if ceph primary backend is ready, i,e, when a ceph backend
        is configured after config_controller, it is considered ready when
        both controller nodes and 1st pair of storage nodes are reconfigured
        with ceph
        :param api:
        :return:
        """
        ceph_backend = None
        backend_list = api.storage_backend_get_list()
        for backend in backend_list:
            if backend.backend == constants.SB_TYPE_CEPH and \
               backend.name == constants.SB_DEFAULT_NAMES[
                   constants.SB_TYPE_CEPH]:
                ceph_backend = backend
                break
        if not ceph_backend:
            return False

        if ceph_backend.state != constants.SB_STATE_CONFIGURED:
            return False

        if ceph_backend.task == constants.SB_TASK_PROVISION_STORAGE:
            return False

        # if both controllers are reconfigured and 1st pair storage nodes
        # are provisioned, the task will be either reconfig_worker or none
        return True

    @staticmethod
    def get_ceph_tier_size(dbapi, rpcapi, tier_name):
        try:
            # Make sure the default ceph backend is configured
            if not StorageBackendConfig.has_backend_configured(
                dbapi,
                constants.SB_TYPE_CEPH
            ):
                return 0

            tier_size = \
                rpcapi.get_ceph_tier_size(pecan.request.context,
                                          tier_name)
            return int(tier_size)
        except Exception as exp:
            LOG.exception(exp)
            return 0

    @staticmethod
    def get_ceph_max_replication(api):
        """
        Replication in some tiers may be smaller than for other tiers.
        Get maximum replication configured in the cluster.
        """
        replication = 1
        min_replication = 1
        backends = api.storage_ceph_get_list()
        for bk in backends:
            tier_replication, tier_min_replication = \
                StorageBackendConfig.get_ceph_pool_replication(api, bk)
            if tier_replication > replication:
                replication = tier_replication
            if tier_min_replication > min_replication:
                tier_min_replication = min_replication
        if not backends:
            # No backend configured? - return defaults
            replication = constants.CEPH_REPLICATION_FACTOR_DEFAULT
            min_replication = constants.CEPH_REPLICATION_MAP_DEFAULT[replication]
        return replication, min_replication

    @staticmethod
    def get_ceph_pool_replication(api, ceph_backend=None):
        """
        return the values of 'replication' and 'min_replication'
        capabilities as configured in ceph backend
        :param api:
        :param ceph_backend: ceph backend object type for a tier
        :return: replication, min_replication
        """
        # Get ceph backend from db
        if not ceph_backend:
            # get replication of primary tier
            ceph_backend = StorageBackendConfig.get_backend(
                api,
                constants.CINDER_BACKEND_CEPH
            )

        # if no backend is added, return default value
        if not ceph_backend:
            LOG.warning("No Ceph storage backend config")
            return 0, 0

        pool_size = int(ceph_backend.capabilities[
                constants.CEPH_BACKEND_REPLICATION_CAP])
        pool_min_size = int(ceph_backend.capabilities[
                constants.CEPH_BACKEND_MIN_REPLICATION_CAP])
        return pool_size, pool_min_size

    @staticmethod
    def get_ceph_backend_task(api):
        """
        return current ceph backend task
        :param: api
        :return:
        """
        # Get ceph backend from db
        ceph_backend = StorageBackendConfig.get_backend(
            api,
            constants.CINDER_BACKEND_CEPH
        )

        return ceph_backend.task

    @staticmethod
    def get_ceph_backend_state(api):
        """
        return current ceph backend state
        :param: api
        :return:
        """
        # Get ceph backend from db
        ceph_backend = StorageBackendConfig.get_backend(
            api,
            constants.CINDER_BACKEND_CEPH
        )

        return ceph_backend.state

    @staticmethod
    def is_ceph_backend_restore_in_progress(api):
        """
        check ceph primary backend has a restore task set
        :param api:
        :return:
        """
        for backend in api.storage_backend_get_list():
            if backend.backend == constants.SB_TYPE_CEPH and \
                   backend.name == constants.SB_DEFAULT_NAMES[
                       constants.SB_TYPE_CEPH]:
                return backend.task == constants.SB_TASK_RESTORE

    @staticmethod
    def get_enabled_services(dbapi, filter_unconfigured=True,
                             filter_shared=False):
        """ Get the list of enabled services
        :param dbapi
        :param filter_unconfigured: Determine weather to ignore unconfigured services
        :param filter_shared: Determine weather to ignore shared services
        :returns: list of services
        """
        services = []
        if not filter_shared:
            system = dbapi.isystem_get_one()
            shared_services = system.capabilities.get('shared_services', None)
            services = [] if shared_services is None else ast.literal_eval(shared_services)

        backend_list = dbapi.storage_backend_get_list()
        for backend in backend_list:
            backend_services = [] if backend.services is None else backend.services.split(',')
            for service in backend_services:
                if (backend.state == constants.SB_STATE_CONFIGURED or
                        not filter_unconfigured):
                    if service not in services:
                        services.append(service)
        return services
        # TODO(oponcea): Check for external cinder backend & test multiregion

    @staticmethod
    def is_service_enabled(dbapi, service, filter_unconfigured=True,
                           filter_shared=False):
        """ Checks if a service is enabled
        :param dbapi
        :param service: service name, one of constants.SB_SVC_*
        :param unconfigured: check also unconfigured/failed services
        :returns: True or false
        """
        if service in StorageBackendConfig.get_enabled_services(
                dbapi, filter_unconfigured, filter_shared):
            return True
        else:
            return False


class K8RbdProvisioner(object):
    """ Utility methods for getting the k8 overrides for internal ceph
    from a corresponding storage backend.
    """

    @staticmethod
    def getListFromNamespaces(bk, get_configured=False):
        cap = bk['capabilities']
        capab_type = constants.K8S_RBD_PROV_NAMESPACES if not get_configured else \
            constants.K8S_RBD_PROV_NAMESPACES_READY

        return [] if not cap.get(capab_type) else \
            cap[capab_type].split(',')

    @staticmethod
    def setNamespacesFromList(bk, namespace_list, set_configured=False):
        capab_type = constants.K8S_RBD_PROV_NAMESPACES if not set_configured else \
            constants.K8S_RBD_PROV_NAMESPACES_READY
        bk[capab_type] = ','.join(namespace_list)
        return bk[capab_type]

    @staticmethod
    def getNamespacesDelta(bk):
        """ Get changes in namespaces
        :returns namespaces_to_add, namespaces_to_rm
        """
        namespaces = K8RbdProvisioner.getListFromNamespaces(bk)
        namespaces_configured = K8RbdProvisioner.getListFromNamespaces(bk, get_configured=True)
        namespaces_to_add = set(namespaces) - set(namespaces_configured)
        namespaces_to_rm = set(namespaces_configured) - set(namespaces)
        return namespaces_to_add, namespaces_to_rm

    @staticmethod
    def get_storage_class_name(bk):
        """ Get the name of the storage class for an rbd provisioner
        :param bk: Ceph storage backend object
        :returns: name of the rbd provisioner
        """
        if bk['capabilities'].get(constants.K8S_RBD_PROV_STORAGECLASS_NAME):
            name = bk['capabilities'][constants.K8S_RBD_PROV_STORAGECLASS_NAME]
        elif bk.name == constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH]:
            name = constants.K8S_RBD_PROV_STOR_CLASS_NAME
        else:
            name = bk.name + '-' + constants.K8S_RBD_PROV_STOR_CLASS_NAME

        return str(name)

    @staticmethod
    def get_pool(bk):
        """ Get the name of the ceph pool for an rbd provisioner
        This naming convention is valid only for internal backends
        :param bk: Ceph storage backend object
        :returns: name of the rbd provisioner
        """
        if bk['name'] == constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH]:
            return constants.CEPH_POOL_KUBE_NAME
        else:
            return str(constants.CEPH_POOL_KUBE_NAME + '-' + bk['name'])

    @staticmethod
    def get_user_id(bk):
        """ Get the non admin user name for an rbd provisioner secret
        :param bk: Ceph storage backend object
        :returns: name of the rbd provisioner
        """
        if bk['name'] == constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH]:
            name = K8RbdProvisioner.get_pool(bk)
        else:
            name = K8RbdProvisioner.get_pool(bk)

        prefix = 'ceph-pool'
        return str(prefix + '-' + name)

    @staticmethod
    def get_user_secret_name(bk):
        """ Get the name for the non admin secret key of a pool
        :param bk: Ceph storage backend object
        :returns: name of k8 secret
        """
        if bk['name'] == constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH]:
            name = K8RbdProvisioner.get_pool(bk)
        else:
            name = K8RbdProvisioner.get_pool(bk)

        base_name = 'ceph-pool'
        return str(base_name + '-' + name)
