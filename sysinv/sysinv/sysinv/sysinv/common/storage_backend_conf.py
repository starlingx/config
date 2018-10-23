# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System Inventory Storage Backend Utilities and helper functions."""


import pecan
import wsme
import ast

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

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
            primary_backends = filter(
                lambda b: b['name'] == constants.SB_DEFAULT_NAMES[
                    constants.SB_TYPE_CEPH],
                storage_cephs)
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
        """ Check is a backend is configured. """
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
        try:
            dbapi.network_get_by_type(
                constants.NETWORK_TYPE_INFRA
            )
            network_type = constants.NETWORK_TYPE_INFRA
        except exception.NetworkTypeNotFound:
            network_type = constants.NETWORK_TYPE_MGMT

        targets = {
            '%s-%s' % (constants.CONTROLLER_0_HOSTNAME,
                       network_type): 'ceph-mon-0-ip',
            '%s-%s' % (constants.CONTROLLER_1_HOSTNAME,
                       network_type): 'ceph-mon-1-ip',
            '%s-%s' % (constants.STORAGE_0_HOSTNAME,
                       network_type): 'ceph-mon-2-ip'
        }
        results = {}
        addrs = dbapi.addresses_get_all()
        for addr in addrs:
            if addr.name in targets:
                results[targets[addr.name]] = addr.address
        if len(results) != len(targets):
            raise exception.IncompleteCephMonNetworkConfig(
                targets=targets, results=results)
        return results

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
        # are provisioned, the task will be either reconfig_compute or none
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
    def get_ceph_pool_replication(api):
        """
        return the values of 'replication' and 'min_replication'
        capabilities as configured in ceph backend
        :param api:
        :return: replication, min_replication
        """
        # Get ceph backend from db
        ceph_backend = StorageBackendConfig.get_backend(
            api,
            constants.CINDER_BACKEND_CEPH
        )

        # Workaround for upgrade from R4 to R5, where 'capabilities' field
        # does not exist in R4 backend entry
        if hasattr(ceph_backend, 'capabilities'):
            if constants.CEPH_BACKEND_REPLICATION_CAP in ceph_backend.capabilities:
                pool_size = int(ceph_backend.capabilities[
                                constants.CEPH_BACKEND_REPLICATION_CAP])

                pool_min_size = constants.CEPH_REPLICATION_MAP_DEFAULT[pool_size]
            else:
                # Should not get here
                pool_size = constants.CEPH_REPLICATION_FACTOR_DEFAULT
                pool_min_size = constants.CEPH_REPLICATION_MAP_DEFAULT[pool_size]
        else:
            # upgrade compatibility with R4
            pool_size = constants.CEPH_REPLICATION_FACTOR_DEFAULT
            pool_min_size = constants.CEPH_REPLICATION_MAP_DEFAULT[pool_size]

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
    def set_img_conversions_defaults(dbapi, controller_fs_api):
        """
        initialize img_conversion partitions with default values if not
        already done
        :param dbapi
        :param controller_fs_api
        """
        # Img conversions identification
        values = {'name': constants.FILESYSTEM_NAME_IMG_CONVERSIONS,
                  'logical_volume': constants.FILESYSTEM_LV_DICT[
                      constants.FILESYSTEM_NAME_IMG_CONVERSIONS],
                  'replicated': False}

        # Abort if is already defined
        controller_fs_list = dbapi.controller_fs_get_list()
        for fs in controller_fs_list:
            if values['name'] == fs.name:
                LOG.info("Image conversions already defined, "
                         "avoiding reseting values")
                return

        # Check if there is enough space available
        rootfs_max_GiB, cgtsvg_max_free_GiB = controller_fs_api.get_controller_fs_limit()
        args = {'avail': cgtsvg_max_free_GiB,
                'min': constants.DEFAULT_SMALL_IMG_CONVERSION_STOR_SIZE,
                'lvg': constants.LVG_CGTS_VG}
        if cgtsvg_max_free_GiB >= constants.DEFAULT_IMG_CONVERSION_STOR_SIZE:
            img_conversions_gib = constants.DEFAULT_IMG_CONVERSION_STOR_SIZE
        elif cgtsvg_max_free_GiB >= constants.DEFAULT_SMALL_IMG_CONVERSION_STOR_SIZE:
            img_conversions_gib = constants.DEFAULT_SMALL_IMG_CONVERSION_STOR_SIZE
        else:
            msg = _("Not enough space for image conversion partition. "
                    "Please ensure that '%(lvg)s' VG has at least %(min)s GiB free space."
                    "Currently available: %(avail)s GiB." % args)
            raise wsme.exc.ClientSideError(msg)

        args['size'] = img_conversions_gib
        LOG.info("Available space in '%(lvg)s' is %(avail)s GiB "
                 "from which img_conversions will use %(size)s GiB." % args)

        # Create entry
        values['size'] = img_conversions_gib
        dbapi.controller_fs_create(values)

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

    @staticmethod
    def get_k8s_secret(secret_name, namespace=None):
        try:
            cmd = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf',
                   'get', 'secrets', secret_name]
            if namespace:
                cmd.append('--namespace=%s' % namespace)
            stdout, _ = cutils.execute(*cmd, run_as_root=False)
        except exception.ProcessExecutionError as e:
            if "not found" in e.stderr.lower():
                return None
            raise exception.SysinvException(
                "Error getting secret: %s in namespace: %s, "
                "Details: %s" % (secret_name, namespace, str(e)))

        return stdout

    @staticmethod
    def create_k8s_pool_secret(bk, key=None, namespace=None, force=False):
        user_secret_name = K8RbdProvisioner.get_user_secret_name(bk)

        if K8RbdProvisioner.get_k8s_secret(user_secret_name,
                                           namespace=namespace):
            if not force:
                return
            # Key already exists
            LOG.warning("K8S Secret for backend: %s and namespace: %s exists and "
                        "should not be present! Removing existing and creating "
                        "a new one." % (bk['name'], namespace))
            K8RbdProvisioner.remove_k8s_pool_secret(bk, namespace)

        LOG.info("Creating Kubernetes RBD Provisioner Ceph pool secret "
                 "for namespace: %s." % namespace)
        try:
            # Create the k8s secret for the given Ceph pool and namespace.
            cmd = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf',
                   'create', 'secret', 'generic',
                   user_secret_name,
                   '--type=kubernetes.io/rbd']
            if key:
                cmd.append('--from-literal=key=%s' % key)
            if namespace:
                cmd.append('--namespace=%s' % namespace)
            _, _ = cutils.execute(*cmd, run_as_root=False)
        except exception.ProcessExecutionError as e:
            raise exception.SysinvException(
                "Could not create Kubernetes secret: %s for backend: %s, "
                "namespace: %s, Details: %s." %
                (user_secret_name, bk['name'], namespace, str(e)))

    @staticmethod
    def remove_k8s_pool_secret(bk, namespace):
        user_secret_name = K8RbdProvisioner.get_user_secret_name(bk)
        if not K8RbdProvisioner.get_k8s_secret(user_secret_name,
                                               namespace=namespace):
            LOG.warning("K8S secret for backend: %s and namespace: %s "
                        "does not exists. Skipping removal." % (bk['name'], namespace))
            return
        try:
            # Remove the k8s secret from given namepsace.
            cmd = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf',
                   'delete', 'secret', user_secret_name,
                   '--namespace=%s' % namespace]
            _, _ = cutils.execute(*cmd, run_as_root=False)
        except exception.ProcessExecutionError as e:
            raise exception.SysinvException(
                "Could not remove Kubernetes secret: %s for backend: %s, "
                "namespace: %s, Details: %s." %
                (user_secret_name, bk['name'], namespace, str(e)))

    @staticmethod
    def create_k8s_admin_secret():
        admin_secret_name = constants.K8S_RBD_PROV_ADMIN_SECRET_NAME
        namespace = constants.K8S_RBD_PROV_NAMESPACE_DEFAULT

        if K8RbdProvisioner.get_k8s_secret(
                admin_secret_name, namespace=namespace):
            # Key already exists
            return

        LOG.info("Creating Kubernetes RBD Provisioner Ceph admin secret.")
        try:
            # TODO(oponcea): Get admin key on Ceph clusters with
            # enabled authentication. For now feed an empty key
            # to satisfy RBD Provisioner requirements.
            cmd = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf',
                   'create', 'secret', 'generic',
                   admin_secret_name,
                   '--type=kubernetes.io/rbd',
                   '--from-literal=key=']
            cmd.append('--namespace=%s' % namespace)
            _, _ = cutils.execute(*cmd, run_as_root=False)
        except exception.ProcessExecutionError as e:
            raise exception.SysinvException(
                "Could not create Kubernetes secret: %s, namespace: %s,"
                "Details: %s" % (admin_secret_name, namespace, str(e)))

    @staticmethod
    def remove_k8s_admin_secret():
        admin_secret_name = constants.K8S_RBD_PROV_ADMIN_SECRET_NAME
        namespace = constants.K8S_RBD_PROV_NAMESPACE_DEFAULT

        if not K8RbdProvisioner.get_k8s_secret(
                admin_secret_name, namespace=namespace):
            # Secret does not exist.
            return

        LOG.info("Removing Kubernetes RBD Provisioner Ceph admin secret.")
        try:
            cmd = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf',
                   'delete', 'secret', admin_secret_name,
                   '--namespace=%s' % namespace]
            _, _ = cutils.execute(*cmd, run_as_root=False)
        except exception.ProcessExecutionError as e:
            raise exception.SysinvException(
                "Could not delete Kubernetes secret: %s, namespace: %s,"
                "Details: %s." % (admin_secret_name, namespace, str(e)))
