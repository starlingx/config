# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright 2016 UnitedStack Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
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

import copy
import jsonpatch
import re

from oslo_utils import strutils
from oslo_serialization import jsonutils

import pecan
from pecan import rest
import six

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1.utils import SBApiHelper as api_helper
from sysinv.common import ceph
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.common.storage_backend_conf import K8RbdProvisioner
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common import uuidutils
from sysinv.openstack.common.gettextutils import _


LOG = log.getLogger(__name__)

CAPABILITIES = {
    'backend': [constants.CEPH_BACKEND_REPLICATION_CAP,
                constants.CEPH_BACKEND_MIN_REPLICATION_CAP],
    constants.SB_SVC_CINDER: [],
    constants.SB_SVC_GLANCE: [],
    constants.SB_SVC_SWIFT: [],
    constants.SB_SVC_NOVA: [],
    constants.SB_SVC_RBD_PROVISIONER: [constants.K8S_RBD_PROV_NAMESPACES,
                                       constants.K8S_RBD_PROV_STORAGECLASS_NAME],
}

MANDATORY_CAP = {
    'backend': [constants.CEPH_BACKEND_REPLICATION_CAP,
                constants.CEPH_BACKEND_MIN_REPLICATION_CAP],
    constants.SB_SVC_CINDER: [],
    constants.SB_SVC_GLANCE: [],
    constants.SB_SVC_SWIFT: [],
    constants.SB_SVC_NOVA: [],
    constants.SB_SVC_RBD_PROVISIONER: [],
}


class StorageCephPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class StorageCeph(base.APIBase):
    """API representation of a ceph storage.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a ceph storage.
    """

    def _get_ceph_tier_size(self):
        if not self.tier_name:
            return 0

        return StorageBackendConfig.get_ceph_tier_size(
            pecan.request.dbapi,
            pecan.request.rpcapi,
            self.tier_name
        )

    def _set_ceph_tier_size(self, value):
        return

    uuid = types.uuid
    "Unique UUID for this ceph storage backend."

    cinder_pool_gib = int
    "The cinder pool GiB of storage ceph - ceph cinder-volumes pool quota."

    glance_pool_gib = int
    "The glance pool GiB of storage ceph - ceph images pool quota."

    ephemeral_pool_gib = int
    "The ephemeral pool GiB of storage ceph - ceph ephemeral pool quota."

    object_pool_gib = int
    "The object gateway pool GiB of storage ceph - ceph object gateway pool "
    "quota."

    kube_pool_gib = int
    "The k8s pool GiB of storage ceph - ceph pool quota for k8s."

    object_gateway = bool
    "If object gateway is configured."

    tier_id = int
    "The id of storage tier associated with this backend"

    tier_name = wtypes.text
    "The name of storage tier associated with this backend"

    tier_uuid = wtypes.text
    "The uuid of storage tier associated with this backend"

    ceph_total_space_gib = wsme.wsproperty(
        int,
        _get_ceph_tier_size,
        _set_ceph_tier_size,
        mandatory=False)
    "The total Ceph tier cluster size"

    links = [link.Link]
    "A list containing a self link and associated storage backend links."

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    # Inherited attributes from the base class
    backend = wtypes.text
    "Represents the storage backend (file, lvm, or ceph)."

    name = wtypes.text
    "The name of the backend (to differentiate between multiple common backends)."

    state = wtypes.text
    "The state of the backend. It can be configured or configuring."

    task = wtypes.text
    "Current task of the corresponding cinder backend."

    services = wtypes.text
    "The openstack services that are supported by this storage backend."

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                                                  six.integer_types)}
    "Meta data for the storage backend"

    # Confirmation parameter [API-only field]
    confirmed = types.boolean
    "Represent confirmation that the backend operation should proceed"

    def __init__(self, **kwargs):
        defaults = {'uuid': uuidutils.generate_uuid(),
                    'state': constants.SB_STATE_CONFIGURING,
                    'task': constants.SB_TASK_NONE,
                    'capabilities': {},
                    'services': None,
                    'confirmed': False,
                    'object_gateway': False}

        self.fields = list(objects.storage_ceph.fields.keys())

        # 'confirmed' is not part of objects.storage_backend.fields
        # (it's an API-only attribute)
        self.fields.append('confirmed')

        # Set the value for any of the field
        for k in self.fields:
            if k == 'object_gateway':
                v = kwargs.get(k)
                if v:
                    try:
                        v = strutils.bool_from_string(
                            v, strict=True)
                    except ValueError as e:
                        raise exception.Invalid(e)
            setattr(self, k, kwargs.get(k, defaults.get(k)))

    @classmethod
    def convert_with_links(cls, rpc_storage_ceph, expand=True):

        stor_ceph = StorageCeph(**rpc_storage_ceph.as_dict())

        # Don't expose ID attributes.
        stor_ceph.tier_id = wtypes.Unset

        if not expand:
            stor_ceph.unset_fields_except(['uuid',
                                           'created_at',
                                           'updated_at',
                                           'cinder_pool_gib',
                                           'isystem_uuid',
                                           'backend',
                                           'name',
                                           'state',
                                           'task',
                                           'services',
                                           'capabilities',
                                           'glance_pool_gib',
                                           'ephemeral_pool_gib',
                                           'object_pool_gib',
                                           'kube_pool_gib',
                                           'object_gateway',
                                           'ceph_total_space_gib',
                                           'tier_name',
                                           'tier_uuid'])

        stor_ceph.links =\
            [link.Link.make_link('self', pecan.request.host_url,
                                 'storage_ceph',
                                 stor_ceph.uuid),
             link.Link.make_link('bookmark', pecan.request.host_url,
                                 'storage_ceph',
                                 stor_ceph.uuid,
                                 bookmark=True)]
        return stor_ceph


class StorageCephCollection(collection.Collection):
    """API representation of a collection of ceph storage backends."""

    storage_ceph = [StorageCeph]
    "A list containing ceph storage backend objects."

    def __init__(self, **kwargs):
        self._type = 'storage_ceph'

    @classmethod
    def convert_with_links(cls, rpc_storage_ceph, limit, url=None,
                           expand=False, **kwargs):
        collection = StorageCephCollection()
        collection.storage_ceph = \
            [StorageCeph.convert_with_links(p, expand)
             for p in rpc_storage_ceph]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'StorageCephController'


class StorageCephController(rest.RestController):
    """REST controller for ceph storage backend."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def _get_storage_ceph_collection(self, marker, limit, sort_key, sort_dir,
                                     expand=False, resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.storage_ceph.get_by_uuid(
                pecan.request.context,
                marker)

        ceph_storage_backends = \
                pecan.request.dbapi.storage_ceph_get_list(
                    limit,
                    marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)

        return StorageCephCollection \
            .convert_with_links(ceph_storage_backends,
                                limit,
                                url=resource_url,
                                expand=expand,
                                sort_key=sort_key,
                                sort_dir=sort_dir)

    @wsme_pecan.wsexpose(StorageCephCollection, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of ceph storage backends."""
        return self._get_storage_ceph_collection(marker, limit, sort_key,
                                                 sort_dir)

    @wsme_pecan.wsexpose(StorageCeph, types.uuid)
    def get_one(self, storage_ceph_uuid):
        """Retrieve information about the given ceph storage backend."""

        rpc_storage_ceph = objects.storage_ceph.get_by_uuid(
            pecan.request.context,
            storage_ceph_uuid)
        return StorageCeph.convert_with_links(rpc_storage_ceph)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(StorageCeph, body=StorageCeph)
    def post(self, storage_ceph):
        """Create a new storage backend."""

        try:
            storage_ceph = storage_ceph.as_dict()
            new_storage_ceph = _create(storage_ceph)

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create "
                                             "a storage_ceph record."))

        return StorageCeph.convert_with_links(new_storage_ceph)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [StorageCephPatchType])
    @wsme_pecan.wsexpose(StorageCeph, types.uuid,
                         body=[StorageCephPatchType])
    def patch(self, storceph_uuid, patch):
        """Update the current ceph storage configuration."""
        return _patch(storceph_uuid, patch)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, storageceph_uuid):
        """Delete a backend."""
        return _delete(storageceph_uuid)


#
# Common operation functions
#


def _get_options_string(storage_ceph):
    opt_str = ""
    caps = storage_ceph.get('capabilities', {})
    services = api_helper.getListFromServices(storage_ceph)

    # get the backend parameters
    backend_dict = caps.get("backend", {})
    be_str = ""
    for key in backend_dict:
        be_str += "\t%s: %s\n" % (key, backend_dict[key])

    # Only show the backend values if any are present
    if len(be_str) > 0:
        opt_str = "Backend:\n%s" % be_str

    # Get any supported service parameters
    for svc in constants.SB_CEPH_SVCS_SUPPORTED:
        svc_dict = caps.get(svc, None)
        if svc_dict and svc in services:
            svc_str = ""
            for key in svc_dict:
                svc_str += "\t%s: %s\n" % (key, svc_dict.get(key, None))

            if len(svc_str) > 0:
                opt_str += "%s:\n%s" % (svc.title(), svc_str)

    if len(opt_str) > 0:
        opt_str = "Applying the following options:\n\n" + opt_str
    return opt_str


def _discover_and_validate_backend_config_data(caps_dict, confirmed):
    # Validate parameters
    for k in CAPABILITIES['backend']:
        v = caps_dict.get(k, None)
        if not v:
            raise wsme.exc.ClientSideError("Missing required backend "
                                           "parameter: %s" % k)

        if utils.is_aio_simplex_system(pecan.request.dbapi):
            supported_replication = constants.AIO_SX_CEPH_REPLICATION_FACTOR_SUPPORTED
        else:
            supported_replication = constants.CEPH_REPLICATION_FACTOR_SUPPORTED

        # Validate replication factor
        if k == constants.CEPH_BACKEND_REPLICATION_CAP:
            v_supported = supported_replication
            msg = _("Required backend parameter "
                    "\'%s\' has invalid value \'%s\'. "
                    "Supported values are %s." %
                    (k, v, str(v_supported)))
            try:
                v = int(v)
            except ValueError:
                raise wsme.exc.ClientSideError(msg)
            if v not in v_supported:
                raise wsme.exc.ClientSideError(msg)

        # Validate min replication factor
        # In R5 the value for min_replication is fixed and determined
        # from the value of replication factor as defined in
        # constants.CEPH_REPLICATION_MAP_DEFAULT.
        elif k == constants.CEPH_BACKEND_MIN_REPLICATION_CAP:
            rep = int(caps_dict[constants.CEPH_BACKEND_REPLICATION_CAP])
            v_supported = constants.CEPH_REPLICATION_MAP_SUPPORTED[rep]
            msg = _("Missing or invalid value for backend parameter \'%s\', "
                    "when replication is set as \'%s\'. Supported values are "
                    "%s." % (k, rep, str(v_supported)))
            try:
                v = int(v)
            except ValueError:
                raise wsme.exc.ClientSideError(msg)
            if v not in v_supported:
                raise wsme.exc.ClientSideError(msg)

        else:
            continue

    # Make sure that ceph mon api has been called and IPs have been reserved
    # TODO(oponcea): remove condition once ceph_mon code is refactored.
    if confirmed:
        try:
            StorageBackendConfig.get_ceph_mon_ip_addresses(pecan.request.dbapi)
        except exception.IncompleteCephMonNetworkConfig as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_('Ceph Monitor configuration is '
                                             'required prior to adding the '
                                             'ceph backend'))


def _discover_and_validate_cinder_capabilities(caps_dict, storage_ceph):
    # Currently there is no backend specific data for this backend
    pass


def _discover_and_validate_glance_capabilities(caps_dict, storage_ceph):
    # Currently there is no backend specific data for this backend
    pass


def _discover_and_validate_swift_capabilities(caps_dict, storage_ceph):
    # Currently there is no backend specific data for this backend
    pass


def _discover_and_validate_nova_capabilities(caps_dict, storage_ceph):
    # Currently there is no backend specific data for this backend
    pass


def _discover_and_validate_rbd_provisioner_capabilities(caps_dict, storage_ceph):
    # Use same regex that Kubernetes uses to validate its labels
    r = re.compile(r'[a-z0-9]([-a-z0-9]*[a-z0-9])')
    msg_help = ("Each name or label must consist of lower case "
                "alphanumeric characters or '-', and must start "
                "and end with an alphanumeric character.")

    # Check for a valid list of namespaces
    if constants.K8S_RBD_PROV_NAMESPACES in caps_dict:
        namespaces = caps_dict[constants.K8S_RBD_PROV_NAMESPACES].split(',')
        for namespace in namespaces:
            if not r.match(namespace):
                msg = _("Invalid list of namespaces provided: '%s' please "
                        "provide a valid comma separated list of Kubernetes "
                        "namespaces. %s" % (namespaces, msg_help))
                raise wsme.exc.ClientSideError(msg)

    if constants.K8S_RBD_PROV_STORAGECLASS_NAME in caps_dict:
        # Check for a valid RBD StorageClass name
        name = caps_dict[constants.K8S_RBD_PROV_STORAGECLASS_NAME]
        if not r.match(name):
                msg = _("Invalid RBD StorageClass name '%s'. %s" %
                        (name, msg_help))
                raise wsme.exc.ClientSideError(msg)

        # Check the uniqueness of RBD StorageClass name in DB.
        if constants.K8S_RBD_PROV_STORAGECLASS_NAME in caps_dict:
            ceph_backends = [bk for bk in pecan.request.dbapi.storage_backend_get_list()
                             if bk.backend == constants.SB_TYPE_CEPH and
                             bk.id != storage_ceph['id']]
            storclass_names = [bk.capabilities.get(constants.K8S_RBD_PROV_STORAGECLASS_NAME)
                               for bk in ceph_backends]
            if name in storclass_names:
                msg = _("RBD StorageClass name '%s'is already used by another backend." % name)
                raise wsme.exc.ClientSideError(msg)


def _check_backend_ceph(req, storage_ceph, confirmed=False):
    # check for the backend parameters
    capabilities = storage_ceph.get('capabilities', {})

    # Discover the latest config data for the supported service
    _discover_and_validate_backend_config_data(capabilities, confirmed)

    for k in CAPABILITIES['backend']:
        if not capabilities.get(k, None):
            raise wsme.exc.ClientSideError(_("Missing required backend "
                                           "parameter: %s" % k))

    # Check restrictions based on the primary or seconday backend.:
    if api_helper.is_primary_ceph_backend(storage_ceph['name']):
        supported_svcs = constants.SB_CEPH_SVCS_SUPPORTED

    else:
        supported_svcs = constants.SB_TIER_CEPH_SECONDARY_SVCS

        # Patching: Allow disabling of services on any secondary tier
        if (storage_ceph['services'] and
                storage_ceph['services'].lower() == 'none'):
            storage_ceph['services'] = None

        # Clear the default state/task
        storage_ceph['state'] = constants.SB_STATE_CONFIGURED
        storage_ceph['task'] = constants.SB_TASK_NONE

    # go through the service list and validate
    req_services = api_helper.getListFromServices(storage_ceph)
    for svc in req_services:
        if svc not in supported_svcs:
            raise wsme.exc.ClientSideError(
                _("Service %s is not supported for the %s backend %s" %
                  (svc, constants.SB_TYPE_CEPH, storage_ceph['name'])))

        # Service is valid. Discover the latest config data for the supported
        # service.
        discover_func = eval(
            '_discover_and_validate_' + svc.replace('-', '_') + '_capabilities')
        discover_func(capabilities, storage_ceph)

        # Service is valid. Check the params
        for k in MANDATORY_CAP[svc]:
            if not capabilities.get(k, None):
                raise wsme.exc.ClientSideError(
                    _("Missing required %s service parameter: %s" % (svc, k)))

    # TODO (rchurch): Remove this in R6 with object_gateway refactoring. Should
    # be enabled only if the service is present in the service list. Special
    # case for now: enable object_gateway if defined in service list
    if constants.SB_SVC_SWIFT in req_services:
        storage_ceph['object_gateway'] = True

    # Update based on any discovered values
    storage_ceph['capabilities'] = capabilities

    # Additional checks based on operation
    if req == constants.SB_API_OP_CREATE:
        # The ceph backend must be associated with a storage tier
        tierId = storage_ceph.get('tier_id') or storage_ceph.get('tier_uuid')
        if not tierId:
            if api_helper.is_primary_ceph_backend(storage_ceph['name']):
                # Adding the default ceph backend, use the default ceph tier
                try:
                    tier = pecan.request.dbapi.storage_tier_query(
                        {'name': constants.SB_TIER_DEFAULT_NAMES[
                            constants.SB_TIER_TYPE_CEPH]})
                except exception.StorageTierNotFoundByName:
                    raise wsme.exc.ClientSideError(
                        _("Default tier not found for this backend."))
            else:
                raise wsme.exc.ClientSideError(_("No tier specified for this "
                                                 "backend."))
        else:
            try:
                tier = pecan.request.dbapi.storage_tier_get(tierId)
            except exception.StorageTierNotFound:
                raise wsme.exc.ClientSideError(_("No tier with uuid %s found.") % tierId)
        storage_ceph.update({'tier_id': tier.id})

    # TODO (rchurch): Put this back
    # elif req == constants.SB_API_OP_MODIFY or req == constants.SB_API_OP_DELETE:
    #     raise wsme.exc.ClientSideError("API Operation %s is not supported for "
    #                                    "the %s backend" %
    #                                    (req, constants.SB_TYPE_CEPH))

    # Check for confirmation
    if not confirmed and api_helper.is_primary_ceph_tier(tier.name):
        _options_str = _get_options_string(storage_ceph)
        replication = capabilities[constants.CEPH_BACKEND_REPLICATION_CAP]
        if utils.is_aio_simplex_system(pecan.request.dbapi):
            what = 'osds'
        else:
            what = 'storage nodes'
        raise wsme.exc.ClientSideError(
            _("%s\nWARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE "
              "CANCELLED. \n\nBy confirming this operation, Ceph backend will "
              "be created.\nA minimum of %s %s are required to "
              "complete the configuration.\nPlease set the 'confirmed' field "
              "to execute this operation for the %s "
              "backend.") % (_options_str, replication, what,
                             constants.SB_TYPE_CEPH))


def check_and_update_services(storage_ceph):
    """Update backends' services that allow a single service instance."""
    req_services = api_helper.getListFromServices(storage_ceph)

    check_svcs = [constants.SB_SVC_GLANCE, constants.SB_SVC_NOVA]
    check_data = {constants.SB_SVC_GLANCE: ['glance_pool'],
                  constants.SB_SVC_NOVA: ['ephemeral_pool']}

    for s in check_svcs:
        if s in req_services:
            for sb in pecan.request.dbapi.storage_backend_get_list():
                if (sb.backend == constants.SB_TYPE_CEPH_EXTERNAL and
                        s in sb.get('services')):
                    services = api_helper.getListFromServices(sb)
                    services.remove(s)
                    cap = sb.capabilities
                    for k in check_data[s]:
                        cap.pop(k, None)
                    values = {'services': ','.join(services),
                              'capabilities': cap}
                    pecan.request.dbapi.storage_backend_update(
                        sb.uuid, values)


def validate_k8s_namespaces(values):
    """ Check if a list of namespaces is configured in Kubernetes """
    configured_namespaces = \
        pecan.request.rpcapi.get_k8s_namespaces(pecan.request.context)
    invalid_namespaces = []
    for namespace in values:
        if namespace not in configured_namespaces:
            invalid_namespaces.append(namespace)

    if invalid_namespaces:
        msg = _("Error configuring rbd-provisioner service. "
                "The following Kubernetes namespaces are not "
                "configured: %s." % ', '.join(invalid_namespaces))
        raise wsme.exc.ClientSideError(msg)


def _check_and_update_rbd_provisioner(new_storceph, remove=False):
    """ Check and/or update RBD Provisioner configuration """
    capab = new_storceph['capabilities']
    if remove:
        # Remove the RBD Provisioner
        del capab[constants.K8S_RBD_PROV_NAMESPACES]
        if constants.K8S_RBD_PROV_STORAGECLASS_NAME in capab:
            del capab[constants.K8S_RBD_PROV_STORAGECLASS_NAME]
    else:
        bk_services = api_helper.getListFromServices(new_storceph)
        if constants.SB_SVC_RBD_PROVISIONER not in bk_services:
            # RBD Provisioner service not involved, return early
            return new_storceph

        # Use default namespace if not specified
        if not capab.get(constants.K8S_RBD_PROV_NAMESPACES):
            capab[constants.K8S_RBD_PROV_NAMESPACES] = \
                constants.K8S_RBD_PROV_NAMESPACE_DEFAULT

        namespaces_to_add, namespaces_to_rm = K8RbdProvisioner.getNamespacesDelta(new_storceph)
        if not namespaces_to_add and not namespaces_to_rm:
            # No changes to namespaces, return early
            return new_storceph

        validate_k8s_namespaces(K8RbdProvisioner.getListFromNamespaces(new_storceph))

    # Check if cluster is configured
    if not utils.is_aio_system(pecan.request.dbapi):
        # On multinode is enough if storage hosts are available
        storage_hosts = pecan.request.dbapi.ihost_get_by_personality(
            constants.STORAGE
        )
        available_storage_hosts = [h for h in storage_hosts if
                                   h['availability'] == constants.AVAILABILITY_AVAILABLE]
        if not available_storage_hosts:
            LOG.info("No storage hosts installed, delaying "
                     "rbd-provisioner configuration.")
            # Configuration will be resumed when first storage node comes up and
            # after pools are configured.
            return new_storceph
    else:
        # On 1 node system check if primary backend is configured
        ceph_bk = StorageBackendConfig.get_configured_backend(pecan.request.dbapi,
                                                              constants.SB_TYPE_CEPH)
        if not ceph_bk:
            # Configuration will be resumed after backend configuration completes
            LOG.info("Ceph not configured, delaying rbd-provisioner configuration.")
            return new_storceph

    return new_storceph


def _apply_backend_changes(op, sb_obj):
    services = api_helper.getListFromServices(sb_obj.as_dict())

    if op == constants.SB_API_OP_MODIFY:
        if sb_obj.name == constants.SB_DEFAULT_NAMES[
                constants.SB_TYPE_CEPH]:

            # Apply manifests for primary tier
            pecan.request.rpcapi.update_ceph_config(pecan.request.context,
                                                    sb_obj.uuid,
                                                    services)


def _apply_nova_specific_changes(sb_obj, old_sb_obj=None):
    """If the backend's services have been modified and nova has been either
       added or (re)moved, set the hosts with worker functionality and a
       certain nova-local instance backing to Config out-of-date.
    """
    services = api_helper.getListFromServices(sb_obj.as_dict())

    if old_sb_obj:
        old_services = api_helper.getListFromServices(old_sb_obj.as_dict())
    else:
        old_services = []
    diff_services = set(services) ^ set(old_services)

    if constants.SB_SVC_NOVA in diff_services:
        pecan.request.rpcapi.config_update_nova_local_backed_hosts(
            pecan.request.context,
            constants.LVG_NOVA_BACKING_REMOTE)

#
# Create
#


def _set_defaults(storage_ceph):
    if utils.is_aio_simplex_system(pecan.request.dbapi):
        def_replication = str(constants.AIO_SX_CEPH_REPLICATION_FACTOR_DEFAULT)
    else:
        def_replication = str(constants.CEPH_REPLICATION_FACTOR_DEFAULT)

    def_min_replication = \
        str(constants.CEPH_REPLICATION_MAP_DEFAULT[int(def_replication)])

    # When primary backend is configured then get defaults from there if configured
    ceph_backend = StorageBackendConfig.get_backend(
        pecan.request.dbapi,
        constants.CINDER_BACKEND_CEPH
    )
    if ceph_backend:
        cap = ceph_backend['capabilities']
        def_replication = cap.get(constants.CEPH_BACKEND_REPLICATION_CAP,
                                  def_replication)
        def_min_replication = cap.get(constants.CEPH_BACKEND_MIN_REPLICATION_CAP,
                                      def_min_replication)

    # If 'replication' parameter is provided with a valid value and optional
    # 'min_replication' parameter is not provided, default its value
    # depending on the 'replication' value
    requested_cap = storage_ceph['capabilities']
    if constants.CEPH_BACKEND_REPLICATION_CAP in requested_cap:
        req_replication = requested_cap[constants.CEPH_BACKEND_REPLICATION_CAP]
        if int(req_replication) in constants.CEPH_REPLICATION_FACTOR_SUPPORTED:
            if constants.CEPH_BACKEND_MIN_REPLICATION_CAP not in requested_cap:
                def_min_replication = \
                    str(constants.CEPH_REPLICATION_MAP_DEFAULT[int(req_replication)])

    def_capabilities = {
        constants.CEPH_BACKEND_REPLICATION_CAP: def_replication,
        constants.CEPH_BACKEND_MIN_REPLICATION_CAP: def_min_replication,
    }

    defaults = {
        'backend': constants.SB_TYPE_CEPH,
        'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH],
        'state': constants.SB_STATE_CONFIGURING,
        'task': constants.SB_TASK_APPLY_MANIFESTS,
        'services': None,
        'capabilities': def_capabilities,
        'cinder_pool_gib': None,
        'glance_pool_gib': None,
        'ephemeral_pool_gib': None,
        'object_pool_gib': None,
        'kube_pool_gib': None,
        'object_gateway': False,
    }

    sc = api_helper.set_backend_data(storage_ceph,
                                     defaults,
                                     CAPABILITIES,
                                     constants.SB_CEPH_SVCS_SUPPORTED)

    # Ceph is our default storage backend and is added at configuration
    # set state and task accordingly.
    if sc['name'] == constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH]:
        sc['state'] = constants.SB_STATE_CONFIGURED
        if utils.is_aio_simplex_system(pecan.request.dbapi):
            sc['task'] = None
        else:
            sc['task'] = constants.SB_TASK_PROVISION_STORAGE

    return sc


def _create(storage_ceph):
    # Validate provided capabilities at creation
    _capabilities_semantic_checks(storage_ceph.get('capabilities', {}))

    # Set the default for the storage backend
    storage_ceph = _set_defaults(storage_ceph)

    # Execute the common semantic checks for all backends, if a backend is
    # not present this will not return
    api_helper.common_checks(constants.SB_API_OP_CREATE,
                             storage_ceph)

    # Run the backend specific semantic checks to validate that we have all the
    # required parameters for manifest application
    _check_backend_ceph(constants.SB_API_OP_CREATE,
                        storage_ceph,
                        storage_ceph.pop('confirmed', False))

    # Setup new rbd-provisioner keys and services early on.
    # Failures here are critical and no backend should be created
    storage_ceph = _check_and_update_rbd_provisioner(storage_ceph)

    check_and_update_services(storage_ceph)

    # Conditionally update the DB based on any previous create attempts. This
    # creates the StorageCeph object.
    system = pecan.request.dbapi.isystem_get_one()
    storage_ceph['forisystemid'] = system.id
    storage_ceph_obj = pecan.request.dbapi.storage_ceph_create(storage_ceph)

    # Mark the storage tier as in-use
    try:
        pecan.request.dbapi.storage_tier_update(
            storage_ceph_obj.tier_id,
            {'forbackendid': storage_ceph_obj.id,
             'status': constants.SB_TIER_STATUS_IN_USE})
    except exception.StorageTierNotFound as e:
        # Shouldn't happen. Log exception. Backend is created but tier status
        # is not updated.
        LOG.exception(e)

    # Retrieve the main StorageBackend object.
    storage_backend_obj = pecan.request.dbapi.storage_backend_get(storage_ceph_obj.id)

    # Enable the backend:
    _apply_backend_changes(constants.SB_API_OP_CREATE, storage_backend_obj)

    # Make any needed changes for nova local.
    _apply_nova_specific_changes(storage_backend_obj)

    return storage_ceph_obj


#
# Update/Modify/Patch
#

def _capabilities_semantic_checks(caps_dict):
    """ Early check of capabilities """

    # Get supported capabilities
    valid_data = {}
    for key in caps_dict:
        if key in CAPABILITIES['backend']:
            valid_data[key] = caps_dict[key]
            continue
        for svc in constants.SB_CEPH_SVCS_SUPPORTED:
            if key in CAPABILITIES[svc]:
                valid_data[key] = caps_dict[key]

    # Raise exception if unsupported capabilities are passed
    invalid_data = set(caps_dict.keys()) - set(valid_data.keys())
    if valid_data.keys() != caps_dict.keys():
        # Build short customer message to help with supported capabilities
        # he can then search for them in the manual.
        params = "    backend: %s\n" % ", ".join(CAPABILITIES['backend'])
        for svc in constants.SB_CEPH_SVCS_SUPPORTED:
            if CAPABILITIES[svc]:
                params += "    %s service: %s\n" % (svc, ", ".join(CAPABILITIES[svc]))
        msg = ("Invalid Ceph parameters: '%s', supported "
               "parameters:\n%s" % (", ".join(invalid_data), params))
        raise wsme.exc.ClientSideError(msg)

    return valid_data


def _pre_patch_checks(storage_ceph_obj, patch_obj):
    storage_ceph_dict = storage_ceph_obj.as_dict()

    for p in patch_obj:
        if p['path'] == '/capabilities':
            patch_caps_dict = p['value']

            # Validate the change to make sure it valid
            patch_caps_dict = _capabilities_semantic_checks(patch_caps_dict)

            # If 'replication' parameter is provided with a valid value and optional
            # 'min_replication' parameter is not provided, default its value
            # depending on the 'replication' value.
            if constants.CEPH_BACKEND_REPLICATION_CAP in patch_caps_dict:
                req_replication = patch_caps_dict[constants.CEPH_BACKEND_REPLICATION_CAP]
                if int(req_replication) in constants.CEPH_REPLICATION_FACTOR_SUPPORTED:
                    if constants.CEPH_BACKEND_MIN_REPLICATION_CAP not in patch_caps_dict:
                        req_min_replication = \
                            str(constants.CEPH_REPLICATION_MAP_DEFAULT[int(req_replication)])
                        patch_caps_dict[constants.CEPH_BACKEND_MIN_REPLICATION_CAP] = \
                            req_min_replication

            current_caps_dict = storage_ceph_dict.get('capabilities', {})
            for k in (set(current_caps_dict.keys()) -
                      set(patch_caps_dict.keys())):
                patch_caps_dict[k] = current_caps_dict[k]

            p['value'] = patch_caps_dict

        elif p['path'] == '/object_gateway':
            p['value'] = p['value'] in ['true', 'True']

        elif p['path'] == '/services':
            # Make sure we aren't disabling all services on the primary tier. - Not currently supported
            if p['value'].lower == 'none':
                if api_helper.is_primary_ceph_tier(storage_ceph_obj.tier_name):
                    raise wsme.exc.ClientSideError(
                        _("Disabling all service for the %s tier is not "
                          "supported.") % storage_ceph_obj.tier_name)

            current_svcs = set([])
            if storage_ceph_obj.services:
                current_svcs = set(storage_ceph_obj.services.split(','))
            updated_svcs = set(p['value'].split(','))

            # Make sure we aren't removing a service.on the primary tier. - Not currently supported.
            if len(current_svcs - updated_svcs):
                new_svc = current_svcs - updated_svcs
                if (api_helper.is_primary_ceph_tier(
                        storage_ceph_obj.tier_name) and
                        new_svc != set([constants.SB_SVC_RBD_PROVISIONER])):
                    raise wsme.exc.ClientSideError(
                        _("Removing %s is not supported.") % ','.join(
                            current_svcs - updated_svcs))
            p['value'] = ','.join(updated_svcs)


def _check_replication_number(new_cap, orig_cap):
    ceph_task = StorageBackendConfig.get_ceph_backend_task(pecan.request.dbapi)
    ceph_state = StorageBackendConfig.get_ceph_backend_state(pecan.request.dbapi)
    if utils.is_aio_simplex_system(pecan.request.dbapi):
        # On single node install we allow both increasing and decreasing
        # replication on the fly.
        if ceph_state != constants.SB_STATE_CONFIGURED:
            raise wsme.exc.ClientSideError(
                _("Can not modify ceph replication factor when "
                  "storage backend state is '%s'. Operation is "
                  "supported for state '%s'" %
                  (ceph_state, constants.SB_STATE_CONFIGURED)))

    else:
        if utils.is_aio_duplex_system(pecan.request.dbapi):
            # Replication change is not allowed on two node configuration
            raise wsme.exc.ClientSideError(
                _("Can not modify ceph replication factor on "
                  "two node configuration."))

        if ceph.get_ceph_storage_model() == constants.CEPH_CONTROLLER_MODEL:
            # Replication change is not allowed when storage OSDs
            # are enabled on controllers.
            raise wsme.exc.ClientSideError(
                _("Can not modify replication factor on "
                  "'%s' ceph deployment model." % constants.CEPH_CONTROLLER_MODEL))

        # On a standard install we allow modifications of ceph storage
        # backend parameters after the manifests have been applied and
        # before first storage node has been configured.
        if ceph_task != constants.SB_TASK_PROVISION_STORAGE and \
                        ceph_state != constants.SB_STATE_CONFIGURING:
            raise wsme.exc.ClientSideError(
                _("Can not modify ceph replication factor when "
                  "storage backend state is \'%s\' and task is \'%s.\' "
                  "Operation supported for state \'%s\' and task \'%s.\'" %
                  (ceph_state, ceph_task,
                   constants.SB_STATE_CONFIGURING,
                   constants.SB_TASK_PROVISION_STORAGE)))

        # Changing replication factor once the first storage node
        # has been installed (pools created) is not supported.
        storage_hosts = pecan.request.dbapi.ihost_get_by_personality(
            constants.STORAGE)
        if storage_hosts:
            raise wsme.exc.ClientSideError(
                _("Can not modify ceph replication factor once "
                  "a storage node has been installed. This operation "
                  "is not supported."))

        # Changing ceph replication to a smaller factor
        # than previously configured is not supported.
        if int(new_cap[constants.CEPH_BACKEND_REPLICATION_CAP]) < \
             int(orig_cap[constants.CEPH_BACKEND_REPLICATION_CAP]):
            raise wsme.exc.ClientSideError(
                _("Can not modify ceph replication factor from %s to "
                  "a smaller value %s. This operation is not supported." %
                  (orig_cap[constants.CEPH_BACKEND_REPLICATION_CAP],
                   new_cap[constants.CEPH_BACKEND_REPLICATION_CAP])))


# TODO(CephPoolsDecouple): remove
def _is_quotaconfig_changed(ostorceph, storceph):
    if storceph and ostorceph:
        if (storceph.cinder_pool_gib != ostorceph.cinder_pool_gib or
                storceph.glance_pool_gib != ostorceph.glance_pool_gib or
                storceph.ephemeral_pool_gib != ostorceph.ephemeral_pool_gib or
                storceph.object_pool_gib != ostorceph.object_pool_gib or
                storceph.kube_pool_gib != ostorceph.kube_pool_gib):
            return True
    return False


# TODO(CephPoolsDecouple): remove
def _check_pool_quotas_data(ostorceph, storceph):
    # Only relevant for ceph backend
    if not StorageBackendConfig.has_backend_configured(
            pecan.request.dbapi,
            constants.CINDER_BACKEND_CEPH):
        msg = _("This operation is for '%s' backend only." %
                constants.CINDER_BACKEND_CEPH)
        raise wsme.exc.ClientSideError(msg)

    # Validate quota values
    pools_key = ['cinder_pool_gib',
                 'glance_pool_gib',
                 'ephemeral_pool_gib',
                 'object_pool_gib',
                 'kube_pool_gib']
    for k in pools_key:
        if storceph[k]:
            if (k != 'cinder_pool_gib' and k != 'kube_pool_gib' and not
                    api_helper.is_primary_ceph_backend(storceph['name'])):
                raise wsme.exc.ClientSideError(_(
                    "Secondary ceph backend only supports cinder and kube "
                    "pools."))

            if (not cutils.is_int_like(storceph[k]) or
                    int(storceph[k]) < 0):
                raise wsme.exc.ClientSideError(
                    _("%s must be a positive integer.") % k)

    if storceph['object_pool_gib']:
        if not storceph['object_gateway'] and not ostorceph.object_gateway:
            raise wsme.exc.ClientSideError(_("Can not modify object_pool_gib "
                                             "when object_gateway is false."))

    # can't configure quota less than already occupied space
    # zero means unlimited so it is an acceptable value
    pools_usage = \
        pecan.request.rpcapi.get_ceph_pools_df_stats(pecan.request.context)
    if not pools_usage:
        raise wsme.exc.ClientSideError(
            _("The ceph storage pool quotas cannot be configured while "
              "there are no available storage nodes present."))

    for ceph_pool in pools_usage:
        if api_helper.is_primary_ceph_tier(storceph['tier_name']):
            if ceph_pool['name'] == constants.CEPH_POOL_VOLUMES_NAME:
                if (int(storceph['cinder_pool_gib']) > 0 and
                    (int(ceph_pool['stats']['bytes_used']) >
                     int(storceph['cinder_pool_gib'] * 1024 ** 3))):
                    raise wsme.exc.ClientSideError(
                        _("The configured quota for the cinder pool (%s GiB) "
                          "must be greater than the already occupied space (%s GiB)")
                        % (storceph['cinder_pool_gib'],
                           float(ceph_pool['stats']['bytes_used']) / (1024 ** 3)))
            elif ceph_pool['name'] == constants.CEPH_POOL_KUBE_NAME:
                if (int(storceph['kube_pool_gib']) > 0 and
                    (int(ceph_pool['stats']['bytes_used']) >
                     int(storceph['kube_pool_gib'] * 1024 ** 3))):
                    raise wsme.exc.ClientSideError(
                        _("The configured quota for the kube pool (%s GiB) "
                          "must be greater than the already occupied space (%s GiB)")
                        % (storceph['kube_pool_gib'],
                           float(ceph_pool['stats']['bytes_used']) / (1024 ** 3)))
            elif ceph_pool['name'] == constants.CEPH_POOL_EPHEMERAL_NAME:
                if (int(storceph['ephemeral_pool_gib']) > 0 and
                    (int(ceph_pool['stats']['bytes_used']) >
                     int(storceph['ephemeral_pool_gib'] * 1024 ** 3))):
                    raise wsme.exc.ClientSideError(
                        _("The configured quota for the ephemeral pool (%s GiB) "
                          "must be greater than the already occupied space (%s GiB)")
                        % (storceph['ephemeral_pool_gib'],
                           float(ceph_pool['stats']['bytes_used']) / (1024 ** 3)))
            elif ceph_pool['name'] == constants.CEPH_POOL_IMAGES_NAME:
                if (int(storceph['glance_pool_gib']) > 0 and
                    (int(ceph_pool['stats']['bytes_used']) >
                     int(storceph['glance_pool_gib'] * 1024 ** 3))):
                    raise wsme.exc.ClientSideError(
                        _("The configured quota for the glance pool (%s GiB) "
                          "must be greater than the already occupied space (%s GiB)")
                        % (storceph['glance_pool_gib'],
                           float(ceph_pool['stats']['bytes_used']) / (1024 ** 3)))
            elif ceph_pool['name'] in constants.CEPH_POOL_OBJECT_GATEWAY_NAME:
                if (int(storceph['object_pool_gib']) > 0 and
                    (int(ceph_pool['stats']['bytes_used']) >
                     int(storceph['object_pool_gib'] * 1024 ** 3))):
                    raise wsme.exc.ClientSideError(
                        _("The configured quota for the object pool (%s GiB) "
                          "must be greater than the already occupied space (%s GiB)")
                        % (storceph['object_pool_gib'],
                           float(ceph_pool['stats']['bytes_used']) / (1024 ** 3)))
        else:
            if storceph['tier_name'] in ceph_pool['name']:
                if constants.CEPH_POOL_VOLUMES_NAME in ceph_pool['name']:
                    if (int(storceph['cinder_pool_gib']) > 0 and
                        (int(ceph_pool['stats']['bytes_used']) >
                         int(storceph['cinder_pool_gib'] * 1024 ** 3))):
                        raise wsme.exc.ClientSideError(
                            _("The configured quota for the cinder pool (%s GiB) "
                              "must be greater than the already occupied space (%s GiB)")
                            % (storceph['cinder_pool_gib'],
                               float(ceph_pool['stats']['bytes_used']) / (1024 ** 3)))
                elif K8RbdProvisioner.get_pool(storceph) == ceph_pool['name']:
                    if (int(storceph['kube_pool_gib']) > 0 and
                        (int(ceph_pool['stats']['bytes_used']) >
                         int(storceph['kube_pool_gib'] * 1024 ** 3))):
                        raise wsme.exc.ClientSideError(
                            _("The configured quota for the kube pool (%s GiB) "
                              "must be greater than the already occupied space (%s GiB)")
                            % (storceph['kube_pool_gib'],
                               float(ceph_pool['stats']['bytes_used']) / (1024 ** 3)))

    # sanity check the quota
    total_quota_gib = 0
    total_quota_bytes = 0
    for k in pools_key:
        if storceph[k] is not None:
            total_quota_gib += int(storceph[k])
            total_quota_bytes += int(storceph[k]) * 1024 ** 3

    tier_size = pecan.request.rpcapi.get_ceph_tier_size(pecan.request.context,
                                                        storceph['tier_name'])

    if api_helper.is_primary_ceph_tier(storceph['tier_name']):
        if int(tier_size) != total_quota_gib:
            raise wsme.exc.ClientSideError(
                _("Total Pool quotas (%s GiB) must be the exact size of the "
                  "storage tier size (%s GiB)")
                % (total_quota_gib, int(tier_size)))
    else:
        if total_quota_gib > int(tier_size):
            raise wsme.exc.ClientSideError(
                _("Total Pool quotas (%s GiB) must not be greater that the "
                  "size of the storage tier (%s GiB)")
                % (total_quota_gib, int(tier_size)))


# TODO(CephPoolsDecouple): remove
def _update_pool_quotas(storceph):
    # In R4, the object data pool name could be either
    # CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER or CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL
    object_pool_name = pecan.request.rpcapi.get_ceph_object_pool_name(pecan.request.context)
    if object_pool_name is None:
        raise wsme.exc.ClientSideError(_("Ceph object data pool does not exist."))

    if api_helper.is_primary_ceph_tier(storceph['tier_name']):
        pools = [{'name': constants.CEPH_POOL_VOLUMES_NAME,
                  'quota_key': 'cinder_pool_gib'},
                 {'name': constants.CEPH_POOL_IMAGES_NAME,
                  'quota_key': 'glance_pool_gib'},
                 {'name': constants.CEPH_POOL_EPHEMERAL_NAME,
                  'quota_key': 'ephemeral_pool_gib'},
                 {'name': object_pool_name,
                  'quota_key': 'object_pool_gib'},
                 {'name': constants.CEPH_POOL_KUBE_NAME,
                  'quota_key': 'kube_pool_gib'}]
    else:
        pools = [{'name': "{0}-{1}".format(constants.CEPH_POOL_VOLUMES_NAME,
                                           storceph['tier_name']),
                  'quota_key': 'cinder_pool_gib'},
                 {'name': "{0}-{1}".format(constants.CEPH_POOL_KUBE_NAME,
                                           storceph['tier_name']),
                  'quota_key': 'kube_pool_gib'}
                 ]

    for p in pools:
        if storceph[p['quota_key']] is not None:
            LOG.info("Setting %s pool quota to: %s GB",
                     p['name'],
                     storceph[p['quota_key']])
            pool_max_bytes = storceph[p['quota_key']] * 1024 ** 3
            pecan.request.rpcapi.set_osd_pool_quota(pecan.request.context,
                                                    p['name'],
                                                    pool_max_bytes)


def _check_object_gateway_install(dbapi):
    # Ensure we have the required number of monitors
    if utils.is_aio_system(dbapi):
        api_helper.check_minimal_number_of_controllers(1)
    else:
        api_helper.check_minimal_number_of_controllers(2)
    api_helper.check_swift_enabled()


def _patch(storceph_uuid, patch):
    # Obtain current ceph storage object.
    rpc_storceph = objects.storage_ceph.get_by_uuid(
        pecan.request.context,
        storceph_uuid)

    object_gateway_install = False
    patch_obj = jsonpatch.JsonPatch(patch)
    for p in patch_obj:
        if p['path'] == '/capabilities':
            p['value'] = jsonutils.loads(p['value'])
    ostorceph = copy.deepcopy(rpc_storceph)

    # Validate provided patch data meets validity checks
    _pre_patch_checks(rpc_storceph, patch_obj)

    # Obtain a ceph storage object with the patch applied.
    try:
        storceph_config = StorageCeph(**jsonpatch.apply_patch(
            rpc_storceph.as_dict(),
            patch_obj))

    except utils.JSONPATCH_EXCEPTIONS as e:
        raise exception.PatchError(patch=patch, reason=e)

    # Update current ceph storage object.
    for field in objects.storage_ceph.fields:
        if (field in storceph_config.as_dict() and
                rpc_storceph[field] != storceph_config.as_dict()[field]):
            rpc_storceph[field] = storceph_config.as_dict()[field]

    # Obtain the fields that have changed.
    delta = rpc_storceph.obj_what_changed()
    # TODO(CephPoolsDecouple): remove quota values
    allowed_attributes = ['services', 'capabilities', 'task',
                          'cinder_pool_gib',
                          'glance_pool_gib',
                          'ephemeral_pool_gib',
                          'object_pool_gib',
                          'kube_pool_gib',
                          'object_gateway']
    # TODO(CephPoolsDecouple): remove variable
    quota_attributes = ['cinder_pool_gib', 'glance_pool_gib',
                        'ephemeral_pool_gib', 'object_pool_gib',
                        'kube_pool_gib']

    if len(delta) == 0 and rpc_storceph['state'] != constants.SB_STATE_CONFIG_ERR:
        raise wsme.exc.ClientSideError(
            _("No changes to the existing backend settings were detected."))

    # Get changes to services
    services_added = (
        set(api_helper.getListFromServices(storceph_config.as_dict())) -
        set(api_helper.getListFromServices(ostorceph.as_dict()))
    )

    services_removed = (
        set(api_helper.getListFromServices(ostorceph.as_dict())) -
        set(api_helper.getListFromServices(storceph_config.as_dict()))
    )

    # Some services allow fast settings update, check if we are in this case.
    # Adding/removing services or just making changes to the configuration
    # these services depend on will not trigger manifest application.
    fast_config = False
    if not (delta - set(['capabilities']) - set(['services'])):
        fast_cfg_services = [constants.SB_SVC_NOVA, constants.SB_SVC_RBD_PROVISIONER,
                             constants.SB_SVC_CINDER, constants.SB_SVC_GLANCE]

        # Changes to unrelated capabilities?
        storceph_cap = storceph_config.as_dict()['capabilities'].items()
        ostorceph_cap = ostorceph.as_dict()['capabilities'].items()
        related_cap = []
        for service in fast_cfg_services:
            related_cap.extend(CAPABILITIES[service])
        cap_modified = dict(set(storceph_cap) - set(ostorceph_cap))
        unrelated_cap_modified = [k for k in cap_modified.keys() if k not in related_cap]

        # Changes to unrelated services?
        unrelated_services_modified = ((set(services_added) |
                                        set(services_removed)) -
                                       set(fast_cfg_services))

        if not unrelated_services_modified and not unrelated_cap_modified:
            # We only have changes to fast configurable services and/or to their capabilities
            fast_config = True

    # TODO(CephPoolsDecouple): remove variable
    quota_only_update = True
    replication_only_update = False
    for d in delta:
        if d not in allowed_attributes:
            raise wsme.exc.ClientSideError(
                _("Can not modify '%s' with this operation." % d))

        # TODO(CephPoolsDecouple): remove condition
        if d not in quota_attributes:
            quota_only_update = False

        # TODO (rchurch): In R6, refactor and remove object_gateway attribute
        # and DB column. This should be driven by if the service is added to
        # the services list
        if d == 'object_gateway':
            if ostorceph[d]:
                raise wsme.exc.ClientSideError(
                    _("Ceph Object Gateway can not be turned off."))
            else:
                object_gateway_install = True

                # Adjust service list based on the pre-R5 object_gateway_install
                if constants.SB_SVC_SWIFT not in storceph_config.services:
                    storceph_config.services = ','.join(
                        [storceph_config.services, constants.SB_SVC_SWIFT])
                    storceph_config.task = constants.SB_TASK_ADD_OBJECT_GATEWAY
        elif d == 'services':
            # Adjust object_gateway if swift is added to the services list
            # rather than added via the object_gateway attribute
            if (constants.SB_SVC_SWIFT in storceph_config.services and
                  (ostorceph.services and
                   constants.SB_SVC_SWIFT not in ostorceph.services)):
                storceph_config.object_gateway = True
                storceph_config.task = constants.SB_TASK_ADD_OBJECT_GATEWAY
                object_gateway_install = True

        elif d == 'capabilities':
            # Go through capabilities parameters and check
            # if any values changed
            scaporig = set(ostorceph.as_dict()['capabilities'].items())
            scapconfig = set(storceph_config.as_dict()['capabilities'].items())
            scapcommon = scaporig & scapconfig
            new_cap = {}
            if 0 < len(scapcommon) == len(scapconfig):
                raise wsme.exc.ClientSideError(
                    _("No changes to the existing backend "
                      "settings were detected."))

            # select parameters which are new or have changed
            new_cap.update(dict(scapconfig - scapcommon))

            # Semantic checks on new or modified parameters:
            orig_cap = ostorceph.as_dict()['capabilities']
            if ((constants.CEPH_BACKEND_REPLICATION_CAP in new_cap and
                    constants.CEPH_BACKEND_REPLICATION_CAP in orig_cap) or
                    (constants.CEPH_BACKEND_MIN_REPLICATION_CAP in new_cap and
                     constants.CEPH_BACKEND_MIN_REPLICATION_CAP in orig_cap)):
                # Semantic checks for replication number change
                _check_replication_number(new_cap, orig_cap)
                if len(new_cap) == 1 and (constants.CEPH_BACKEND_REPLICATION_CAP in new_cap or
                                          constants.CEPH_BACKEND_MIN_REPLICATION_CAP in new_cap):
                    replication_only_update = True
                if len(new_cap) == 2 and (constants.CEPH_BACKEND_REPLICATION_CAP in new_cap and
                                          constants.CEPH_BACKEND_MIN_REPLICATION_CAP in new_cap):
                    replication_only_update = True

    LOG.info("SYS_I orig    storage_ceph: %s " % ostorceph.as_dict())
    LOG.info("SYS_I patched storage_ceph: %s " % storceph_config.as_dict())

    LOG.info("Don't check quotas")

    # Execute the common semantic checks for all backends, if backend
    # is not present this will not return.
    api_helper.common_checks(constants.SB_API_OP_MODIFY,
                             rpc_storceph.as_dict())

    # Run the backend specific semantic checks
    _check_backend_ceph(constants.SB_API_OP_MODIFY,
                        rpc_storceph.as_dict(),
                        True)

    # TODO (rchurch): In R6, refactor and remove object_gateway
    # attribute and DB column. This should be driven by if the service
    # is added to the services list
    if object_gateway_install:
        _check_object_gateway_install(pecan.request.dbapi)

    for field in objects.storage_ceph.fields:
        if (field in storceph_config.as_dict() and
                rpc_storceph[field] != storceph_config.as_dict()[field]):
            rpc_storceph[field] = storceph_config.as_dict()[field]

    LOG.info("SYS_I new     storage_ceph: %s " % rpc_storceph.as_dict())
    try:
        check_and_update_services(rpc_storceph.as_dict())

        rpc_storceph.save()

        # TODO(CephPoolsDecouple): rework - remove quota_only_update
        if ((not quota_only_update and
             not fast_config and
             not replication_only_update) or
                (storceph_config.state == constants.SB_STATE_CONFIG_ERR)):
            # Enable the backend changes:
            _apply_backend_changes(constants.SB_API_OP_MODIFY,
                                   rpc_storceph)

        _apply_nova_specific_changes(rpc_storceph, ostorceph)

        return StorageCeph.convert_with_links(rpc_storceph)

    except exception.HTTPNotFound:
        msg = _("StorCeph update failed: storceph %s : "
                " patch %s"
                % (storceph_config, patch))
        raise wsme.exc.ClientSideError(msg)
    except Exception as e:
        rpc_storceph = objects.storage_ceph.get_by_uuid(
            pecan.request.context,
            storceph_uuid)
        for field in allowed_attributes:
            if (field in ostorceph.as_dict() and
                    rpc_storceph[field] != ostorceph.as_dict()[field]):
                rpc_storceph[field] = ostorceph.as_dict()[field]
        rpc_storceph.save()
        msg = _("There was an error trying to update the backend. Please "
                "investigate and try again: %s" % str(e))
        raise wsme.exc.ClientSideError(msg)

#
# Delete
#


def _delete(sb_uuid):
    # LOG.error("sb_uuid %s" % sb_uuid)

    storage_ceph_obj = pecan.request.dbapi.storage_ceph_get(sb_uuid)

    # LOG.error("delete %s" % storage_ceph_obj.as_dict())

    # Execute the common semantic checks for all backends, if backend is not
    # present this will not return
    api_helper.common_checks(constants.SB_API_OP_DELETE,
                             storage_ceph_obj.as_dict())

    # Run the backend specific semantic checks
    _check_backend_ceph(constants.SB_API_OP_DELETE,
                        storage_ceph_obj.as_dict(),
                        True)

    # Enable the backend changes:
    _apply_backend_changes(constants.SB_API_OP_DELETE, storage_ceph_obj)

    # decouple backend from storage tier
    try:
        tier_obj = pecan.request.dbapi.storage_tier_get(storage_ceph_obj.tier_id)
        if tier_obj.stors:
            status = constants.SB_TIER_STATUS_IN_USE
        else:
            status = constants.SB_TIER_STATUS_DEFINED
        pecan.request.dbapi.storage_tier_update(tier_obj.id,
            {'forbackendid': None, 'status': status})
    except exception.StorageTierNotFound as e:
        # Shouldn't happen. Log exception. Try to delete the backend anyway
        LOG.exception(e)

    try:
        pecan.request.dbapi.storage_backend_destroy(storage_ceph_obj.id)
    except exception.HTTPNotFound:
        msg = _("Deletion of backend %s failed" % storage_ceph_obj.uuid)
        raise wsme.exc.ClientSideError(msg)
