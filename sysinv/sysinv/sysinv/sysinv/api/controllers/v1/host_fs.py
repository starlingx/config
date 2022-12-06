#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import jsonpatch
import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class HostFsPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class HostFs(base.APIBase):
    """API representation of a host_fs.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a host's filesystems.
    """

    uuid = types.uuid
    "Unique UUID for this host_fs"

    name = wsme.wsattr(wtypes.text, mandatory=True)

    size = int

    logical_volume = wsme.wsattr(wtypes.text)

    forihostid = int
    "The ihostid that this host_fs belongs to"

    ihost_uuid = types.uuid
    "The UUID of the host this host_fs belongs to"

    links = [link.Link]
    "A list containing a self link and associated host_fs links"

    def __init__(self, **kwargs):
        self.fields = list(objects.host_fs.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # API-only attribute)
        self.fields.append('action')
        setattr(self, 'action', kwargs.get('action', None))

    @classmethod
    def convert_with_links(cls, rpc_host_fs, expand=True):
        host_fs = HostFs(**rpc_host_fs.as_dict())
        if not expand:
            host_fs.unset_fields_except(['uuid', 'name', 'size',
                                        'logical_volume',
                                         'created_at', 'updated_at',
                                         'ihost_uuid', 'forihostid'])

        # never expose the ihost_id attribute, allow exposure for now
        host_fs.forihostid = wtypes.Unset
        host_fs.links = [link.Link.make_link('self', pecan.request.host_url,
                                             'host_fs', host_fs.uuid),
                         link.Link.make_link('bookmark',
                                             pecan.request.host_url,
                                             'host_fs', host_fs.uuid,
                                             bookmark=True)]

        return host_fs


class HostFsCollection(collection.Collection):
    """API representation of a collection of host_fs."""

    host_fs = [HostFs]
    "A list containing host_fs objects"

    def __init__(self, **kwargs):
        self._type = 'host_fs'

    @classmethod
    def convert_with_links(cls, rpc_host_fs, limit, url=None,
                           expand=False, **kwargs):
        collection = HostFsCollection()
        collection.host_fs = [HostFs.convert_with_links(p, expand)
                              for p in rpc_host_fs]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


def _calculate_requested_growth(host_fs_list, host_fs_list_new):
    """ Check host filesystem data and return growth
        returns: cgtsvg_growth_gib
    """

    cgtsvg_growth_gib = 0

    for fs in host_fs_list_new:
        for fs_current in host_fs_list:
            if fs_current.name == fs.name:
                orig = int(float(fs_current.size))
                new = int(fs.size)
                LOG.info(
                    "_calculate_requested_growth orig=%s: %s" % (orig, new))
                if orig > new:
                    raise wsme.exc.ClientSideError(_("'%s'  must be at least: "
                                                     "%s" % (fs.name, orig)))
                cgtsvg_growth_gib += (new - orig)

    return cgtsvg_growth_gib


LOCK_NAME = 'FsController'


class HostFsController(rest.RestController):
    """REST controller for host_fs."""

    _custom_actions = {
        'detail': ['GET'],
        'update_many': ['PUT'],
    }

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts

    def _get_host_fs_collection(self, ihost_uuid, marker, limit, sort_key,
                                sort_dir, expand=False, resource_url=None):
        if self._from_ihosts and not ihost_uuid:
            raise exception.InvalidParameterValue(_(
                "Host id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.host_fs.get_by_uuid(
                pecan.request.context,
                marker)

        if ihost_uuid:
            host_fs = pecan.request.dbapi.host_fs_get_by_ihost(
                ihost_uuid, limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        else:
            host_fs = pecan.request.dbapi.host_fs_get_list(limit, marker_obj,
                                                           sort_key=sort_key,
                                                           sort_dir=sort_dir)

        return HostFsCollection.convert_with_links(host_fs, limit,
                                                   url=resource_url,
                                                   expand=expand,
                                                   sort_key=sort_key,
                                                   sort_dir=sort_dir)

    @wsme_pecan.wsexpose(HostFsCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, ihost_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of filesystems for the given host."""

        return self._get_host_fs_collection(ihost_uuid, marker, limit,
                                            sort_key, sort_dir)

    @wsme_pecan.wsexpose(HostFsCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, ihost_uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of filesystems for the given host with detail."""

        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "host_fs":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['host_fs', 'detail'])
        return self._get_host_fs_collection(ihost_uuid,
                                            marker, limit,
                                            sort_key, sort_dir,
                                            expand, resource_url)

    @wsme_pecan.wsexpose(HostFs, types.uuid)
    def get_one(self, host_fs_uuid):
        """Retrieve the filesystem information about the given host."""
        LOG.info("get one: %s" % host_fs_uuid)
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_host_fs = objects.host_fs.get_by_uuid(pecan.request.context,
                                              host_fs_uuid)
        return HostFs.convert_with_links(rpc_host_fs)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [HostFsPatchType])
    @wsme_pecan.wsexpose(HostFs, types.uuid,
                         body=[HostFsPatchType])
    def patch(self, host_fs_uuid, patch):
        raise exception.OperationNotPermitted

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [HostFsPatchType])
    @wsme_pecan.wsexpose(None, types.uuid, body=[[HostFsPatchType]])
    def update_many(self, ihost_uuid, patch):
        """Update existing filesystems for a host."""

        LOG.info("patch_data: %s" % patch)

        # Validate input filesystem names
        current_host_fs_list = pecan.request.dbapi.host_fs_get_by_ihost(ihost_uuid)
        current_host_lvg_list = pecan.request.dbapi.ilvg_get_by_ihost(ihost_uuid)
        host = pecan.request.dbapi.ihost_get(ihost_uuid)

        modified_fs = []

        for p_list in patch:
            p_obj_list = jsonpatch.JsonPatch(p_list)

            for p_obj in p_obj_list:
                if p_obj['path'] == '/action':
                    value = p_obj['value']
                    patch.remove(p_list)

        for p_list in patch:
            p_obj_list = jsonpatch.JsonPatch(p_list)
            for p_obj in p_obj_list:
                if p_obj['path'] == '/name':
                    fs_display_name = p_obj['value']
                    fs_name = fs_display_name
                elif p_obj['path'] == '/size':
                    size = p_obj['value']

            # TODO(rchurch): Remove optional filesystem creation once Zero Touch
            # provisioning properly supports optional creation API. Currently it
            # only supports resize operations of existing filesystems. Here we
            # will skip this semantic check, run through the others, then create
            # the new optional filesystem
            create_first = False
            if fs_name not in [fs['name'] for fs in current_host_fs_list]:
                if fs_name not in constants.FS_CREATION_ALLOWED:
                    msg = _("HostFs update failed: invalid filesystem "
                            "'%s' " % fs_display_name)
                    raise wsme.exc.ClientSideError(msg)
                else:
                    create_first = True

            if not cutils.is_int_like(size):
                msg = _("HostFs update failed: filesystem '%s' "
                        "size must be an integer " % fs_display_name)
                raise wsme.exc.ClientSideError(msg)

            elif utils.is_drbd_fs_resizing():
                msg = _("HostFs update failed: there is a drdb filesystem "
                        "resize in progress, please retry again later.")
                raise wsme.exc.ClientSideError(msg)

            elif not utils.is_host_lvg_updated(current_host_fs_list, current_host_lvg_list):
                msg = _("HostFs update failed: a LVG update is still "
                        "pending, please retry again later.")
                raise wsme.exc.ClientSideError(msg)

            # TODO(rchurch): Remove optional filesystem creation once Zero Touch
            # provisioning properly supports optional creation API.
            if create_first:
                try:
                    new_fs = {'name': fs_name, 'size': 1, 'ihost_uuid': ihost_uuid,
                              constants.FS_OP: constants.FS_OP_RESIZE}
                    _create(new_fs)
                except exception.SysinvException as e:
                    LOG.exception(e)
                    raise wsme.exc.ClientSideError(_("Invalid data: failed to create a"
                                                     " filesystem"))
                current_size = 1
                # Re-populate host-fs-list
                current_host_fs_list = pecan.request.dbapi.host_fs_get_by_ihost(ihost_uuid)
            else:
                current_size = [fs['size'] for
                                fs in current_host_fs_list
                                if fs['name'] == fs_name][0]

            if int(size) <= int(current_size):
                msg = _("HostFs update failed: size for filesystem '%s' "
                        "should be bigger than %s " % (
                            fs_display_name, current_size))
                raise wsme.exc.ClientSideError(msg)

            modified_fs += [fs_name]

        if not modified_fs:
            msg = _("HostFs update failed: no filesystems to update")
            raise wsme.exc.ClientSideError(msg)

        host_fs_list_new = []
        for fs in current_host_fs_list:
            replaced = False
            for p_list in patch:
                p_obj_list = jsonpatch.JsonPatch(p_list)
                for p_obj in p_obj_list:
                    if p_obj['value'] == fs['name']:
                        try:
                            host_fs_list_new += [HostFs(
                                      **jsonpatch.apply_patch(fs.as_dict(), p_obj_list))]
                            replaced = True
                            break
                        except utils.JSONPATCH_EXCEPTIONS as e:
                            raise exception.PatchError(patch=p_list, reason=e)
                if replaced:
                    break
            if not replaced:
                host_fs_list_new += [fs]

        requested_growth_gib = \
            _calculate_requested_growth(current_host_fs_list, host_fs_list_new)

        LOG.info("Requested growth in GiB: %s" % requested_growth_gib)

        cgtsvg_free_space_gib = utils.get_node_cgtsvg_limit(host)

        if requested_growth_gib > cgtsvg_free_space_gib:
            msg = _("HostFs update failed: Not enough free space on %s. "
                    "Current free space %s GiB, "
                    "requested total increase %s GiB" %
                    (constants.LVG_CGTS_VG, cgtsvg_free_space_gib, requested_growth_gib))
            LOG.warning(msg)
            raise wsme.exc.ClientSideError(msg)

        for fs in host_fs_list_new:
            if fs.name in modified_fs:
                value = {'size': fs.size}
                pecan.request.dbapi.host_fs_update(fs.uuid, value)

        try:
            if (host.invprovision in [constants.PROVISIONED,
                                      constants.PROVISIONING]):

                # perform rpc to conductor to perform config apply
                pecan.request.rpcapi.update_host_filesystem_config(
                        pecan.request.context,
                        host=host,
                        filesystem_list=modified_fs,)

        except Exception as e:
            msg = _("Failed to update filesystem size for %s" % host.hostname)
            LOG.error("%s with patch %s with exception %s" % (msg, patch, e))
            raise wsme.exc.ClientSideError(msg)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, host_fs_uuid):
        """Delete a host filesystem."""

        host_fs = objects.host_fs.get_by_uuid(pecan.request.context,
                                      host_fs_uuid).as_dict()
        ihost_uuid = host_fs['ihost_uuid']
        host = pecan.request.dbapi.ihost_get(ihost_uuid)
        host_fs[constants.FS_OP] = constants.FS_OP_DELETE
        staged = _delete(host_fs)

        try:
            # TODO(rchurch): Need to add a state/status column to the host_fs DB
            # so status information can be passed to the end-user
            if staged:
                LOG.info("STAGING: %s filesystem to be deleted at unlock" % host_fs['name'])
            else:
                LOG.info("REQUEST: %s filesystem will be deleted NOW" % host_fs['name'])
                pecan.request.rpcapi.update_host_filesystem_config(
                        pecan.request.context,
                        host=host,
                        filesystem_list=[host_fs['name']],)

        except Exception as e:
            msg = _("Failed to delete filesystem %s" % host_fs['name'])
            LOG.error("%s with exception %s" % (msg, e))
            pecan.request.dbapi.host_fs_create(host.id, host_fs)
            raise wsme.exc.ClientSideError(msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(HostFs, body=HostFs)
    def post(self, host_fs):
        """Create a host filesystem."""

        try:
            host_fs = host_fs.as_dict()
            host_fs[constants.FS_OP] = constants.FS_OP_CREATE
            (staged, host_fs) = _create(host_fs)

            ihost_uuid = host_fs['ihost_uuid']
            ihost_uuid.strip()

            host = pecan.request.dbapi.ihost_get(ihost_uuid)
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create a"
                                             " filesystem"))
        try:
            # TODO(rchurch): Need to add a state/status column to the host_fs DB
            # so status information can be passed to the end-user
            if staged:
                LOG.info("STAGING: %s filesystem on host %s to be created at unlock" % (
                    host_fs['name'], host.hostname))
            else:
                LOG.info("REQUEST: %s filesystem on host %s will be created NOW" % (
                    host_fs['name'], host.hostname))
                pecan.request.rpcapi.update_host_filesystem_config(
                    pecan.request.context,
                    host=host,
                    filesystem_list=[host_fs['name']],)

        except Exception as e:
            msg = _("Failed to add filesystem name for %s" % host.hostname)
            LOG.error("%s with exception %s" % (msg, e))
            pecan.request.dbapi.host_fs_destroy(host_fs['id'])
            raise wsme.exc.ClientSideError(msg)

        return HostFs.convert_with_links(host_fs)


def _check_host_fs(host_fs):
    """Check host state"""

    if host_fs['name'] not in constants.FS_CREATION_ALLOWED:
        raise wsme.exc.ClientSideError(
            _("Unsupported filesystem. Only the following filesystems are supported"
              "for creation or deletion: %s" % str(constants.FS_CREATION_ALLOWED)))

    ihost_uuid = host_fs['ihost_uuid']
    ihost_uuid.strip()

    try:
        ihost = pecan.request.dbapi.ihost_get(ihost_uuid)
    except exception.ServerNotFound:
        raise wsme.exc.ClientSideError(_("Invalid ihost_uuid %s"
                                        % ihost_uuid))

    if host_fs['name'] not in constants.FILESYSTEM_HOSTS_SUPPORTED_LIST_DICT[
            ihost.personality]:
        raise wsme.exc.ClientSideError(
            _("Filesystem %s can not be added on %s nodes") % (
                host_fs['name'], ihost.personality))

    # FILESYSTEM_NAME_INSTANCES:
    # Can only be created when host is locked. This is currently required as
    # this filesystem and instances from the nova-local volume group can't exist
    # at the same time as they share a common mount point. No runtime changes to
    # nova-local are currently allowed.
    #
    # The exception is to support zero-touch provisioning after initial unlock
    # when the filesystem will be created and resized. A conflict with
    # nova-local if initially provisioned will be caught below.
    if (host_fs[constants.FS_OP] != constants.FS_OP_RESIZE and
        constants.WORKER in ihost['subfunctions'] and
        host_fs['name'] == constants.FILESYSTEM_NAME_INSTANCES and
        (ihost['administrative'] != constants.ADMIN_LOCKED or
         ihost['ihost_action'] == constants.UNLOCK_ACTION)):
            raise wsme.exc.ClientSideError(_("Host must be locked to make changes "
                                             "to %s") % host_fs['name'])

    # FILESYSTEM_NAME_INSTANCES:
    # Make sure there is only a single source for /var/lib/nova/instances
    ihost_ilvgs = pecan.request.dbapi.ilvg_get_by_ihost(ihost_uuid)
    for lvg in ihost_ilvgs:
        if (lvg.lvm_vg_name == constants.LVG_NOVA_LOCAL and
                lvg.vg_state != constants.LVG_DEL):
            raise wsme.exc.ClientSideError(_(
                "Cannot create %s while volume group %s is enabled. Delete the "
                "volume group and try again.") % (
                    host_fs['name'], constants.LVG_NOVA_LOCAL))

    # FILESYSTEM_NAME_IMAGE_CONVERSION:
    # Can be created at any time as this needs to reside on both controllers
    # when enabled. In a duplex setup one host may be locked for maintenance, so
    # still allow proper provisioning in locked/unlocked states
    if (constants.CONTROLLER in ihost['subfunctions'] and
        host_fs['name'] == constants.FILESYSTEM_NAME_IMAGE_CONVERSION and
        ihost['availability'] not in [constants.AVAILABILITY_AVAILABLE,
                                      constants.AVAILABILITY_ONLINE,
                                      constants.AVAILABILITY_DEGRADED]):
            raise wsme.exc.ClientSideError(
                _("Controller must be available/online/degraded to add %s filesystem") %
                host_fs['name'])


def _create(host_fs):
    """Create a host filesystem"""

    _check_host_fs(host_fs)

    ihost_uuid = host_fs['ihost_uuid']
    ihost_uuid.strip()

    ihost = pecan.request.dbapi.ihost_get(ihost_uuid)
    # See if this filesystem name already exists
    if cutils.is_filesystem_enabled(pecan.request.dbapi, ihost_uuid, host_fs['name']):
        raise wsme.exc.ClientSideError(
            _("Filesystem name (%s) already present" % host_fs['name']))

    requested_growth_gib = int(float(host_fs['size']))

    LOG.info("Requested growth in GiB: %s for fs %s on host %s" %
            (requested_growth_gib, host_fs['name'], ihost_uuid))

    cgtsvg_free_space_gib = utils.get_node_cgtsvg_limit(ihost)

    if requested_growth_gib > cgtsvg_free_space_gib:
        msg = _("HostFs update failed: Not enough free space on %s. "
                "Current free space %s GiB, "
                "requested total increase %s GiB" %
                (constants.LVG_CGTS_VG, cgtsvg_free_space_gib, requested_growth_gib))
        LOG.warning(msg)
        raise wsme.exc.ClientSideError(msg)

    data = {
        'name': host_fs['name'],
        'size': host_fs['size'],
        'logical_volume': constants.FILESYSTEM_LV_DICT[host_fs['name']]
    }

    forihostid = ihost['id']
    host_fs = pecan.request.dbapi.host_fs_create(forihostid, data)

    staged = True if host_fs['name'] == constants.FILESYSTEM_NAME_INSTANCES else False
    return (staged, host_fs)


def _delete(host_fs):
    """Delete a host filesystem."""

    _check_host_fs(host_fs)

    ihost = pecan.request.dbapi.ihost_get(host_fs['forihostid'])
    try:
        pecan.request.dbapi.host_fs_destroy(host_fs['id'])
    except exception.HTTPNotFound:
        msg = _("Deleting Filesystem failed: host %s filesystem %s"
                % (ihost.hostname, host_fs['name']))
        raise wsme.exc.ClientSideError(msg)

    staged = True if host_fs['name'] == constants.FILESYSTEM_NAME_INSTANCES else False
    return staged
