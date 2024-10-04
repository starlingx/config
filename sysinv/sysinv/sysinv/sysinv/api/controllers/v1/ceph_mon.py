# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright 2013 UnitedStack Inc.
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
# Copyright (c) 2013-2019,2024 Wind River Systems, Inc.
#

import jsonpatch
import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from oslo_utils import uuidutils
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import ceph
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

from sysinv.common.storage_backend_conf import StorageBackendConfig

LOG = log.getLogger(__name__)


class CephMonPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class CephMon(base.APIBase):
    """API representation of a ceph mon.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a ceph mon.
    """

    uuid = types.uuid
    "Unique UUID for this ceph mon."

    device_path = wtypes.text
    "The disk device path on host that cgts-vg will be extended to create " \
        "ceph-mon-lv."

    device_node = wtypes.text
    "The disk device node on host that cgts-vg will be extended to create " \
        "ceph-mon-lv."

    forihostid = int
    "The id of the host the ceph mon belongs to."

    ihost_uuid = types.uuid
    "The UUID of the host this ceph mon belongs to"

    hostname = wtypes.text
    "The name of host this ceph mon belongs to."

    ceph_mon_dev = wtypes.text
    "The disk device on both controllers that cgts-vg will be extended " \
        "to create ceph-mon-lv."

    ceph_mon_gib = int
    "The ceph-mon-lv size in GiB, for Ceph backend only."

    state = wtypes.text
    "The state of the monitor. It can be configured or configuring."

    task = wtypes.text
    "Current task of the corresponding ceph monitor."

    links = [link.Link]
    "A list containing a self link and associated ceph_mon links"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):

        defaults = {'state': constants.SB_STATE_CONFIGURED,
                    'task': constants.SB_TASK_NONE}

        self.fields = list(objects.ceph_mon.fields.keys())

        for k in self.fields:
            setattr(self, k, kwargs.get(k, defaults.get(k)))

        if not self.uuid:
            self.uuid = uuidutils.generate_uuid()

    @classmethod
    def convert_with_links(cls, rpc_ceph_mon, expand=True):

        ceph_mon = CephMon(**rpc_ceph_mon.as_dict())
        if not expand:
            ceph_mon.unset_fields_except(['created_at',
                                          'updated_at',
                                          'ihost_uuid',
                                          'forihostid',
                                          'uuid',
                                          'device_path',
                                          'device_node',
                                          'ceph_mon_dev',
                                          'ceph_mon_gib',
                                          'state',
                                          'task',
                                          'hostname'])

        if ceph_mon.device_path:
            disks = pecan.request.dbapi.idisk_get_by_ihost(ceph_mon.forihostid)
            for disk in disks:
                if disk.device_path == ceph_mon.device_path:
                    ceph_mon.device_node = disk.device_node
                    break

        # never expose the isystem_id attribute
        ceph_mon.forihostid = wtypes.Unset

        ceph_mon.links = [link.Link.make_link('self',
                                              pecan.request.host_url,
                                              'ceph_mon',
                                              ceph_mon.uuid),
                          link.Link.make_link('bookmark',
                                              pecan.request.host_url,
                                              'ceph_mon',
                                              ceph_mon.uuid,
                                              bookmark=True)]
        return ceph_mon


def _check_ceph_mon_api_availability():
    """Check the permission of using ceph-mon-* commands
       according to the system's storage backend."""

    if not StorageBackendConfig.has_backend(
            pecan.request.dbapi, constants.SB_TYPE_CEPH):
        raise wsme.exc.ClientSideError(
            _("ceph-mon API commands are only allowed for use with '%s' "
              "as the storage backend." % (constants.SB_TYPE_CEPH)))


def _check_node_has_free_disk_space(host, ceph_mon_gib):
    """ Check node for ceph_mon free disk space.
        If check failed, raise error with msg.
    """
    cgtsvg_max_free_gib = utils.get_node_cgtsvg_limit(host)

    if cutils.is_aio_duplex_system(pecan.request.dbapi):
        LOG.debug("_check_node_has_free_disk_space This is aio-dx - "
            "calculate required space for host-fs ceph-lv too")
        ceph_mon_gib = 2 * ceph_mon_gib

    LOG.debug("_check_node_has_free_disk_space hostname: %s, ceph_mon_gib: %s, "
             "cgtsvg_max_free_gib: %s"
             % (host.hostname, ceph_mon_gib,
                cgtsvg_max_free_gib))

    if (ceph_mon_gib > cgtsvg_max_free_gib):
        msg = _(
            "Node '%s' does not have enough free space available in cgts-vg volume group "
            "to allocate ceph-mon data. %s GiB is required but %s GiB is available." %
            (host.hostname,
             ceph_mon_gib,
             cgtsvg_max_free_gib))
        raise wsme.exc.ClientSideError(msg)


def _check_ceph_mon_size(new_cephmon, old_cephmon=None):
    """ Check ceph-mon size boundaries and verify if there is enough disk space on the host
        If an old_cephmon is not set, consider this is a CREATE operation and
        if an old_cephmon is set, consider this is a RESIZE operation.
        If check fails, raise an exception with a message
    """
    if not cutils.is_int_like(new_cephmon['ceph_mon_gib']):
        raise wsme.exc.ClientSideError(
            _("ceph_mon_gib must be an integer."))

    new_ceph_mon_gib = int(new_cephmon['ceph_mon_gib'])
    if old_cephmon:
        old_ceph_mon_gib = int(old_cephmon['ceph_mon_gib'])
        lower_boundary = old_ceph_mon_gib + 1
    else:
        old_ceph_mon_gib = 0
        lower_boundary = constants.SB_CEPH_MON_GIB_MIN

    # Check boundaries
    if (new_ceph_mon_gib < lower_boundary
            or new_ceph_mon_gib > constants.SB_CEPH_MON_GIB_MAX):
        raise wsme.exc.ClientSideError(
            _("ceph_mon_gib = %s. Value must be between %s and %s."
              % (new_ceph_mon_gib, lower_boundary,
                 constants.SB_CEPH_MON_GIB_MAX)))

    # Verify if there is enough free space on cgts-vg for ceph-mon on selected host
    ihost = objects.host.get_by_uuid(pecan.request.context, new_cephmon['ihost_uuid'])
    size_needed = new_ceph_mon_gib - old_ceph_mon_gib
    _check_node_has_free_disk_space(ihost, size_needed)


class CephMonCollection(collection.Collection):
    """API representation of a collection of storage backends."""

    ceph_mon = [CephMon]
    "A list containing ceph monitors."

    def __init__(self, **kwargs):
        self._type = 'ceph_mon'

    @classmethod
    def convert_with_links(cls, rpc_ceph_mons, limit, url=None,
                           expand=False, **kwargs):
        collection = CephMonCollection()
        collection.ceph_mon = \
            [CephMon.convert_with_links(p, expand)
             for p in rpc_ceph_mons]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'CephMonController'


class CephMonController(rest.RestController):
    """REST controller for ceph monitors."""

    _custom_actions = {
        'detail': ['GET'],
        'summary': ['GET'],
        'ip_addresses': ['GET'],
    }

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts

    def _get_ceph_mon_collection(self, ihost_uuid, marker, limit,
                                 sort_key, sort_dir, expand=False,
                                 resource_url=None):

        if self._from_ihosts and not ihost_uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.ceph_mon.get_by_uuid(
                pecan.request.context,
                marker)

        if ihost_uuid:
            ceph_mon = pecan.request.dbapi.ceph_mon_get_by_ihost(
                ihost_uuid,
                limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        else:
            ceph_mon = pecan.request.dbapi.ceph_mon_get_list(
                limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)

        return CephMonCollection \
            .convert_with_links(ceph_mon,
                                limit,
                                url=resource_url,
                                expand=expand,
                                sort_key=sort_key,
                                sort_dir=sort_dir)

    @wsme_pecan.wsexpose(CephMonCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, host_uuid=None, marker=None, limit=None, sort_key='id',
                sort_dir='asc'):
        """Retrieve a list of ceph mons."""

        return self._get_ceph_mon_collection(host_uuid, marker, limit,
                                             sort_key, sort_dir)

    @wsme_pecan.wsexpose(CephMon, types.uuid)
    def get_one(self, ceph_mon_uuid):
        """Retrieve information about the given ceph mon."""
        rpc_ceph_mon = objects.ceph_mon.get_by_uuid(pecan.request.context,
                                                    ceph_mon_uuid)
        return CephMon.convert_with_links(rpc_ceph_mon)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(CephMonCollection, body=CephMon)
    def post(self, cephmon):
        """Create list of new ceph mons."""

        # Check whether the use of ceph-mon API for creation is allowed.
        _check_ceph_mon_api_availability()

        try:
            cephmon = cephmon.as_dict()
            new_ceph_mons = _create(cephmon)

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create "
                                             "a ceph mon record."))
        return CephMonCollection.convert_with_links(new_ceph_mons, limit=None,
                                                    url=None, expand=False,
                                                    sort_key='id',
                                                    sort_dir='asc')

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [CephMonPatchType])
    @wsme_pecan.wsexpose(CephMon, types.uuid,
                         body=[CephMonPatchType])
    def patch(self, cephmon_uuid, patch):
        """Update the current storage configuration."""

        if not StorageBackendConfig.has_backend_configured(
            pecan.request.dbapi,
            constants.CINDER_BACKEND_CEPH
        ):
            raise wsme.exc.ClientSideError(
                _("Ceph backend is not configured.")
            )

        rpc_cephmon = objects.ceph_mon.get_by_uuid(pecan.request.context,
                                                   cephmon_uuid)

        is_aio_dx = cutils.is_aio_duplex_system(pecan.request.dbapi)

        is_ceph_mon_gib_changed = False

        patch = [p for p in patch if '/controller' not in p['path']]

        # Check if either ceph mon size or disk has to change.
        for p in patch:
            if '/ceph_mon_gib' in p['path']:
                if rpc_cephmon.ceph_mon_gib != p['value']:
                    is_ceph_mon_gib_changed = True

        if not is_ceph_mon_gib_changed:
            LOG.info("ceph_mon parameters are not changed")
            raise wsme.exc.ClientSideError(
                _("Warning: ceph_mon parameters are not changed."))

        # replace isystem_uuid and ceph_mon_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        state_rel_path = ['/uuid', '/id', '/forihostid',
                          '/device_node', '/device_path']
        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(_("The following fields can not be "
                                             "modified: %s" %
                                             state_rel_path))

        try:
            cephmon = CephMon(**jsonpatch.apply_patch(
                rpc_cephmon.as_dict(),
                patch_obj))
        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        if is_ceph_mon_gib_changed:
            _check_ceph_mon_size(cephmon.as_dict(), rpc_cephmon.as_dict())
            utils.check_all_ceph_mon_growth(cephmon.ceph_mon_gib)

        for field in objects.ceph_mon.fields:
            if rpc_cephmon[field] != cephmon.as_dict()[field]:
                rpc_cephmon[field] = cephmon.as_dict()[field]

        LOG.info("SYS_I  cephmon: %s " % cephmon.as_dict())

        # if this is an AIO-DX, must update host-fs ceph to the same size to support
        # the three ceph monitors solution
        rpc_hostfs_list = []
        if is_aio_dx:
            LOG.info("This is an AIO-DX. Update ceph host-fs with the new ceph-mon size.")
            host_fs_list = pecan.request.dbapi.host_fs_get_by_ihost(ihost=cephmon.forihostid)
            for fs in host_fs_list:
                if fs['name'] == constants.FILESYSTEM_NAME_CEPH:
                    hostfs_uuid = fs['uuid']
                    hostfs = objects.host_fs.get_by_uuid(pecan.request.context, hostfs_uuid)
                    hostfs['size'] = rpc_cephmon.ceph_mon_gib
                    rpc_hostfs_list.append(hostfs)

        try:
            rpc_cephmon.save()
            # Apply host-fs ceph changes too if this is an AIO-DX
            if is_aio_dx:
                for rpc_hostfs in rpc_hostfs_list:
                    rpc_hostfs.save()
        except exception.HTTPNotFound:
            msg = _("Ceph Mon update failed: uuid %s : "
                    " patch %s"
                    % (rpc_cephmon.uuid, patch))
            raise wsme.exc.ClientSideError(msg)

        if is_ceph_mon_gib_changed:
            # Update the task for ceph storage backend.
            StorageBackendConfig.update_backend_states(
                pecan.request.dbapi,
                constants.CINDER_BACKEND_CEPH,
                task=constants.SB_TASK_RESIZE_CEPH_MON_LV
            )

            # Mark controllers and storage node as Config out-of-date.
            pecan.request.rpcapi.update_storage_config(
                pecan.request.context,
                update_storage=is_ceph_mon_gib_changed,
                reinstall_required=False
            )

        return CephMon.convert_with_links(rpc_cephmon)

    @wsme_pecan.wsexpose(wtypes.text)
    def ip_addresses(self):
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "ceph_mon":
            raise exception.HTTPNotFound
        _, ceph_mon_ip_addresses = StorageBackendConfig.get_ceph_mon_ip_addresses(
            pecan.request.dbapi)
        return ceph_mon_ip_addresses

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, six.text_type, status_code=204)
    def delete(self, host_uuid):
        """Delete a ceph_mon."""

        _delete(host_uuid)


def _set_defaults(ceph_mon):
    defaults = {
        'uuid': None,
        'ceph_mon_gib': constants.SB_CEPH_MON_GIB,
        'ceph_mon_dev': None,
        'state': constants.SB_STATE_CONFIGURED,
        'task': constants.SB_TASK_NONE,
    }

    storage_ceph_merged = ceph_mon.copy()
    for key in storage_ceph_merged:
        if storage_ceph_merged[key] is None and key in defaults:
            storage_ceph_merged[key] = defaults[key]

    for key in defaults:
        if key not in storage_ceph_merged:
            storage_ceph_merged[key] = defaults[key]

    return storage_ceph_merged


def _create(ceph_mon):
    # validate host
    try:
        chost = pecan.request.dbapi.ihost_get(ceph_mon['ihost_uuid'])
    except exception.ServerNotFound:
        raise wsme.exc.ClientSideError(
            _("Host not found uuid: %s ." % ceph_mon['ihost_uuid']))

    ceph_mon['forihostid'] = chost['id']
    ceph_mon['hostname'] = chost['hostname']
    ceph_mon['device_path'] = chost['rootfs_device']

    # check if ceph monitor is already configured
    if pecan.request.dbapi.ceph_mon_get_by_ihost(ceph_mon['forihostid']):
        raise wsme.exc.ClientSideError(
            _("Ceph monitor already configured for host '%s'." % chost['hostname']))

    # only one instance of the 3rd ceph monitor is allowed
    ceph_mons = pecan.request.dbapi.ceph_mon_get_list()
    for mon in ceph_mons:
        h = pecan.request.dbapi.ihost_get(mon['forihostid'])
        if h.personality in [constants.STORAGE, constants.WORKER]:
            raise wsme.exc.ClientSideError(
                _("Ceph monitor already configured for host '%s'." % h['hostname']))

    # Adding a ceph monitor to a worker selects Ceph's deployment model
    if chost['personality'] == constants.WORKER:
        # Only if replication model is CONTROLLER or not yet defined
        is_aio = cutils.is_aio_system(pecan.request.dbapi)
        stor_model = ceph.get_ceph_storage_model()
        worker_stor_models = [constants.CEPH_CONTROLLER_MODEL, constants.CEPH_UNDEFINED_MODEL]
        if stor_model not in worker_stor_models or is_aio:
            raise wsme.exc.ClientSideError(
                _("Can not add a storage monitor to a worker if "
                  "ceph's deployments model is already set to %s or system is All-in-one."
                  % stor_model))

        replication, min_replication = \
            StorageBackendConfig.get_ceph_max_replication(pecan.request.dbapi)
        supported_replication = constants.CEPH_CONTROLLER_MODEL_REPLICATION_SUPPORTED
        if replication not in supported_replication:
            raise wsme.exc.ClientSideError(
                _("Ceph monitor can be added to a worker only if "
                  "replication is set to: %s'. Please update replication "
                  "before configuring a monitor on a worker node." % supported_replication))

    # only accept a 3rd ceph monitor if this is storage-0 or any other worker
    if chost['personality'] == constants.STORAGE and chost['hostname'] != constants.STORAGE_0_HOSTNAME:
        raise wsme.exc.ClientSideError(
            _("Ceph monitor can only be added to storage-0 or any worker."))

    ceph_mon = _set_defaults(ceph_mon)

    # Size of ceph-mon logical volume must be the same for all
    # monitors so we get the size from any or use default.
    ceph_mons = pecan.request.dbapi.ceph_mon_get_list()
    if ceph_mons:
        ceph_mon['ceph_mon_gib'] = ceph_mons[0]['ceph_mon_gib']

    _check_ceph_mon_size(ceph_mon)

    pecan.request.rpcapi.reserve_ip_for_third_monitor_node(
        pecan.request.context, chost.hostname)

    # In case we add the monitor on a worker node, the state
    # and task must be set properly.
    if chost.personality == constants.WORKER:
        if (chost.administrative == constants.ADMIN_UNLOCKED and
                chost.operational == constants.OPERATIONAL_ENABLED):
            ceph_mon['state'] = constants.SB_STATE_CONFIGURING
        elif (chost.administrative == constants.ADMIN_LOCKED and
                chost.availability == constants.AVAILABILITY_ONLINE):
            ceph_mon['state'] = constants.SB_STATE_CONFIGURING_ON_UNLOCK

        task = {ceph_mon['hostname']: ceph_mon['state']}
        ceph_mon['task'] = str(task)

    LOG.info("Creating ceph-mon DB entry for host uuid %s: %s" %
             (ceph_mon['ihost_uuid'], str(ceph_mon)))
    new_ceph_mon = pecan.request.dbapi.ceph_mon_create(ceph_mon)

    # We update the base config when adding a dynamic monitor.
    # At this moment the only possibility to add a dynamic monitor
    # is on a worker node, so we check for that.
    if (chost.personality == constants.WORKER and
            new_ceph_mon['state'] == constants.SB_STATE_CONFIGURING):
        try:
            # Storage nodes are not supported on a controller based
            # storage model.
            personalities = [constants.WORKER]
            pecan.request.rpcapi.update_ceph_base_config(
                pecan.request.context,
                personalities)
        except Exception:
            values = {'state': constants.SB_STATE_CONFIG_ERR, 'task': None}
            pecan.request.dbapi.ceph_mon_update(new_ceph_mon['uuid'], values)
            raise

    # The return value needs to be iterable, so make it a list.
    return [new_ceph_mon]


def _delete(host_uuid):
    ceph_mon = pecan.request.dbapi.ceph_mon_get_by_ihost(host_uuid)
    if ceph_mon:
        ceph_mon = ceph_mon[0]
    else:
        raise wsme.exc.ClientSideError(
            _("No Ceph Monitor defined for host with uuid: %s" % host_uuid))

    if ceph_mon.state == constants.SB_STATE_CONFIG_ERR:
        try:
            pecan.request.dbapi.ceph_mon_destroy(ceph_mon.uuid)
        except exception.HTTPNotFound:
            raise wsme.exc.ClientSideError("Deleting Ceph Monitor failed!")
    else:
        raise wsme.exc.ClientSideError(
            _("Direct Ceph monitor delete only allowed for state '%s'. "
              "Please lock and delete node to remove the configured Ceph Monitor."
              % constants.SB_STATE_CONFIG_ERR))
