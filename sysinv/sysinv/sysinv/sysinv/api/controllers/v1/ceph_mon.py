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
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#

import jsonpatch

import pecan
from pecan import rest

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import controller_fs as controller_fs_utils
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common import uuidutils
from sysinv.openstack.common.gettextutils import _

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

    hostname = wtypes.text
    "The name of host this ceph mon belongs to."

    ceph_mon_dev = wtypes.text
    "The disk device on both controllers that cgts-vg will be extended " \
        "to create ceph-mon-lv."

    ceph_mon_gib = int
    "The ceph-mon-lv size in GiB, for Ceph backend only."

    ceph_mon_dev_ctrl0 = wtypes.text
    "The disk device on controller-0 that cgts-vg will be extended " \
        "to create ceph-mon-lv"

    ceph_mon_dev_ctrl1 = wtypes.text
    "The disk device on controller-1 that cgts-vg will be extended " \
        "to create ceph-mon-lv"

    links = [link.Link]
    "A list containing a self link and associated ceph_mon links"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = objects.ceph_mon.fields.keys()

        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        if not self.uuid:
            self.uuid = uuidutils.generate_uuid()

        self.fields.append('ceph_mon_dev')
        setattr(self, 'ceph_mon_dev', kwargs.get('ceph_mon_dev', None))

        self.fields.append('ceph_mon_dev_ctrl0')
        setattr(self, 'ceph_mon_dev_ctrl0',
                kwargs.get('ceph_mon_dev_ctrl0', None))

        self.fields.append('ceph_mon_dev_ctrl1')
        setattr(self, 'ceph_mon_dev_ctrl1',
                kwargs.get('ceph_mon_dev_ctrl1', None))

        self.fields.append('device_node')
        setattr(self, 'device_node', kwargs.get('device_node', None))

    @classmethod
    def convert_with_links(cls, rpc_ceph_mon, expand=True):

        ceph_mon = CephMon(**rpc_ceph_mon.as_dict())
        if not expand:
            ceph_mon.unset_fields_except(['created_at',
                                          'updated_at',
                                          'forihostid',
                                          'uuid',
                                          'device_path',
                                          'device_node',
                                          'ceph_mon_dev',
                                          'ceph_mon_gib',
                                          'ceph_mon_dev_ctrl0',
                                          'ceph_mon_dev_ctrl1',
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


def _check_ceph_mon(new_cephmon, old_cephmon=None):

    if not cutils.is_int_like(new_cephmon['ceph_mon_gib']):
        raise wsme.exc.ClientSideError(
            _("ceph_mon_gib must be an integer."))

    new_ceph_mon_gib = int(new_cephmon['ceph_mon_gib'])
    if old_cephmon:
        old_ceph_mon_gib = int(old_cephmon['ceph_mon_gib']) + 1
    else:
        old_ceph_mon_gib = constants.SB_CEPH_MON_GIB_MIN

    if new_ceph_mon_gib < old_ceph_mon_gib \
            or new_ceph_mon_gib > constants.SB_CEPH_MON_GIB_MAX:
        raise wsme.exc.ClientSideError(
            _("ceph_mon_gib = %s. Value must be between %s and %s."
              % (new_ceph_mon_gib, old_ceph_mon_gib,
                 constants.SB_CEPH_MON_GIB_MAX)))


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
            _check_ceph_mon(cephmon.as_dict(), rpc_cephmon.as_dict())
            controller_fs_utils._check_controller_fs(
                ceph_mon_gib_new=cephmon.ceph_mon_gib)

        for field in objects.ceph_mon.fields:
            if rpc_cephmon[field] != cephmon.as_dict()[field]:
                rpc_cephmon[field] = cephmon.as_dict()[field]

        LOG.info("SYS_I  cephmon: %s " % cephmon.as_dict())

        try:
            rpc_cephmon.save()
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
        return StorageBackendConfig.get_ceph_mon_ip_addresses(
            pecan.request.dbapi)


def _set_defaults(ceph_mon):
    defaults = {
        'ceph_mon_gib': constants.SB_CEPH_MON_GIB,
        'ceph_mon_dev': None,
        'ceph_mon_dev_ctrl0': None,
        'ceph_mon_dev_ctrl1': None,
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
    ceph_mon = _set_defaults(ceph_mon)

    _check_ceph_mon(ceph_mon)

    controller_fs_utils._check_controller_fs(
        ceph_mon_gib_new=ceph_mon['ceph_mon_gib'])

    pecan.request.rpcapi.reserve_ip_for_first_storage_node(
        pecan.request.context)

    new_ceph_mons = list()
    chosts = pecan.request.dbapi.ihost_get_by_personality(constants.CONTROLLER)
    for chost in chosts:
        # Check if mon exists
        ceph_mons = pecan.request.dbapi.ceph_mon_get_by_ihost(chost.uuid)
        if ceph_mons:
                pecan.request.dbapi.ceph_mon_update(
                    ceph_mons[0].uuid, {'ceph_mon_gib': ceph_mon['ceph_mon_gib']}
                )
                new_ceph_mons.append(ceph_mons[0])
        else:
            ceph_mon_new = dict()
            ceph_mon_new['uuid'] = None
            ceph_mon_new['forihostid'] = chost.id
            ceph_mon_new['ceph_mon_gib'] = ceph_mon['ceph_mon_gib']

            LOG.info("creating ceph_mon_new for %s: %s" %
                     (chost.hostname, str(ceph_mon_new)))
            new_ceph_mons.append(pecan.request.dbapi.ceph_mon_create(ceph_mon_new))

    return new_ceph_mons
