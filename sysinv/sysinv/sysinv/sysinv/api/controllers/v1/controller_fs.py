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
# Copyright (c) 2013-2020 Wind River Systems, Inc.
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


class ControllerFsPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class ControllerFs(base.APIBase):
    """API representation of a controller_fs.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a ControllerFs.

    """

    uuid = types.uuid
    "Unique UUID for this controller_fs"

    name = wsme.wsattr(wtypes.text, mandatory=True)

    size = int

    logical_volume = wsme.wsattr(wtypes.text)

    replicated = bool

    state = wtypes.text
    "The state of controller_fs indicates a drbd file system resize operation"

    forisystemid = int
    "The isystemid that this controller_fs belongs to"

    isystem_uuid = types.uuid
    "The UUID of the system this controller_fs belongs to"

    action = wtypes.text
    "Represent the action on the controller_fs"

    links = [link.Link]
    "A list containing a self link and associated controller_fs links"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = list(objects.controller_fs.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # API-only attribute)
        self.fields.append('action')
        setattr(self, 'action', kwargs.get('action', None))

    @classmethod
    def convert_with_links(cls, rpc_controller_fs, expand=True):
        controller_fs = ControllerFs(**rpc_controller_fs.as_dict())
        if not expand:
            controller_fs.unset_fields_except(['created_at',
                                               'updated_at',
                                               'uuid',
                                               'name',
                                               'size',
                                               'logical_volume',
                                               'replicated',
                                               'state',
                                               'isystem_uuid'])

        # never expose the isystem_id attribute
        controller_fs.isystem_id = wtypes.Unset

        # never expose the isystem_id attribute, allow exposure for now
        # controller_fs.forisystemid = wtypes.Unset
        controller_fs.links = [
            link.Link.make_link('self', pecan.request.host_url,
                                'controller_fs', controller_fs.uuid),
            link.Link.make_link('bookmark', pecan.request.host_url,
                                'controller_fs', controller_fs.uuid,
                                bookmark=True)
        ]
        return controller_fs


class ControllerFsCollection(collection.Collection):
    """API representation of a collection of ControllerFs."""

    controller_fs = [ControllerFs]
    "A list containing ControllerFs objects"

    def __init__(self, **kwargs):
        self._type = 'controller_fs'

    @classmethod
    def convert_with_links(cls, rpc_controller_fs, limit, url=None,
                           expand=False, **kwargs):
        collection = ControllerFsCollection()
        collection.controller_fs = [ControllerFs.convert_with_links(p, expand)
                                    for p in rpc_controller_fs]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


def _total_size_controller_multi_fs(controller_fs_new_list):
    """This function is called to verify file system capability on
    controller with primary (initial) storage backend already configured
    calling from initial config (config_controller stage) will result in
    failure
    """
    total_size = 0
    for fs in controller_fs_new_list:
        if fs.name == constants.FILESYSTEM_NAME_DATABASE:
            total_size += (2 * fs.size)
        else:
            total_size += fs.size
    return total_size


def _total_size_controller_fs(controller_fs_new, controller_fs_list):
    """This function is called to verify file system capability on
    controller with primary (initial) storage backend already configured
    calling from initial config (config_controller stage) will result in
    failure
    """
    total_size = 0

    for fs in controller_fs_list:
        size = fs['size']
        if controller_fs_new and fs['name'] == controller_fs_new['name']:
            size = controller_fs_new['size']
        if fs['name'] == "database":
            size = size * 2
        total_size += size

    LOG.info(
        "_total_size_controller_fs total filesysem size %s" % total_size)
    return total_size


def _check_relative_controller_multi_fs(controller_fs_new_list):
    """
    This function verifies the relative controller_fs sizes.
    :param controller_fs_new_list:
    :return: None.  Raise Client exception on failure.
    """

    chosts = pecan.request.dbapi.ihost_get_by_personality(constants.CONTROLLER)

    for chost in chosts:

        # Get the current backup size for the controller host
        backup_gib = 0
        backup_gib_min = constants.BACKUP_OVERHEAD

        hostfs_list = pecan.request.dbapi.host_fs_get_by_ihost(chost.uuid)
        for host_fs in hostfs_list:
            if host_fs['name'] == constants.FILESYSTEM_NAME_BACKUP:
                backup_gib = host_fs['size']
                break

        for fs in controller_fs_new_list:
            if fs.name == constants.FILESYSTEM_NAME_DATABASE:
                database_gib = fs.size
                backup_gib_min += fs.size
            elif fs.name == constants.FILESYSTEM_NAME_PLATFORM:
                platform_gib = fs.size
                backup_gib_min += fs.size

        LOG.info(
            "_check_relative_controller_multi_fs min backup size %s" % backup_gib_min)

        if backup_gib < backup_gib_min:
            raise wsme.exc.ClientSideError(_("backup size of %d is "
                                             "insufficient for host %s. "
                                             "Minimum backup size of %d is "
                                             "required based upon platform size %d "
                                             "and database size %d. "
                                             "Rejecting modification "
                                             "request." %
                                             (backup_gib,
                                              chost.hostname,
                                              backup_gib_min,
                                              platform_gib,
                                              database_gib
                                              )))


def _check_controller_multi_fs(controller_fs_new_list,
                               ceph_mon_gib_new=None,
                               cgtsvg_growth_gib=None):

    ceph_mons = pecan.request.dbapi.ceph_mon_get_list()

    if not ceph_mon_gib_new:
        if ceph_mons:
            ceph_mon_gib_new = ceph_mons[0].ceph_mon_gib
        else:
            ceph_mon_gib_new = 0

    LOG.info("_check_controller__multi_fs ceph_mon_gib_new = %s" % ceph_mon_gib_new)

    cgtsvg_max_free_GiB = _get_controller_cgtsvg_limit()

    LOG.info("_check_controller_multi_fs cgtsvg_max_free_GiB = %s " %
             cgtsvg_max_free_GiB)

    _check_relative_controller_multi_fs(controller_fs_new_list)

    LOG.info("_check_controller_multi_fs ceph_mon_gib_new = %s" % ceph_mon_gib_new)

    rootfs_configured_size_GiB = \
        _total_size_controller_multi_fs(controller_fs_new_list) + ceph_mon_gib_new

    LOG.info("_check_controller_multi_fs rootfs_configured_size_GiB = %s" %
             rootfs_configured_size_GiB)

    if cgtsvg_growth_gib and (cgtsvg_growth_gib > cgtsvg_max_free_GiB):
        msg = _("Total target growth size %s GiB "
                "exceeds growth limit of %s GiB." %
                (cgtsvg_growth_gib, cgtsvg_max_free_GiB))
        raise wsme.exc.ClientSideError(msg)


def _check_relative_controller_fs(controller_fs_new, controller_fs_list):
    """
    This function verifies the relative controller_fs sizes.
    :param controller_fs_new:
    :param controller_fs_list:
    :return: None.  Raise Client exception on failure.
    """

    database_gib = 0
    platform_gib = 0

    chosts = pecan.request.dbapi.ihost_get_by_personality(
        constants.CONTROLLER)

    for chost in chosts:
        # Get the current backup size for the controller host
        backup_gib = 0
        hostfs_list = pecan.request.dbapi.host_fs_get_by_ihost(chost.uuid)
        for fs in hostfs_list:
            if fs['name'] == constants.FILESYSTEM_NAME_BACKUP:
                backup_gib = fs['size']
                break

        for fs in controller_fs_list:
            if controller_fs_new and fs['name'] == controller_fs_new['name']:
                fs['size'] = controller_fs_new['size']

            if fs['name'] == constants.FILESYSTEM_NAME_PLATFORM:
                platform_gib = fs['size']
            elif fs['name'] == constants.FILESYSTEM_NAME_DATABASE:
                database_gib = fs['size']

        if backup_gib == 0:
            LOG.info(
                "_check_relative_controller_fs backup filesystem not yet setup")
            return

        # Required mininum backup filesystem size
        backup_gib_min = platform_gib + database_gib + constants.BACKUP_OVERHEAD

        if backup_gib < backup_gib_min:
            raise wsme.exc.ClientSideError(_("backup size of %d is "
                                             "insufficient for host %s. "
                                             "Minimum backup size of %d is "
                                             "required based on upon "
                                             "platform=%d and database=%d and "
                                             "backup overhead of %d. "
                                             "Rejecting modification "
                                             "request." %
                                             (backup_gib,
                                              chost.hostname,
                                              backup_gib_min,
                                              platform_gib,
                                              database_gib,
                                              constants.BACKUP_OVERHEAD
                                              )))


def _check_controller_state():
    """
    This function verifies the administrative, operational, availability of
    each controller.
    """
    chosts = pecan.request.dbapi.ihost_get_by_personality(
        constants.CONTROLLER)

    for chost in chosts:
        utils.is_host_state_valid_for_fs_resize(chost)

    return True


def _get_controller_cgtsvg_limit():
    """Calculate space for controller fs
       returns: cgtsvg_max_free_GiB

    """
    cgtsvg0_free_mib = 0
    cgtsvg1_free_mib = 0
    cgtsvg_max_free_GiB = 0

    chosts = pecan.request.dbapi.ihost_get_by_personality(
        constants.CONTROLLER)
    for chost in chosts:
        if chost.hostname == constants.CONTROLLER_0_HOSTNAME:
            ipvs = pecan.request.dbapi.ipv_get_by_ihost(chost.uuid)
            for ipv in ipvs:
                if (ipv.lvm_vg_name == constants.LVG_CGTS_VG and
                        ipv.pv_state != constants.PROVISIONED):
                    msg = _("Cannot resize filesystem. There are still "
                            "unprovisioned physical volumes on controller-0.")
                    raise wsme.exc.ClientSideError(msg)

            ilvgs = pecan.request.dbapi.ilvg_get_by_ihost(chost.uuid)
            for ilvg in ilvgs:
                if (ilvg.lvm_vg_name == constants.LVG_CGTS_VG and
                   ilvg.lvm_vg_size and ilvg.lvm_vg_total_pe):
                    cgtsvg0_free_mib = (int(ilvg.lvm_vg_size) *
                                        int(ilvg.lvm_vg_free_pe) // int(
                        ilvg.lvm_vg_total_pe)) // (1024 * 1024)
                    break

        else:
            ipvs = pecan.request.dbapi.ipv_get_by_ihost(chost.uuid)
            for ipv in ipvs:
                if (ipv.lvm_vg_name == constants.LVG_CGTS_VG and
                        ipv.pv_state != constants.PROVISIONED):
                    msg = _("Cannot resize filesystem. There are still "
                            "unprovisioned physical volumes on controller-1.")
                    raise wsme.exc.ClientSideError(msg)

            ilvgs = pecan.request.dbapi.ilvg_get_by_ihost(chost.uuid)
            for ilvg in ilvgs:
                if (ilvg.lvm_vg_name == constants.LVG_CGTS_VG and
                   ilvg.lvm_vg_size and ilvg.lvm_vg_total_pe):
                    cgtsvg1_free_mib = (int(ilvg.lvm_vg_size) *
                                        int(ilvg.lvm_vg_free_pe) // int(
                        ilvg.lvm_vg_total_pe)) // (1024 * 1024)
                    break

    LOG.info("_get_controller_cgtsvg_limit cgtsvg0_free_mib=%s, "
             "cgtsvg1_free_mib=%s" % (cgtsvg0_free_mib, cgtsvg1_free_mib))

    if cgtsvg0_free_mib > 0 and cgtsvg1_free_mib > 0:
        cgtsvg_max_free_GiB = min(cgtsvg0_free_mib, cgtsvg1_free_mib) // 1024
        LOG.info("min of cgtsvg0_free_mib=%s and cgtsvg1_free_mib=%s is "
                 "cgtsvg_max_free_GiB=%s" %
                 (cgtsvg0_free_mib, cgtsvg1_free_mib, cgtsvg_max_free_GiB))
    elif cgtsvg1_free_mib > 0:
        cgtsvg_max_free_GiB = cgtsvg1_free_mib // 1024
    else:
        cgtsvg_max_free_GiB = cgtsvg0_free_mib // 1024

    LOG.info("SYS_I filesystem limits cgtsvg0_free_mib=%s, "
             "cgtsvg1_free_mib=%s, cgtsvg_max_free_GiB=%s"
             % (cgtsvg0_free_mib, cgtsvg1_free_mib, cgtsvg_max_free_GiB))

    return cgtsvg_max_free_GiB


def _check_ceph_mon_growth(ceph_mon_gib):
    """ Check growth of ceph_mon in controller.
        There is additional items to check for controller_fs compared with
        check_node_ceph_mon_growth().
    """
    controller_fs_list = pecan.request.dbapi.controller_fs_get_list()

    cgtsvg_max_free_GiB = _get_controller_cgtsvg_limit()

    LOG.info("_check_ceph_mon_growth ceph_mon_gib = %s, "
        "cgtsvg_max_free_GiB = %s" % (ceph_mon_gib, cgtsvg_max_free_GiB))

    _check_relative_controller_fs(None, controller_fs_list)

    rootfs_configured_size_GiB = \
        _total_size_controller_fs(None, controller_fs_list) + ceph_mon_gib
    LOG.info("_check_ceph_mon_growth rootfs_configured_size_GiB = %s" %
             rootfs_configured_size_GiB)

    utils.check_node_ceph_mon_growth(None, ceph_mon_gib, cgtsvg_max_free_GiB)


def _check_controller_multi_fs_data(context, controller_fs_list_new):
    """ Check controller filesystem data and return growth
        returns: cgtsvg_growth_gib
    """

    cgtsvg_growth_gib = 0

    lvdisplay_keys = [constants.FILESYSTEM_LV_DICT[constants.FILESYSTEM_NAME_DATABASE],
                      constants.FILESYSTEM_LV_DICT[constants.FILESYSTEM_NAME_PLATFORM]]

    lvdisplay_dict = pecan.request.rpcapi.get_controllerfs_lv_sizes(context)

    for key in lvdisplay_keys:
        if not lvdisplay_dict.get(key, None):
            raise wsme.exc.ClientSideError(_("Unable to determine the "
                                             "current size of %s. "
                                             "Rejecting modification "
                                             "request." % key))

    for fs in controller_fs_list_new:
        lv = fs.logical_volume
        if lvdisplay_dict.get(lv, None):
            orig = int(float(lvdisplay_dict[lv]))
            new = int(fs.size)
            if fs.name == constants.FILESYSTEM_NAME_DATABASE:
                orig = orig // 2

            if orig > new:
                raise wsme.exc.ClientSideError(_("'%s'  must be at least: "
                                                 "%s" % (fs.name, orig)))
            if fs.name == constants.FILESYSTEM_NAME_DATABASE:
                cgtsvg_growth_gib += 2 * (new - orig)
            else:
                cgtsvg_growth_gib += (new - orig)

    LOG.info("_check_controller_multi_fs_data cgtsvg_growth_gib=%s" %
             cgtsvg_growth_gib)

    return cgtsvg_growth_gib


LOCK_NAME = 'FsController'


class ControllerFsController(rest.RestController):
    """REST controller for ControllerFs."""

    _custom_actions = {
        'detail': ['GET'],
        'update_many': ['PUT'],
    }

    def __init__(self, from_isystems=False):
        self._from_isystems = from_isystems

    def _get_controller_fs_collection(self, isystem_uuid, marker, limit,
                                      sort_key, sort_dir, expand=False,
                                      resource_url=None):

        if self._from_isystems and not isystem_uuid:
            raise exception.InvalidParameterValue(_(
                "System id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.controller_fs.get_by_uuid(
                pecan.request.context, marker)
        if isystem_uuid:
            controller_fs = pecan.request.dbapi.controller_fs_get_by_isystem(
                isystem_uuid, limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        else:
            controller_fs = \
                pecan.request.dbapi.controller_fs_get_list(limit, marker_obj,
                                                           sort_key=sort_key,
                                                           sort_dir=sort_dir)

        return ControllerFsCollection.convert_with_links(controller_fs, limit,
                                                         url=resource_url,
                                                         expand=expand,
                                                         sort_key=sort_key,
                                                         sort_dir=sort_dir)

    @wsme_pecan.wsexpose(ControllerFsCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, isystem_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of controller_fs."""

        return self._get_controller_fs_collection(isystem_uuid, marker, limit,
                                                  sort_key, sort_dir)

    @wsme_pecan.wsexpose(ControllerFsCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, isystem_uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of controller_fs with detail."""

        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "controller_fs":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['controller_fs', 'detail'])
        return self._get_controller_fs_collection(isystem_uuid, marker, limit,
                                                  sort_key, sort_dir,
                                                  expand, resource_url)

    @wsme_pecan.wsexpose(ControllerFs, types.uuid)
    def get_one(self, controller_fs_uuid):
        """Retrieve information about the given controller_fs."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_controller_fs = \
            objects.controller_fs.get_by_uuid(pecan.request.context,
                                              controller_fs_uuid)
        return ControllerFs.convert_with_links(rpc_controller_fs)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [ControllerFsPatchType])
    @wsme_pecan.wsexpose(ControllerFs, types.uuid,
                         body=[ControllerFsPatchType])
    def patch(self, controller_fs_uuid, patch):
        """Update the current controller_fs configuration."""
        raise exception.OperationNotPermitted

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [ControllerFsPatchType])
    @wsme_pecan.wsexpose(None, types.uuid, body=[[ControllerFsPatchType]])
    def update_many(self, isystem_uuid, patch):
        """Update the current controller_fs configuration."""

        if self._from_isystems and not isystem_uuid:
            raise exception.InvalidParameterValue(_(
                "System id not specified."))

        # Validate if there are pending updates on the controllers lvg
        controller_hosts = pecan.request.dbapi.ihost_get_by_personality(
            constants.CONTROLLER
        )

        controllers_lvg_updated = True
        for host in controller_hosts:
            host_fs_list = pecan.request.dbapi.host_fs_get_by_ihost(host.uuid)
            host_lvg_list = pecan.request.dbapi.ilvg_get_by_ihost(host.uuid)
            controllers_lvg_updated = controllers_lvg_updated and \
                utils.is_host_lvg_updated(host_fs_list, host_lvg_list)

        # Validate input filesystem names
        controller_fs_list = pecan.request.dbapi.controller_fs_get_list()
        valid_fs_list = []
        if controller_fs_list:
            valid_fs_list = {fs.name: fs.size for fs in controller_fs_list}

        reinstall_required = False
        reboot_required = False
        modified_fs = []
        update_fs_list = []
        for p_list in patch:
            p_obj_list = jsonpatch.JsonPatch(p_list)
            for p_obj in p_obj_list:
                if p_obj['path'] == '/name':
                    fs_name = p_obj['value']
                    if fs_name in update_fs_list:
                        msg = _("Duplicate fs_name "
                                "'%s' in parameter list" % fs_name)
                        raise wsme.exc.ClientSideError(msg)
                    else:
                        update_fs_list.append(fs_name)
                elif p_obj['path'] == '/size':
                    size = p_obj['value']

            if fs_name not in valid_fs_list.keys():
                msg = _("ControllerFs update failed: invalid filesystem "
                        "'%s' " % fs_name)
                raise wsme.exc.ClientSideError(msg)
            elif not cutils.is_int_like(size):
                msg = _("ControllerFs update failed: filesystem '%s' "
                        "size must be an integer " % fs_name)
                raise wsme.exc.ClientSideError(msg)
            elif int(size) <= int(valid_fs_list[fs_name]):
                msg = _("ControllerFs update failed: size for filesystem '%s' "
                        "should be bigger than %s " % (fs_name, valid_fs_list[fs_name]))
                raise wsme.exc.ClientSideError(msg)
            elif not controllers_lvg_updated:
                msg = _("ControllerFs update failed: controllers have pending LVG "
                        "updates, please retry again later.")
                raise wsme.exc.ClientSideError(msg)

            if fs_name in constants.SUPPORTED_REPLICATED_FILEYSTEM_LIST:
                if utils.is_drbd_fs_resizing():
                    raise wsme.exc.ClientSideError(
                        _("A drbd sync operation is currently in progress. "
                          "Retry again later.")
                    )

            modified_fs += [fs_name]

        controller_fs_list_new = []
        for fs in controller_fs_list:
            replaced = False
            for p_list in patch:
                p_obj_list = jsonpatch.JsonPatch(p_list)
                for p_obj in p_obj_list:
                    if p_obj['value'] == fs['name']:
                        try:
                            controller_fs_list_new += [ControllerFs(
                                      **jsonpatch.apply_patch(fs.as_dict(), p_obj_list))]
                            replaced = True
                            break
                        except utils.JSONPATCH_EXCEPTIONS as e:
                            raise exception.PatchError(patch=p_list, reason=e)
                if replaced:
                    break
            if not replaced:
                controller_fs_list_new += [fs]

        cgtsvg_growth_gib = _check_controller_multi_fs_data(
                               pecan.request.context,
                               controller_fs_list_new)

        if _check_controller_state():
            _check_controller_multi_fs(controller_fs_list_new,
                                       cgtsvg_growth_gib=cgtsvg_growth_gib)
            for fs in controller_fs_list_new:
                if fs.name in modified_fs:
                    value = {'size': fs.size}
                    if fs.replicated:
                        value.update({'state': constants.CONTROLLER_FS_RESIZING_IN_PROGRESS})
                    pecan.request.dbapi.controller_fs_update(fs.uuid, value)

        try:
            # perform rpc to conductor to perform config apply
            pecan.request.rpcapi.update_storage_config(
                    pecan.request.context,
                    update_storage=False,
                    reinstall_required=reinstall_required,
                    reboot_required=reboot_required,
                    filesystem_list=modified_fs
            )

        except Exception as e:
            msg = _("Failed to update filesystem size ")
            LOG.error("%s with patch %s with exception %s" % (msg, patch, e))
            raise wsme.exc.ClientSideError(msg)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, controller_fs_uuid):
        """Delete a controller_fs."""
        raise exception.OperationNotPermitted

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(ControllerFs, body=ControllerFs)
    def post(self, controllerfs):
        """Create a new controller_fs."""
        raise exception.OperationNotPermitted
