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
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#


import jsonpatch

import pecan
from pecan import rest

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import health
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _
from fm_api import constants as fm_constants

from sysinv.common.storage_backend_conf import StorageBackendConfig

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

    The database GiB of controller_fs - maps to
          /var/lib/postgresql (pgsql-lv)
    The image GiB of controller_fs - maps to
          /opt/cgcs (cgcs-lv)
    The image conversion GiB of controller_fs - maps to
          /opt/img-conversions (img-conversions-lv)
    The backup GiB of controller_fs - maps to
          /opt/backups (backup-lv)
    The scratch GiB of controller_fs - maps to
          /scratch (scratch-lv)
    The extension GiB of controller_fs - maps to
          /opt/extension (extension-lv)
    The gnocchi GiB of controller_fs - maps to
          /opt/gnocchi (gnocchi-lv)
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
        self.fields = objects.controller_fs.fields.keys()
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

        # we display the cgcs file system as glance to the customer
        if controller_fs.name == constants.FILESYSTEM_NAME_CGCS:
            controller_fs.name = constants.FILESYSTEM_DISPLAY_NAME_CGCS

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

    if cutils.is_virtual():
        return

    backup_gib_min = constants.BACKUP_OVERHEAD
    for fs in controller_fs_new_list:
        if fs.name == constants.FILESYSTEM_NAME_DATABASE:
            database_gib = fs.size
            backup_gib_min += fs.size
        elif fs.name == constants.FILESYSTEM_NAME_CGCS:
            cgcs_gib = fs.size
            backup_gib_min += fs.size
        elif fs.name == constants.FILESYSTEM_NAME_BACKUP:
            backup_gib = fs.size

    if backup_gib < backup_gib_min:
        raise wsme.exc.ClientSideError(_("backup size of %d is "
                                         "insufficient. "
                                         "Minimum backup size of %d is "
                                         "required based upon glance size %d "
                                         "and database size %d. "
                                         "Rejecting modification "
                                         "request." %
                                         (backup_gib,
                                          backup_gib_min,
                                          cgcs_gib,
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

    device_path_ctrl0 = None
    device_path_ctrl1 = None

    if ceph_mons:
        for ceph_mon in ceph_mons:
            ihost = pecan.request.dbapi.ihost_get(ceph_mon.forihostid)
            if ihost.hostname == constants.CONTROLLER_0_HOSTNAME:
                device_path_ctrl0 = ceph_mon.device_path
            if ihost.hostname == constants.CONTROLLER_1_HOSTNAME:
                device_path_ctrl1 = ceph_mon.device_path

    rootfs_max_GiB, cgtsvg_max_free_GiB = \
        _get_controller_fs_limit(device_path_ctrl0, device_path_ctrl1)

    LOG.info("_check_controller_multi_fs rootfs_max_GiB = %s cgtsvg_max_free_GiB = %s " %
             (rootfs_max_GiB, cgtsvg_max_free_GiB))

    _check_relative_controller_multi_fs(controller_fs_new_list)

    LOG.info("_check_controller_multi_fs ceph_mon_gib_new = %s" % ceph_mon_gib_new)

    rootfs_configured_size_GiB = \
        _total_size_controller_multi_fs(controller_fs_new_list) + ceph_mon_gib_new

    LOG.info("_check_controller_multi_fs rootfs_configured_size_GiB = %s" %
             rootfs_configured_size_GiB)

    if cgtsvg_growth_gib and (cgtsvg_growth_gib > cgtsvg_max_free_GiB):
        if ceph_mon_gib_new:
            msg = _(
                "Total target growth size %s GiB for database "
                "(doubled for upgrades), glance, img-conversions, "
                "scratch, backup, extension and ceph-mon exceeds "
                "growth limit of %s GiB." %
                (cgtsvg_growth_gib, cgtsvg_max_free_GiB)
            )
        else:
            msg = _(
                "Total target growth size %s GiB for database "
                "(doubled for upgrades), glance, img-conversions, scratch, "
                "backup and extension exceeds growth limit of %s GiB." %
                (cgtsvg_growth_gib, cgtsvg_max_free_GiB)
            )
        raise wsme.exc.ClientSideError(msg)


def _check_relative_controller_fs(controller_fs_new, controller_fs_list):
    """
    This function verifies the relative controller_fs sizes.
    :param controller_fs_new:
    :param controller_fs_list:
    :return: None.  Raise Client exception on failure.
    """

    if cutils.is_virtual():
        return

    backup_gib = 0
    database_gib = 0
    cgcs_gib = 0

    for fs in controller_fs_list:
        if controller_fs_new and fs['name'] == controller_fs_new['name']:
            fs['size'] = controller_fs_new['size']

        if fs['name'] == "backup":
            backup_gib = fs['size']
        elif fs['name'] == constants.DRBD_CGCS:
            cgcs_gib = fs['size']
        elif fs['name'] == "database":
            database_gib = fs['size']

    if backup_gib == 0:
        LOG.info(
            "_check_relative_controller_fs backup filesystem not yet setup")
        return

    # Required mininum backup filesystem size
    backup_gib_min = cgcs_gib + database_gib + constants.BACKUP_OVERHEAD

    if backup_gib < backup_gib_min:
        raise wsme.exc.ClientSideError(_("backup size of %d is "
                                         "insufficient. "
                                         "Minimum backup size of %d is "
                                         "required based on upon "
                                         "glance=%d and database=%d and "
                                         "backup overhead of %d. "
                                         "Rejecting modification "
                                         "request." %
                                         (backup_gib,
                                          backup_gib_min,
                                          cgcs_gib,
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
        if (chost.administrative != constants.ADMIN_UNLOCKED or
                chost.availability != constants.AVAILABILITY_AVAILABLE or
                chost.operational != constants.OPERATIONAL_ENABLED):

            # A node can become degraded due to not free space available in a FS
            # and thus block the resize operation. If the only alarm that degrades
            # a controller node is a filesystem alarm, we shouldn't block the resize
            # as the resize itself will clear the degrade.
            health_helper = health.Health(pecan.request.dbapi)
            degrade_alarms = health_helper.get_alarms_degrade(
                alarm_ignore_list=[fm_constants.FM_ALARM_ID_FS_USAGE],
                entity_instance_id_filter="controller-")
            allowed_resize = False
            if (not degrade_alarms and
                    chost.availability == constants.AVAILABILITY_DEGRADED):
                allowed_resize = True

            if not allowed_resize:
                alarm_explanation = ""
                if degrade_alarms:
                    alarm_explanation = "Check alarms with the following IDs: %s" % str(degrade_alarms)
                raise wsme.exc.ClientSideError(
                    _("This operation requires controllers to be %s, %s, %s. "
                    "Current status is %s, %s, %s. %s." %
                    (constants.ADMIN_UNLOCKED, constants.OPERATIONAL_ENABLED,
                    constants.AVAILABILITY_AVAILABLE,
                    chost.administrative, chost.operational,
                    chost.availability, alarm_explanation)))

    return True


def _get_controller_fs_limit(device_path_ctrl0, device_path_ctrl1):
    """Calculate space for controller rootfs plus ceph_mon_dev
       returns: fs_max_GiB
                cgtsvg_max_free_GiB

    """
    reserved_space = constants.CONTROLLER_ROOTFS_RESERVED
    CFS_RESIZE_BUFFER_GIB = 2  # reserve space and ensure no rounding errors

    max_disk_size_controller0 = 0
    max_disk_size_controller1 = 0

    idisks0 = None
    idisks1 = None
    cgtsvg0_free_mib = 0
    cgtsvg1_free_mib = 0
    cgtsvg_max_free_GiB = 0

    chosts = pecan.request.dbapi.ihost_get_by_personality(
        constants.CONTROLLER)
    for chost in chosts:
        if chost.hostname == constants.CONTROLLER_0_HOSTNAME:
            idisks0 = pecan.request.dbapi.idisk_get_by_ihost(chost.uuid)

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
                                        int(ilvg.lvm_vg_free_pe) / int(
                        ilvg.lvm_vg_total_pe)) / (1024 * 1024)
                    break

        else:
            idisks1 = pecan.request.dbapi.idisk_get_by_ihost(chost.uuid)

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
                                        int(ilvg.lvm_vg_free_pe) / int(
                        ilvg.lvm_vg_total_pe)) / (1024 * 1024)
                    break

    LOG.info("_get_controller_fs_limit cgtsvg0_free_mib=%s, "
             "cgtsvg1_free_mib=%s" % (cgtsvg0_free_mib, cgtsvg1_free_mib))

    # relies on the sizes of the partitions allocated in
    # cgcs/common-bsp/files/TEMPLATE_controller_disk.add.

    for chost in chosts:
        if chost.hostname == constants.CONTROLLER_0_HOSTNAME and idisks0:
            idisks = idisks0
        elif chost.hostname == constants.CONTROLLER_1_HOSTNAME and idisks1:
            idisks = idisks1
        else:
            LOG.error("SYS_I unexpected chost uuid %s hostname %s" %
                      (chost.uuid, chost.hostname))
            continue

        # find the largest disk for each controller
        for idisk in idisks:
            capabilities = idisk['capabilities']
            if 'stor_function' in capabilities:
                if capabilities['stor_function'] == 'rootfs':
                    disk_size_gib = idisk.size_mib / 1024
                    if chost.hostname == constants.CONTROLLER_0_HOSTNAME:
                        if disk_size_gib > max_disk_size_controller0:
                            max_disk_size_controller0 = disk_size_gib
                    else:
                        if disk_size_gib > max_disk_size_controller1:
                            max_disk_size_controller1 = disk_size_gib

            if (device_path_ctrl0 == idisk.device_path and
                    chost.hostname == constants.CONTROLLER_0_HOSTNAME):
                disk_size_gib = idisk.size_mib / 1024
                max_disk_size_controller0 += disk_size_gib

            elif (device_path_ctrl1 == idisk.device_path and
                    chost.hostname == constants.CONTROLLER_1_HOSTNAME):
                disk_size_gib = idisk.size_mib / 1024
                max_disk_size_controller1 += disk_size_gib

    if max_disk_size_controller0 > 0 and max_disk_size_controller1 > 0:
        minimax = min(max_disk_size_controller0, max_disk_size_controller1)
        LOG.info("_get_controller_fs_limit minimax=%s" % minimax)
        fs_max_GiB = minimax - reserved_space
    elif max_disk_size_controller1 > 0:
        fs_max_GiB = max_disk_size_controller1 - reserved_space
    else:
        fs_max_GiB = max_disk_size_controller0 - reserved_space

    LOG.info("SYS_I filesystem limits max_disk_size_controller0=%s, "
             "max_disk_size_controller1=%s, reserved_space=%s, fs_max_GiB=%s" %
             (max_disk_size_controller0, max_disk_size_controller1,
              reserved_space, int(fs_max_GiB)))

    if cgtsvg0_free_mib > 0 and cgtsvg1_free_mib > 0:
        cgtsvg_max_free_GiB = min(cgtsvg0_free_mib, cgtsvg1_free_mib) / 1024
        LOG.info("min of cgtsvg0_free_mib=%s and cgtsvg1_free_mib=%s is "
                 "cgtsvg_max_free_GiB=%s" %
                 (cgtsvg0_free_mib, cgtsvg1_free_mib, cgtsvg_max_free_GiB))
    elif cgtsvg1_free_mib > 0:
        cgtsvg_max_free_GiB = cgtsvg1_free_mib / 1024
    else:
        cgtsvg_max_free_GiB = cgtsvg0_free_mib / 1024

    cgtsvg_max_free_GiB -= CFS_RESIZE_BUFFER_GIB

    LOG.info("SYS_I filesystem limits cgtsvg0_free_mib=%s, "
             "cgtsvg1_free_mib=%s, cgtsvg_max_free_GiB=%s"
             % (cgtsvg0_free_mib, cgtsvg1_free_mib, cgtsvg_max_free_GiB))

    return fs_max_GiB, cgtsvg_max_free_GiB


def get_controller_fs_limit():
    ceph_mons = pecan.request.dbapi.ceph_mon_get_list()

    if ceph_mons:
        ceph_mon_gib_new = ceph_mons[0].ceph_mon_gib
    else:
        ceph_mon_gib_new = 0

    LOG.debug("_check_controller_fs ceph_mon_gib_new = %s" % ceph_mon_gib_new)

    device_path_ctrl0 = None
    device_path_ctrl1 = None

    if ceph_mons:
        for ceph_mon in ceph_mons:
            ihost = pecan.request.dbapi.ihost_get(ceph_mon.forihostid)
            if ihost.hostname == constants.CONTROLLER_0_HOSTNAME:
                device_path_ctrl0 = ceph_mon.device_path
            if ihost.hostname == constants.CONTROLLER_1_HOSTNAME:
                device_path_ctrl1 = ceph_mon.device_path

    return _get_controller_fs_limit(device_path_ctrl0, device_path_ctrl1)


def _check_controller_fs(controller_fs_new=None,
                         ceph_mon_gib_new=None,
                         cgtsvg_growth_gib=None,
                         controller_fs_list=None):

    ceph_mons = pecan.request.dbapi.ceph_mon_get_list()

    if not controller_fs_list:
        controller_fs_list = pecan.request.dbapi.controller_fs_get_list()

    if not ceph_mon_gib_new:
        if ceph_mons:
            ceph_mon_gib_new = ceph_mons[0].ceph_mon_gib
        else:
            ceph_mon_gib_new = 0
    else:
        if ceph_mons:
            cgtsvg_growth_gib = ceph_mon_gib_new - ceph_mons[0].ceph_mon_gib
        else:
            cgtsvg_growth_gib = ceph_mon_gib_new

    device_path_ctrl0 = None
    device_path_ctrl1 = None

    if ceph_mons:
        for ceph_mon in ceph_mons:
            ihost = pecan.request.dbapi.ihost_get(ceph_mon.forihostid)
            if ihost.hostname == constants.CONTROLLER_0_HOSTNAME:
                device_path_ctrl0 = ceph_mon.device_path
            if ihost.hostname == constants.CONTROLLER_1_HOSTNAME:
                device_path_ctrl1 = ceph_mon.device_path

    rootfs_max_GiB, cgtsvg_max_free_GiB = \
        _get_controller_fs_limit(device_path_ctrl0, device_path_ctrl1)

    LOG.info("_check_controller_fs ceph_mon_gib_new = %s" % ceph_mon_gib_new)
    LOG.info("_check_controller_fs cgtsvg_growth_gib = %s" % cgtsvg_growth_gib)
    LOG.info("_check_controller_fs rootfs_max_GiB = %s" % rootfs_max_GiB)
    LOG.info("_check_controller_fs cgtsvg_max_free_GiB = %s" % cgtsvg_max_free_GiB)

    _check_relative_controller_fs(controller_fs_new, controller_fs_list)

    rootfs_configured_size_GiB = \
        _total_size_controller_fs(controller_fs_new,
                                  controller_fs_list) + ceph_mon_gib_new

    LOG.info("_check_controller_fs rootfs_configured_size_GiB = %s" %
             rootfs_configured_size_GiB)

    if cgtsvg_growth_gib and (cgtsvg_growth_gib > cgtsvg_max_free_GiB):
        if ceph_mon_gib_new:
            msg = _(
                "Total target growth size %s GiB for database "
                "(doubled for upgrades), glance, img-conversions, "
                "scratch, backup, extension and ceph-mon exceeds "
                "growth limit of %s GiB." %
                (cgtsvg_growth_gib, cgtsvg_max_free_GiB)
            )
        else:
            msg = _(
                "Total target growth size %s GiB for database "
                "(doubled for upgrades), glance, img-conversions, scratch, "
                "backup and extension exceeds growth limit of %s GiB." %
                (cgtsvg_growth_gib, cgtsvg_max_free_GiB)
            )
        raise wsme.exc.ClientSideError(msg)


def _check_controller_multi_fs_data(context, controller_fs_list_new,
                                    modified_fs):
    """ Check controller filesystem data and return growth
        returns: cgtsvg_growth_gib
    """

    cgtsvg_growth_gib = 0

    # Check if we need img_conversions
    img_conversion_required = False
    lvdisplay_keys = [constants.FILESYSTEM_LV_DICT[constants.FILESYSTEM_NAME_DATABASE],
                      constants.FILESYSTEM_LV_DICT[constants.FILESYSTEM_NAME_CGCS],
                      constants.FILESYSTEM_LV_DICT[constants.FILESYSTEM_NAME_BACKUP],
                      constants.FILESYSTEM_LV_DICT[constants.FILESYSTEM_NAME_SCRATCH],
                      constants.FILESYSTEM_LV_DICT[constants.FILESYSTEM_NAME_GNOCCHI]]

    # On primary region, img-conversions always exists in controller_fs DB table.
    # On secondary region, if both glance and cinder are sharing from the primary
    # region, img-conversions won't exist in controller_fs DB table. We already
    # have semantic check not to allow img-conversions resizing.
    if (StorageBackendConfig.has_backend(pecan.request.dbapi, constants.SB_TYPE_LVM) or
            StorageBackendConfig.has_backend(pecan.request.dbapi, constants.SB_TYPE_CEPH)):
        img_conversion_required = True
        lvdisplay_keys.append(constants.FILESYSTEM_LV_DICT[constants.FILESYSTEM_NAME_IMG_CONVERSIONS])

    if (constants.FILESYSTEM_NAME_IMG_CONVERSIONS in modified_fs and
            not img_conversion_required):
        raise wsme.exc.ClientSideError(
            _("%s is not modifiable: no cinder backend is "
              "currently configured.") % constants.FILESYSTEM_NAME_IMG_CONVERSIONS)

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
                orig = orig / 2

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


LOCK_NAME = 'ControllerFsController'


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
    @wsme_pecan.wsexpose(ControllerFs, types.uuid, body=[[ControllerFsPatchType]])
    def update_many(self, isystem_uuid, patch):
        """Update the current controller_fs configuration."""

        if self._from_isystems and not isystem_uuid:
            raise exception.InvalidParameterValue(_(
                "System id not specified."))

        # Validate input filesystem names
        controller_fs_list = pecan.request.dbapi.controller_fs_get_list()
        valid_fs_list = []
        if controller_fs_list:
            valid_fs_list = {fs.name: fs.size for fs in controller_fs_list}

        reinstall_required = False
        reboot_required = False
        force_resize = False
        modified_fs = []

        for p_list in patch:
            p_obj_list = jsonpatch.JsonPatch(p_list)

            for p_obj in p_obj_list:
                if p_obj['path'] == '/action':
                    value = p_obj['value']
                    patch.remove(p_list)
                    if value == constants.FORCE_ACTION:
                        force_resize = True
                        LOG.info("Force action resize selected")
                        break

        for p_list in patch:
            p_obj_list = jsonpatch.JsonPatch(p_list)
            for p_obj in p_obj_list:
                if p_obj['path'] == '/name':
                    fs_display_name = p_obj['value']
                    if fs_display_name == constants.FILESYSTEM_DISPLAY_NAME_CGCS:
                        fs_name = constants.FILESYSTEM_NAME_CGCS
                    else:
                        fs_name = fs_display_name
                elif p_obj['path'] == '/size':
                    size = p_obj['value']

            if fs_name not in valid_fs_list.keys() or fs_display_name == constants.FILESYSTEM_NAME_CGCS:
                msg = _("ControllerFs update failed: invalid filesystem "
                        "'%s' " % fs_display_name)
                raise wsme.exc.ClientSideError(msg)
            elif not cutils.is_int_like(size):
                msg = _("ControllerFs update failed: filesystem '%s' "
                        "size must be an integer " % fs_display_name)
                raise wsme.exc.ClientSideError(msg)
            elif int(size) <= int(valid_fs_list[fs_name]):
                msg = _("ControllerFs update failed: size for filesystem '%s' "
                        "should be bigger than %s " % (
                            fs_display_name, valid_fs_list[fs_name]))
                raise wsme.exc.ClientSideError(msg)
            elif (fs_name == constants.FILESYSTEM_NAME_CGCS and
                  StorageBackendConfig.get_backend(pecan.request.dbapi,
                                                   constants.CINDER_BACKEND_CEPH)):
                if force_resize:
                    LOG.warn("Force resize ControllerFs: %s, though Ceph "
                             "storage backend is configured" % fs_display_name)
                else:
                    raise wsme.exc.ClientSideError(
                        _("ControllerFs %s size is not modifiable as Ceph is "
                          "configured. Update size via Ceph Storage Pools." %
                          fs_display_name))

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
                    if p_obj['path'] == '/name':
                        if p_obj['value'] == constants.FILESYSTEM_DISPLAY_NAME_CGCS:
                            p_obj['value'] = constants.FILESYSTEM_NAME_CGCS

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
                               controller_fs_list_new,
                               modified_fs)

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
