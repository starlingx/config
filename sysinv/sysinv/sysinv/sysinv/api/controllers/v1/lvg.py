# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright 2013 UnitedStack Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2021,2024,2026 Wind River Systems, Inc.
#

import math
import jsonpatch
import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import pv as pv_api
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class LVGPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/address', '/ihost_uuid']


class LVG(base.APIBase):
    """API representation of a ilvg.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an lvg.
    """

    uuid = types.uuid
    "Unique UUID for this lvg"

    vg_state = wtypes.text
    "Represent the transition state of the ilvg"

    lvm_vg_name = wtypes.text
    "LVM Volume Group's name"

    lvm_vg_uuid = wtypes.text
    "LVM Volume Group's UUID"

    lvm_vg_access = wtypes.text
    "LVM Volume Group access setting"

    lvm_max_lv = int
    "LVM Volume Group's max logical volumes"

    lvm_cur_lv = int
    "LVM Volume Group's current logical volumes"

    lvm_max_pv = int
    "LVM Volume Group's max physical volumes"

    lvm_cur_pv = int
    "LVM Volume Group's current physical volumes"

    lvm_vg_size = int
    "LVM Volume Group's total size"

    lvm_vg_avail_size = int
    "LVM Volume Group's available size. API only attribute"

    lvm_vg_total_pe = int
    "LVM Volume Group's total PEs"

    lvm_vg_free_pe = int
    "LVM Volume Group's free PEs"

    # lvm_function parameter: [API-only field]
    lvm_function = str
    "LVM Function"

    # lvm_type parameter: [API-only field]
    lvm_type = str
    "LVM Type (thin or thick)"

    lvm_pool_size = int
    "LVM Thin Pool Size (in GB)"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                                                  six.integer_types)}
    "This lvg's meta data"

    forihostid = int
    "The ihostid that this ilvg belongs to"

    ihost_uuid = types.uuid
    "The UUID of the host this lvg belongs to"

    links = [link.Link]
    "A list containing a self link and associated lvg links"

    ipvs = [link.Link]
    "Links to the collection of ipvs on this lvg"

    def __init__(self, **kwargs):
        self.fields = list(objects.lvg.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        if not self.uuid:
            self.uuid = uuidutils.generate_uuid()

        self.fields.append('lvm_vg_avail_size')
        setattr(self, 'lvm_vg_avail_size', kwargs.get('lvm_vg_avail_size', 0))

    @classmethod
    def convert_with_links(cls, rpc_lvg, expand=True):
        lvg = LVG(**rpc_lvg.as_dict())
        if not expand:
            lvg.unset_fields_except(['uuid', 'lvm_vg_name', 'vg_state',
                                     'lvm_vg_uuid', 'lvm_vg_access',
                                     'lvm_max_lv', 'lvm_cur_lv',
                                     'lvm_max_pv', 'lvm_cur_pv',
                                     'lvm_vg_size', 'lvm_vg_avail_size',
                                     'lvm_vg_total_pe',
                                     'lvm_vg_free_pe', 'capabilities',
                                     'lvm_function', 'lvm_type',
                                     'lvm_pool_size',
                                     'created_at', 'updated_at',
                                     'ihost_uuid', 'forihostid'])

        # To calculate Volume Group's available size in byte:
        # lvm_vg_size is Volume Group's total size in byte
        # lvm_vg_free_pe is Volume Group's free Physical Extents
        # lvm_vg_total_pe is Volume Group's total Physical Extents
        if lvg.lvm_vg_total_pe and lvg.lvm_vg_total_pe > 0:
            lvg.lvm_vg_avail_size = \
                lvg.lvm_vg_size * lvg.lvm_vg_free_pe // lvg.lvm_vg_total_pe
        else:
            lvg.lvm_vg_avail_size = 0

        # never expose the ihost_id attribute, allow exposure for now
        lvg.forihostid = wtypes.Unset
        lvg.links = [link.Link.make_link('self', pecan.request.host_url,
                                         'ilvgs', lvg.uuid),
                     link.Link.make_link('bookmark',
                                         pecan.request.host_url,
                                         'ilvgs', lvg.uuid,
                                         bookmark=True)]
        if expand:
            lvg.ipvs = [link.Link.make_link('self',
                                            pecan.request.host_url,
                                            'ilvgs',
                                            lvg.uuid + "/ipvs"),
                        link.Link.make_link('bookmark',
                                            pecan.request.host_url,
                                            'ilvgs',
                                            lvg.uuid + "/ipvs",
                                            bookmark=True)]

        return lvg


class LVGCollection(collection.Collection):
    """API representation of a collection of lvgs."""

    ilvgs = [LVG]
    "A list containing lvg objects"

    def __init__(self, **kwargs):
        self._type = 'ilvgs'

    @classmethod
    def convert_with_links(cls, rpc_lvgs, limit, url=None,
                           expand=False, **kwargs):
        collection = LVGCollection()
        collection.ilvgs = [LVG.convert_with_links(p, expand)
                            for p in rpc_lvgs]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'LVGController'


class LVGController(rest.RestController):
    """REST controller for ilvgs."""

    ipvs = pv_api.PVController(from_ihosts=True, from_ilvg=True)
    "Expose ipvs as a sub-element of ilvgs"

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts

    def _get_lvgs_collection(self, ihost_uuid, marker, limit, sort_key,
                             sort_dir, expand=False, resource_url=None):
        if self._from_ihosts and not ihost_uuid:
            raise exception.InvalidParameterValue(_(
                "Host id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.lvg.get_by_uuid(
                pecan.request.context,
                marker)

        if ihost_uuid:
            lvgs = pecan.request.dbapi.ilvg_get_by_ihost(
                ihost_uuid, limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        else:
            lvgs = pecan.request.dbapi.ilvg_get_list(limit, marker_obj,
                                                     sort_key=sort_key,
                                                     sort_dir=sort_dir)

        return LVGCollection.convert_with_links(lvgs, limit,
                                                url=resource_url,
                                                expand=expand,
                                                sort_key=sort_key,
                                                sort_dir=sort_dir)

    @wsme_pecan.wsexpose(LVGCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, ihost_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of lvgs."""

        return self._get_lvgs_collection(ihost_uuid, marker, limit,
                                         sort_key, sort_dir)

    @wsme_pecan.wsexpose(LVGCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, ihost_uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of lvgs with detail."""
        # NOTE: /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "ilvgs":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['lvgs', 'detail'])
        return self._get_lvgs_collection(ihost_uuid,
                                         marker, limit,
                                         sort_key, sort_dir,
                                         expand, resource_url)

    @wsme_pecan.wsexpose(LVG, types.uuid)
    def get_one(self, lvg_uuid):
        """Retrieve information about the given lvg."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_lvg = objects.lvg.get_by_uuid(pecan.request.context, lvg_uuid)
        return LVG.convert_with_links(rpc_lvg)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(LVG, body=LVG)
    def post(self, lvg):
        """Create a new lvg."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            lvg = lvg.as_dict()
            LOG.debug("lvg post dict= %s" % lvg)

            new_lvg = _create(lvg)
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create a"
                                             " local volume group object"))
        return LVG.convert_with_links(new_lvg)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [LVGPatchType])
    @wsme_pecan.wsexpose(LVG, types.uuid,
                         body=[LVGPatchType])
    def patch(self, lvg_uuid, patch):
        """Update an existing lvg."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        LOG.debug("patch_data: %s" % patch)

        rpc_lvg = objects.lvg.get_by_uuid(
            pecan.request.context, lvg_uuid)

        # replace ihost_uuid and ilvg_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        for p in patch_obj:
            if p['path'] == '/ihost_uuid':
                p['path'] = '/forihostid'
                ihost = objects.host.get_by_uuid(pecan.request.context,
                                                 p['value'])
                p['value'] = ihost.id
            elif p['path'] == '/capabilities':
                p['value'] = jsonutils.loads(p['value'])

        try:
            lvg = LVG(**jsonpatch.apply_patch(rpc_lvg.as_dict(),
                                              patch_obj))
        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Semantic Checks
        _check("modify", lvg.as_dict(), rpc_lvg.as_dict())
        lvm_csi_resizing = False

        try:
            # Update only the fields that have changed
            for field in objects.lvg.fields:
                if rpc_lvg[field] != getattr(lvg, field):
                    if lvg.lvm_vg_name != constants.LVG_CGTS_VG:
                        rpc_lvg[field] = getattr(lvg, field)
                        continue

                    # CGTS VG only supports lvm_function and lvm_thin_size
                    # changes. Any other changes should be rejected.
                    if field != 'capabilities':
                        raise wsme.exc.ClientSideError(
                            _("%s volume group does not support changes "
                              "to %s." % (lvg.lvm_vg_name, field)))

                    if not lvg.capabilities:
                        continue
                    # Analyze if the change is a resize
                    lvg_ps = lvg.capabilities.get('lvm_pool_size', None)
                    rpc_ps = rpc_lvg['capabilities'].get('lvm_pool_size', None)
                    if lvg_ps and rpc_ps and lvg_ps != rpc_ps:
                        lvm_csi_resizing = True

                    # Updates capabilities dictionary
                    rpc_lvg['capabilities'].update(lvg.capabilities)

            # Update mate controller LVG type for cinder-volumes
            if lvg.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
                mate_lvg = _get_mate_ctrl_lvg(lvg.as_dict())
                lvm_type = lvg.capabilities.get(constants.LVG_CINDER_PARAM_LVM_TYPE)
                if mate_lvg and lvm_type:
                    mate_lvg_caps = mate_lvg['capabilities']
                    mate_type = mate_lvg_caps.get(constants.LVG_CINDER_PARAM_LVM_TYPE)
                    if lvm_type != mate_type:
                        mate_lvg_caps[constants.LVG_CINDER_PARAM_LVM_TYPE] = lvm_type
                        pecan.request.dbapi.ilvg_update(mate_lvg['uuid'],
                            {'capabilities': mate_lvg_caps})

            # Save
            rpc_lvg.save()
            # Save method doesn't detect changes on second level parameters
            pecan.request.dbapi.ilvg_update(
                                rpc_lvg.uuid,
                                {'capabilities': rpc_lvg['capabilities']})
            if lvg.lvm_vg_name == constants.LVG_CGTS_VG:
                pecan.request.rpcapi.update_cgts_vg_lvm_csi_capabilities(
                    pecan.request.context,
                    rpc_lvg['ihost_uuid'],
                    rpc_lvg['uuid'],
                    lvm_csi_resizing)

            return LVG.convert_with_links(rpc_lvg)
        except exception.HTTPNotFound:
            msg = _("LVG update failed: host %s vg %s : patch %s"
                    % (ihost['hostname'], lvg.lvm_vg_name, patch))
            raise wsme.exc.ClientSideError(msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, lvg_uuid):
        """Delete a lvg."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        lvg = objects.lvg.get_by_uuid(pecan.request.context,
                                      lvg_uuid).as_dict()
        _delete(lvg)


def _set_defaults(lvg):
    defaults = {
        'vg_state': constants.LVG_ADD,
        'lvm_vg_uuid': None,
        'lvm_vg_access': None,
        'lvm_max_lv': 0,
        'lvm_cur_lv': 0,
        'lvm_max_pv': 0,
        'lvm_cur_pv': 0,
        'lvm_vg_size': 0,
        'lvm_vg_avail_size': 0,
        'lvm_vg_total_pe': 0,
        'lvm_vg_free_pe': 0,
        'capabilities': {},
    }

    lvg_merged = lvg.copy()
    for key in lvg_merged:
        if lvg_merged[key] is None and key in defaults:
            lvg_merged[key] = defaults[key]

    for key in defaults:
        if key not in lvg_merged:
            lvg_merged[key] = defaults[key]

    caps = lvg_merged['capabilities']
    if caps.get('lvm_function', '') == constants.LVM_CSI_PROVISIONING_FUNCTION:
        if not caps.get('lvm_type', ''):
            caps['lvm_type'] = constants.LVM_CSI_PROVISIONING_MODE_THICK

    return lvg_merged


def _check_host(lvg):

    ihost = pecan.request.dbapi.ihost_get(lvg['forihostid'])

    if not ihost.subfunctions:
        raise wsme.exc.ClientSideError(_("Host %s has uninitialized "
                                         "subfunctions.") %
                                       ihost.hostname)
    elif constants.STORAGE in ihost.subfunctions:
        raise wsme.exc.ClientSideError(_("Volume group operations not allowed "
                                         "on hosts with personality: %s") %
                                       constants.STORAGE)
    elif (constants.WORKER not in ihost.subfunctions and
              lvg['lvm_vg_name'] == constants.LVG_NOVA_LOCAL):
        raise wsme.exc.ClientSideError(_("%s can only be added to a host which "
                                         "has a %s subfunction.") %
                                       (constants.LVG_NOVA_LOCAL,
                                        constants.WORKER))
    if (constants.WORKER in ihost['subfunctions'] and
            lvg['lvm_vg_name'] == constants.LVG_NOVA_LOCAL and
            (ihost['administrative'] != constants.ADMIN_LOCKED or
             ihost['ihost_action'] == constants.UNLOCK_ACTION)):
        raise wsme.exc.ClientSideError(_("Host must be locked"))


def _get_mate_ctrl_lvg(lvg):
    """ Return the lvg object with same VG name of mate controller """
    ihost = pecan.request.dbapi.ihost_get(lvg['forihostid'])
    if ihost.personality != constants.CONTROLLER:
        raise wsme.exc.ClientSideError(
            _("Internal Error: VG %(vg)s exists on a host with "
              "%(pers)s personality." % {'vg': lvg['lvm_vg_name'],
                                         'pers': ihost.personality}))
    mate_hostname = cutils.get_mate_controller_hostname(ihost['hostname'])
    try:
        mate_ctrl = pecan.request.dbapi.ihost_get_by_hostname(mate_hostname)
    except exception.NodeNotFound:
        return None
    mate_ilvgs = pecan.request.dbapi.ilvg_get_by_ihost(mate_ctrl.id)
    for ilvg in mate_ilvgs:
        if ilvg['lvm_vg_name'] == lvg['lvm_vg_name']:
            return ilvg
    return None


def _check(op, lvg, rpc_lvg=None):
    # Semantic checks
    LOG.debug("Semantic check for %s operation" % op)

    # Check host and host state
    _check_host(lvg)

    lvg['lvm_function'] = lvg['capabilities'].get('lvm_function', None)
    lvg['lvm_type'] = lvg['capabilities'].get('lvm_type', None)
    lvg['lvm_pool_size'] = lvg['capabilities'].get('lvm_pool_size', None)

    # Check for required volume group name
    if not lvg['lvm_function'] \
       and lvg['lvm_vg_name'] not in constants.LVG_ALLOWED_VGS:
        grp = "'%s' or '%s'" % (constants.LVG_NOVA_LOCAL,
                                constants.LVG_CGTS_VG)
        raise wsme.exc.ClientSideError(
            _("Volume Group name (%s) must be \"%s\"") % (lvg['lvm_vg_name'],
                                                          grp))

    if op == "add":
        if lvg['lvm_vg_name'] == constants.LVG_CGTS_VG:
            raise wsme.exc.ClientSideError(
                _("%s volume group already exists") % constants.LVG_CGTS_VG)

        # Check if lvm-csi parameters are correctly configured
        if (lvg['lvm_function'] == constants.LVM_CSI_PROVISIONING_FUNCTION
           and not lvg['lvm_type']):
            raise wsme.exc.ClientSideError(
                _("When %s function is set, the type is required") %
                constants.LVM_CSI_PROVISIONING_FUNCTION)
        if lvg['lvm_type'] and not lvg['lvm_function']:
            raise wsme.exc.ClientSideError(
                _("%s provisioning requires to set the function as %s") %
                (lvg['lvm_type'], constants.LVM_CSI_PROVISIONING_FUNCTION))
        if lvg['lvm_pool_size']:
            raise wsme.exc.ClientSideError(
                _("The pool size option is reserved to %s volume group.") %
                constants.LVG_CGTS_VG)

    elif op == "modify":
        rpc_lvg['lvm_function'] = rpc_lvg['capabilities'] \
            .get('lvm_function', None)
        rpc_lvg['lvm_type'] = rpc_lvg['capabilities'].get('lvm_type', None)
        rpc_lvg['lvm_pool_size'] = rpc_lvg['capabilities'] \
            .get('lvm_pool_size', None)

        # Sanity check: parameters
        if lvg['lvm_vg_name'] == constants.LVG_NOVA_LOCAL:
            raise wsme.exc.ClientSideError(_("%s volume group does not have "
                                           "any parameters to modify") %
                                           lvg['lvm_vg_name'])
        if lvg['lvm_pool_size']:
            if (not rpc_lvg['lvm_function'] or rpc_lvg['lvm_function'] !=
               constants.LVM_CSI_PROVISIONING_FUNCTION) \
               and not lvg['lvm_function']:
                raise wsme.exc.ClientSideError(
                    _("It's not possible to resize thin pool without LVM "
                      "function properly configured"))
            if lvg['lvm_function'] and lvg['lvm_function'] != constants \
               .LVM_CSI_PROVISIONING_FUNCTION:
                raise wsme.exc.ClientSideError(
                    _("It's not possible to resize the thin pool and change "
                      "the function to %s") %
                    lvg['lvm_function'])

            _check_pool_resize(rpc_lvg, lvg)

        if lvg['lvm_function']:
            if lvg['lvm_function'] == 'none':
                if lvg['lvm_pool_size']:
                    raise wsme.exc.ClientSideError(
                        _("It's not possible to set pool size parameter "
                          "when the function is set to none"))
                rpc_lvg['capabilities'].pop('lvm_function', None)
                rpc_lvg['capabilities'].pop('lvm_pool_size', None)
                rpc_lvg['capabilities'].pop('lvm_type', None)
                lvg['vg_state'] = constants.PROVISIONING

            if lvg['lvm_vg_name'] == constants.LVG_CGTS_VG:
                if not lvg['lvm_pool_size'] and lvg['lvm_function'] == \
                   constants.LVM_CSI_PROVISIONING_FUNCTION:
                    lvg['lvm_vg_avail_size'] = \
                        (lvg['lvm_vg_size'] * lvg['lvm_vg_free_pe'] //
                         lvg['lvm_vg_total_pe'])
                    if lvg['lvm_vg_avail_size'] < 1:
                        raise wsme.exc.ClientSideError(
                            _("There is no space available to create a "
                              "thin pool for %s") %
                            constants.LVG_CGTS_VG)
                    lvg['lvm_pool_size'] = int(math.floor(
                                            float(lvg['lvm_vg_avail_size'] / 2) /  # pylint: disable=old-division
                                            (1024 ** 3) * 1000) / 1000.0)

                    lvg['capabilities']['lvm_pool_size'] = lvg['lvm_pool_size']
                    lvg['vg_state'] = constants.PROVISIONING
                if lvg['lvm_function'] == constants\
                        .LVM_CSI_PROVISIONING_FUNCTION:
                    lvg['capabilities']['lvm_type'] = constants\
                        .LVM_CSI_PROVISIONING_MODE_THIN
                    lvg['lvm_type'] = lvg['capabilities']['lvm_type']
            else:
                if lvg['lvm_pool_size']:
                    raise wsme.exc.ClientSideError(
                        _("Its only possible to set the pool size for %s "
                          "volume group") %
                        constants.LVG_CGTS_VG)
                lvg['vg_state'] = constants.PROVISIONING
        else:
            if rpc_lvg['lvm_function'] and rpc_lvg['lvm_function'] == 'none' \
               and lvg['lvm_pool_size']:
                raise wsme.exc.ClientSideError(
                    _("It's not possible to set any other parameter when the "
                      "function is set to none"))
            lvg['vg_state'] = constants.PROVISIONING
    elif op == "delete":
        if lvg['lvm_vg_name'] == constants.LVG_CGTS_VG:
            raise wsme.exc.ClientSideError(_("%s volume group cannot be deleted") %
                                           constants.LVG_CGTS_VG)
        elif lvg['lvm_vg_name'] == constants.LVG_NOVA_LOCAL:
            # We never have more than 1 LV in nova-local VG
            pass
    else:
        raise wsme.exc.ClientSideError(
            _("Internal Error: Invalid Volume Group operation: %s" % op))

    return lvg


def _check_pool_resize(current_lvg, new_lvg):
    current_pool_size = current_lvg['capabilities'].get('lvm_pool_size', None)
    new_pool_size = new_lvg['capabilities'].get('lvm_pool_size', None)

    if new_pool_size is None or current_pool_size is None:
        return

    try:
        old_value = int(current_pool_size)
        new_value = int(new_pool_size)

        if old_value > new_value:
            raise wsme.exc.ClientSideError(
                _("It's not possible to reduce the size of a thin pool"))

        current_lvg['lvm_vg_avail_size'] = \
            (current_lvg['lvm_vg_size'] * current_lvg['lvm_vg_free_pe'] //
                current_lvg['lvm_vg_total_pe'])

        available_space = int(math.floor(float(
                                     current_lvg['lvm_vg_avail_size']) /  # pylint: disable=old-division
                                     (1024 ** 3) * 1000) / 1000.0)
        if (new_value - old_value) > available_space:
            raise wsme.exc.ClientSideError(
                _("There is no sufficient space on VG to resize the pool."
                  "%s GB are needed, but the VG has only %s GB") %
                (new_value - old_value, available_space))

        new_lvg['vg_state'] = constants.PROVISIONING
    except ValueError:
        raise wsme.exc.ClientSideError(
            _("Please only use integer values for the pool size: %s") %
            new_pool_size)


def _create(lvg):
    # Get host
    ihostId = lvg.get('forihostid') or lvg.get('ihost_uuid')
    ihost = pecan.request.dbapi.ihost_get(ihostId)
    if uuidutils.is_uuid_like(ihostId):
        forihostid = ihost['id']
    else:
        forihostid = ihostId
    lvg.update({'forihostid': forihostid})
    LOG.debug("lvg post lvgs ihostid: %s" % forihostid)
    lvg['ihost_uuid'] = ihost['uuid']

    # Set defaults - before checks to allow for optional attributes
    lvg = _set_defaults(lvg)

    # Semantic checks
    lvg = _check("add", lvg)

    # Make sure there is only a single source for /var/lib/nova/instances
    if lvg['lvm_vg_name'] == constants.LVG_NOVA_LOCAL:
        if cutils.is_host_filesystem_enabled(pecan.request.dbapi, lvg['ihost_uuid'],
                                             constants.FILESYSTEM_NAME_INSTANCES):
            raise wsme.exc.ClientSideError(
                _("%s volume group can not be added while filesystem %s exists. Remove "
                  "the filesytem and try again." % (lvg['lvm_vg_name'],
                                                    constants.FILESYSTEM_NAME_INSTANCES)))

    # See if this volume group already exists
    ilvgs = pecan.request.dbapi.ilvg_get_all(forihostid=forihostid)
    lvg_in_db = False
    for vg in ilvgs:
        if vg['lvm_vg_name'] == lvg['lvm_vg_name']:
            lvg_in_db = True
            # User is adding again so complain
            if (vg['vg_state'] == constants.LVG_ADD or
                    vg['vg_state'] == constants.PROVISIONED):
                raise wsme.exc.ClientSideError(_("Volume Group (%s) "
                                                    "already present" %
                                                    vg['lvm_vg_name']))

            # Prevent re-adding so that we don't end up in a state where
            # the cloud admin has removed a subset of the PVs rendering the
            # VG as unusable because of LV corruption
            if vg['vg_state'] == constants.LVG_DEL:
                # User changed mind and is re-adding
                values = {'vg_state': constants.LVG_ADD}
                try:
                    LOG.info("Update ilvg values: %s" % values)
                    pecan.request.dbapi.ilvg_update(vg.id, values)
                except exception.HTTPNotFound:
                    msg = _("LVG update failed: host (%s) LVG (%s)"
                            % (ihost['hostname'], vg['lvm_pv_name']))
                    raise wsme.exc.ClientSideError(msg)
            ret_lvg = vg
            break

    if not lvg_in_db:
        # Create the new volume group entry
        ret_lvg = pecan.request.dbapi.ilvg_create(forihostid, lvg)

    return ret_lvg


def _delete(lvg):

    # Semantic checks
    lvg = _check("delete", lvg)
    cap_function = lvg['capabilities'].get('lvm_function')
    # Update physical volumes
    ihost = pecan.request.dbapi.ihost_get(lvg['forihostid']).as_dict()
    ipvs = pecan.request.dbapi.ipv_get_all(forihostid=ihost['id'])
    for pv in ipvs:
        if pv.forilvgid == lvg['id']:
            values = {'forilvgid': None,
                      'pv_state': constants.LVG_DEL}
            try:
                pecan.request.dbapi.ipv_update(pv.id, values)
            except exception.HTTPNotFound:
                msg = _("PV update of ilvg_uuid failed: "
                        "host %s PV %s"
                        % (ihost['hostname'], pv.lvm_pv_name))
                raise wsme.exc.ClientSideError(msg)

            if constants.PV_TYPE_DISK in pv['pv_type']:
                # Update disk
                idisks = pecan.request.dbapi.idisk_get_all(foripvid=pv.id)
                for d in idisks:
                    if d['uuid'] == pv['disk_or_part_uuid']:
                        values = {'foripvid': None}
                        try:
                            pecan.request.dbapi.idisk_update(d.id, values)
                        except exception.HTTPNotFound:
                            msg = _("Disk update of foripvid failed: "
                                    "host %s PV %s"
                                    % (ihost['hostname'], pv.lvm_pv_name))
                            raise wsme.exc.ClientSideError(msg)
            elif pv['pv_type'] == constants.PV_TYPE_PARTITION:
                # Update disk partition
                partitions = pecan.request.dbapi.partition_get_all(foripvid=pv.id)
                for p in partitions:
                    if p['uuid'] == pv['disk_or_part_uuid']:
                        values = {'foripvid': None}
                        try:
                            pecan.request.dbapi.partition_update(p.id, values)
                        except exception.HTTPNotFound:
                            msg = _("Disk patition update of foripvid failed: "
                                    "host %s PV %s"
                                    % (ihost['hostname'], pv.lvm_pv_name))
                            raise wsme.exc.ClientSideError(msg)

            # Delete the DB entries on unprovisioned hosts as these are just
            # staged in the DB and were never actually created by manifests
            if (lvg['lvm_vg_name'] == constants.LVG_NOVA_LOCAL and
                    ihost.get('invprovision') != constants.PROVISIONED):
                try:
                    pecan.request.dbapi.ipv_destroy(pv.id)
                except exception.HTTPNotFound:
                    msg = _("PV delete of ilvg_uuid failed: "
                            "host %s PV %s"
                            % (ihost['hostname'], pv.lvm_pv_name))
                    raise wsme.exc.ClientSideError(msg)

    if (lvg['lvm_vg_name'] == constants.LVG_NOVA_LOCAL and
            ihost.get('invprovision') != constants.PROVISIONED):
        try:
            pecan.request.dbapi.ilvg_destroy(lvg['id'])
        except exception.HTTPNotFound:
            msg = _("Deleting LVG failed: host %s lvg %s"
                    % (ihost['hostname'], lvg['lvm_vg_name']))
            raise wsme.exc.ClientSideError(msg)
    elif cap_function == constants.LVM_CSI_PROVISIONING_FUNCTION:
        try:
            pecan.request.dbapi.ilvg_update(lvg['id'],
                                            {'vg_state': constants.LVG_DEL})
            if (cap_function == constants.LVM_CSI_PROVISIONING_FUNCTION
               and ihost.get('invprovision') == constants.PROVISIONED):
                pecan.request.rpcapi.delete_lvm_csi_lvg_pv(
                    pecan.request.context,
                    lvg['ihost_uuid'],
                    lvg,
                    pv)
        except exception.HTTPNotFound:
            msg = _("Deleting LVG failed: host %s lvg %s"
                    % (ihost['hostname'], lvg['lvm_vg_name']))
            raise wsme.exc.ClientSideError(msg)
    else:
        # Mark the lvg for deletion
        values = {'vg_state': constants.LVG_DEL}
        try:
            pecan.request.dbapi.ilvg_update(lvg['id'], values)
        except exception.HTTPNotFound:
            msg = _("Marking lvg for deletion failed: host %s lvg %s"
                    % (ihost['hostname'], lvg['lvm_vg_name']))
            raise wsme.exc.ClientSideError(msg)
