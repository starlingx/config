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
# Copyright (c) 2015-2016 Wind River Systems, Inc.
#

import jsonpatch
import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

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
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


class DRBDConfigPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class DRBDConfig(base.APIBase):
    """API representation of DRBD Configuration.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an drbdconfig.
    """

    uuid = types.uuid
    "Unique UUID for this drbdconfig"

    link_util = int
    "The DRBD engineered link utilization percent during resync."

    num_parallel = int
    "The DRBD number of parallel filesystems to resync."

    rtt_ms = float
    "The DRBD replication nodes round-trip-time ms."

    action = wtypes.text
    "Represent the action on the drbdconfig."

    forisystemid = int
    "The isystemid that this drbdconfig belongs to"

    isystem_uuid = types.uuid
    "The UUID of the system this drbdconfig belongs to"

    links = [link.Link]
    "A list containing a self link and associated drbdconfig links"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = list(objects.drbdconfig.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # 'action' is not part of objects.drbdconfig.fields
        # (it's an API-only attribute)
        self.fields.append('action')
        setattr(self, 'action', kwargs.get('action', None))

    @classmethod
    def convert_with_links(cls, rpc_drbdconfig, expand=True):
        # fields = ['uuid', 'address'] if not expand else None
        # drbd = drbdconfig.from_rpc_object(rpc_drbdconfig, fields)

        drbd = DRBDConfig(**rpc_drbdconfig.as_dict())
        if not expand:
            drbd.unset_fields_except(['uuid',
                                      'link_util',
                                      'num_parallel',
                                      'rtt_ms',
                                      'isystem_uuid',
                                      'created_at',
                                      'updated_at'])

        # never expose the isystem_id attribute
        drbd.isystem_id = wtypes.Unset

        # never expose the isystem_id attribute, allow exposure for now
        # drbd.forisystemid = wtypes.Unset

        drbd.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'drbdconfigs',
                                          drbd.uuid),
                      link.Link.make_link('bookmark', pecan.request.host_url,
                                          'drbdconfigs',
                                          drbd.uuid,
                                          bookmark=True)
                      ]

        return drbd


class DRBDConfigCollection(collection.Collection):
    """API representation of a collection of drbdconfigs."""

    drbdconfigs = [DRBDConfig]
    "A list containing drbdconfig objects"

    def __init__(self, **kwargs):
        self._type = 'drbdconfigs'

    @classmethod
    def convert_with_links(cls, rpc_drbdconfigs, limit, url=None,
                           expand=False, **kwargs):
        collection = DRBDConfigCollection()
        collection.drbdconfigs = [DRBDConfig.convert_with_links(p, expand)
                                  for p in rpc_drbdconfigs]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


##############
# UTILS
##############

def _check_drbdconfig_data(action, drbdconfig):

    if not cutils.is_int_like(drbdconfig['link_util']):
        raise wsme.exc.ClientSideError(
            _("DRBD link_util must be an integer."))

    if not cutils.is_float_like(drbdconfig['rtt_ms']):
        raise wsme.exc.ClientSideError(
            _("DRBD rtt_ms must be a float."))

    if ((int(drbdconfig['link_util']) < constants.DRBD_LINK_UTIL_MIN) or
            (int(drbdconfig['link_util']) > constants.DRBD_LINK_UTIL_MAX)):

        raise wsme.exc.ClientSideError(
            _("DRBD link_util must be within: %d to %d"
              % (constants.DRBD_LINK_UTIL_MIN, constants.DRBD_LINK_UTIL_MAX)))

    if float(drbdconfig['rtt_ms']) < constants.DRBD_RTT_MS_MIN:
        raise wsme.exc.ClientSideError(
            _("DRBD rtt_ms must be at least: %.1f ms"
              % constants.DRBD_RTT_MS_MIN))

    if float(drbdconfig['rtt_ms']) > constants.DRBD_RTT_MS_MAX:
        raise wsme.exc.ClientSideError(
            _("DRBD rtt_ms must less than: %.1f ms"
              % constants.DRBD_RTT_MS_MAX))

    return drbdconfig


LOCK_NAME = 'drbdconfigsController'


class drbdconfigsController(rest.RestController):
    """REST controller for drbdconfigs."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_isystems=False):
        self._from_isystems = from_isystems

    def _get_drbdconfigs_collection(self, isystem_uuid, marker, limit,
                                    sort_key, sort_dir, expand=False,
                                    resource_url=None):

        if self._from_isystems and not isystem_uuid:
            raise exception.InvalidParameterValue(
                _("System id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.drbdconfig.get_by_uuid(pecan.request.context,
                                                        marker)

        if isystem_uuid:
            drbds = pecan.request.dbapi.drbdconfig_get_by_isystem(
                isystem_uuid, limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        else:
            drbds = pecan.request.dbapi.drbdconfig_get_list(limit,
                                                            marker_obj,
                                                            sort_key=sort_key,
                                                            sort_dir=sort_dir)

        return DRBDConfigCollection.convert_with_links(drbds, limit,
                                                       url=resource_url,
                                                       expand=expand,
                                                       sort_key=sort_key,
                                                       sort_dir=sort_dir)

    @wsme_pecan.wsexpose(DRBDConfigCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, isystem_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of drbdconfigs. Only one per system"""

        return self._get_drbdconfigs_collection(isystem_uuid, marker, limit,
                                                sort_key, sort_dir)

    @wsme_pecan.wsexpose(DRBDConfigCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, isystem_uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of drbdconfigs with detail."""

        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "drbdconfigs":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['drbdconfigs', 'detail'])
        return self._get_drbdconfigs_collection(isystem_uuid,
                                                marker, limit,
                                                sort_key, sort_dir,
                                                expand, resource_url)

    @wsme_pecan.wsexpose(DRBDConfig, types.uuid)
    def get_one(self, drbdconfig_uuid):
        """Retrieve information about the given drbdconfig."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_drbdconfig = objects.drbdconfig.get_by_uuid(pecan.request.context,
                                                        drbdconfig_uuid)
        return DRBDConfig.convert_with_links(rpc_drbdconfig)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(DRBDConfig, body=DRBDConfig)
    def post(self, drbdconf):
        """Create a new drbdconfig."""
        raise exception.OperationNotPermitted

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [DRBDConfigPatchType])
    @wsme_pecan.wsexpose(DRBDConfig, types.uuid,
                         body=[DRBDConfigPatchType])
    def patch(self, drbdconfig_uuid, patch):
        """Update the current drbd configuration."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_drbdconfig = objects.drbdconfig.get_by_uuid(pecan.request.context,
                                                        drbdconfig_uuid)

        action = None
        for p in patch:
            if '/action' in p['path']:
                value = p['value']
                patch.remove(p)
                if value in (constants.APPLY_ACTION, constants.INSTALL_ACTION):
                    action = value
                break

        # replace isystem_uuid and drbdconfig_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        if action == constants.INSTALL_ACTION:
            state_rel_path = ['/uuid', '/id', '/forisystemid', '/isystem_uuid']
        else:
            # fix num_parallel to 1 during config_controller
            # as drbd sync is changed to serial
            state_rel_path = ['/uuid', '/id', '/forisystemid', '/isystem_uuid', '/num_parallel']
        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(
                _("The following fields can not be modified: %s" %
                    state_rel_path))

        for p in patch_obj:
            if p['path'] == '/isystem_uuid':
                isystem = objects.system.get_by_uuid(pecan.request.context,
                                                     p['value'])
                p['path'] = '/forisystemid'
                p['value'] = isystem.id

        try:
            drbd = DRBDConfig(**jsonpatch.apply_patch(
                rpc_drbdconfig.as_dict(),
                patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        odrbd = pecan.request.dbapi.drbdconfig_get_one()

        LOG.warn("SYS_I odrbdconfig: %s drbdconfig: %s, action: %s" %
                 (odrbd.as_dict(), drbd.as_dict(), action))

        drbd = _check_drbdconfig_data(action, drbd.as_dict())

        if utils.is_drbd_fs_resizing():
            raise wsme.exc.ClientSideError(
                _("Cannot modify drbd config as "
                  "a drbd file system resize is taking place."))
        try:
            # Update only the fields that have changed
            for field in objects.drbdconfig.fields:
                if rpc_drbdconfig[field] != drbd[field]:
                    rpc_drbdconfig[field] = drbd[field]

            delta = rpc_drbdconfig.obj_what_changed()
            if delta:
                rpc_drbdconfig.save()

                if action == constants.APPLY_ACTION:
                    # perform rpc to conductor to perform config apply
                    pecan.request.rpcapi.update_drbd_config(
                        pecan.request.context)
            else:
                LOG.info("No drbdconfig changes")

            return DRBDConfig.convert_with_links(rpc_drbdconfig)

        except exception.HTTPNotFound:
            msg = _("DRBD Config update failed: drbdconfig %s : "
                    " patch %s" % (drbd, patch))
            raise wsme.exc.ClientSideError(msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, drbdconfig_uuid):
        """Delete a drbdconfig."""
        raise exception.OperationNotPermitted
