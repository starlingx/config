# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import jsonpatch
import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _

LOG = log.getLogger(__name__)


ALLOWED_DATANETWORK_TYPES = [
    constants.DATANETWORK_TYPE_FLAT,
    constants.DATANETWORK_TYPE_VLAN,
    constants.DATANETWORK_TYPE_VXLAN,
]

VXLAN_DYNAMIC_REQUIRED_PARAMS = ['multicast_group', 'port_num', 'ttl']
VXLAN_STATIC_REQUIRED_PARAMS = ['port_num', 'ttl']


class DataNetworkPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class DataNetwork(base.APIBase):
    """API representation of an datanetwork.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of a
    datanetwork.
    """

    id = int
    "Unique ID for this datanetwork"

    uuid = types.uuid
    "Unique UUID for this datanetwork"

    network_type = wtypes.text
    "Represent the datanetwork type for the datanetwork"

    name = wtypes.text
    "Unique name for this datanetwork"

    description = wtypes.text
    "Represent the user description for the datanetwork"

    mtu = int
    "Represent the MTU size (bytes) of the datanetwork"

    multicast_group = wtypes.text
    "Multicast group  for this datanetwork. VxLan only"

    port_num = int
    "Vxlan Port for this datanetwork. VxLan only"

    ttl = int
    "Time To Live for this datanetwork. VxLan only"

    mode = wtypes.text
    "Mode for this datanetwork. VxLan only"

    def __init__(self, **kwargs):
        self.fields = objects.datanetwork.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_datanetwork, expand=True):
        datanetwork = DataNetwork(**rpc_datanetwork.as_dict())
        if not expand:
            datanetwork.unset_fields_except(
                ['id', 'uuid', 'network_type', 'name',
                 'description', 'mtu',
                 'multicast_group', 'port_num', 'ttl', 'mode'])

        return datanetwork

    def _validate_network_type(self):
        if self.network_type not in ALLOWED_DATANETWORK_TYPES:
            raise ValueError(_("DataNetwork type %s not supported") %
                             self.network_type)

    def validate_syntax(self):
        """
        Validates the syntax of each field.
        """
        self._validate_network_type()


class DataNetworkCollection(collection.Collection):
    """API representation of a collection of datanetworks."""

    datanetworks = [DataNetwork]
    "A list containing DataNetwork objects"

    def __init__(self, **kwargs):
        self._type = 'datanetworks'

    @classmethod
    def convert_with_links(cls, rpc_datanetworks, limit, url=None,
                           expand=False, **kwargs):
        collection = DataNetworkCollection()
        collection.datanetworks = [DataNetwork.convert_with_links(n, expand)
                                   for n in rpc_datanetworks]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'DataNetworkController'


class DataNetworkController(rest.RestController):
    """REST controller for DataNetworks."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_datanetwork_collection(
            self, marker=None, limit=None, sort_key=None,
            sort_dir=None, expand=False, resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None

        if marker:
            marker_obj = objects.datanetwork.get_by_uuid(
                pecan.request.context, marker)

        datanetworks = pecan.request.dbapi.datanetworks_get_all(
            limit=limit, marker=marker_obj,
            sort_key=sort_key, sort_dir=sort_dir)

        return DataNetworkCollection.convert_with_links(
            datanetworks, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _get_one(self, datanetwork_uuid):
        rpc_datanetwork = objects.datanetwork.get_by_uuid(
            pecan.request.context, datanetwork_uuid)
        return DataNetwork.convert_with_links(rpc_datanetwork)

    @staticmethod
    def _check_network_type(datanetwork):
        if 'network_type' not in datanetwork:
            raise wsme.exc.ClientSideError(
                _('DataNetwork network_type is required.'))

        network_type = datanetwork['network_type']
        if network_type not in ALLOWED_DATANETWORK_TYPES:
            raise ValueError(_("DataNetwork type %s is not supported") %
                             network_type)

    @staticmethod
    def _check_datanetwork_name(datanetwork):
        if 'name' not in datanetwork:
            raise wsme.exc.ClientSideError(
                _('DataNetwork name is required.'))

        name = datanetwork['name']
        if name.lower() == constants.DATANETWORK_TYPE_NONE:
            raise ValueError(_("DataNetwork name '%s' is not allowed") % name)

    @staticmethod
    def _check_new_datanetwork_mtu_or_set_default(datanetwork):
        if 'mtu' not in datanetwork:
            datanetwork['mtu'] = constants.DEFAULT_MTU
        utils.validate_mtu(datanetwork['mtu'])

    @staticmethod
    def _check_datanetwork_vxlan(datanetwork):
        if datanetwork['network_type'] != constants.DATANETWORK_TYPE_VXLAN:
            return

        mode = datanetwork.get('mode', constants.DATANETWORK_MODE_DYNAMIC)
        if mode == constants.DATANETWORK_MODE_STATIC:
            required_vxlan_params = VXLAN_STATIC_REQUIRED_PARAMS
        else:
            required_vxlan_params = VXLAN_DYNAMIC_REQUIRED_PARAMS

        missing = set(required_vxlan_params).difference(datanetwork.keys())
        if missing:
            raise wsme.exc.ClientSideError(
                _("VxLan parameters '%s' are required for '%s' mode.") %
                (list(missing), mode))

        multicast_group = datanetwork.get('multicast_group')
        if mode == constants.DATANETWORK_MODE_STATIC:
            if multicast_group:
                raise wsme.exc.ClientSideError(
                    _('VxLan of mode %s does not support multicast_group.') %
                    mode)
        else:
            if not cutils.validate_ip_multicast_address(multicast_group):
                raise wsme.exc.ClientSideError(
                    _("multicast group '%s' is not a valid "
                      "multicast ip address.") %
                    multicast_group)

    def _check_datanetwork(self, datanetwork):
        self._check_network_type(datanetwork)
        self._check_datanetwork_name(datanetwork)
        self._check_new_datanetwork_mtu_or_set_default(datanetwork)
        self._check_datanetwork_vxlan(datanetwork)

    @staticmethod
    def _check_update_mtu(rpc_datanetwork):
        # Check interfaces using this datanetwork
        ifdns = pecan.request.dbapi.interface_datanetwork_get_by_datanetwork(
            rpc_datanetwork.uuid)

        for ifdn in ifdns:
            interface_obj = pecan.request.dbapi.iinterface_get(
                ifdn.interface_uuid)
            if interface_obj.imtu < rpc_datanetwork.mtu:
                msg = _("The datanetwork MTU '%s' must be smaller than "
                        "assigned interface MTU '%s'." %
                        (rpc_datanetwork.mtu, interface_obj.imtu))
                raise wsme.exc.ClientSideError(msg)

    def _create_datanetwork(self, datanetwork):
        # Perform syntactic validation
        datanetwork.validate_syntax()

        # Perform semantic validation
        datanetwork = datanetwork.as_dict()
        self._check_datanetwork(datanetwork)

        result = pecan.request.dbapi.datanetwork_create(datanetwork)

        return DataNetwork.convert_with_links(result)

    @wsme_pecan.wsexpose(DataNetworkCollection,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of DataNetworks."""

        return self._get_datanetwork_collection(marker, limit,
                                                sort_key=sort_key,
                                                sort_dir=sort_dir)

    @wsme_pecan.wsexpose(DataNetwork, wtypes.text)
    def get_one(self, datanetwork_id):
        """Retrieve a single DataNetwork."""

        return self._get_one(datanetwork_id)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(DataNetwork, body=DataNetwork)
    def post(self, datanetwork):
        """Create a new Data Network."""

        return self._create_datanetwork(datanetwork)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(six.text_type, [DataNetworkPatchType])
    @wsme_pecan.wsexpose(DataNetwork, six.text_type,
                         body=[DataNetworkPatchType])
    def patch(self, datanetwork_id, patch):
        """Update an existing datanetwork."""

        rpc_datanetwork = \
            objects.datanetwork.get_by_uuid(
                pecan.request.context, datanetwork_id)

        utils.validate_patch(patch)
        patch_obj = jsonpatch.JsonPatch(patch)
        LOG.info("datanetwork  patch_obj=%s" % patch_obj)

        try:
            datanetwork = DataNetwork(**jsonpatch.apply_patch(
                rpc_datanetwork.as_dict(), patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        LOG.info("rpc_datanetwork=%s datanetwork=%s" %
                 (rpc_datanetwork.as_dict(), datanetwork))

        fields = objects.datanetwork.fields

        for field in fields:
            if (field in rpc_datanetwork and
                    rpc_datanetwork[field] != getattr(datanetwork, field)):
                rpc_datanetwork[field] = getattr(datanetwork, field)

        delta = rpc_datanetwork.obj_what_changed()
        if not delta:
            return DataNetwork.convert_with_links(rpc_datanetwork)

        delta_list = list(delta)

        allowed_updates = ['mtu', 'description']
        if not set(delta_list).issubset(allowed_updates):
            extra = set(allowed_updates).difference(delta_list)
            raise wsme.exc.ClientSideError(
                _("DataNetwork '%s' attributes '%s' may not be modified ") %
                (rpc_datanetwork.uuid, extra))

        values = {}
        if 'mtu' in delta_list:
            self._check_update_mtu(rpc_datanetwork)
            values.update({'mtu': rpc_datanetwork.mtu})

        if 'description' in delta_list:
            values.update({'description': rpc_datanetwork.description})

        rpc_datanetwork.save()

        return DataNetwork.convert_with_links(rpc_datanetwork)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, datanetwork_uuid):
        """Delete a Data Network."""

        # Only allow delete if there are no associated interfaces
        ifdns = pecan.request.dbapi.interface_datanetwork_get_by_datanetwork(
            datanetwork_uuid)
        if ifdns:
            raise wsme.exc.ClientSideError(
                _("DataNetwork '%s' is still assigned to interfaces. "
                  "Check interface-datanetwork.") % datanetwork_uuid)

        pecan.request.dbapi.datanetwork_destroy(datanetwork_uuid)
