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
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
import wsme
import pecan
from pecan import rest
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import utils as cutils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common.gettextutils import _

from sysinv import objects


class InterfaceDataNetwork(base.APIBase):

    id = int
    "Unique ID for this interface data network"

    uuid = types.uuid
    "Unique UUID for this interface data network"

    forihostid = int
    "The ID of the host the interface data network belongs to"

    interface_uuid = types.uuid
    "Unique UUID of the parent interface"

    ifname = wtypes.text
    "User defined name of the interface"

    datanetwork_id = int
    "Unique ID of the parent datanetwork"

    datanetwork_uuid = types.uuid
    "Unique UUID of the parent datanetwork"

    datanetwork_name = wtypes.text
    "User defined name of the datanetwork"

    network_type = wtypes.text
    "Represents the type for the datanetwork"

    def __init__(self, **kwargs):
        self.fields = objects.interface_datanetwork.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_interface_datanetwork, expand=True):
        interface_datanetwork = InterfaceDataNetwork(
            **rpc_interface_datanetwork.as_dict())
        if not expand:
            interface_datanetwork.unset_fields_except([
                'forihostid', 'id', 'uuid', 'interface_uuid', 'ifname',
                'datanetwork_id', 'datanetwork_uuid',
                'datanetwork_name', 'network_type'
            ])
        return interface_datanetwork


class InterfaceDataNetworkCollection(collection.Collection):
    """API representation of a collection of IP addresses."""

    interface_datanetworks = [InterfaceDataNetwork]
    "A list containing Interface Data Network objects"

    def __init__(self, **kwargs):
        self._type = 'interface_datanetworks'

    @classmethod
    def convert_with_links(cls, rpc_interface_datanetwork, limit, url=None,
                           expand=False, **kwargs):
        collection = InterfaceDataNetworkCollection()
        collection.interface_datanetworks = [
            InterfaceDataNetwork.convert_with_links(p, expand)
            for p in rpc_interface_datanetwork]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'InterfaceDataNetworkController'


class InterfaceDataNetworkController(rest.RestController):

    def __init__(self, parent=None):
        self._parent = parent

    def _create_interface_datanetwork(self, interface_datanetwork):
        interface_datanetwork_dict = interface_datanetwork.as_dict()
        interface_datanetwork_dict['uuid'] = str(uuid.uuid4())

        # Remove UUIDs from dict to be replaced with IDs
        interface_uuid = interface_datanetwork_dict.pop('interface_uuid')
        datanetwork_uuid = interface_datanetwork_dict.pop('datanetwork_uuid')

        interface_id = self._get_interface_id(interface_uuid)

        try:
            datanetwork_obj = \
                pecan.request.dbapi.datanetwork_get(datanetwork_uuid)
        except exception.DataNetworkNotFound:
            msg = _("DataNetwork with uuid '%s' does not exist. " %
                    datanetwork_uuid)
            raise wsme.exc.ClientSideError(msg)

        datanetwork_id = datanetwork_obj['id']

        interface_datanetwork_dict['interface_id'] = interface_id
        interface_datanetwork_dict['datanetwork_id'] = datanetwork_id

        interface_obj = pecan.request.dbapi.iinterface_get(interface_uuid)
        self._check_host(interface_obj.ihost_uuid)

        self._check_interface_class(interface_obj)
        self._check_interface_mtu(interface_obj, datanetwork_obj)
        self._check_duplicate_interface_datanetwork(interface_datanetwork_dict)
        self._check_iftype_network_type(interface_obj, datanetwork_obj)
        self._check_datanetwork_used(interface_obj, datanetwork_obj)

        result = pecan.request.dbapi.interface_datanetwork_create(
            interface_datanetwork_dict)

        return InterfaceDataNetwork.convert_with_links(result)

    def _get_interface_datanetwork_collection(
            self, parent_uuid=None, marker=None, limit=None, sort_key=None,
            sort_dir=None, expand=False, resource_url=None):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None

        if marker:
            marker_obj = objects.interface_datanetwork.get_by_uuid(
                pecan.request.context, marker)

        if self._parent == "ihosts":
            interface_datanetworks = \
                pecan.request.dbapi.interface_datanetwork_get_by_host(
                    parent_uuid,
                    limit=limit, marker=marker_obj,
                    sort_key=sort_key, sort_dir=sort_dir)
        elif self._parent == "iinterfaces":
            interface_datanetworks = \
                pecan.request.dbapi.interface_datanetwork_get_by_interface(
                    parent_uuid, limit=limit, marker=marker_obj,
                    sort_key=sort_key, sort_dir=sort_dir)
        else:
            interface_datanetworks = \
                pecan.request.dbapi.interface_datanetwork_get_all(
                    limit=limit, marker=marker_obj,
                    sort_key=sort_key, sort_dir=sort_dir)

        return InterfaceDataNetworkCollection.convert_with_links(
            interface_datanetworks, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    @staticmethod
    def _get_one(interface_datanetwork_uuid):
        rpc_interface_datanetwork = objects.interface_datanetwork.get_by_uuid(
            pecan.request.context, interface_datanetwork_uuid)
        return InterfaceDataNetwork.convert_with_links(
            rpc_interface_datanetwork)

    @staticmethod
    def _check_interface_class(interface_obj):
        if (not interface_obj.ifclass or
                interface_obj.ifclass == constants.INTERFACE_CLASS_NONE):
            values = {'ifclass': constants.INTERFACE_CLASS_DATA}
            pecan.request.dbapi.iinterface_update(interface_obj.uuid, values)
            return
        else:
            # Allow ifclass data, pcipt and sriov to assign data networks
            if interface_obj.ifclass not in [constants.INTERFACE_CLASS_DATA,
                    constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                    constants.INTERFACE_CLASS_PCI_SRIOV]:
                msg = _("An interface with interface class '%s' "
                        "cannot assign datanetworks." %
                        interface_obj.ifclass)
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _check_host(host_uuid):
        host = pecan.request.dbapi.ihost_get(host_uuid)
        if host.administrative != constants.ADMIN_LOCKED:
            msg = _("Operation Rejected: Host '%s' is adminstrative '%s' " %
                    (host.hostname, host.administrative))
            raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _check_interface_mtu(interface_obj, datanetwork_obj):
        if datanetwork_obj.network_type == constants.DATANETWORK_TYPE_VXLAN:
            overhead = constants.VXLAN_MTU_OVERHEAD
        else:
            overhead = 0

        if interface_obj.imtu < datanetwork_obj.mtu + overhead:
            msg = _("The interface MTU %s must be larger than the '%s' "
                    "datanetwork MTU requirement." %
                    (interface_obj.imtu, datanetwork_obj.mtu))
            raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _query_interface_datanetwork(interface_datanetwork):
        try:
            result = pecan.request.dbapi.interface_datanetwork_query(
                interface_datanetwork)
        except exception.InterfaceDataNetworkNotFoundByKeys:
            return None
        return result

    def _check_duplicate_interface_datanetwork(self, interface_datanetwork):
        ifdn = self._query_interface_datanetwork(interface_datanetwork)
        if not ifdn:
            return
        msg = _("Interface '%s' assignment with Data Network '%s' "
                "already exists."
                % (ifdn['ifname'],
                   ifdn['datanetwork_name']))
        raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _check_iftype_network_type(interface_obj, datanetwork_obj):
        if interface_obj.iftype == constants.INTERFACE_TYPE_VLAN:
            if datanetwork_obj.network_type == constants.DATANETWORK_TYPE_VLAN:
                msg = _("VLAN based data network '%s' cannot be "
                        "assigned to a VLAN interface" % datanetwork_obj.name)
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _check_datanetwork_used(interface, datanetwork):
        if interface.ifclass != constants.INTERFACE_CLASS_DATA:
            return
        ifnets = pecan.request.dbapi.interface_datanetwork_get_by_datanetwork(
            datanetwork.uuid)
        for i in ifnets:
            if (i.forihostid == interface.forihostid and
                    i.interface_id != interface.id):
                iface = pecan.request.dbapi.iinterface_get(i.interface_id)
                if iface.ifclass == constants.INTERFACE_CLASS_DATA:
                    msg = _("Data interface %(ifname)s is already "
                            "attached to this Data Network: "
                            "%(datanetwork)s." %
                            {'ifname': i.ifname,
                             'datanetwork': datanetwork.name})
                    raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _get_interface_id(interface_uuid):
        interface = pecan.request.dbapi.iinterface_get(interface_uuid)
        return interface['id']

    @staticmethod
    def _get_datanetwork_id_and_type(datanetwork_uuid):
        datanetwork = pecan.request.dbapi.datanetwork_get(datanetwork_uuid)
        return datanetwork['id'], datanetwork['network_type']

    @wsme_pecan.wsexpose(InterfaceDataNetwork, types.uuid)
    def get_one(self, interface_datanetwork_uuid):
        return self._get_one(interface_datanetwork_uuid)

    @wsme_pecan.wsexpose(InterfaceDataNetworkCollection,
                         wtypes.text, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, parent_uuid=None, marker=None,
                limit=None, sort_key='id', sort_dir='asc'):
        return self._get_interface_datanetwork_collection(
            parent_uuid, marker, limit, sort_key, sort_dir)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(InterfaceDataNetwork, body=InterfaceDataNetwork)
    def post(self, interface_datanetwork):
        return self._create_interface_datanetwork(interface_datanetwork)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, interface_datanetwork_uuid):
        ifdn_obj = pecan.request.dbapi.interface_datanetwork_get(
            interface_datanetwork_uuid)
        interface_obj = pecan.request.dbapi.iinterface_get(
            ifdn_obj.interface_uuid)
        self._check_host(interface_obj.ihost_uuid)
        pecan.request.dbapi.interface_datanetwork_destroy(
            interface_datanetwork_uuid)
