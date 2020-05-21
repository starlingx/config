#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan
from oslo_log import log
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv import objects

LOG = log.getLogger(__name__)


class DeviceImageState(base.APIBase):
    """API representation of a device_image_state.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a device image.
    """

    id = int
    "Unique ID for this device_image_state"

    uuid = types.uuid
    "Unique UUID for this device_image_state"

    host_id = int
    "Represent the host id of the host that the pci_device belongs to"

    host_uuid = types.uuid
    "Represent the UUID of the host that the pci_device belongs to"

    pcidevice_id = int
    "Represent the id of pci_device"

    pcidevice_uuid = types.uuid
    "Represent the uuid of pci_device"

    image_id = int
    "Represent the id of device image"

    image_uuid = types.uuid
    "Represent the uuid of device image"

    status = wtypes.text
    "Firmware update status"

    update_start_time = wtypes.datetime.datetime
    "Represents the start time of the device image update"

    updated_at = wtypes.datetime.datetime
    "The time at which the record is updated "

    links = [link.Link]
    "A list containing a self link and associated device image state links"

    def __init__(self, **kwargs):
        self.fields = list(objects.device_image_state.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_device_image_state, expand=True):
        device_image_state = DeviceImageState(**rpc_device_image_state.as_dict())
        if not expand:
            device_image_state.unset_fields_except(
                ['id', 'uuid', 'host_id', 'host_uuid',
                 'pcidevice_id', 'pcidevice_uuid',
                 'image_id', 'image_uuid', 'status',
                 'update_start_time', 'updated_at'])

        # do not expose the id attribute
        device_image_state.host_id = wtypes.Unset
        return device_image_state


class DeviceImageStateCollection(collection.Collection):
    """API representation of a collection of device_image_state."""

    device_image_state = [DeviceImageState]
    "A list containing device_image_state objects"

    def __init__(self, **kwargs):
        self._type = 'device_image_state'

    @classmethod
    def convert_with_links(cls, rpc_device_image_state, limit, url=None,
                           expand=False, **kwargs):
        collection = DeviceImageStateCollection()
        collection.device_image_state = [DeviceImageState.convert_with_links(p, expand)
                              for p in rpc_device_image_state]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'DeviceImageStateController'


class DeviceImageStateController(rest.RestController):
    """REST controller for device image state."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_device_image_state_collection(
            self, marker=None, limit=None, sort_key=None,
            sort_dir=None, expand=False, resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None
        if marker:
            marker_obj = objects.device_image_state.get_by_uuid(
                pecan.request.context,
                marker)

        states = pecan.request.dbapi.device_image_state_get_list(
            limit=limit, marker=marker_obj,
            sort_key=sort_key, sort_dir=sort_dir)

        return DeviceImageStateCollection.convert_with_links(
            states, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _get_one(self, uuid):
        obj = objects.device_image_state.get_by_uuid(
            pecan.request.context, uuid)
        return DeviceImageState.convert_with_links(obj)

    @wsme_pecan.wsexpose(DeviceImageStateCollection,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of device image state."""

        return self._get_device_image_state_collection(marker, limit,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(DeviceImageState, wtypes.text)
    def get_one(self, deviceimagestate_uuid):
        """Retrieve a single device image state."""

        return self._get_one(deviceimagestate_uuid)
