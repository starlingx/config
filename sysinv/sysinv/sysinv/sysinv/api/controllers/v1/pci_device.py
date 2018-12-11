# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
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
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _

LOG = log.getLogger(__name__)


class PCIDevicePatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return []


class PCIDevice(base.APIBase):
    """API representation of an PCI device

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an
    Pci Device .
    """

    uuid = types.uuid
    "Unique UUID for this device"

    type = wtypes.text
    "Represent the type of device"

    name = wtypes.text
    "Represent the name of the device. Unique per host"

    pciaddr = wtypes.text
    "Represent the pci address of the device"

    pclass_id = wtypes.text
    "Represent the numerical pci class of the device"

    pvendor_id = wtypes.text
    "Represent the numerical pci vendor of the device"

    pdevice_id = wtypes.text
    "Represent the numerical pci device of the device"

    pclass = wtypes.text
    "Represent the pci class description of the device"

    pvendor = wtypes.text
    "Represent the pci vendor description of the device"

    pdevice = wtypes.text
    "Represent the pci device description of the device"

    psvendor = wtypes.text
    "Represent the pci svendor of the device"

    psdevice = wtypes.text
    "Represent the pci sdevice of the device"

    numa_node = int
    "Represent the numa node or zone sdevice of the device"

    sriov_totalvfs = int
    "The total number of available SR-IOV VFs"

    sriov_numvfs = int
    "The number of configured SR-IOV VFs"

    sriov_vfs_pci_address = wtypes.text
    "The PCI Addresses of the VFs"

    driver = wtypes.text
    "The kernel driver for this device"

    extra_info = wtypes.text
    "Extra information for this device"

    host_id = int
    "Represent the host_id the device belongs to"

    host_uuid = types.uuid
    "Represent the UUID of the host the device belongs to"

    enabled = types.boolean
    "Represent the enabled status of the device"

    links = [link.Link]
    "Represent a list containing a self link and associated device links"

    def __init__(self, **kwargs):
        self.fields = objects.pci_device.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_device, expand=True):
        device = PCIDevice(**rpc_device.as_dict())
        if not expand:
            device.unset_fields_except(['uuid', 'host_id',
                                        'name', 'pciaddr', 'pclass_id',
                                        'pvendor_id', 'pdevice_id', 'pclass',
                                        'pvendor', 'pdevice', 'psvendor',
                                        'psdevice', 'numa_node',
                                        'sriov_totalvfs', 'sriov_numvfs',
                                        'sriov_vfs_pci_address', 'driver',
                                        'host_uuid', 'enabled',
                                        'created_at', 'updated_at'])

        # do not expose the id attribute
        device.host_id = wtypes.Unset
        device.node_id = wtypes.Unset

        device.links = [link.Link.make_link('self', pecan.request.host_url,
                                            'pci_devices', device.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'pci_devices', device.uuid,
                                          bookmark=True)
                        ]
        return device


class PCIDeviceCollection(collection.Collection):
    """API representation of a collection of PciDevice objects."""

    pci_devices = [PCIDevice]
    "A list containing PciDevice objects"

    def __init__(self, **kwargs):
        self._type = 'pci_devices'

    @classmethod
    def convert_with_links(cls, rpc_devices, limit, url=None,
                           expand=False, **kwargs):
        collection = PCIDeviceCollection()
        collection.pci_devices = [PCIDevice.convert_with_links(d, expand)
                                  for d in rpc_devices]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'PCIDeviceController'


class PCIDeviceController(rest.RestController):
    """REST controller for PciDevices."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts

    def _get_pci_devices_collection(self, uuid, marker, limit, sort_key,
                                sort_dir, expand=False, resource_url=None):
        if self._from_ihosts and not uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None
        if marker:
            marker_obj = objects.pci_device.get_by_uuid(
                                        pecan.request.context,
                                        marker)
        if self._from_ihosts:
            devices = pecan.request.dbapi.pci_device_get_by_host(
                                                    uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        else:
            if uuid:
                devices = pecan.request.dbapi.pci_device_get_by_host(
                                                    uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
            else:
                devices = pecan.request.dbapi.pci_device_get_list(
                                                    limit, marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

        return PCIDeviceCollection.convert_with_links(devices, limit,
                                                      url=resource_url,
                                                      expand=expand,
                                                      sort_key=sort_key,
                                                      sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PCIDeviceCollection, types.uuid, types.uuid,
                         int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of devices."""
        return self._get_pci_devices_collection(uuid,
                                          marker, limit, sort_key, sort_dir)

    @wsme_pecan.wsexpose(PCIDeviceCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of devices with detail."""

        # NOTE: /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "pci_devices":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['pci_devices', 'detail'])
        return self._get_pci_devices_collection(uuid, marker, limit, sort_key,
                                                sort_dir, expand, resource_url)

    @wsme_pecan.wsexpose(PCIDevice, types.uuid)
    def get_one(self, device_uuid):
        """Retrieve information about the given device."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_device = objects.pci_device.get_by_uuid(
            pecan.request.context, device_uuid)
        return PCIDevice.convert_with_links(rpc_device)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [PCIDevicePatchType])
    @wsme_pecan.wsexpose(PCIDevice, types.uuid,
                         body=[PCIDevicePatchType])
    def patch(self, device_uuid, patch):
        """Update an existing device."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_device = objects.pci_device.get_by_uuid(
            pecan.request.context, device_uuid)

        # replace host_uuid and with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        for p in patch_obj:
            if p['path'] == '/host_uuid':
                p['path'] = '/host_id'
                host = objects.host.get_by_uuid(pecan.request.context,
                                                p['value'])
                p['value'] = host.id

        try:
            device = PCIDevice(**jsonpatch.apply_patch(rpc_device.as_dict(),
                                                       patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Semantic checks
        host = pecan.request.dbapi.ihost_get(device.host_id)
        _check_host(host)

        # Update fields that have changed
        for field in objects.pci_device.fields:
            if rpc_device[field] != getattr(device, field):
                _check_field(field)
                rpc_device[field] = getattr(device, field)

        rpc_device.save()
        return PCIDevice.convert_with_links(rpc_device)


def _check_host(host):
    if utils.is_aio_simplex_host_unlocked(host):
        raise wsme.exc.ClientSideError(_('Host must be locked.'))
    elif host.administrative != constants.ADMIN_LOCKED and not \
            utils.is_host_simplex_controller(host):
        raise wsme.exc.ClientSideError(_('Host must be locked.'))
    if constants.WORKER not in host.subfunctions:
        raise wsme.exc.ClientSideError(_('Can only modify worker node cores.'))


def _check_field(field):
    if field not in ["enabled", "name"]:
        raise wsme.exc.ClientSideError(_('Modifying %s attribute restricted') % field)
