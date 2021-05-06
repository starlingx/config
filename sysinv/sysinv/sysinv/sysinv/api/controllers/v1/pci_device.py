# Copyright (c) 2015-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
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
from sysinv.common import device as dconstants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

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

    sriov_vf_driver = wtypes.text
    "The driver of configured SR-IOV VFs"

    sriov_vf_pdevice_id = wtypes.text
    "The SR-IOV VF PCI device id for this device"

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

    bmc_build_version = wtypes.text
    "Represent the BMC build version of the fpga device"

    bmc_fw_version = wtypes.text
    "Represent the BMC firmware version of the fpga device"

    root_key = wtypes.text
    "Represent the root key of the fpga device"

    revoked_key_ids = wtypes.text
    "Represent the key revocation ids of the fpga device"

    boot_page = wtypes.text
    "Represent the boot page of the fpga device"

    bitstream_id = wtypes.text
    "Represent the bitstream id of the fpga device"

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
                                        'sriov_vfs_pci_address',
                                        'sriov_vf_driver',
                                        'sriov_vf_pdevice_id', 'driver',
                                        'host_uuid', 'enabled',
                                        'bmc_build_version', 'bmc_fw_version',
                                        'root_key', 'revoked_key_ids',
                                        'boot_page', 'bitstream_id',
                                        'created_at', 'updated_at'])

        # do not expose the id attribute
        device.host_id = wtypes.Unset
        device.node_id = wtypes.Unset

        # if not FPGA device, hide these attributes
        if device.pclass_id != dconstants.PCI_DEVICE_CLASS_FPGA:
            device.bmc_build_version = wtypes.Unset
            device.bmc_fw_version = wtypes.Unset
            device.root_key = wtypes.Unset
            device.revoked_key_ids = wtypes.Unset
            device.boot_page = wtypes.Unset
            device.bitstream_id = wtypes.Unset

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

        # replace host_uuid with corresponding host_id
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

        sriov_update = _check_device_sriov(device.as_dict(), host)

        # Update fields that have changed
        for field in objects.pci_device.fields:
            value = getattr(device, field)
            if rpc_device[field] != value:
                _check_field(field)
                if (field in ['sriov_vf_driver', 'driver'] and
                        value == 'none'):
                    rpc_device[field] = None
                else:
                    rpc_device[field] = getattr(device, field)

        if sriov_update:
            # Set indication of pending configuration (runtime manifest apply)
            # for this device
            if not rpc_device['extra_info']:
                rpc_device['extra_info'] = ''
            rpc_device['extra_info'] += dconstants.DEVICE_APPLY_PENDING

        rpc_device.save()

        if sriov_update:
            pecan.request.rpcapi.update_sriov_config(
                pecan.request.context, host['uuid'])

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
    if field not in ["enabled", "name", "driver", "sriov_numvfs", "sriov_vf_driver"]:
        raise wsme.exc.ClientSideError(_('Modifying %s attribute restricted') % field)


def _check_device_sriov(device, host):
    sriov_update = False
    if (device['pdevice_id'] in dconstants.SRIOV_ENABLED_FEC_DEVICE_IDS and
            host.invprovision != constants.PROVISIONED):
        raise wsme.exc.ClientSideError(_("Cannot configure device %s "
                    "until host %s is unlocked for the first time." %
                    (device['uuid'], host.hostname)))

    if (device['pdevice_id'] not in dconstants.SRIOV_ENABLED_FEC_DEVICE_IDS and
            'sriov_numvfs' in device.keys() and device['sriov_numvfs']):
        raise wsme.exc.ClientSideError(_("The number of SR-IOV VFs is specified "
                                         "but the device is not supported for SR-IOV"))

    if (device['pdevice_id'] not in dconstants.SRIOV_ENABLED_FEC_DEVICE_IDS and
            'sriov_vf_driver' in device.keys() and device['sriov_vf_driver']):
        raise wsme.exc.ClientSideError(_("The SR-IOV VF driver is specified "
                                         "but the device is not supported for SR-IOV"))

    if device['pdevice_id'] not in dconstants.SRIOV_ENABLED_FEC_DEVICE_IDS:
        return sriov_update

    if 'sriov_numvfs' not in device.keys():
        raise wsme.exc.ClientSideError(_("The number of SR-IOV VFs must be specified"))
    else:
        if ('sriov_vf_driver' in device.keys() and device['sriov_vf_driver'] and
                device['sriov_vf_driver'] != dconstants.FPGA_INTEL_5GNR_FEC_DRIVER_NONE and
                device['sriov_numvfs'] is None):
            raise wsme.exc.ClientSideError(_("Value for number of SR-IOV VFs must be specified."))

        if device['sriov_numvfs'] and device['sriov_numvfs'] < 0:
            raise wsme.exc.ClientSideError(_("Value for number of SR-IOV VFs must be >= 0."))

        if ('sriov_vf_driver' in device.keys() and device['sriov_vf_driver'] and
                device['sriov_vf_driver'] != dconstants.FPGA_INTEL_5GNR_FEC_DRIVER_NONE and
                device['sriov_numvfs'] == 0):
            raise wsme.exc.ClientSideError(_("Value for number of SR-IOV VFs must be > 0."))

        if 'sriov_totalvfs' in device.keys():
            if not device['sriov_totalvfs']:
                raise wsme.exc.ClientSideError(_("SR-IOV cannot be configured on this interface"))
            if device['sriov_numvfs'] and device['sriov_numvfs'] > device['sriov_totalvfs']:
                raise wsme.exc.ClientSideError(_(
                    "The device supports a maximum of %s VFs" % device['sriov_totalvfs']))

    if 'sriov_vf_driver' not in device.keys():
        raise wsme.exc.ClientSideError(_("The SR-IOV VF driver must be specified"))
    else:
        if (device['sriov_vf_driver'] is not None and
                device['pdevice_id'] in
                dconstants.SRIOV_ENABLED_FEC_DEVICE_IDS and
                device['sriov_vf_driver'] not in
                dconstants.FPGA_INTEL_5GNR_FEC_VF_VALID_DRIVERS):
            msg = (_("Value for SR-IOV VF driver must be one of "
                "{}").format(', '.join(dconstants.FPGA_INTEL_5GNR_FEC_VF_VALID_DRIVERS)))
            raise wsme.exc.ClientSideError(msg)

    if ('driver' in device.keys() and device['driver'] and
            device['pdevice_id'] in dconstants.SRIOV_ENABLED_FEC_DEVICE_IDS and
            device['driver'] not in
            dconstants.FPGA_INTEL_5GNR_FEC_PF_VALID_DRIVERS):
        msg = (_("Value for SR-IOV PF driver must be one of "
                 "{}").format(', '.join(dconstants.FPGA_INTEL_5GNR_FEC_PF_VALID_DRIVERS)))
        raise wsme.exc.ClientSideError(msg)

    sriov_update = True
    return sriov_update
