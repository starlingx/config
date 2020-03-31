#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import utils
from cgtsclient.v1 import ihost as ihost_utils


def do_device_image_state_list(cc, args):
    """List image to device mapping with status."""

    device_image_state = cc.device_image_state.list()
    for d in device_image_state[:]:
        pdevice = cc.pci_device.get(d.pcidevice_uuid)
        setattr(d, 'pciaddr', getattr(pdevice, 'pciaddr'))
        host = ihost_utils._find_ihost(cc, getattr(pdevice, 'host_uuid'))
        setattr(d, 'hostname', host.hostname)
    labels = ['hostname', 'PCI device address', 'Device image uuid', 'status',
              'Update start time', 'updated_at']
    fields = ['hostname', 'pciaddr', 'image_uuid', 'status',
              'update_start_time', 'updated_at']
    utils.print_list(device_image_state, fields, labels, sortby=1)
