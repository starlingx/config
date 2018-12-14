#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import collections
from sysinv.common import constants

from . import base


class DevicePuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for device configuration"""

    def _get_device_id_index(self, host):
        """
        Builds a dictionary of device lists indexed by device id.
        """
        devices = collections.defaultdict(list)
        for device in self.dbapi.pci_device_get_all(hostid=host.id):
            devices[device.pdevice_id].append(device)
        return devices

    def _get_host_qat_device_config(self, pci_device_list):
        """
        Builds a config dictionary for QAT devices to be used by the platform
        devices (compute) puppet resource.
        """
        device_config = {}
        qat_c62x_devices = pci_device_list[constants.NOVA_PCI_ALIAS_QAT_C62X_PF_DEVICE]
        if len(qat_c62x_devices) != 0:
            for idx, device in enumerate(qat_c62x_devices):
                name = 'pci-%s' % device.pciaddr
                dev = {
                    'qat_idx': idx,
                    "device_id": "c62x",
                }
                device_config.update({name: dev})

        qat_dh895xcc_devices = pci_device_list[constants.NOVA_PCI_ALIAS_QAT_DH895XCC_PF_DEVICE]
        if len(qat_dh895xcc_devices) != 0:
            for idx, device in enumerate(qat_dh895xcc_devices):
                name = 'pci-%s' % device.pciaddr
                dev = {
                    'qat_idx': idx,
                    "device_id": "dh895xcc",
                }
                device_config.update({name: dev})

        if len(device_config) == 0:
            return {}

        return {
            'platform::devices::qat::device_config': device_config,
            'platform::devices::qat::service_enabled': True,
        }

    def get_host_config(self, host):
        if constants.WORKER not in host.subfunctions:
            # configuration only required for compute hosts
            return {}

        devices = self._get_device_id_index(host)
        if len(devices) == 0:
            # no pci devices on the system
            return {}

        device_config = {}

        qat_devices = self._get_host_qat_device_config(devices)
        if qat_devices:
            device_config.update(qat_devices)

        return device_config
