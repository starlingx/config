#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import collections
from sysinv.common import constants
from sysinv.common import device as dconstants

from sysinv.puppet import base
from sysinv.puppet import quoted_str


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

    def _get_host_acclr_fec_device_config(self, pci_device_list):
        """
        Builds a config dictionary for FEC devices to be used by the
        platform devices (worker) puppet resource.
        """
        vf_config = {}
        device_config = {}
        acclr_config = {}
        puppet_dflt = 'platform::devices::fpga::fec::params::device_config'

        for dv in dconstants.ACCLR_FEC_RESOURCES:
            for device in pci_device_list[dv]:
                # Pass extra parameters to puppet
                if 'dvconf' in dconstants.ACCLR_FEC_RESOURCES[dv]:
                    acclr_config.update(
                         dconstants.ACCLR_FEC_RESOURCES[dv]['dvconf'])

                name = 'pci-%s' % device.pciaddr

                # Format the vf addresses as quoted strings in order to prevent
                # puppet from treating the address as a time/date value
                vf_addrs = device.get('sriov_vfs_pci_address', [])
                if vf_addrs:
                    vf_addrs = [quoted_str(addr.strip())
                                for addr in vf_addrs.split(",") if addr]
                    if len(vf_addrs) == device.get('sriov_numvfs', 0):
                        vf_driver = device.get('sriov_vf_driver', None)
                        if vf_driver:
                            if constants.SRIOV_DRIVER_TYPE_VFIO in vf_driver:
                                vf_driver = constants.SRIOV_DRIVER_VFIO_PCI
                        for addr in vf_addrs:
                            vf_config.update({
                                addr: {
                                    'addr': addr,
                                    'driver': vf_driver
                                }
                            })

                pf_config = {
                    device.pciaddr: {
                        'num_vfs': device['sriov_numvfs'],
                        'addr': quoted_str(device['pciaddr'].strip()),
                        'driver': device['driver'],
                        'device_id': device['pdevice_id']
                    }
                }
                device_config = {
                    name: {
                        'pf_config': pf_config,
                        'vf_config': vf_config
                    }
                }

            acclr_config.update({puppet_dflt: device_config})

        return acclr_config

    def _get_host_acclr_device_config(self, pci_device_list):
        """
        Builds a config dictionary for FEC devices to be used by the platform
        devices (worker) puppet resource.
        """
        acclr_config = {}
        for acclr_devid in dconstants.SRIOV_ENABLED_FEC_DEVICE_IDS:
            if acclr_devid not in pci_device_list:
                continue

            acclr_device = pci_device_list[acclr_devid]
            if acclr_device:
                acclr_config.update(self._get_host_acclr_fec_device_config(
                    acclr_device))

        return acclr_config

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

        acclr_devices = self._get_host_acclr_fec_device_config(devices)
        if acclr_devices:
            device_config.update(acclr_devices)

        return device_config
