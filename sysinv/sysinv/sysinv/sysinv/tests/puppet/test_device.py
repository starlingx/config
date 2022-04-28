# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.puppet import base
from sysinv.common import device as dconstants


class DeviceHostTestCase(base.PuppetTestCaseMixin,
                           dbbase.WorkerHostTestCase):

    def setUp(self):
        super(DeviceHostTestCase, self).setUp()
        self.pci_device1 = dbutils.create_test_pci_device(
            host_id=self.host.id,
            pciaddr='0000:b7:00.0',
            pdevice_id=dconstants.PCI_DEVICE_ID_ACC100_INTEL_5GNR_FEC_PF,
            pclass='Processing accelerators',
            pclass_id='120000',
            driver='igb_uio',
            sriov_totalvfs=8,
            sriov_numvfs=4,
            sriov_vf_driver='igb_uio',
            sriov_vfs_pci_address='0000:b7:00.1,0000:b7:00.2,0000:b7:00.3,0000:b7:00.4'
        )
        self.pci_device2 = dbutils.create_test_pci_device(
            host_id=self.host.id,
            pciaddr='0000:b4:00.0',
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            pclass='Processing accelerators',
            pclass_id='120000',
            driver='igb_uio',
            sriov_totalvfs=8,
            sriov_numvfs=4,
            sriov_vf_driver='igb_uio',
            sriov_vfs_pci_address='0000:b4:00.1,0000:b4:00.2,0000:b4:00.3,0000:b4:00.4'
        )
        self.pci_device3 = dbutils.create_test_pci_device(
            host_id=self.host.id,
            pciaddr='0000:b8:00.0',
            pdevice_id=dconstants.PCI_DEVICE_ID_ACC100_INTEL_5GNR_FEC_PF,
            pclass='Processing accelerators',
            pclass_id='120000',
            driver='igb_uio',
            sriov_totalvfs=8,
            sriov_numvfs=4,
            sriov_vf_driver='igb_uio',
            sriov_vfs_pci_address='0000:b8:00.1,0000:b8:00.2,0000:b8:00.3,0000:b8:00.4'
        )
        self.pci_device4 = dbutils.create_test_pci_device(
            host_id=self.host.id,
            pciaddr='0000:be:00.0',
            pdevice_id=dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            pclass='Processing accelerators',
            pclass_id='120000',
            driver='igb_uio',
            sriov_totalvfs=8,
            sriov_numvfs=4,
            sriov_vf_driver='igb_uio',
            sriov_vfs_pci_address='0000:be:00.1,0000:be:00.2,0000:be:00.3,0000:be:00.4'
        )

    def test_generate_fpga_fec_device_config(self):
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(
            self.mock_write_config, {
                'platform::devices::fpga::fec::params::device_config': {
                    'pci-0000:b7:00.0': {
                        'pf_config': {
                            '0000:b7:00.0': {
                                'addr': '0000:b7:00.0',
                                'device_id': '0d5c',
                                'driver': 'igb_uio',
                                'num_vfs': 4
                            }
                        },
                        'vf_config': {
                            '0000:b7:00.1': {
                                'addr': '0000:b7:00.1',
                                'driver': 'igb_uio'
                            },
                            '0000:b7:00.2': {
                                'addr': '0000:b7:00.2',
                                'driver': 'igb_uio'
                            },
                            '0000:b7:00.3': {
                                'addr': '0000:b7:00.3',
                                'driver': 'igb_uio'
                            },
                            '0000:b7:00.4': {
                                'addr': '0000:b7:00.4',
                                'driver': 'igb_uio'
                            }
                        }
                    },
                    'pci-0000:b4:00.0': {
                        'pf_config': {
                            '0000:b4:00.0': {
                                'addr': '0000:b4:00.0',
                                'device_id': '0d8f',
                                'driver': 'igb_uio',
                                'num_vfs': 4
                            }
                        },
                        'vf_config': {
                            '0000:b4:00.1': {
                                'addr': '0000:b4:00.1',
                                'driver': 'igb_uio'
                            },
                            '0000:b4:00.2': {
                                'addr': '0000:b4:00.2',
                                'driver': 'igb_uio'
                            },
                            '0000:b4:00.3': {
                                'addr': '0000:b4:00.3',
                                'driver': 'igb_uio'
                            },
                            '0000:b4:00.4': {
                                'addr': '0000:b4:00.4',
                                'driver': 'igb_uio'
                            }
                        }
                    },
                    'pci-0000:b8:00.0': {
                        'pf_config': {
                            '0000:b8:00.0': {
                                'addr': '0000:b8:00.0',
                                'device_id': '0d5c',
                                'driver': 'igb_uio',
                                'num_vfs': 4
                            }
                        },
                        'vf_config': {
                            '0000:b8:00.1': {
                                'addr': '0000:b8:00.1',
                                'driver': 'igb_uio'
                            },
                            '0000:b8:00.2': {
                                'addr': '0000:b8:00.2',
                                'driver': 'igb_uio'
                            },
                            '0000:b8:00.3': {
                                'addr': '0000:b8:00.3',
                                'driver': 'igb_uio'
                            },
                            '0000:b8:00.4': {
                                'addr': '0000:b8:00.4',
                                'driver': 'igb_uio'
                            }
                        }
                    },
                    'pci-0000:be:00.0': {
                        'pf_config': {
                            '0000:be:00.0': {
                                'addr': '0000:be:00.0',
                                'device_id': '0d8f',
                                'driver': 'igb_uio',
                                'num_vfs': 4
                            }
                        },
                        'vf_config': {
                            '0000:be:00.1': {
                                'addr': '0000:be:00.1',
                                'driver': 'igb_uio'
                            },
                            '0000:be:00.2': {
                                'addr': '0000:be:00.2',
                                'driver': 'igb_uio'
                            },
                            '0000:be:00.3': {
                                'addr': '0000:be:00.3',
                                'driver': 'igb_uio'
                            },
                            '0000:be:00.4': {
                                'addr': '0000:be:00.4',
                                'driver': 'igb_uio'
                            }
                        }
                    }
                }
            }
        )
