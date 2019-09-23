#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import openstack


class LibvirtHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the libvirt chart"""

    CHART = common.HELM_CHART_LIBVIRT

    SERVICE_NAME = common.HELM_CHART_LIBVIRT

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'conf': {
                    'libvirt': {
                        'listen_addr': '0.0.0.0'
                    },
                    'qemu': {
                        'user': "root",
                        'group': "root",
                        'cgroup_controllers': ["cpu", "cpuacct", "cpuset", "freezer", "net_cls", "perf_event"],
                        'namespaces': [],
                        'clear_emulator_capabilities': 0
                    }
                },
                'pod': {
                    'mounts': {
                        'libvirt': {
                            'libvirt': self._get_mount_uefi_overrides()
                        }
                    }
                }
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
