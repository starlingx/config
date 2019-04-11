#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from sysinv.helm import common
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)


class LibvirtHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the libvirt chart"""

    CHART = constants.HELM_CHART_LIBVIRT

    SERVICE_NAME = 'libvirt'

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'conf': {
                    'libvirt': {
                        'listen_addr': '0.0.0.0'
                    },
                    'ceph': {
                        'enabled': False
                    },
                    'qemu': {
                        'user': "root",
                        'group': "root",
                        'cgroup_controllers': ["cpu", "cpuacct", "cpuset"],
                        'namespaces': [],
                        'clear_emulator_capabilities': 0
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
