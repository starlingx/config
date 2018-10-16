#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import netaddr

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.common.storage_backend_conf import K8RbdProvisioner
from sysinv.openstack.common import log as logging

from . import base
from . import common

LOG = logging.getLogger(__name__)


class RbdProvisionerHelm(base.BaseHelm):
    """Class to encapsulate helm operations for the rbd-provisioner chart"""

    CHART = constants.HELM_CHART_RBD_PROVISIONER
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_KUBE_SYSTEM
    ]

    SERVICE_PORT_MON = 6789

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):

        def is_rbd_provisioner_bk(bk):
            if bk.services is None:
                return False

            # Note: No support yet for external ceph. For it to work we need to
            # get the ip addresses of the monitors from external ceph conf file
            # or add them as overrides.
            return (bk.backend == constants.CINDER_BACKEND_CEPH and
                    constants.SB_SVC_RBD_PROVISIONER in bk.services)

        backends = self.dbapi.storage_backend_get_list()
        rbd_provisioner_bks = [bk for bk in backends if is_rbd_provisioner_bk(bk)]

        if not rbd_provisioner_bks:
            return {}  # ceph is not configured

        ceph_mon_ips = StorageBackendConfig.get_ceph_mon_ip_addresses(
            self.dbapi).values()

        classdefaults = {
                          "monitors": [
                              self._format_ceph_mon_address(ceph_mon_ips[0]),
                              self._format_ceph_mon_address(ceph_mon_ips[1]),
                              self._format_ceph_mon_address(ceph_mon_ips[2])
                          ],
                          "adminId": constants.K8S_RBD_PROV_USER_NAME,
                          "adminSecretName": constants.K8S_RBD_PROV_ADMIN_SECRET_NAME
                        }

        classes = []
        for bk in rbd_provisioner_bks:
            cls = {
                    "name": K8RbdProvisioner.get_storage_class_name(bk),
                    "pool": K8RbdProvisioner.get_pool(bk),
                    "userId": K8RbdProvisioner.get_user_id(bk),
                    "userSecretName": K8RbdProvisioner.get_user_secret_name(bk)
                  }
            classes.append(cls)

        overrides = {
            common.HELM_NS_KUBE_SYSTEM: {
                "classdefaults": classdefaults,
                "classes": classes
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _format_ceph_mon_address(self, ip_address):
        if netaddr.IPAddress(ip_address).version == constants.IPV4_FAMILY:
            return '%s:%d' % (ip_address, self.SERVICE_PORT_MON)
        else:
            return '[%s]:%d' % (ip_address, self.SERVICE_PORT_MON)
