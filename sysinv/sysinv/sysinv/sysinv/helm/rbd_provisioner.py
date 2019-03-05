#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common.storage_backend_conf import K8RbdProvisioner
from sysinv.openstack.common import log as logging

from sysinv.helm import base
from sysinv.helm import common

LOG = logging.getLogger(__name__)


class RbdProvisionerHelm(base.BaseHelm):
    """Class to encapsulate helm operations for the rbd-provisioner chart"""

    CHART = constants.HELM_CHART_RBD_PROVISIONER
    SUPPORTED_NAMESPACES = \
        base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_OPENSTACK]

    SERVICE_NAME = 'rbd-provisioner'
    SERVICE_PORT_MON = 6789

    def get_overrides(self, namespace=None):

        backends = self.dbapi.storage_backend_get_list()
        ceph_bks = [bk for bk in backends if bk.backend == constants.SB_TYPE_CEPH]

        if not ceph_bks:
            return {}  # ceph is not configured

        classdefaults = {
            "monitors": self._get_formatted_ceph_monitor_ips(),
            "adminId": constants.K8S_RBD_PROV_USER_NAME,
            "adminSecretName": constants.K8S_RBD_PROV_ADMIN_SECRET_NAME
        }

        # Get tier info.
        tiers = self.dbapi.storage_tier_get_list()

        classes = []
        for bk in ceph_bks:
            # Get the ruleset for the new kube-rbd pool.
            tier = next((t for t in tiers if t.forbackendid == bk.id), None)
            if not tier:
                raise Exception("No tier present for backend %s" % bk.name)

            rule_name = "{0}{1}{2}".format(
                tier.name,
                constants.CEPH_CRUSH_TIER_SUFFIX,
                "-ruleset").replace('-', '_')

            cls = {
                    "name": K8RbdProvisioner.get_storage_class_name(bk),
                    "pool_name": K8RbdProvisioner.get_pool(bk),
                    "replication": int(bk.capabilities.get("replication")),
                    "crush_rule_name": rule_name,
                    "chunk_size": 64,
                    "userId": K8RbdProvisioner.get_user_id(bk),
                    "userSecretName": K8RbdProvisioner.get_user_secret_name(bk)
                  }
            classes.append(cls)

        overrides = {
            common.HELM_NS_OPENSTACK: {
                "classdefaults": classdefaults,
                "classes": classes,
                "images": self._get_images_overrides(),
                "pods": self._get_pod_overrides()
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_pod_overrides(self):
        overrides = {
            'replicas': {
                'rbd-provisioner': self._num_controllers()
            }
        }
        return overrides

    def _get_images_overrides(self):
        # TODO: Remove after ceph upgrade
        # Format the name of the stx specific ceph config helper
        local_docker_registry_ip = self._get_management_address()
        ceph_config_helper_image = "{}:{}/{}/{}{}:{}".format(
            local_docker_registry_ip, common.REGISTRY_PORT, common.REPO_LOC,
            common.DOCKER_SRCS[self.docker_repo_source][common.IMG_PREFIX_KEY],
            'ceph-config-helper', self.docker_repo_tag)

        return {
            'tags': {
                'rbd_provisioner_storage_init': ceph_config_helper_image,
            }
        }
