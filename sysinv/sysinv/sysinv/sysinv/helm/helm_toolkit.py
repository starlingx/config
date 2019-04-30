#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from sysinv.helm import common
from sysinv.helm import base

LOG = logging.getLogger(__name__)


class HelmToolkitHelm(base.BaseHelm):
    """Class to encapsulate helm operations for the helm toolkit"""

    CHART = constants.HELM_CHART_HELM_TOOLKIT
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_HELM_TOOLKIT,
    ]

    # (WZ) This code will be moved to a proper place once meta-overrides
    # for the manifest can be generated not thru a specific chart.
    # Note: The application-apply mode is associated with the application not
    #       the namespace. So app_name needs to be passed in.
    def get_meta_overrides(self, namespace, app_name=None, mode=None):
        def _meta_overrides(app_name, mode):
            if not app_name:
                # Application is unknown, so ignore mode.
                LOG.info("App is None. Ignore mode.")
                return {}
            elif app_name not in constants.HELM_APP_APPLY_MODES.keys():
                LOG.info("App %s is not supported. Ignore mode." % app_name)
                return {}
            elif mode == constants.OPENSTACK_RESTORE_DB:
                # During application restore, first bring up
                # MariaDB service.
                return {
                    'schema': 'armada/Manifest/v1',
                    'metadata': {
                        'schema': 'metadata/Document/v1',
                        'name': 'armada-manifest'
                    },
                    'data': {
                        'release_prefix': 'osh',
                        'chart_groups': [
                            'kube-system-ingress',
                            'openstack-ingress',
                            'provisioner',
                            'openstack-mariadb',
                        ]
                    }
                }
            elif mode == constants.OPENSTACK_RESTORE_STORAGE:
                # After MariaDB data is restored, restore Keystone,
                # Glance and Cinder.
                return {
                    'schema': 'armada/Manifest/v1',
                    'metadata': {
                        'schema': 'metadata/Document/v1',
                        'name': 'armada-manifest'
                    },
                    'data': {
                        'release_prefix': 'osh',
                        'chart_groups': [
                            'kube-system-ingress',
                            'openstack-ingress',
                            'provisioner',
                            'openstack-mariadb',
                            'openstack-memcached',
                            'openstack-rabbitmq',
                            'openstack-keystone',
                            'openstack-glance',
                            'openstack-cinder',
                        ]
                    }
                }
            else:
                # When mode is OPENSTACK_RESTORE_NORMAL or None,
                # bring up all the openstack services.
                return {}

        overrides = {
            common.HELM_NS_HELM_TOOLKIT: _meta_overrides(app_name, mode)
        }
        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_HELM_TOOLKIT: {}
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
