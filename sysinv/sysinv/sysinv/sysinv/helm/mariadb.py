#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import openstack


class MariadbHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the mariadb chart"""

    CHART = common.HELM_CHART_MARIADB

    def _num_server_replicas(self):
        return self._num_controllers()

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': {
                    'replicas': {
                        'server': self._num_server_replicas(),
                        'ingress': self._num_controllers()
                    }
                },
                'endpoints': self._get_endpoints_overrides(),
                'conf': {
                    'database': {
                        'config_override': self._get_database_config_override()
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

    def _get_database_config_override(self):
        listen_host = "0.0.0.0"
        if self._is_ipv6_cluster_service():
            listen_host = "::"
        return "[mysqld]\n" \
               "bind_address=::\n" \
               "wsrep_provider_options=\"evs.suspect_timeout=PT30S; " \
               "gmcast.peer_timeout=PT15S; " \
               "gmcast.listen_addr=tcp://%s:{{ tuple \"oslo_db\" " \
               "\"direct\" \"wsrep\" . | " \
               "include \"helm-toolkit.endpoints.endpoint_port_lookup\" }}\"" % listen_host

    def _get_endpoints_overrides(self):
        return {
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.CHART, [])
            }
        }
