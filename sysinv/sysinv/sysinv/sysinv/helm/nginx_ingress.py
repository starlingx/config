#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging
from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import elastic

LOG = logging.getLogger(__name__)


class NginxIngressHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for nginx-ingress"""

    CHART = common.HELM_CHART_NGINX_INGRESS

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_MONITOR: {}}

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
