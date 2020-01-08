#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from oslo_log import log

from sysinv.common import constants
from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import elastic

import yaml

LOG = log.getLogger(__name__)


class ElasticsearchCuratorHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for elasticsearch curator"""

    CHART = common.HELM_CHART_ELASTICSEARCH_CURATOR

    def get_overrides(self, namespace=None):

        # Default to basing our limits on the system override value
        # for the elasticsearch-data pvc size.
        data_volume_size_gb = self.DATA_VOLUME_SIZE_GB

        # If there are user overrides for the elasticsearch-data
        # pvc, base our limits on those instead.
        app = self.dbapi.kube_app_get(constants.HELM_APP_MONITOR)
        db_chart = self.dbapi.helm_override_get(
            app_id=app.id,
            name=common.HELM_CHART_ELASTICSEARCH_DATA,
            namespace=common.HELM_NS_MONITOR)

        if db_chart:
            db_user_overrides = db_chart.user_overrides

            # Check if there are user overrides for storage.
            if db_user_overrides:
                user_overrides = yaml.load(db_user_overrides)
                try:
                    volume_resources = user_overrides['volumeClaimTemplate']
                    storage = volume_resources['resources']['requests']['storage']
                    # Only support Gi units, as elasticsearch-curator
                    # only accepts Gigabyte values.
                    if storage.endswith("Gi"):
                        data_volume_size_gb = int(storage[:-2])
                except KeyError:
                    pass
                except Exception as e:
                    LOG.warn("Cannot parse elasticsearch-data volume size: %s" % e)

        # Elasticsearch reports index size back to curator calculated over all
        # shards on all data nodes, so multiply by 2 as it is configured for
        # 2 shards per index (primary and replica, on 1 data node each).
        # If only one data node is present (AIO-SX or locked controller in a
        # dual controller config), curator will make the adjustment, and factor
        # down its given index size limits.
        data_volume_size_gb = 2 * data_volume_size_gb

        # Give 50% of elasticsearch data volume
        # to filebeat, 40% to metricbeat and 10% to collectd, all
        # modified by a safety margin due to elasticsearch disk allocation
        # settings and cronjob running every half hour.

        # Set margin factor to 83%, as elasticsearch currently has
        # default cluster.routing.allocation.disk settings set to:
        # low: 85%, high 90%, flood_stage: 95%.
        volume_size_with_margin_factor = 0.83 * data_volume_size_gb

        filebeat_limit_int = int(0.5 * volume_size_with_margin_factor)
        filebeat_limit = str(filebeat_limit_int)

        metricbeat_limit_int = int(0.4 * volume_size_with_margin_factor)
        metricbeat_limit = str(metricbeat_limit_int)

        collectd_limit_int = int(0.1 * volume_size_with_margin_factor)
        collectd_limit = str(collectd_limit_int)

        # Expose important overrides.
        overrides = {
            common.HELM_NS_MONITOR: {
                'env': {
                    'FILEBEAT_INDEX_LIMIT_GB': filebeat_limit,
                    'METRICBEAT_INDEX_LIMIT_GB': metricbeat_limit,
                    'COLLECTD_INDEX_LIMIT_GB': collectd_limit,
                },
                # Run job every half hour.
                'cronjob': {'schedule': "*/30 * * * *"},
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
