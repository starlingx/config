# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System inventory Armada monitor manifest operator."""

from oslo_log import log

from sysinv.common import constants
from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import manifest_base as base
from sysinv.helm.logstash import LogstashHelm
from sysinv.helm.kibana import KibanaHelm
from sysinv.helm.elasticsearch_master import ElasticsearchMasterHelm
from sysinv.helm.elasticsearch_client import ElasticsearchClientHelm
from sysinv.helm.elasticsearch_curator import ElasticsearchCuratorHelm
from sysinv.helm.elasticsearch_data import ElasticsearchDataHelm
from sysinv.helm.filebeat import FilebeatHelm
from sysinv.helm.metricbeat import MetricbeatHelm
from sysinv.helm.nginx_ingress import NginxIngressHelm
from sysinv.helm.kube_state_metrics import KubeStateMetricsHelm

LOG = log.getLogger('object')


class MonitorArmadaManifestOperator(base.ArmadaManifestOperator):

    APP = constants.HELM_APP_MONITOR
    ARMADA_MANIFEST = 'monitor-armada-manifest'

    CHART_GROUP_NGINX = 'nginx-ingress'
    CHART_GROUP_KIBANA = 'kibana'
    CHART_GROUP_ELASTICSEARCH = 'elasticsearch'
    CHART_GROUP_ELASTICSEARCH_CURATOR = 'elasticsearch-curator'
    CHART_GROUP_LOGSTASH = 'logstash'
    CHART_GROUP_FILEBEAT = 'filebeat'
    CHART_GROUP_METRICBEAT = 'metricbeat'
    CHART_GROUP_KUBESTATEMETRICS = 'kube-state-metrics'
    CHART_GROUPS_LUT = {
        NginxIngressHelm.CHART: CHART_GROUP_NGINX,
        KibanaHelm.CHART: CHART_GROUP_KIBANA,
        ElasticsearchMasterHelm.CHART: CHART_GROUP_ELASTICSEARCH,
        ElasticsearchClientHelm.CHART: CHART_GROUP_ELASTICSEARCH,
        ElasticsearchDataHelm.CHART: CHART_GROUP_ELASTICSEARCH,
        ElasticsearchCuratorHelm.CHART: CHART_GROUP_ELASTICSEARCH_CURATOR,
        LogstashHelm.CHART: CHART_GROUP_LOGSTASH,
        FilebeatHelm.CHART: CHART_GROUP_FILEBEAT,
        MetricbeatHelm.CHART: CHART_GROUP_METRICBEAT,
        KubeStateMetricsHelm.CHART: CHART_GROUP_KUBESTATEMETRICS
    }

    CHARTS_LUT = {
        NginxIngressHelm.CHART: 'nginx-ingress',
        KibanaHelm.CHART: 'kibana',
        ElasticsearchMasterHelm.CHART: 'elasticsearch-master',
        ElasticsearchClientHelm.CHART: 'elasticsearch-client',
        ElasticsearchDataHelm.CHART: 'elasticsearch-data',
        ElasticsearchCuratorHelm.CHART: 'elasticsearch-curator',
        LogstashHelm.CHART: 'logstash',
        FilebeatHelm.CHART: 'filebeat',
        MetricbeatHelm.CHART: 'metricbeat',
        KubeStateMetricsHelm.CHART: 'kube-state-metrics'
    }

    def manifest_chart_groups_disable(self, dbapi, namespace, chart_group):
        """ Disable charts in chart group

        :param dbapi: DB api object
        :param namespace: cgroup namespace
        :param chart_group: the manifest chart group
        """
        charts = []
        for k, v in self.CHART_GROUPS_LUT.items():
            if v == chart_group:
                charts.append(k)

        app_id = dbapi.kube_app_get(self.APP).id

        for chart in charts:
            db_helm_override = dbapi.helm_override_get(
                app_id, chart, namespace)

            db_helm_override.system_overrides.update({'enabled': False})
            dbapi.helm_override_update(
                app_id, chart, namespace,
                {'system_overrides': db_helm_override.system_overrides})

    def chart_group_remove(self, dbapi, namespace, chart_group):
        self.manifest_chart_groups_delete(self.ARMADA_MANIFEST, chart_group)
        self.manifest_chart_groups_disable(dbapi, namespace, chart_group)

    def platform_mode_manifest_updates(self, dbapi, mode):
        """ Update the application manifest based on the platform

        :param dbapi: DB api object
        :param mode: mode to control how to apply the application manifest
        """

        try:
            system = dbapi.isystem_get_one()
        except exception.NotFound:
            LOG.exception("System %s not found.")
            raise

        if (system.distributed_cloud_role ==
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):

            # remove the chart_groups not needed in this configuration
            self.chart_group_remove(dbapi,
                                    common.HELM_NS_MONITOR,
                                    self.CHART_GROUP_NGINX)
            self.chart_group_remove(dbapi,
                                    common.HELM_NS_MONITOR,
                                    self.CHART_GROUP_KIBANA)
            self.chart_group_remove(dbapi,
                                    common.HELM_NS_MONITOR,
                                    self.CHART_GROUP_ELASTICSEARCH)
            self.chart_group_remove(dbapi,
                                    common.HELM_NS_MONITOR,
                                    self.CHART_GROUP_ELASTICSEARCH_CURATOR)
