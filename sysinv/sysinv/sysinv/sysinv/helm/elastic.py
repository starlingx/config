#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import re
from sysinv.helm import base
from sysinv.helm import common

from sysinv.common import constants


class ElasticBaseHelm(base.BaseHelm):
    """Class to encapsulate Elastic service operations for helm"""

    SUPPORTED_NAMESPACES = \
         base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_MONITOR]

    SUPPORTED_APP_NAMESPACES = {
        constants.HELM_APP_MONITOR:
            base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_MONITOR]
    }

    # Size of elasticsearch data volume.
    DATA_VOLUME_SIZE_GB = 150

    NODE_PORT = 31001
    PREFIX = "mon"
    ELASTICSEARCH_CLIENT_PATH = "/%s-elasticsearch-client" % PREFIX

    @property
    def CHART(self):
        # subclasses must define the property: CHART='name of chart'
        # if an author of a new chart forgets this, NotImplementedError is raised
        raise NotImplementedError

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def _is_enabled(self, app_name, chart_name, namespace):
        """
        Check if the chart is enable at a system level

        :param app_name: Application name
        :param chart_name: Chart supplied with the application
        :param namespace: Namespace where the chart will be executed

        Returns true by default if an exception occurs as most charts are
        enabled.
        """
        return super(ElasticBaseHelm, self)._is_enabled(
            app_name, chart_name, namespace)

    def execute_manifest_updates(self, operator):
        # On application load this chart is enabled. Only disable if specified
        # by the user
        if not self._is_enabled(operator.APP, self.CHART,
                                common.HELM_NS_MONITOR):
            operator.chart_group_chart_delete(
                operator.CHART_GROUPS_LUT[self.CHART],
                operator.CHARTS_LUT[self.CHART])

    def get_system_info_overrides(self):
        # Get the system name and system uuid from the database
        # for use in setting overrides.  Also returns a massaged
        # version of the system name for use in elasticsearch index,
        # and beats templates.
        #
        # Since the system_name_for_index is used as the index name
        # in elasticsearch, in the beats templates, and in also in the url
        # setting up the templates, we must be fairly restrictive here.
        # The Helm Chart repeats this same regular expression substitution,
        # but we perform it here as well so the user can see what is being used
        # when looking at the overrides.

        system = self.dbapi.isystem_get_one()

        system_name = system.name.encode('utf8', 'strict')
        system_uuid = system.uuid.encode('utf8', 'strict')
        system_name_for_index = re.sub('[^A-Za-z0-9-]+', '', system_name.lower())

        # fields must be set to a non-empty value.
        if not system_name:
            system_name = "None"
        system_fields = {
            "name": system_name,
            "uid": system_uuid,
        }

        return system_fields, system_name_for_index
