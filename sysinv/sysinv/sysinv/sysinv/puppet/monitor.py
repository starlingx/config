#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from sysinv.common import constants
from sysinv.common import utils
from sysinv.helm import common as helm_common
from sysinv.puppet import base


class MonitorPuppet(base.BasePuppet):
    """Class to encapsulate elastic monitor configuration"""

    LOGSTASH_COLLECTD_PORT = "31005"

    def get_system_config(self):

        config = {}
        if utils.is_monitor_applied(self.dbapi):

            logstash_active = utils.is_chart_enabled(
                self.dbapi, constants.HELM_APP_MONITOR,
                helm_common.HELM_CHART_LOGSTASH,
                helm_common.HELM_NS_MONITOR)

            if logstash_active:
                config = {
                    'platform::collectd::params::server_port':
                        self.LOGSTASH_COLLECTD_PORT,
                }

        return config
