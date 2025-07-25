# Copyright (c) 2020-2023, 2025 Wind River Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

from sysinv.cert_mon import utils
from sysinv.cert_mon.certificate_mon_manager import CertificateMonManager

DC_ROLE_TIMEOUT_SECONDS = 180
DC_ROLE_DELAY_SECONDS = 5

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class CertificateMonitorService(service.Service):
    """Lifecycle manager for a running audit service."""

    def __init__(self):
        super(CertificateMonitorService, self).__init__()
        self.dc_role = utils.DC_ROLE_UNDETECTED
        self.manager = CertificateMonManager()

    def start(self):
        super(CertificateMonitorService, self).start()
        self._get_dc_role()
        utils.init_keystone_auth_opts()
        self.manager.start_monitor(self.dc_role)
        self.manager.start_periodic_tasks()

    def stop(self):
        self.manager.stop_periodic_tasks()
        self.manager.stop_monitor()
        super(CertificateMonitorService, self).stop()

    def _get_dc_role(self):
        if self.dc_role != utils.DC_ROLE_UNDETECTED:
            return self.dc_role
        utils.init_keystone_auth_opts()
        delay = DC_ROLE_DELAY_SECONDS
        max_dc_role_attempts = DC_ROLE_TIMEOUT_SECONDS // delay
        dc_role_attempts = 1
        while dc_role_attempts < max_dc_role_attempts:
            try:
                self.dc_role = utils.get_dc_role()
                return self.dc_role
            except Exception as e:
                LOG.info("Unable to get DC role: %s [attempt: %s]",
                         str(e), dc_role_attempts)
            time.sleep(delay)
            dc_role_attempts += 1
        raise Exception('Failed to obtain DC role from keystone')
