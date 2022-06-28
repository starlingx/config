# Copyright (c) 2021-2022 Wind River Systems, Inc.
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

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

from sysinv.cert_alarm.certificate_alarm_manager import CertificateAlarmManager

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class CertificateAlarmService(service.Service):
    """Lifecycle manager for a running audit service."""

    def __init__(self):
        super(CertificateAlarmService, self).__init__()
        self.manager = CertificateAlarmManager()

    def start(self):
        super(CertificateAlarmService, self).start()
        self.manager.start_audits()

    def stop(self):
        self.manager.stop_audits()
        super(CertificateAlarmService, self).stop()
