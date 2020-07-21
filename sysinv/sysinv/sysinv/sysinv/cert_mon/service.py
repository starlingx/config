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
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

from sysinv.cert_mon.certificate_mon_manager import CertificateMonManager

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class CertificateMonitorService(service.Service):
    """Lifecycle manager for a running audit service."""

    def __init__(self):
        super(CertificateMonitorService, self).__init__()
        self.manager = CertificateMonManager()

    def start(self):
        super(CertificateMonitorService, self).start()
        self.manager.start_audit()
        self.manager.start_monitor()

    def stop(self):
        self.manager.stop_audit()
        self.manager.stop_monitor()
        super(CertificateMonitorService, self).stop()
