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
import oslo_messaging
from oslo_service import service

from sysinv.cert_mon import messaging as rpc_messaging
from sysinv.cert_mon import utils
from sysinv.cert_mon.certificate_mon_manager import CertificateMonManager
from sysinv.common import constants

RPC_API_VERSION = '1.0'
TOPIC_DCMANAGER_NOTFICATION = 'DCMANAGER-NOTIFICATION'

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class CertificateMonitorService(service.Service):
    """Lifecycle manager for a running audit service."""

    def __init__(self):
        super(CertificateMonitorService, self).__init__()
        self.rpc_api_version = RPC_API_VERSION
        self.topic = TOPIC_DCMANAGER_NOTFICATION
        self._rpc_server = None
        self.target = None
        self.manager = CertificateMonManager()

    def start(self):
        super(CertificateMonitorService, self).start()
        self.manager.start_monitor()
        dc_role = utils.get_dc_role()
        if dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            self.manager.start_audit()
            self.target = oslo_messaging.Target(
                version=self.rpc_api_version,
                server=CONF.host,
                topic=self.topic)

            self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
            self._rpc_server.start()
        elif dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            self.manager.start_audit()

    def stop(self):
        dc_role = utils.get_dc_role()
        if dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            self._stop_rpc_server()
            self.manager.stop_audit()
        elif dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            self.manager.stop_audit()

        self.manager.stop_monitor()
        super(CertificateMonitorService, self).stop()
        rpc_messaging.cleanup()

    def _stop_rpc_server(self):
        # Stop RPC server
        try:
            self._rpc_server.stop()
            self._rpc_server.wait()
            LOG.info('Engine service stopped successfully')
        except Exception as ex:
            LOG.error('Failed to stop engine service: %s' % ex)
            LOG.exception(ex)

    def subcloud_online(self, context, subcloud_name=None):
        """
        Trigger a subcloud online audit
        """
        LOG.info("%s is online. An online audit is queued"
                 % subcloud_name)
        self.manager.audit_subcloud(subcloud_name)

    def subcloud_managed(self, context, subcloud_name=None):
        """
        Trigger a subcloud audit
        """
        LOG.info("%s is managed. An audit is queued"
                 % subcloud_name)
        self.manager.audit_subcloud(subcloud_name)
