# Copyright (c) 2020-2022 Wind River Systems, Inc.
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
import oslo_messaging
from oslo_service import service

from sysinv.cert_mon import messaging as rpc_messaging
from sysinv.cert_mon import utils
from sysinv.cert_mon.certificate_mon_manager import CertificateMonManager
from sysinv.common import constants

RPC_API_VERSION = '1.0'
TOPIC_DCMANAGER_NOTFICATION = 'DCMANAGER-NOTIFICATION'

DC_ROLE_TIMEOUT_SECONDS = 180
DC_ROLE_DELAY_SECONDS = 5

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
        self.dc_role = utils.DC_ROLE_UNDETECTED
        self.manager = CertificateMonManager()

    def start(self):
        super(CertificateMonitorService, self).start()
        self._get_dc_role()
        self.manager.start_monitor(self.dc_role)
        # Note: self.dc_role can be None (if non-DC system):
        if self.dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            self.manager.start_audit()
            self.target = oslo_messaging.Target(
                version=self.rpc_api_version,
                server=CONF.host,
                topic=self.topic)
            self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
            self._rpc_server.start()
        elif self.dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            self.manager.start_audit()

    def stop(self):
        if self.dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            self._stop_rpc_server()
            self.manager.stop_audit()
        elif self.dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            self.manager.stop_audit()
        self.manager.stop_monitor()
        super(CertificateMonitorService, self).stop()
        rpc_messaging.cleanup()

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

    def _stop_rpc_server(self):
        # Stop RPC server
        # only for DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER
        if self._rpc_server:
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

    def subcloud_sysinv_endpoint_update(self, ctxt, subcloud_name, endpoint):
        """Update sysinv endpoint of dc token cache"""
        LOG.info("Update subloud: %s sysinv endpoint" % subcloud_name)
        self.manager.subcloud_sysinv_endpoint_update(subcloud_name, endpoint)
