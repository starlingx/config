# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2020 Wind River Systems, Inc.
#

"""
Client side of the agent RPC API.
"""

from oslo_log import log
from sysinv.objects import base as objects_base
import sysinv.openstack.common.rpc.proxy

LOG = log.getLogger(__name__)

MANAGER_TOPIC = 'sysinv.fpga_agent_manager'


class AgentAPI(sysinv.openstack.common.rpc.proxy.RpcProxy):
    """Client side of the agent RPC API.

    API version history:

        1.0 - Initial version.
    """

    RPC_API_VERSION = '1.0'

    def __init__(self, topic=None):
        if topic is None:
            topic = MANAGER_TOPIC

        super(AgentAPI, self).__init__(
            topic=topic,
            serializer=objects_base.SysinvObjectSerializer(),
            default_version=self.RPC_API_VERSION)

    def host_device_update_image(self, context, hostname, pci_addr,
                                 filename, transaction_id, retimer_included):
        LOG.info("sending device_update_image to host %s" % hostname)
        topic = '%s.%s' % (self.topic, hostname)
        return self.cast(context,
                         self.make_msg('device_update_image',
                                       pci_addr=pci_addr, filename=filename,
                                       transaction_id=transaction_id,
                                       retimer_included=retimer_included),
                         topic=topic)
