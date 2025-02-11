# Copyright (c) 2022,2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

"""
Client side of the agent RPC API using ZeroMQ backend.
"""

from oslo_config import cfg
from oslo_log import log
from sysinv.agent.rpcapi import AgentAPI as BaseAgentAPI
from sysinv.agent.rpcapi import MANAGER_TOPIC
from sysinv.zmq_rpc.zmq_rpc import ZmqRpcClient

CONF = cfg.CONF
LOG = log.getLogger(__name__)


class AgentAPI(ZmqRpcClient, BaseAgentAPI):
    def __init__(self, topic=None):
        if topic is None:
            topic = MANAGER_TOPIC
        host = None
        port = CONF.rpc_zeromq_agent_bind_port
        super(AgentAPI, self).__init__(host, port, topic)

    def call(self, context, msg, topic=None, version=None, timeout=None):
        return super(AgentAPI, self).call(context, msg, timeout)

    def cast(self, context, msg, topic=None, version=None):
        return super(AgentAPI, self).cast(context, msg)

    def fanout_cast(self, context, msg, topic=None, version=None):
        return super(AgentAPI, self).fanout_cast(context, msg)
