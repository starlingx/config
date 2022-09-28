# Copyright (c) 2022 Wind River Systems, Inc.
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
from sysinv.zmq_rpc.zmq_rpc import is_rpc_hybrid_mode_active
from sysinv.zmq_rpc.zmq_rpc import is_zmq_backend_available

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
        if is_rpc_hybrid_mode_active():
            host_uuid = msg['args']['host_uuid']
            if not is_zmq_backend_available(host_uuid):
                LOG.debug("RPC hybrid mode is active and agent zmq backend is "
                          "not yet available in host {}. Calling RPC call "
                          "method {} through rabbitmq".format(host_uuid,
                                                              msg['method']))
                rpcapi = BaseAgentAPI()
                return rpcapi.call(context, msg, topic, version, timeout)

        return super(AgentAPI, self).call(context, msg, timeout)

    def cast(self, context, msg, topic=None, version=None):
        if is_rpc_hybrid_mode_active():
            host_uuid = msg['args']['host_uuid']
            if not is_zmq_backend_available(host_uuid):
                LOG.debug("RPC hybrid mode is active and agent zmq backend is "
                          "not yet available in host {}. Calling RPC cast "
                          "method {} through rabbitmq".format(host_uuid,
                                                              msg['method']))
                rpcapi = BaseAgentAPI()
                return rpcapi.cast(context, msg, topic, version)

        return super(AgentAPI, self).cast(context, msg)

    def fanout_cast(self, context, msg, topic=None, version=None):
        if is_rpc_hybrid_mode_active():
            method = msg['method']
            LOG.debug("RPC hybrid mode is active. Calling RPC fanout_cast "
                      "method {} through rabbitmq and zmq".format(method))
            rpcapi = BaseAgentAPI()
            rpcapi.fanout_cast(context, msg, topic, version)
        return super(AgentAPI, self).fanout_cast(context, msg)
