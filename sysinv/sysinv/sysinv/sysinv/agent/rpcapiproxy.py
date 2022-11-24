# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

from oslo_config import cfg
from oslo_log import log
import sysinv.agent.rpcapi as rpcapi
from sysinv.agent.rpcapizmq import AgentAPI as ZMQAgentAPI
from sysinv.agent.rpcapi import AgentAPI as AMQPAgentAPI
from sysinv.zmq_rpc.zmq_rpc import is_rpc_hybrid_mode_active

LOG = log.getLogger(__name__)
MANAGER_TOPIC = rpcapi.MANAGER_TOPIC


def AgentAPI(topic=None):
    rpc_backend = cfg.CONF.rpc_backend
    rpc_backend_zeromq = cfg.CONF.rpc_backend_zeromq
    rpc_backend_hybrid_mode = is_rpc_hybrid_mode_active()
    LOG.debug("Current agent rpc_backend: {} "
              "use_zeromq: {} hybrid_mode: {}".format(rpc_backend,
                                                      rpc_backend_zeromq,
                                                      rpc_backend_hybrid_mode))
    if rpc_backend_zeromq:
        return ZMQAgentAPI(topic)
    return AMQPAgentAPI(topic)
