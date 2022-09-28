# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import os
from oslo_config import cfg
from oslo_log import log

import sysinv.conductor.rpcapi as rpcapi
from sysinv.conductor.rpcapi import ConductorAPI as AMQPConductorAPI
from sysinv.conductor.rpcapizmq import ConductorAPI as ZMQConductorAPI
from sysinv.zmq_rpc.zmq_rpc import is_rpc_hybrid_mode_active
from sysinv.zmq_rpc.zmq_rpc import check_connection

LOG = log.getLogger(__name__)
MANAGER_TOPIC = rpcapi.MANAGER_TOPIC


def ConductorAPI(topic=None):
    rpc_backend_zeromq = cfg.CONF.rpc_backend_zeromq
    rpc_backend_hybrid_mode = is_rpc_hybrid_mode_active()
    rpc_backend = cfg.CONF.rpc_backend
    LOG.debug("Current conductor rpc_backend: {} "
              "use_zeromq: {} hybrid_mode: {}".format(rpc_backend,
                                                      rpc_backend_zeromq,
                                                      rpc_backend_hybrid_mode))
    # Hybrid mode is expected to be defined for controller-1 only during upgrade
    # all other nodes should be running ZeroMQ exclusively
    if rpc_backend_hybrid_mode:
        # in controller-1 agent, we need to know if conductor
        # is able to listen to ZeroRPC.
        # If conductor is running on same host, we know it is running in
        # hybrid mode, and we assume ZeroMQ is preferred.
        # Otherwise, it can be conductor running on controller-0 before
        # migrate to ZeroMQ, so we verify before send the RPC call
        # if ZeroMQ is running and if yes, use it, otherwise use RabbitMQ
        if os.path.isfile("/var/run/sysinv-conductor.pid"):
            return ZMQConductorAPI(topic)
        else:
            if check_connection(cfg.CONF.rpc_zeromq_conductor_bind_ip,
                                cfg.CONF.rpc_zeromq_conductor_bind_port):
                return ZMQConductorAPI(topic)
            else:
                return AMQPConductorAPI(topic)
    if rpc_backend_zeromq:
        return ZMQConductorAPI(topic)
    return AMQPConductorAPI(topic)
