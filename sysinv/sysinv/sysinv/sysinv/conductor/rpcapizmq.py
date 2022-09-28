# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

"""
Client side of the conductor RPC API using ZeroMQ backend.
"""

import os
from oslo_config import cfg
from oslo_log import log
from sysinv.common import constants
from sysinv.conductor.rpcapi import ConductorAPI as BaseConductorAPI
from sysinv.conductor.rpcapi import MANAGER_TOPIC
from sysinv.zmq_rpc.zmq_rpc import ZmqRpcClient

CONF = cfg.CONF
LOG = log.getLogger(__name__)


class ConductorAPI(ZmqRpcClient, BaseConductorAPI):
    def __init__(self, topic=None):
        if topic is None:
            topic = MANAGER_TOPIC
        host = CONF.rpc_zeromq_conductor_bind_ip

        # It is expected to have a value assigned
        # if we are using default value, puppet was not executed or
        # there was an issue.
        # We can still use it in case conductor is running locally
        # otherwise we try to communicate using controller hostname
        if host == "::" and not os.path.isfile("/var/run/sysinv-conductor.pid"):
            host = constants.CONTROLLER_HOSTNAME

        port = CONF.rpc_zeromq_conductor_bind_port
        super(ConductorAPI, self).__init__(host, port, topic)

    def call(self, context, msg, topic=None, version=None, timeout=None):
        return super(ConductorAPI, self).call(context, msg, timeout)

    def cast(self, context, msg, topic=None, version=None):
        return super(ConductorAPI, self).cast(context, msg)

    def fanout_cast(self, context, msg, topic=None, version=None):
        return super(ConductorAPI, self).fanout_cast(context, msg)
