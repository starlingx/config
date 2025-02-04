# Copyright (c) 2022,2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

from oslo_config import cfg
from oslo_log import log

import sysinv.conductor.rpcapi as rpcapi
from sysinv.conductor.rpcapi import ConductorAPI as AMQPConductorAPI
from sysinv.conductor.rpcapizmq import ConductorAPI as ZMQConductorAPI

LOG = log.getLogger(__name__)
MANAGER_TOPIC = rpcapi.MANAGER_TOPIC


def ConductorAPI(topic=None):
    rpc_backend_zeromq = cfg.CONF.rpc_backend_zeromq
    rpc_backend = cfg.CONF.rpc_backend
    LOG.debug("Current conductor rpc_backend: {} "
              "use_zeromq: {}".format(rpc_backend,
                                      rpc_backend_zeromq
                                      ))
    if rpc_backend_zeromq:
        return ZMQConductorAPI(topic)
    # TODO(RemoveOpenstackRPCBackend): The legacy openstack.common.rpc backend
    # is not used anymore. However the unit tests use a fake implementation of
    # this backend. Unit tests need to be adjusted to use a mockable/fake
    # version zeromq rpc backend and then the legacy openstack.common.rpc code
    # can be removed from source tree.
    # We return the AMQPConductorAPI here just for the unit tests.
    LOG.warn(f"Using rpc_backend {rpc_backend} is only intended for unit tests")
    return AMQPConductorAPI(topic)
