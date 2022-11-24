# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import zerorpc
from oslo_config import cfg
from sysinv.zmq_rpc.serializer import decode
from sysinv.zmq_rpc.serializer import encode


CONF = cfg.CONF


class ClientProvider(object):
    def __init__(self):
        self.clients = {}

    def _create_client(self, endpoint):
        # pylint: disable=unexpected-keyword-arg
        return zerorpc.Client(
            connect_to=endpoint,
            encoder=encode,
            decoder=decode,
            # TODO: with the default of 5s we get heartbeat timeouts when
            #  executing some RPCs that take longer than that to finish.
            #  We need to understand why this is happening because this scenario
            #  should be supported by zerorpc
            heartbeat=None,
            # TODO: we need to determine the correct timeout value here based on
            #  the max time an RPC can take to execute
            timeout=CONF.rpc_response_timeout)

    def get_client_for_endpoint(self, endpoint):
        client = self.clients.get(endpoint, None)
        if client is None:
            client = self._create_client(endpoint)
            self.clients[endpoint] = client
        return client

    def cleanup(self):
        for endpoint, client in self.clients.items():
            try:
                client.close()
            except Exception:
                pass
        self.clients.clear()
