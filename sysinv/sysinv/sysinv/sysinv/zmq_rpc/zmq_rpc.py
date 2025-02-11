# Copyright (c) 2022-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import dns.resolver
import zerorpc
import eventlet

from eventlet import greenthread
from oslo_log import log
from zerorpc import exceptions

from sysinv.db import api
from sysinv.common import constants
from sysinv.common import utils
from sysinv.objects.base import SysinvObject
from sysinv.zmq_rpc.client_provider import ClientProvider
from sysinv.zmq_rpc.serializer import decode
from sysinv.zmq_rpc.serializer import encode
import sysinv.openstack.common.rpc.common as rpc_common

LOG = log.getLogger(__name__)

client_provider = ClientProvider()


class RpcWrapper(object):
    def __init__(self, target):
        self.target = target
        self.target_methods = [f for f in dir(self.target) if
                               not f.startswith('_')]

    def __getattr__(self, func):
        def method(context, **kwargs):
            if func in self.target_methods:
                # hydrate any sysinv object passed as argument with the context
                kwargs = self._inject_context(context, kwargs)
                LOG.debug("Calling RPC server method {} with context {} args {}"
                          .format(func, context, kwargs))
                retval = getattr(self.target, func)(context, **kwargs)
                LOG.debug("Finished RPC server method {} with context {} args {}"
                          .format(func, context, kwargs))
                return retval
            else:
                raise AttributeError

        return method

    def __dir__(self):
        return dir(self.target)

    def _process_iterable(self, context, action_fn, values):
        """Process an iterable, taking an action on each value.
        :param:context: Request context
        :param:action_fn: Action to take on each item in values
        :param:values: Iterable container of things to take action on
        :returns: A new container of the same type (except set) with
                  items from values having had action applied.
        """
        iterable = values.__class__
        if iterable == set:
            # NOTE(danms): A set can't have an unhashable value inside, such as
            # a dict. Convert sets to tuples, which is fine, since we can't
            # send them over RPC anyway.
            iterable = tuple
        return iterable([action_fn(context, value) for value in values])

    def _inject_context_to_arg(self, ctx, arg):
        if isinstance(arg, SysinvObject):
            arg._context = ctx
        elif isinstance(arg, (tuple, list, set)):
            arg = self._process_iterable(ctx, self._inject_context_to_arg, arg)
        return arg

    def _inject_context(self, context, kwargs):
        new_kwargs = dict()
        for argname, arg in kwargs.items():
            new_kwargs[argname] = self._inject_context_to_arg(context, arg)
        return new_kwargs


class ZmqRpcServer(object):
    def __init__(self, target, host, port):
        self.target = target
        self.host = host
        self.port = port
        self.endpoint = get_tcp_endpoint(host, port)
        self.server = None

    def run(self):
        def _run_in_thread():
            try:
                if self.host in [constants.CONTROLLER_FQDN,
                                 constants.CONTROLLER_0_FQDN,
                                 constants.CONTROLLER_1_FQDN]:
                    v4_results = dns.resolver.resolve(self.host, 'A',
                                                      raise_on_no_answer=False)
                    v6_results = dns.resolver.resolve(self.host, 'AAAA',
                                                      raise_on_no_answer=False)
                    host_ip = None
                    dns_results = None
                    if v6_results:
                        dns_results = v6_results
                    elif v4_results:
                        dns_results = v4_results
                    if dns_results is not None:
                        host_ip = dns_results[0]
                    else:
                        LOG.error("Failed to resolve DNS host {}".format(self.host))
                        return

                    self.endpoint = get_tcp_endpoint(host_ip, self.port)
                    LOG.debug("Resolved fqdn host={} host_ip={} endpoint={}"
                              .format(self.host, host_ip, self.endpoint))

                LOG.info("Starting zmq server at {}".format(self.endpoint))
                # pylint: disable=unexpected-keyword-arg
                # TODO with the default of 5s hearbeat we get LostRemote
                #  exceptions when executing some RPCs that take longer than
                #  that to finish. We need to understand why this happens
                #  because this scenario should be supported by zerorpc
                self.server = zerorpc.Server(RpcWrapper(self.target),
                                             heartbeat=None,
                                             encoder=encode,
                                             decoder=decode)
                self.server.bind(self.endpoint)
                self.server.run()
            except eventlet.greenlet.GreenletExit:
                return
            except Exception as e:
                LOG.error("Error while running zmq rpc server at {}: "
                          "{}".format(self.endpoint, str(e)))
                return

        return greenthread.spawn(_run_in_thread)

    def stop(self):
        if self.server:
            self.server.close()
            client_provider.cleanup()


class ZmqRpcClient(object):
    def __init__(self, host, port, topic):
        try:
            self.host = host
            self.port = port
            self.topic = topic
            self.client = None
            if host is not None:
                endpoint = get_tcp_endpoint(host, port)
                self.client = client_provider.get_client_for_endpoint(endpoint)

            LOG.debug("Started zmq rpc client to [{}]:{}".format(
                self.host, self.port))
        except Exception as e:
            LOG.error("Error while running zmq client to {}:{}: {}".format(
                self.host, self.port, str(e)))

    def _exec(self, client, context, method, **kwargs):
        if not client:
            host_uuid = kwargs.get('host_uuid', None)
            if host_uuid is None:
                raise Exception(f"Remote call/cast to {method} is missing "
                                f"host_uuid parameter for rpc endpoint")
            dbapi = api.get_instance()
            host = dbapi.ihost_get(host_uuid)
            if (utils.is_fqdn_ready_to_use()
                    and host.personality == constants.CONTROLLER):
                if host.hostname == constants.CONTROLLER_0_HOSTNAME:
                    host_fqdn = constants.CONTROLLER_0_FQDN
                elif host.hostname == constants.CONTROLLER_1_HOSTNAME:
                    host_fqdn = constants.CONTROLLER_1_FQDN
                endpoint = get_tcp_endpoint(host_fqdn, self.port)
            else:
                address = utils.get_primary_address_by_name(dbapi,
                                    utils.format_address_name(host.hostname,
                                                    constants.NETWORK_TYPE_MGMT),
                                    constants.NETWORK_TYPE_MGMT, True)
                endpoint = get_tcp_endpoint(address.address, self.port)
            client = client_provider.get_client_for_endpoint(endpoint)

        try:
            LOG.debug(
                "Calling RPC client method {} with context {} args {}".format(
                    method, context, kwargs))
            return getattr(client, method)(context, **kwargs)
        except exceptions.TimeoutExpired:
            raise rpc_common.Timeout(topic=self.topic,
                                     method=method)
        except exceptions.RemoteError as e:
            raise rpc_common.RemoteError(exc_type=e.name,
                                         value=e.msg,
                                         traceback=e.traceback)
        except exceptions.LostRemote as e:
            raise rpc_common.LostRemote(lost_remote_msg=str(e),
                                        topic=self.topic,
                                        method=method)

    def call(self, context, msg, timeout=None):
        method = msg['method']
        args = msg['args']
        if timeout is not None:
            args['timeout_'] = timeout
        return self._exec(self.client, context, method, **args)

    def cast(self, context, msg):
        method = msg['method']
        args = msg['args']
        args['async_'] = True
        return self._exec(self.client, context, method, **args)

    def fanout_cast(self, context, msg):
        method = msg['method']
        args = msg['args']
        args['async_'] = True
        endpoints = self.get_fanout_endpoints()
        for endpoint in endpoints:
            client = client_provider.get_client_for_endpoint(endpoint)
            LOG.debug("Calling fanout method {} to endpoint {}".format(
                method, endpoint))
            self._exec(client, context, method, **args)

    def get_fanout_endpoints(self):
        endpoints = []
        dbapi = api.get_instance()
        hosts = dbapi.ihost_get_list()
        for host in hosts:
            LOG.debug(
                "Evaluating host {} to add as endpoint ("
                "availability={}, operational={}, "
                "personality={}, subfunctions={})".format(
                    host.hostname, host.availability, host.operational,
                    host.personality, host.subfunctions))
            if (utils.is_initial_config_complete() and utils.is_fqdn_ready_to_use()
                    and host.personality == constants.CONTROLLER):
                if host.hostname == constants.CONTROLLER_0_HOSTNAME:
                    host_fqdn = constants.CONTROLLER_0_FQDN
                elif host.hostname == constants.CONTROLLER_1_HOSTNAME:
                    host_fqdn = constants.CONTROLLER_1_FQDN
                endpoint = get_tcp_endpoint(host_fqdn, self.port)
            else:
                address = utils.get_primary_address_by_name(
                    dbapi,
                    utils.format_address_name(
                        host.hostname,
                        constants.NETWORK_TYPE_MGMT),
                    constants.NETWORK_TYPE_MGMT,
                    False)

                if address:
                    endpoint = get_tcp_endpoint(address.address, self.port)
                else:
                    LOG.error(
                        "Skipping host %s as its address could not be found",
                        host.hostname if host.hostname else "unknown-host",
                    )
                    continue

            endpoints.append(endpoint)
            LOG.debug("Add host {} with endpoint {} to fanout request".format(
                host.hostname, endpoint))
        if not endpoints:
            endpoint = get_tcp_endpoint("::", self.port)
            LOG.warning("No host available. Add localhost with endpoint {} "
                        "to fanout request.".format(endpoint))
            endpoints.append(endpoint)
        return endpoints


def get_tcp_endpoint(host, port):
    return "tcp://[{}]:{}".format(host, port)


def check_connection(host, port):
    ret = True
    endpoint = get_tcp_endpoint(host, port)
    client = client_provider.get_client_for_endpoint(endpoint)
    try:
        client._zerorpc_list()
    except (zerorpc.TimeoutExpired, zerorpc.RemoteError):
        ret = False
    return ret
