# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import ipaddress
import netaddr
import uuid

from oslo_utils import timeutils
from sysinv.objects.base import SysinvObject
from sysinv.common.context import RequestContext
from sysinv.openstack.common.context import RequestContext as BaseRequestContext
from sysinv.openstack.common.rpc.amqp import RpcContext
from sysinv.openstack.common.rpc.common import CommonRpcContext


def encode(obj, chain=None):
    if isinstance(obj, (RequestContext, BaseRequestContext,
                        RpcContext, CommonRpcContext)):
        if isinstance(obj, RequestContext):
            context_type = b'request'
        elif isinstance(obj, BaseRequestContext):
            context_type = b'base_request'
        elif isinstance(obj, RpcContext):
            context_type = b'rpc'
        else:
            context_type = b'common_rpc'
        return {b'context': True,
                b'context_type': context_type,
                b'data': obj.to_dict()}
    if hasattr(obj, 'obj_to_primitive') and callable(obj.obj_to_primitive):
        return obj.obj_to_primitive()
    if isinstance(obj, datetime.datetime):
        return obj.strftime(timeutils.PERFECT_TIME_FORMAT)
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if netaddr and isinstance(obj, (netaddr.IPAddress, netaddr.IPNetwork)):
        return str(obj)
    if ipaddress and isinstance(obj,
                                (ipaddress.IPv4Address,
                                 ipaddress.IPv6Address)):
        return str(obj)
    if isinstance(obj, Exception):
        return repr(obj)
    return obj if chain is None else chain(obj)


def decode(obj, chain=None):
    try:
        if b'context' in obj:
            context_dict = obj[b'data']
            context_type = obj[b'context_type']
            if context_type == b'request':
                return RequestContext.from_dict(context_dict)
            if context_type == b'base_request':
                return BaseRequestContext.from_dict(context_dict)
            if context_type == b'rpc':
                return RpcContext.from_dict(context_dict)
            return CommonRpcContext.from_dict(context_dict)
        if isinstance(obj, dict) and 'sysinv_object.name' in obj:
            return SysinvObject.obj_from_primitive(obj)
        return obj if chain is None else chain(obj)
    except KeyError:
        return obj if chain is None else chain(obj)
