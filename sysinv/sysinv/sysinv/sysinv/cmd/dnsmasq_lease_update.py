#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#


"""
Handle lease database updates from dnsmasq DHCP server
This file was based on dhcpbridge.py from nova
"""

from __future__ import print_function

import sys
import os

from oslo_config import cfg

from sysinv.common import service as sysinv_service

from sysinv.openstack.common import context
from sysinv.conductor import rpcapi as conductor_rpcapi
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

CONF = cfg.CONF


def add_lease(mac, ip_address):
    """Called when a new lease is created."""

    ctxt = context.get_admin_context()
    rpcapi = conductor_rpcapi.ConductorAPI(topic=conductor_rpcapi.MANAGER_TOPIC)

    cid = None
    cid = os.getenv('DNSMASQ_CLIENT_ID')

    tags = None
    tags = os.getenv('DNSMASQ_TAGS')

    if tags is not None:
        # TODO: Maybe this shouldn't be synchronous - if this hangs, we could
        # cause dnsmasq to get stuck...
        rpcapi.handle_dhcp_lease(ctxt, tags, mac, ip_address, cid)


def old_lease(mac, ip_address):
    """Called when an old lease is recognized."""

    # This happens when a node is rebooted, but it can also happen if the
    # node was deleted and then rebooted, so we need to re-add in that case.

    ctxt = context.get_admin_context()
    rpcapi = conductor_rpcapi.ConductorAPI(topic=conductor_rpcapi.MANAGER_TOPIC)

    cid = None
    cid = os.getenv('DNSMASQ_CLIENT_ID')

    tags = None
    tags = os.getenv('DNSMASQ_TAGS')

    if tags is not None:
        # TODO: Maybe this shouldn't be synchronous - if this hangs, we could
        # cause dnsmasq to get stuck...
        rpcapi.handle_dhcp_lease(ctxt, tags, mac, ip_address, cid)


def del_lease(mac, ip_address):
    """Called when a lease expires."""
    # We will only delete the ihost when it is requested by the user.
    pass


def add_action_parsers(subparsers):
    # NOTE(cfb): dnsmasq always passes mac, and ip. hostname
    #            is passed if known. We don't care about
    #            hostname, but argparse will complain if we
    #            do not accept it.
    for action in ['add', 'del', 'old']:
        parser = subparsers.add_parser(action)
        parser.add_argument('mac')
        parser.add_argument('ip')
        parser.add_argument('hostname', nargs='?', default='')
        parser.set_defaults(func=globals()[action + '_lease'])


CONF.register_cli_opt(
    cfg.SubCommandOpt('action',
                      title='Action options',
                      help='Available dnsmasq_lease_update options',
                      handler=add_action_parsers))


def main():
    # Parse config file and command line options, then start logging
    # The mac is to be truncated to 17 characters, which is the proper
    # length of a mac address, in order to handle IPv6 where a DUID
    # is provided instead of a mac address.  The truncated DUID is
    # then equivalent to the mac address.
    sysinv_service.prepare_service(sys.argv)

    LOG = log.getLogger(__name__)

    if CONF.action.name in ['add', 'del', 'old']:
        msg = (_("Called '%(action)s' for mac '%(mac)s' with ip '%(ip)s'") %
               {"action": CONF.action.name,
                "mac": CONF.action.mac[-17:],
                "ip": CONF.action.ip})
        LOG.info(msg)
        CONF.action.func(CONF.action.mac[-17:], CONF.action.ip)
    else:
        LOG.error(_("Unknown action: %(action)") % {"action":
                                                    CONF.action.name})
