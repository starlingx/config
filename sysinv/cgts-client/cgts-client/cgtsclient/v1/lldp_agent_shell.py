#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient.v1 import ihost as ihost_utils


class LldpAgentObj:
    def __init__(self, dictionary):
        for k, v in dictionary.items():
            setattr(self, k, v)


def _print_lldp_agent_show(agent):
    fields = ['uuid', 'host_uuid',
              'created_at', 'updated_at',
              'uuid', 'port_name', 'chassis_id', 'port_identifier', 'ttl',
              'system_description', 'system_name', 'system_capabilities',
              'management_address', 'port_description', 'dot1_lag',
              'dot1_vlan_names',
              'dot3_mac_status', 'dot3_max_frame'
              ]
    labels = ['uuid', 'host_uuid',
              'created_at', 'updated_at',
              'uuid', 'local_port', 'chassis_id', 'port_identifier', 'ttl',
              'system_description', 'system_name', 'system_capabilities',
              'management_address', 'port_description', 'dot1_lag',
              'dot1_vlan_names',
              'dot3_mac_status', 'dot3_max_frame'
              ]
    data = [(f, getattr(agent, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


def _lldp_carriage_formatter(value):
    chars = ['\n', '\\n', '\r', '\\r']
    for char in chars:
        if char in value:
            value = value.replace(char, '. ')
    return value


def _lldp_system_name_formatter(lldp):
    system_name = getattr(lldp, 'system_name')
    if system_name:
        return _lldp_carriage_formatter(system_name)


def _lldp_system_description_formatter(lldp):
    system_description = getattr(lldp, 'system_description')
    if system_description:
        return _lldp_carriage_formatter(system_description)


def _lldp_port_description_formatter(lldp):
    port_description = getattr(lldp, 'port_description')
    if port_description:
        return _lldp_carriage_formatter(port_description)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_lldp_agent_list(cc, args):
    """List host lldp agents."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    agents = cc.lldp_agent.list(ihost.uuid)

    field_labels = ['uuid', 'local_port', 'status', 'chassis_id', 'port_id',
                    'system_name', 'system_description']
    fields = ['uuid', 'port_name', 'status', 'chassis_id', 'port_identifier',
              'system_name', 'system_description']
    formatters = {'system_name': _lldp_system_name_formatter,
                  'system_description': _lldp_system_description_formatter,
                  'port_description': _lldp_port_description_formatter}

    utils.print_list(agents, fields, field_labels, sortby=1,
                     formatters=formatters)


@utils.arg('uuid',
           metavar='<uuid>',
           help="UUID of the LLDP agent")
def do_lldp_agent_show(cc, args):
    """Show LLDP agent attributes."""
    agent = cc.lldp_agent.get(args.uuid)
    _print_lldp_agent_show(agent)
    return
