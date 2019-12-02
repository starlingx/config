#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import iinterface as iinterface_utils


def _print_iinterface_show(cc, iinterface):
    fields = ['ifname', 'iftype', 'ports',
              'imac', 'imtu', 'ifclass', 'ptp_role',
              'aemode', 'schedpolicy', 'txhashpolicy',
              'uuid', 'ihost_uuid',
              'vlan_id', 'uses', 'used_by',
              'created_at', 'updated_at', 'sriov_numvfs', 'sriov_vf_driver']
    optional_fields = ['ipv4_mode', 'ipv6_mode', 'ipv4_pool', 'ipv6_pool']
    rename_fields = [{'field': 'dpdksupport', 'label': 'accelerated'}]
    data = [(f, getattr(iinterface, f, '')) for f in fields]
    data += [(f, getattr(iinterface, f, '')) for f in optional_fields
             if hasattr(iinterface, f)]
    data += [(f['label'], getattr(iinterface, f['field'], '')) for f in rename_fields
             if hasattr(iinterface, f['field'])]
    utils.print_tuple_list(data)


def _find_interface(cc, ihost, ifnameoruuid):
    interfaces = cc.iinterface.list(ihost.uuid)
    for i in interfaces:
        if i.ifname == ifnameoruuid or i.uuid == ifnameoruuid:
            break
    else:
        raise exc.CommandError('Interface not found: host %s if %s' % (ihost.hostname, ifnameoruuid))
    return i


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('ifnameoruuid',
           metavar='<interface name or uuid>',
           help="Name or UUID of interface")
def do_host_if_show(cc, args):
    """Show interface attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    i = _find_interface(cc, ihost, args.ifnameoruuid)
    iinterface_utils._get_ports(cc, ihost, i)

    _print_iinterface_show(cc, i)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('-a', '--all',
           action='store_true',
           help='List all interface, including those without a configured network type')
def do_host_if_list(cc, args):
    """List interfaces."""

    iinterfaces = cc.iinterface.list(args.hostnameorid)
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    for i in iinterfaces[:]:
        iinterface_utils._get_ports(cc, ihost, i)
        if not args.all:
            if i.ifclass is None and i.used_by == []:
                iinterfaces.remove(i)
        attr_str = "MTU=%s" % i.imtu
        if i.iftype == 'ae':
            attr_str = "%s,AE_MODE=%s" % (attr_str, i.aemode)
            if i.aemode in ['balanced', '802.3ad']:
                attr_str = "%s,AE_XMIT_POLICY=%s" % (
                    attr_str, i.txhashpolicy)
        if i.ifclass and i.ifclass == 'data':
            if False in i.dpdksupport:
                attr_str = "%s,accelerated=False" % attr_str
            else:
                attr_str = "%s,accelerated=True" % attr_str
        setattr(i, 'attrs', attr_str)

    field_labels = ['uuid', 'name', 'class', 'type', 'vlan id', 'ports',
                    'uses i/f', 'used by i/f', 'attributes']
    fields = ['uuid', 'ifname', 'ifclass', 'iftype', 'vlan_id', 'ports',
              'uses', 'used_by', 'attrs']
    utils.print_list(
        iinterfaces, fields, field_labels, sortby=0, no_wrap_fields=['ports'])


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('ifnameoruuid',
           metavar='<interface name or uuid>',
           help="Name or UUID of interface")
def do_host_if_delete(cc, args):
    """Delete an interface."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    i = _find_interface(cc, ihost, args.ifnameoruuid)
    cc.iinterface.delete(i.uuid)
    print('Deleted interface: host %s if %s' % (args.hostnameorid, args.ifnameoruuid))


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('ifname',
           metavar='<interface name>',
           help="Name of interface [REQUIRED]")
@utils.arg('iftype',
           metavar='<iftype>',
           choices=['ae', 'vlan', 'virtual', 'vf'],
           nargs='?',
           help="Type of the interface")
@utils.arg('-a', '--aemode',
           metavar='<ae mode>',
           choices=['balanced', 'active_standby', '802.3ad'],
           help='The AE mode (balanced or active_standby or 802.3ad)')
@utils.arg('-x', '--txhashpolicy',
           metavar='<txhashpolicy>',
           choices=['layer2', 'layer2+3', 'layer3+4'],
           help='The balanced tx distribution hash policy')
@utils.arg('-V', '--vlan_id',
           metavar='<vlan_id>',
           help='The VLAN id of the interface')
@utils.arg('-m', '--imtu',
           metavar='<mtu>',
           help='The MTU of the interface')
@utils.arg('-c', '--ifclass',
           metavar='<class>',
           choices=['platform', 'data', 'pci-passthrough', 'pci-sriov', 'none'],
           help='The class of the interface')
@utils.arg('portsorifaces',
           metavar='<portsorifaces>',
           nargs='+',
           help='Name of port(s) or interface(s) [REQUIRED]')
@utils.arg('--ipv4-mode',
           metavar='<ipv4_mode>',
           choices=['disabled', 'static', 'pool'],
           help='The IPv4 address mode of the interface')
@utils.arg('--ipv6-mode',
           metavar='<ipv6_mode>',
           choices=['disabled', 'static', 'link-local', 'pool'],
           help='The IPv6 address mode of the interface')
@utils.arg('--ipv4-pool',
           metavar='<ipv4 pool uuid or name>',
           help='The IPv4 address pool name or uuid if mode is set to \'pool\'')
@utils.arg('--ipv6-pool',
           metavar='<ipv6 pool uuid or name>',
           help='The IPv6 address pool name or uuid if mode is set to \'pool\'')
@utils.arg('-N', '--num-vfs',
           dest='sriov_numvfs',
           metavar='<sriov numvfs>',
           help='The number of SR-IOV VFs of the interface')
@utils.arg('--vf-driver',
           dest='sriov_vf_driver',
           metavar='<sriov vf driver>',
           choices=['netdevice', 'vfio'],
           help='The SR-IOV VF driver for this device')
@utils.arg('--ptp-role',
           dest='ptp_role',
           metavar='<ptp role>',
           choices=['master', 'slave', 'none'],
           help='The PTP role for this interface')
def do_host_if_add(cc, args):
    """Add an interface."""

    field_list = ['ifname', 'iftype', 'imtu', 'ifclass', 'aemode',
                  'txhashpolicy', 'vlan_id', 'ptp_role',
                  'ipv4_mode', 'ipv6_mode', 'ipv4_pool', 'ipv6_pool',
                  'sriov_numvfs', 'sriov_vf_driver']

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    if 'iftype' in user_specified_fields.keys():
        if args.iftype == 'ae' or args.iftype == 'vlan':
            uses = args.portsorifaces
            portnamesoruuids = None
        elif args.iftype == 'virtual':
            uses = None
            portnamesoruuids = []
        elif args.iftype == 'vf':
            uses = args.portsorifaces
            portnamesoruuids = None
        else:
            uses = None
            portnamesoruuids = ','.join(args.portsorifaces)

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    user_specified_fields['ihost_uuid'] = ihost.uuid
    user_specified_fields['ports'] = portnamesoruuids
    user_specified_fields['uses'] = uses
    iinterface = cc.iinterface.create(**user_specified_fields)
    suuid = getattr(iinterface, 'uuid', '')
    try:
        iinterface = cc.iinterface.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created Interface UUID not found: %s' % suuid)

    iinterface_utils._get_ports(cc, ihost, iinterface)
    _print_iinterface_show(cc, iinterface)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('ifnameoruuid',
           metavar='<interface name or uuid>',
           help="Name or UUID of interface [REQUIRED]")
@utils.arg('-n', '--ifname',
           metavar='<new interface name>',
           help='The new name of the interface')
@utils.arg('-m', '--imtu',
           metavar='<mtu>',
           help='The MTU of the interface')
@utils.arg('-a', '--aemode',
           metavar='<ae mode>',
           choices=['balanced', 'active_standby', '802.3ad'],
           help='The AE mode (balanced or active_standby or 802.3ad)')
@utils.arg('-x', '--txhashpolicy',
           metavar='<txhashpolicy>',
           choices=['layer2', 'layer2+3', 'layer3+4'],
           help='The balanced tx distribution hash policy')
@utils.arg('-c', '--ifclass',
           metavar='<class>',
           help='The class of the interface')
@utils.arg('--ipv4-mode',
           metavar='<ipv4_mode>',
           choices=['disabled', 'static', 'pool'],
           help='The IPv4 address mode of the interface')
@utils.arg('--ipv6-mode',
           metavar='<ipv6_mode>',
           choices=['disabled', 'static', 'link-local', 'pool'],
           help='The IPv6 address mode of the interface')
@utils.arg('--ipv4-pool',
           metavar='<ipv4 pool uuid or name>',
           help='The IPv4 address pool name or uuid if mode is set to \'pool\'')
@utils.arg('--ipv6-pool',
           metavar='<ipv6 pool uuid or name>',
           help='The IPv6 address pool name or uuid if mode is set to \'pool\'')
@utils.arg('-N', '--num-vfs',
           dest='sriov_numvfs',
           metavar='<sriov numvfs>',
           help='The number of SR-IOV VFs of the interface')
@utils.arg('--vf-driver',
           dest='sriov_vf_driver',
           metavar='<sriov vf driver>',
           choices=['netdevice', 'vfio'],
           help='The SR-IOV VF driver for this device')
@utils.arg('--ptp-role',
           dest='ptp_role',
           metavar='<ptp role>',
           choices=['master', 'slave', 'none'],
           help='The PTP role for this interface')
def do_host_if_modify(cc, args):
    """Modify interface attributes."""

    rwfields = ['iftype', 'ifname', 'imtu', 'aemode', 'txhashpolicy',
                'ports', 'ifclass', 'ptp_role',
                'ipv4_mode', 'ipv6_mode', 'ipv4_pool', 'ipv6_pool',
                'sriov_numvfs', 'sriov_vf_driver']

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in rwfields and not (v is None))

    interface = _find_interface(cc, ihost, args.ifnameoruuid)
    fields = interface.__dict__
    fields.update(user_specified_fields)

    # Allow setting an interface back to a None type
    if 'ifclass' in user_specified_fields.keys():
        if args.ifclass == 'none':
            iinterface_utils._get_ports(cc, ihost, interface)
            if interface.ports or interface.uses:
                if interface.iftype != 'ae' and interface.iftype != 'vlan':
                    for p in interface.ports:
                        user_specified_fields['ifname'] = p
                        break

    patch = []
    for (k, v) in user_specified_fields.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    iinterface = cc.iinterface.update(interface.uuid, patch)
    iinterface_utils._get_ports(cc, ihost, iinterface)
    _print_iinterface_show(cc, iinterface)
