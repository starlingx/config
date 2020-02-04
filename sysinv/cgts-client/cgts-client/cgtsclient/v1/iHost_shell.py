#
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from collections import OrderedDict
import datetime
import os

from cgtsclient._i18n import _
from cgtsclient.common import constants
from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import icpu as icpu_utils
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import iinterface as iinterface_utils
from cgtsclient.v1 import iprofile as iprofile_utils
from cgtsclient.v1 import istor as istor_utils
from six.moves import input


def _print_ihost_show(ihost, columns=None, output_format=None):
    optional_fields = []
    if columns:
        fields = columns
    else:
        fields = ['id', 'uuid', 'personality', 'hostname', 'invprovision',
                  'administrative', 'operational', 'availability', 'task',
                  'action', 'mgmt_mac', 'mgmt_ip', 'serialid',
                  'capabilities', 'bm_type', 'bm_username', 'bm_ip',
                  'config_applied', 'config_target', 'config_status',
                  'location', 'uptime', 'reserved', 'created_at', 'updated_at',
                  'boot_device', 'rootfs_device', 'install_output', 'console',
                  'tboot', 'vim_progress_status', 'software_load',
                  'install_state', 'install_state_info', 'inv_state',
                  'clock_synchronization']
        optional_fields = ['vsc_controllers', 'ttys_dcd']
        if ihost.subfunctions != ihost.personality:
            fields.append('subfunctions')
            if 'controller' in ihost.subfunctions:
                fields.append('subfunction_oper')
                fields.append('subfunction_avail')
        if ihost.peers:
            fields.append('peers')

    # Do not display the trailing '+' which indicates the audit iterations
    if ihost.install_state_info:
        ihost.install_state_info = ihost.install_state_info.rstrip('+')
    if ihost.install_state:
        ihost.install_state = ihost.install_state.rstrip('+')

    data_list = [(f, getattr(ihost, f, '')) for f in fields]
    if optional_fields:
        data_list += [(f, getattr(ihost, f, '')) for f in optional_fields
                      if hasattr(ihost, f)]

    data = dict(data_list)

    utils.print_dict_with_format(data, wrap=72, output_format=output_format)


def _get_kube_host_upgrade_details(cc):
    # Get the list of kubernetes host upgrades
    kube_host_upgrades = cc.kube_host_upgrade.list()

    # Map the host_id to hostname and personality
    kube_host_upgrade_details = dict()
    for kube_host_upgrade in kube_host_upgrades:
        kube_host_upgrade_details[kube_host_upgrade.host_id] = {
            'target_version': kube_host_upgrade.target_version,
            'control_plane_version': kube_host_upgrade.control_plane_version,
            'kubelet_version': kube_host_upgrade.kubelet_version,
            'status': kube_host_upgrade.status}

    return kube_host_upgrade_details


@utils.arg('hostnameorid', metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('--column',
           action='append',
           default=[],
           help="Specify the column(s) to include, can be repeated")
@utils.arg('--format',
           choices=['table', 'yaml', 'value'],
           help="specify the output format, defaults to table")
def do_host_show(cc, args):
    """Show host attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    _print_ihost_show(ihost, args.column, args.format)


@utils.arg('--column',
           action='append',
           default=[],
           help="Specify the column(s) to include, can be repeated")
@utils.arg('--format',
           choices=['table', 'yaml', 'value'],
           help="specify the output format, defaults to table")
def do_host_list(cc, args):
    """List hosts."""
    ihosts = cc.ihost.list()

    if args.column:
        fields = args.column
    else:
        fields = ['id', 'hostname', 'personality', 'administrative',
                  'operational', 'availability']

    utils.print_list(ihosts, fields, fields, sortby=0,
                     output_format=args.format)


def do_host_upgrade_list(cc, args):
    """List software upgrade info for hosts."""
    ihosts = cc.ihost.list()
    field_labels = ['id', 'hostname', 'personality',
                    'running_release', 'target_release']
    fields = ['id', 'hostname', 'personality',
              'software_load', 'target_load']
    utils.print_list(ihosts, fields, field_labels, sortby=0)


def do_kube_host_upgrade_list(cc, args):
    """List kubernetes upgrade info for hosts."""

    # Get the list of hosts
    ihosts = cc.ihost.list()
    # Get the kubernetes host upgrades
    kube_host_upgrade_details = _get_kube_host_upgrade_details(cc)

    for host in ihosts:
        host.target_version = \
            kube_host_upgrade_details[host.id]['target_version']
        host.control_plane_version = \
            kube_host_upgrade_details[host.id]['control_plane_version']
        host.kubelet_version = \
            kube_host_upgrade_details[host.id]['kubelet_version']
        host.status = \
            kube_host_upgrade_details[host.id]['status']

    field_labels = ['id', 'hostname', 'personality', 'target_version',
                    'control_plane_version', 'kubelet_version', 'status']
    fields = ['id', 'hostname', 'personality', 'target_version',
              'control_plane_version', 'kubelet_version', 'status']
    utils.print_list(ihosts, fields, field_labels, sortby=0)


@utils.arg('-n', '--hostname',
           metavar='<hostname>',
           help='Hostname of the host')
@utils.arg('-p', '--personality',
           metavar='<personality>',
           choices=['controller', 'worker', 'storage', 'network', 'profile'],
           help='Personality or type of host [REQUIRED]')
@utils.arg('-s', '--subfunctions',
           metavar='<subfunctions>',
           choices=['lowlatency'],
           help='Performance profile or subfunctions of host.[Optional]')
@utils.arg('-m', '--mgmt_mac',
           metavar='<mgmt_mac>',
           help='MAC Address of the host mgmt interface [REQUIRED]')
@utils.arg('-i', '--mgmt_ip',
           metavar='<mgmt_ip>',
           help='IP Address of the host mgmt interface (when using static '
                'address allocation)')
@utils.arg('-I', '--bm_ip',
           metavar='<bm_ip>',
           help="IP Address of the host board management interface, "
                "only necessary if this host's board management controller "
                "is not in the primary region")
@utils.arg('-T', '--bm_type',
           metavar='<bm_type>',
           help='Type of the host board management interface')
@utils.arg('-U', '--bm_username',
           metavar='<bm_username>',
           help='Username for the host board management interface')
@utils.arg('-P', '--bm_password',
           metavar='<bm_password>',
           help='Password for the host board management interface')
@utils.arg('-b', '--boot_device',
           metavar='<boot_device>',
           help='Device for boot partition, relative to /dev. Default: sda')
@utils.arg('-r', '--rootfs_device',
           metavar='<rootfs_device>',
           help='Device for rootfs partition, relative to /dev. Default: sda')
@utils.arg('-o', '--install_output',
           metavar='<install_output>',
           choices=['text', 'graphical'],
           help='Installation output format, text or graphical. Default: text')
@utils.arg('-c', '--console',
           metavar='<console>',
           help='Serial console. Default: ttyS0,115200')
@utils.arg('-v', '--vsc_controllers',
           metavar='<vsc_controllers>',
           help='Comma separated active/standby VSC Controller IP addresses')
@utils.arg('-l', '--location',
           metavar='<location>',
           help='Physical location of the host')
@utils.arg('-D', '--ttys_dcd',
           metavar='<true/false>',
           help='Enable/disable serial console data carrier detection')
@utils.arg('-C', '--clock_synchronization',
           metavar='<clock_synchronization>',
           choices=['ntp', 'ptp'],
           help='Clock synchronization, ntp or ptp. Default: ntp')
def do_host_add(cc, args):
    """Add a new host."""
    field_list = ['hostname', 'personality', 'subfunctions',
                  'mgmt_mac', 'mgmt_ip',
                  'bm_ip', 'bm_type', 'bm_username', 'bm_password',
                  'boot_device', 'rootfs_device', 'install_output', 'console',
                  'vsc_controllers', 'location', 'ttys_dcd',
                  'clock_synchronization']
    fields = dict((k, v) for (k, v) in vars(args).items()
                  if k in field_list and not (v is None))

    # This is the expected format of the location field
    if 'location' in fields:
        fields['location'] = {"locn": fields['location']}

    ihost = cc.ihost.create(**fields)
    suuid = getattr(ihost, 'uuid', '')

    try:
        ihost = cc.ihost.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Host not found: %s' % suuid)
    else:
        _print_ihost_show(ihost)


@utils.arg('hostsfile',
           metavar='<hostsfile>',
           help='File containing the XML descriptions of hosts to be '
                'provisioned [REQUIRED]')
def do_host_bulk_add(cc, args):
    """Add multiple new hosts."""
    field_list = ['hostsfile']
    fields = dict((k, v) for (k, v) in vars(args).items()
                  if k in field_list and not (v is None))

    hostsfile = fields['hostsfile']
    if os.path.isdir(hostsfile):
        raise exc.CommandError("Error: %s is a directory." % hostsfile)
    try:
        req = open(hostsfile, 'rb')
    except Exception:
        raise exc.CommandError("Error: Could not open file %s." % hostsfile)

    response = cc.ihost.create_many(req)
    if not response:
        raise exc.CommandError("The request timed out or there was an "
                               "unknown error")
    success = response.get('success')
    error = response.get('error')
    if success:
        print("Success: " + success + "\n")
    if error:
        print("Error:\n" + error)


@utils.arg('-m', '--mgmt_mac',
           metavar='<mgmt_mac>',
           help='MAC Address of the host mgmt interface')
@utils.arg('-i', '--mgmt_ip',
           metavar='<mgmt_ip>',
           help='IP Address of the host mgmt interface')
@utils.arg('-s', '--serialid',
           metavar='<serialid>',
           help='SerialId of the host.')
def donot_host_sysaddlab(cc, args):
    """LAB ONLY Add a new host simulating sysinv."""
    field_list = ['mgmt_mac', 'mgmt_ip', 'serialid']
    fields = dict((k, v) for (k, v) in vars(args).items()
                  if k in field_list and not (v is None))
    fields = utils.args_array_to_dict(fields, 'location')
    ihost = cc.ihost.create(**fields)
    suuid = getattr(ihost, 'uuid', '')

    try:
        ihost = cc.ihost.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % suuid)
    else:
        _print_ihost_show(ihost)
        # field_list.append('uuid')
        # field_list.append('id')
        # data = dict([(f, getattr(ihost, f, '')) for f in field_list])
        # utils.print_dict(data, wrap=72)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           nargs='+',
           help="Name or ID of host")
def do_host_delete(cc, args):
    """Delete a host."""
    for n in args.hostnameorid:
        try:
            cc.ihost.delete(n)
            print('Deleted host %s' % n)
        except exc.HTTPNotFound:
            raise exc.CommandError('host not found: %s' % n)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('attributes',
           metavar='<path=value>',
           nargs='+',
           action='append',
           default=[],
           help="Attributes to update ")
def do_host_update(cc, args):
    """Update host attributes."""
    patch = utils.args_array_to_patch("replace", args.attributes[0])
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        ihost = cc.ihost.update(ihost.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)
    _print_ihost_show(ihost)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('-f', '--force',
           action='store_true',
           default=False,
           help="Force a lock operation ")
def do_host_lock(cc, args):
    """Lock a host."""
    attributes = []

    if args.force is True:
        # Forced lock operation
        attributes.append('action=force-lock')
    else:
        # Normal lock operation
        attributes.append('action=lock')

    patch = utils.args_array_to_patch("replace", attributes)
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        ihost = cc.ihost.update(ihost.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)
    _print_ihost_show(ihost)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('-f', '--force',
           action='store_true',
           default=False,
           help="Force an unlock operation ")
def do_host_unlock(cc, args):
    """Unlock a host."""
    attributes = []

    if args.force is True:
        # Forced unlock operation
        attributes.append('action=force-unlock')
    else:
        # Normal unlock operation
        attributes.append('action=unlock')

    patch = utils.args_array_to_patch("replace", attributes)
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        ihost = cc.ihost.update(ihost.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)
    _print_ihost_show(ihost)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('-f', '--force',
           action='store_true',
           default=False,
           help="Force a host swact operation ")
def do_host_swact(cc, args):
    """Switch activity away from this active host."""
    attributes = []

    if args.force is True:
        # Forced swact operation
        attributes.append('action=force-swact')
    else:
        # Normal swact operation
        attributes.append('action=swact')

    patch = utils.args_array_to_patch("replace", attributes)
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        ihost = cc.ihost.update(ihost.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)
    _print_ihost_show(ihost)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_reset(cc, args):
    """Reset a host."""
    attributes = []
    attributes.append('action=reset')
    patch = utils.args_array_to_patch("replace", attributes)
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        ihost = cc.ihost.update(ihost.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)
    _print_ihost_show(ihost)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_reboot(cc, args):
    """Reboot a host."""
    attributes = []
    attributes.append('action=reboot')
    patch = utils.args_array_to_patch("replace", attributes)
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        ihost = cc.ihost.update(ihost.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)
    _print_ihost_show(ihost)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_reinstall(cc, args):
    """Reinstall a host."""
    attributes = []
    attributes.append('action=reinstall')
    patch = utils.args_array_to_patch("replace", attributes)
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        ihost = cc.ihost.update(ihost.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)
    _print_ihost_show(ihost)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_power_on(cc, args):
    """Power on a host."""
    attributes = []
    attributes.append('action=power-on')
    patch = utils.args_array_to_patch("replace", attributes)
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        ihost = cc.ihost.update(ihost.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)
    _print_ihost_show(ihost)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_power_off(cc, args):
    """Power off a host."""
    attributes = []
    attributes.append('action=power-off')
    patch = utils.args_array_to_patch("replace", attributes)
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        ihost = cc.ihost.update(ihost.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)
    _print_ihost_show(ihost)


def _list_storage(cc, host):
    # Echo list of new host stors
    istors = cc.istor.list(host.uuid)
    for s in istors:
        istor_utils._get_disks(cc, host, s)
    field_labels = ['uuid', 'function', 'capabilities', 'disks']
    fields = ['uuid', 'function', 'capabilities', 'disks']
    utils.print_list(istors, fields, field_labels, sortby=0)

    # Echo list of new host lvgs
    ilvgs = cc.ilvg.list(host.uuid)
    field_labels = ['uuid', 'lvm_vg_name', 'Current PVs']
    fields = ['uuid', 'lvm_vg_name', 'lvm_cur_pv']
    utils.print_list(ilvgs, fields, field_labels, sortby=0)

    # Echo list of new host pvs
    ipvs = cc.ipv.list(host.uuid)
    field_labels = ['uuid', 'lvm_pv_name', 'disk_or_part_device_path',
                    'lvm_vg_name']
    fields = ['uuid', 'lvm_pv_name', 'disk_or_part_device_path', 'lvm_vg_name']
    utils.print_list(ipvs, fields, field_labels, sortby=0)


"""
NOTE (neid):
    all three "do_host_apply_<if|stor|cpu>profile" methods can be replaced
    with a single "do_host_apply_profile"
    sysinv REST API checks what type of profile is being applied and acts
    accordingly
    this allows for profiles with multiple objects
    (eg a profile with cpus and stors)
    or a profile including all of cpu, stor, if
    or a profile including all of cpu, stor, if
"""


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('profilenameoruuid',
           metavar='<if|stor|cpu profile name or uuid>',
           help="Name or ID of the profile")
def do_host_apply_profile(cc, args):
    """Apply a profile to a host."""

    # Assemble patch
    profile = iprofile_utils._find_iprofile(cc, args.profilenameoruuid)
    patch = _prepare_profile_patch(profile.uuid)

    # Send patch
    host = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        host = cc.ihost.update(host.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)

    # Echo list of new host interfaces
    iinterfaces = cc.iinterface.list(host.uuid)
    for i in iinterfaces:
        iinterface_utils._get_ports(cc, host, i)
    field_labels = ['uuid', 'name', 'network type', 'type', 'vlan id', 'ports', 'uses', 'used by', 'mtu', 'provider networks']
    fields = ['uuid', 'ifname', 'networktype', 'iftype', 'vlan_id', 'ports', 'uses', 'used_by', 'imtu', 'providernetworks']
    utils.print_list(iinterfaces, fields, field_labels, sortby=0)

    # Echo list of new host cpus
    icpus = cc.icpu.list(host.uuid)
    field_labels = ['uuid', 'log_core', 'processor', 'phy_core', 'thread',
                    'processor_model', 'assigned_function']
    fields = ['uuid', 'cpu', 'numa_node', 'core', 'thread',
              'cpu_model', 'allocated_function']
    utils.print_list(icpus, fields, field_labels, sortby=1,
                     formatters={'allocated_function':
                                 icpu_utils._cpu_function_tuple_formatter})

    _list_storage(cc, host)

    # Echo list of new memory
    imemory = cc.imemory.list(host.uuid)
    field_labels = ['uuid', 'application_hugepages_1G', 'application_hugepages_2M',
                    'application_hugepages_2M_pending',
                    'application_hugepages_1G_pending']

    fields = ['uuid', 'vm_hugepages_nr_1G', 'vm_hugepages_nr_2M',
              'vm_hugepages_nr_2M_pending', 'vm_hugepages_nr_1G_pending']
    utils.print_list(imemory, fields, field_labels, sortby=0)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('profilenameoruuid',
           metavar='<ifprofile name or uuid>',
           help="Name or ID of interface profile")
def do_host_apply_ifprofile(cc, args):
    """Apply an interface profile to a host."""

    # Assemble patch
    profile = iprofile_utils._find_iprofile(cc, args.profilenameoruuid)
    patch = _prepare_profile_patch(profile.uuid)

    # Send patch
    host = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        host = cc.ihost.update(host.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)

    # Echo list of new host interfaces
    iinterfaces = cc.iinterface.list(host.uuid)
    for i in iinterfaces:
        iinterface_utils._get_ports(cc, host, i)
    field_labels = ['uuid', 'name', 'network type', 'type', 'vlan id', 'ports', 'uses', 'used by', 'mtu', 'provider networks']
    fields = ['uuid', 'ifname', 'networktype', 'iftype', 'vlan_id', 'ports', 'uses', 'used_by', 'imtu', 'providernetworks']
    utils.print_list(iinterfaces, fields, field_labels, sortby=0)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('profilenameoruuid',
           metavar='<profile name or uuid>',
           help="Name or ID of cpu profile")
def do_host_apply_cpuprofile(cc, args):
    """Apply a cpu profile to a host."""
    # Assemble patch
    profile = iprofile_utils._find_iprofile(cc, args.profilenameoruuid)
    patch = _prepare_profile_patch(profile.uuid)

    # Send patch
    host = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        host = cc.ihost.update(host.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)

    # Echo list of new host cpus
    icpus = cc.icpu.list(host.uuid)
    field_labels = ['uuid', 'log_core', 'processor', 'phy_core', 'thread',
                    'processor_model', 'assigned_function']
    fields = ['uuid', 'cpu', 'numa_node', 'core', 'thread',
              'cpu_model', 'allocated_function']
    utils.print_list(icpus, fields, field_labels, sortby=1,
                     formatters={'allocated_function':
                                 icpu_utils._cpu_function_tuple_formatter})


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('profilenameoruuid',
           metavar='<stor profile name or uuid>',
           help="Name or ID of stor profile")
def do_host_apply_storprofile(cc, args):
    """Apply a storage profile to a host."""
    # Assemble patch
    profile = iprofile_utils._find_iprofile(cc, args.profilenameoruuid)
    patch = _prepare_profile_patch(profile.uuid)

    host = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        host = cc.ihost.update(host.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Host not found: %s' % args.hostnameorid)

    _list_storage(cc, host)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('profilenameoruuid',
           metavar='<memory profile name or uuid>',
           help="Name or ID of stor profile")
def do_host_apply_memprofile(cc, args):
    """Apply a memory profile to a host."""
    # Assemble patch
    profile = iprofile_utils._find_iprofile(cc, args.profilenameoruuid)
    patch = _prepare_profile_patch(profile.uuid)

    # Send patch
    host = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        host = cc.ihost.update(host.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)

    # Echo list of new host memory
    imemory = cc.imemory.list(host.uuid)
    field_labels = ['uuid', 'application_hugepages_1G', 'application_hugepages_2M',
                    'application_hugepages_2M_pending', 'application_hugepages_1G_pending',
                    'vswitch_hugepages_nr', 'vswitch_hugepages_size_reqd',
                    'vswitch_hugepages_size_mib']

    fields = ['uuid', 'vm_hugepages_nr_1G', 'vm_hugepages_nr_2M',
              'vm_hugepages_nr_2M_pending', 'vm_hugepages_nr_1G_pending',
              'vswitch_hugepages_nr', 'vswitch_hugepages_reqd',
              'vswitch_hugepages_size_mib']
    utils.print_list(imemory, fields, field_labels, sortby=0)


def _prepare_profile_patch(iprofile_uuid):
    dict = {}
    dict['action'] = 'apply-profile'
    dict['iprofile_uuid'] = iprofile_uuid

    patch = []
    for (k, v) in dict.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': str(v)})

    return patch


def _timestamped(dname, fmt='%Y-%m-%d-%H-%M-%S_{dname}'):
    return datetime.datetime.now().strftime(fmt).format(dname=dname)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_patch_reboot(cc, args):
    """Command has been deprecated."""
    try:
        ihost = cc.ihost.get(args.hostnameorid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Host not found: %s' % args.hostnameorid)

    print("The host-patch-reboot command has been deprecated.")
    print("Please use the following procedure:")
    print("1. Lock the node:")
    print("     system host-lock %s" % ihost.hostname)
    print("2. Issue patch install request:")
    print("     sudo sw-patch host-install %s" % ihost.hostname)
    print("   Or to issue non-blocking requests for parallel install:")
    print("     sudo sw-patch host-install-async %s" % ihost.hostname)
    print("     sudo sw-patch query-hosts")
    print("3. Unlock node once install completes:")
    print("     system host-unlock %s" % ihost.hostname)


@utils.arg('--filename',
           help="The full file path to store the host file. Default './hosts.xml'")
def do_host_bulk_export(cc, args):
    """Export host bulk configurations."""
    result = cc.ihost.bulk_export()

    xml_content = result['content']
    config_filename = './hosts.xml'
    if hasattr(args, 'filename') and args.filename:
        config_filename = args.filename
    try:
        with open(config_filename, 'wb') as fw:
            fw.write(xml_content)
        print(_('Export successfully to %s') % config_filename)
    except IOError:
        print(_('Cannot write to file: %s') % config_filename)

    return


@utils.arg('hostid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('-f', '--force',
           action='store_true',
           default=False,
           help="Force the downgrade operation ")
def do_host_downgrade(cc, args):
    """Perform software downgrade for the specified host."""
    system_type, system_mode = utils._get_system_info(cc)
    simplex = system_mode == constants.SYSTEM_MODE_SIMPLEX

    if simplex:
        warning_message = (
            '\n'
            'WARNING: THIS OPERATION WILL COMPLETELY ERASE ALL DATA FROM THE '
            'SYSTEM.\n'
            'Only proceed once the system data has been copied to another '
            'system.\n'
            'Are you absolutely sure you want to continue?  [yes/N]: ')
        confirm = input(warning_message)
        if confirm != 'yes':
            print("Operation cancelled.")
            return

    ihost = cc.ihost.downgrade(args.hostid, args.force)
    _print_ihost_show(ihost)


@utils.arg('hostid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('-f', '--force',
           action='store_true',
           default=False,
           help="Force the upgrade operation ")
def do_host_upgrade(cc, args):
    """Perform software upgrade for a host."""
    system_type, system_mode = utils._get_system_info(cc)
    simplex = system_mode == constants.SYSTEM_MODE_SIMPLEX

    if simplex:
        warning_message = (
            '\n'
            'WARNING: THIS OPERATION WILL COMPLETELY ERASE ALL DATA FROM THE '
            'SYSTEM.\n'
            'Only proceed once the system data has been copied to another '
            'system.\n'
            'Are you absolutely sure you want to continue?  [yes/N]: ')
        confirm = input(warning_message)
        if confirm != 'yes':
            print("Operation cancelled.")
            return

    ihost = cc.ihost.upgrade(args.hostid, args.force)
    _print_ihost_show(ihost)


@utils.arg('hostid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('component',
           metavar='<component>',
           choices=['control-plane', 'kubelet'],
           help='Kubernetes component to upgrade')
@utils.arg('-f', '--force',
           action='store_true',
           default=False,
           help="Force the kubernetes upgrade operation ")
def do_kube_host_upgrade(cc, args):
    """Perform kubernetes upgrade for a host."""

    if args.component == 'control-plane':
        host = cc.ihost.kube_upgrade_control_plane(args.hostid, args.force)
    elif args.component == 'kubelet':
        host = cc.ihost.kube_upgrade_kubelet(args.hostid, args.force)
    else:
        raise exc.CommandError('Invalid component value: %s' % args.component)

    # Get the kubernetes host upgrades
    kube_host_upgrade_details = _get_kube_host_upgrade_details(cc)

    host.target_version = \
        kube_host_upgrade_details[host.id]['target_version']
    host.control_plane_version = \
        kube_host_upgrade_details[host.id]['control_plane_version']
    host.kubelet_version = \
        kube_host_upgrade_details[host.id]['kubelet_version']
    host.status = \
        kube_host_upgrade_details[host.id]['status']

    fields = ['id', 'hostname', 'personality', 'target_version',
              'control_plane_version', 'kubelet_version', 'status']

    data_list = [(f, getattr(host, f, '')) for f in fields]
    data = dict(data_list)
    ordereddata = OrderedDict(sorted(data.items(), key=lambda t: t[0]))
    utils.print_dict(ordereddata, wrap=72)
