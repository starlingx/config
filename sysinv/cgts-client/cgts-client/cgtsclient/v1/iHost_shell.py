#
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from collections import OrderedDict
import os

from cgtsclient._i18n import _
from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import istor as istor_utils


def _print_ihost_show(ihost, columns=None, output_format=None):
    optional_fields = []
    if columns:
        fields = columns
    else:
        fields = ['id', 'uuid', 'personality', 'hostname', 'invprovision',
                  'administrative', 'operational', 'availability', 'task',
                  'action', 'mgmt_mac', 'serialid', 'capabilities',
                  'bm_type', 'bm_username', 'bm_ip', 'config_applied',
                  'config_target', 'config_status', 'location', 'uptime',
                  'reserved', 'created_at', 'updated_at', 'boot_device',
                  'rootfs_device', 'hw_settle', 'install_output', 'console',
                  'tboot', 'vim_progress_status',
                  'install_state', 'install_state_info', 'inv_state',
                  'clock_synchronization', 'device_image_update',
                  'reboot_needed', 'max_cpu_mhz_configured',
                  'min_cpu_mhz_allowed', 'max_cpu_mhz_allowed',
                  'cstates_available', 'apparmor', 'iscsi_initiator_name',
                  'nvme_host_id', 'nvme_host_nqn', 'sw_version']
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


def do_kube_host_upgrade_list(cc, args):
    """List kubernetes upgrade info for hosts."""

    # Get the list of hosts
    ihosts = cc.ihost.list()
    # Get the kubernetes host upgrades
    kube_host_upgrade_details = _get_kube_host_upgrade_details(cc)

    # Keep only the hosts that have kubernetes upgrade details.
    # Storage nodes aren't part of the kubernetes cluster, for example.
    ihosts = [host for host in ihosts if host.id in kube_host_upgrade_details]

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
           choices=['controller', 'worker', 'edgeworker', 'storage', 'network', 'profile'],
           help='Personality or type of host [REQUIRED]')
@utils.arg('-s', '--subfunctions',
           metavar='<subfunctions>',
           choices=['lowlatency'],
           help='Performance profile or subfunctions of host.[Optional]')
@utils.arg('-m', '--mgmt_mac',
           metavar='<mgmt_mac>',
           help='MAC Address of the host mgmt interface [REQUIRED]')
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
@utils.arg('-R', '--hw_settle',
           metavar='<hw_settle>',
           help='Delay at the start of init to allow hardware to become '
           'available. Default: 0')
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
    field_list = ['hostname', 'personality', 'subfunctions', 'mgmt_mac',
                  'bm_ip', 'bm_type', 'bm_username', 'bm_password',
                  'boot_device', 'rootfs_device', 'hw_settle',
                  'install_output', 'console', 'vsc_controllers', 'location',
                  'ttys_dcd', 'clock_synchronization']
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
@utils.arg('-u', '--unsafe',
           action='store_true',
           default=False,
           help="Force an unsafe operation ")
def do_host_lock(cc, args):
    """Lock a host."""
    attributes = []
    if args.unsafe is True and args.force is True:
        # Unsafe forced lock operation
        attributes.append('action=force-unsafe-lock')
    elif args.force is True:
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
    ihost_utils._find_ihost(cc, args.hostid)

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


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_device_image_update(cc, args):
    """Update device image on a host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        host = cc.ihost.device_image_update(ihost.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError(
            'Device image update failed: host %s' % args.hostnameorid)
    _print_ihost_show(host)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_device_image_update_abort(cc, args):
    """Abort device image update on a host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        host = cc.ihost.device_image_update_abort(ihost.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError(
            'Device image update-abort failed: host %s' % args.hostnameorid)
    _print_ihost_show(host)


@utils.arg('hostnameorid',
           metavar='<hostnameorid>',
           help="Name or ID of host")
@utils.arg('max_cpu_mhz_configured',
           metavar='<max_cpu_mhz_configured>',
           help="Max CPU frequency MHz")
def do_host_cpu_max_frequency_modify(cc, args):
    """Modify host cpu max frequency."""

    attributes = ['max_cpu_mhz_configured=%s' % args.max_cpu_mhz_configured]

    patch = utils.args_array_to_patch("replace", attributes)
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        ihost = cc.ihost.update(ihost.id, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('host not found: %s' % args.hostnameorid)
    _print_ihost_show(ihost)


@utils.arg('hostnameorid',
           metavar='<hostnameorid>',
           help="Name or ID of host")
@utils.arg('kernel',
           metavar='<kernel>',
           choices=['standard', 'lowlatency'],
           help="Kernel image is either standard or lowlatency")
def do_host_kernel_modify(cc, args):
    """
    Modify the kernel image to either standard or lowlatency.
    """
    attributes = {'kernel_provisioned': args.kernel}
    patch = utils.dict_to_patch(attributes)

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        cc.ihost.host_kernel_modify(ihost.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Host not found: %s' % args.hostnameorid)


def _print_kernel_show(kernel, output_format=None):
    fields = ['hostname', 'kernel_provisioned', 'kernel_running']
    data_list = [(f, getattr(kernel, f, '')) for f in fields]
    data = dict(data_list)
    utils.print_dict_with_format(data, wrap=72, output_format=output_format)


@utils.arg('hostnameorid', metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('--format',
           choices=['table', 'yaml', 'value'],
           help="specify the output format, defaults to table")
def do_host_kernel_show(cc, args):
    """Show kernel attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    try:
        kernel = cc.ihost.host_kernel_show(ihost.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Host not found: %s' % args.hostnameorid)
    _print_kernel_show(kernel, args.format)
