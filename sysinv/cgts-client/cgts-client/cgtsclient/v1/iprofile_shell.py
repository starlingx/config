#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from cgtsclient.common import constants
from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ethernetport as ethernetport_utils
from cgtsclient.v1 import icpu as icpu_utils
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import interface_datanetwork as ifdn_utils
from cgtsclient.v1 import interface_network as ifnet_utils
from cgtsclient.v1 import iprofile as iprofile_utils
import math

#
# INTERFACE PROFILES
#


def _get_interface_ports_interfaces(iprofile, interface):

    interface.ports = None
    interface.interfaces = None
    if interface.iftype != 'vlan' and interface.iftype != 'ae':
        ports = iprofile.ports
        if ports and hasattr(ports[0], 'interface_uuid'):
            port_list = [ethernetport_utils.get_port_display_name(p)
                         for p in ports if p.interface_uuid and p.interface_uuid == interface.uuid]
        else:
            port_list = [ethernetport_utils.get_port_display_name(p)
                         for p in ports if p.interface_id and p.interface_id == interface.id]
        interface.ports = port_list

    else:
        interfaces = iprofile.interfaces
        interface_list = [i.ifname for i in interfaces if i.ifname in interface.uses]
        interface.interfaces = interface_list


def get_portconfig(iprofile):
    pstr = ''
    for port in iprofile.ports:
        pstr = pstr + "%s: %s" % (ethernetport_utils.get_port_display_name(port), port.pdevice)
        port.autoneg = 'Yes'  # TODO(jkung) Remove when autoneg supported in DB
        if port.autoneg != 'na':
            pstr = pstr + " | Auto Neg = %s" % (port.autoneg)
        if port.bootp:
            pstr = pstr + " | bootp-IF"
        pstr = pstr + '\n'

    return pstr


def get_interfaceconfig(cc, iprofile):
    istr = ''
    for interface in iprofile.interfaces:
        istr = istr + "%s: " % (interface.ifname)
        if interface.ifclass == 'platform':
            network_names = ifnet_utils.get_network_names(cc, interface)
            istr = istr + "( %s )" % network_names
        elif interface.ifclass == 'data':
            istr = istr + "( %s )" % ifdn_utils.get_datanetwork_names(cc, interface)
        _get_interface_ports_interfaces(iprofile, interface)
        if interface.ports:
            istr = istr + " | %s | PORTS = %s" % (interface.iftype, interface.ports)
        if interface.interfaces:
            istr = istr + " | %s | INTERFACES = %s" % (interface.iftype, interface.interfaces)
        if interface.iftype == 'ae':
            istr = istr + " | %s" % interface.aemode
            if interface.aemode == 'balanced':
                istr = istr + " | %s" % interface.txhashpolicy
        istr = istr + " | MTU = %s" % interface.imtu
        istr = istr + '\n'
    return istr


def get_ifprofile_data(cc, iprofile):
    iprofile.ports = cc.iprofile.list_ethernet_port(iprofile.uuid)
    if iprofile.ports:  # an 'interface' profile
        iprofile.portconfig = get_portconfig(iprofile)
        iprofile.interfaces = cc.iprofile.list_iinterface(iprofile.uuid)
        iprofile.interfaceconfig = get_interfaceconfig(cc, iprofile)


def do_ifprofile_list(cc, args):
    """List interface profiles."""
    profiles = cc.iprofile.list_interface_profiles()
    for profile in profiles:
        profile.portconfig = get_portconfig(profile)
        profile.interfaceconfig = get_interfaceconfig(cc, profile)

    field_labels = ['uuid', 'name', 'port config', 'interface config']
    fields = ['uuid', 'profilename', 'portconfig', 'interfaceconfig']
    utils.print_list(profiles, fields, field_labels, sortby=0)


def _print_ifprofile_show(ifprofile):
    fields = ['profilename', 'portconfig', 'interfaceconfig', 'uuid',
              'created_at', 'updated_at']
    field_labels = ['name', 'port config', 'interface config', 'uuid']
    data = [(f, getattr(ifprofile, f, '')) for f in fields]
    utils.print_tuple_list(data, field_labels)


@utils.arg('ifprofilenameoruuid',
           metavar='<if profile name or uuid>',
           help="Name or UUID of if profile")
def do_ifprofile_show(cc, args):
    """Show interface profile attributes."""
    iprofile = iprofile_utils._find_iprofile(cc, args.ifprofilenameoruuid)

    get_ifprofile_data(cc, iprofile)
    if not iprofile.ports:  # not an 'interface' profile
        raise exc.CommandError('If Profile not found: %s' % args.ifprofilenameoruuid)

    _print_ifprofile_show(iprofile)


@utils.arg('iprofilename',
           metavar='<if profile name>',
           help="Name of if profile [REQUIRED]")
@utils.arg('hostnameoruuid',
           metavar='<hostname or uuid>',
           help='Name or UUID of the host [REQUIRED]')
def do_ifprofile_add(cc, args):
    """Add an interface profile."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameoruuid)

    # create new if profile
    data = {}
    data['profilename'] = args.iprofilename
    data['profiletype'] = constants.PROFILE_TYPE_INTERFACE
    data['ihost_uuid'] = ihost.uuid

    try:
        iprofile = cc.iprofile.create(**data)
    except Exception as e:
        raise exc.CommandError(str(e))

    suuid = getattr(iprofile, 'uuid', '')
    try:
        iprofile = cc.iprofile.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('If Profile not found: %s' % suuid)
    else:
        get_ifprofile_data(cc, iprofile)
        _print_ifprofile_show(iprofile)


@utils.arg('ifprofilenameoruuid',
           metavar='<if profile name or uuid>',
           nargs='+',
           help="Name or UUID of if profile")
def do_ifprofile_delete(cc, args):
    """Delete an interface profile."""
    for n in args.ifprofilenameoruuid:
        iprofile = iprofile_utils._find_iprofile(cc, n)
        try:
            cc.iprofile.delete(iprofile.uuid)
        except exc.HTTPNotFound:
            raise exc.CommandError('if profile delete failed: %s' % n)
        print('Deleted if profile %s' % n)

#
# CPU PROFILES
#


def get_cpuprofile_data(cc, iprofile):
    iprofile.cpus = cc.iprofile.list_icpus(iprofile.uuid)
    iprofile.nodes = cc.iprofile.list_inodes(iprofile.uuid)
    icpu_utils.restructure_host_cpu_data(iprofile)
    iprofile.platform_cores = get_core_list_str(iprofile, icpu_utils.PLATFORM_CPU_TYPE)
    iprofile.vswitch_cores = get_core_list_str(iprofile, icpu_utils.VSWITCH_CPU_TYPE)
    iprofile.shared_cores = get_core_list_str(iprofile, icpu_utils.SHARED_CPU_TYPE)
    iprofile.application_cores = get_core_list_str(iprofile, icpu_utils.APPLICATION_CPU_TYPE)
    iprofile.isolated_cores = get_core_list_str(iprofile, icpu_utils.ISOLATED_CPU_TYPE)


def get_core_list_str(iprofile, function):
    istr = ''
    sep = ''
    for cpuFunc in iprofile.core_assignment:
        if cpuFunc.allocated_function == function:
            for s, cores in cpuFunc.socket_cores.items():
                istr = istr + sep + "Processor %s: %s" % (s, cores)
                sep = ',\n'
            return istr
    return istr


def do_cpuprofile_list(cc, args):
    """List cpu profiles."""
    profiles = cc.iprofile.list_cpu_profiles()
    for profile in profiles:
        icpu_utils.restructure_host_cpu_data(profile)
        profile.platform_cores = get_core_list_str(profile,
                                                   icpu_utils.PLATFORM_CPU_TYPE)
        profile.vswitch_cores = get_core_list_str(profile,
                                                  icpu_utils.VSWITCH_CPU_TYPE)
        profile.shared_cores = get_core_list_str(profile,
                                                 icpu_utils.SHARED_CPU_TYPE)
        profile.application_cores = get_core_list_str(profile, icpu_utils.APPLICATION_CPU_TYPE)
        profile.isolated_cores = get_core_list_str(profile,
                                                   icpu_utils.ISOLATED_CPU_TYPE)

    field_labels = ['uuid', 'name',
                    'processors', 'phy cores per proc', 'hyperthreading',
                    'platform cores', 'vswitch cores', 'shared cores',
                    'application cores', 'application-isolated cores']
    fields = ['uuid', 'profilename',
              'sockets', 'physical_cores', 'hyperthreading',
              'platform_cores', 'vswitch_cores', 'shared_cores', 'application_cores',
              'isolated_cores']
    utils.print_list(profiles, fields, field_labels, sortby=0)


def _print_cpuprofile_show(cpuprofile):
    labels = ['uuid', 'name',
              'processors', 'phy cores per proc', 'hyperthreading',
              'platform cores', 'vswitch cores', 'shared cores', 'application cores',
              'application-isolated cores', 'created_at', 'updated_at']
    fields = ['uuid', 'profilename',
              'sockets', 'physical_cores', 'hyperthreading',
              'platform_cores', 'vswitch_cores', 'shared_cores', 'application_cores',
              'isolated_cores', 'created_at', 'updated_at']
    data = [(f, getattr(cpuprofile, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


@utils.arg('cpuprofilenameoruuid',
           metavar='<cpu profile name or uuid>',
           help="Name or UUID of cpu profile")
def do_cpuprofile_show(cc, args):
    """Show cpu profile attributes."""
    iprofile = iprofile_utils._find_iprofile(cc, args.cpuprofilenameoruuid)
    get_cpuprofile_data(cc, iprofile)
    if not iprofile.cpus:  # not a 'cpu' profile
        raise exc.CommandError('CPU Profile not found: %s' % args.cpuprofilenameoruuid)
    _print_cpuprofile_show(iprofile)


@utils.arg('iprofilename',
           metavar='<cpu profile name>',
           help="Name of cpu profile [REQUIRED]")
@utils.arg('hostnameoruuid',
           metavar='<hostname or uuid>',
           help='Name or UUID of the host [REQUIRED]')
def do_cpuprofile_add(cc, args):
    """Add a cpu profile."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameoruuid)

    # create new cpu profile
    data = {}
    data['profilename'] = args.iprofilename
    data['profiletype'] = constants.PROFILE_TYPE_CPU
    data['ihost_uuid'] = ihost.uuid

    try:
        iprofile = cc.iprofile.create(**data)
    except Exception as e:
        raise exc.CommandError(str(e))

    suuid = getattr(iprofile, 'uuid', '')
    try:
        iprofile = cc.iprofile.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('CPU Profile not found: %s' % suuid)
    else:
        get_cpuprofile_data(cc, iprofile)
        _print_cpuprofile_show(iprofile)


@utils.arg('cpuprofilenameoruuid',
           metavar='<cpu profile name or uuid>',
           nargs='+',
           help="Name or UUID of cpu profile")
def do_cpuprofile_delete(cc, args):
    """Delete a cpu profile."""
    for n in args.cpuprofilenameoruuid:
        iprofile = iprofile_utils._find_iprofile(cc, n)
        try:
            cc.iprofile.delete(iprofile.uuid)
        except exc.HTTPNotFound:
            raise exc.CommandError('Cpu profile delete failed: %s' % n)
        print('Deleted cpu profile %s' % n)


#
# DISK PROFILES
#
def get_storconfig_short(iprofile):
    str = ''
    for stor in iprofile.stors:
        if str != '':
            str = str + "; "
        str = str + "%s" % stor.function
        if stor.function == 'osd':
            str = str + ": %s" % stor.tier_name
    return str


def get_storconfig_detailed(iprofile):
    str = ''
    journals = {}
    count = 0
    for stor in iprofile.stors:
        # count journals
        if stor.function == 'journal':
            count += 1
            journals.update({stor.uuid: count})
    for stor in iprofile.stors:
        str += "function: %s stor" % stor.function
        if stor.function == 'journal' and count > 1:
            str += " %s" % journals[stor.uuid]
        if stor.function == 'osd':
            str += ", ceph journal: size %s GiB, " % (stor.journal_size_mib / 1024)
            if stor.journal_location == stor.uuid:
                str += "collocated on osd stor"
            else:
                str += "on journal stor"
                if count > 1:
                    str += (" %s" % journals[stor.journal_location])
            str += ", for tier: %s" % stor.tier_name
        str = str + "\n"
    return str


def get_diskconfig(iprofile):
    str = ''
    invalid_profile = False
    for disk in iprofile.disks:
        if str != '':
            str = str + "; "
        str = str + "%s: %s GiB" % (disk.device_path, math.floor(float(disk.size_mib) / 1024 * 1000) / 1000.0)
        if not disk.device_path:
            invalid_profile = True
    return str, invalid_profile


def get_partconfig(iprofile):
    str = ''
    for part in iprofile.partitions:
        if str != '':
            str = str + "; "
        str = str + "%s: %s GiB" % (part.device_path, math.floor(float(part.size_mib) / 1024 * 1000) / 1000.0)
    return str


def get_ilvg_config(iprofile):
    str = ''
    for ilvg in iprofile.ilvgs:
        if str != '':
            str += "; "

        capabilities_str = ''
        for k, v in ilvg.capabilities.items():
            if capabilities_str != '':
                capabilities_str += "; "
            capabilities_str += "%s: %s " % (k, v)

        str += "%s, %s" % (ilvg.lvm_vg_name, capabilities_str)
    return str


def get_ipv_config(iprofile):
    str = ''
    for ipv in iprofile.ipvs:
        if str != '':
            str = str + "; "
        str = str + "type %s: %s" % (ipv.pv_type, ipv.disk_or_part_device_path)
    return str


def get_storprofile_data(cc, iprofile, detailed=False):
    profile_disk_invalid = False
    iprofile.disks = cc.iprofile.list_idisks(iprofile.uuid)
    if iprofile.disks:
        iprofile.diskconfig, profile_disk_invalid = get_diskconfig(iprofile)
        iprofile.partitions = cc.iprofile.list_partitions(iprofile.uuid)
        iprofile.partconfig = get_partconfig(iprofile)
        iprofile.stors = cc.iprofile.list_istors(iprofile.uuid)
        if iprofile.stors:
            if detailed:
                iprofile.storconfig = get_storconfig_detailed(iprofile)
            else:
                iprofile.storconfig = get_storconfig_short(iprofile)
        else:
            iprofile.ilvgs = cc.iprofile.list_ilvgs(iprofile.uuid)
            iprofile.ipvs = cc.iprofile.list_ipvs(iprofile.uuid)
            iprofile.ilvg_config = get_ilvg_config(iprofile)
            iprofile.ipv_config = get_ipv_config(iprofile)

    return profile_disk_invalid


def do_storprofile_list(cc, args):
    """List storage profiles."""
    profiles = cc.iprofile.list_storage_profiles()
    storprofiles = []
    localstorprofiles = []
    profile_disk_invalid = False

    for profile in profiles:
        profile.disks = [utils.objectify(n) for n in profile.disks]
        profile.partitions = [utils.objectify(n) for n in profile.partitions]
        profile.stors = [utils.objectify(n) for n in profile.stors]
        profile.ilvgs = [utils.objectify(n) for n in profile.lvgs]
        profile.ipvs = [utils.objectify(n) for n in profile.pvs]

        profile.diskconfig, crt_profile_disk_invalid = get_diskconfig(profile)
        profile_disk_invalid = (profile_disk_invalid or
                                crt_profile_disk_invalid)
        profile.partconfig = get_partconfig(profile)
        profile.storconfig = get_storconfig_short(profile)
        profile.ilvg_config = get_ilvg_config(profile)
        profile.ipv_config = get_ipv_config(profile)

        if profile.profiletype == constants.PROFILE_TYPE_LOCAL_STORAGE:
            localstorprofiles.append(profile)
        else:
            storprofiles.append(profile)

    if profile_disk_invalid:
        print("WARNING: Storage profiles from a previous release are "
              "missing the persistent disk name in the disk config field. "
              "These profiles need to be deleted and recreated.")

    if storprofiles:
        field_labels = ['uuid', 'name', 'disk config', 'partition config',
                        'stor config']
        fields = ['uuid', 'profilename', 'diskconfig', 'partconfig',
                  'storconfig']
        utils.print_list(storprofiles, fields, field_labels, sortby=0)

    if localstorprofiles:
        field_labels = ['uuid', 'name', 'disk config', 'partition config',
                        'physical volume config',
                        'logical volume group config']
        fields = ['uuid', 'profilename', 'diskconfig', 'partconfig',
                  'ipv_config', 'ilvg_config']
        utils.print_list(localstorprofiles, fields, field_labels, sortby=0)


def _print_storprofile_show(storprofile):
    if hasattr(storprofile, 'ilvg_config'):
        fields = ['uuid', 'profilename', 'diskconfig', 'partconfig',
                  'ipv_config', 'ilvg_config']
        field_labels = ['uuid', 'name', 'diskconfig', 'partconfig', 'physical '
                        'volume config', 'logical volume group config']
    else:
        fields = ['profilename', 'diskconfig', 'partconfig', 'storconfig',
                  'uuid', 'created_at', 'updated_at']
        field_labels = ['name', 'diskconfig', 'partconfig', 'storconfig',
                        'uuid', 'created_at', 'updated_at']

    data = [(f, getattr(storprofile, f, '')) for f in fields]
    utils.print_tuple_list(data, field_labels)


@utils.arg('iprofilenameoruuid',
           metavar='<stor profile name or uuid>',
           help="Name or UUID of stor profile")
def do_storprofile_show(cc, args):
    """Show storage profile attributes."""
    iprofile = iprofile_utils._find_iprofile(cc, args.iprofilenameoruuid)

    get_storprofile_data(cc, iprofile)
    if not iprofile.disks:  # not a stor profile
        raise exc.CommandError('Stor Profile not found: %s' % args.ifprofilenameoruuid)

    profile_disk_invalid = get_storprofile_data(cc, iprofile, detailed=True)
    if profile_disk_invalid:
        print("WARNING: This storage profile, from a previous release, is "
              "missing the persistent disk name in the disk config field. "
              "This profile needs to be deleted and recreated.")
    _print_storprofile_show(iprofile)


@utils.arg('iprofilename',
           metavar='<stor profile name>',
           help="Name of stor profile [REQUIRED]")
@utils.arg('hostnameoruuid',
           metavar='<hostname or uuid>',
           help='Name or UUID of the host [REQUIRED]')
def do_storprofile_add(cc, args):
    """Add a storage profile"""
    ihost = ihost_utils._find_ihost(cc, args.hostnameoruuid)

    # create new storage profile
    data = {}
    data['profilename'] = args.iprofilename
    data['profiletype'] = constants.PROFILE_TYPE_STORAGE
    data['ihost_uuid'] = ihost.uuid

    try:
        iprofile = cc.iprofile.create(**data)
    except Exception as e:
        raise exc.CommandError(str(e))

    suuid = getattr(iprofile, 'uuid', '')
    try:
        iprofile = cc.iprofile.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Storage Profile not found: %s' % suuid)
    else:
        get_storprofile_data(cc, iprofile)
        _print_storprofile_show(iprofile)


@utils.arg('iprofilenameoruuid',
           metavar='<stor profile name or uuid>',
           nargs='+',
           help="Name or UUID of stor profile")
def do_storprofile_delete(cc, args):
    """Delete a storage profile."""
    for n in args.iprofilenameoruuid:
        iprofile = iprofile_utils._find_iprofile(cc, n)
        try:
            cc.iprofile.delete(iprofile.uuid)
        except exc.HTTPNotFound:
            raise exc.CommandError('Storage profile delete failed: %s' % n)
        print('Deleted storage profile %s' % n)

#
# MEMORY PROFILES
#


def get_memoryconfig_platform(iprofile):
    str = ''
    for memory in iprofile.memory:
        if str != '':
            str = str + "; "
        str = str + "%s" % (memory.platform_reserved_mib)
    return str


def get_memoryconfig_2M(iprofile):
    str = ''
    for memory in iprofile.memory:
        if str != '':
            str = str + "; "
        str = str + "%s" % (memory.vm_hugepages_nr_2M_pending)
    return str


def get_memoryconfig_1G(iprofile):
    str = ''
    for memory in iprofile.memory:
        if str != '':
            str = str + "; "
        str = str + "%s" % (memory.vm_hugepages_nr_1G_pending)
    return str


def get_memoryconfig_vswitch_nr(iprofile):
    str = ''
    for memory in iprofile.memory:
        if str != '':
            str = str + "; "
        str = str + "%s" % (memory.vswitch_hugepages_reqd)
    return str


def get_memoryconfig_vswitch_size(iprofile):
    str = ''
    for memory in iprofile.memory:
        if str != '':
            str = str + "; "
        str = str + "%s" % (memory.vswitch_hugepages_size_mib)
    return str


def get_memprofile_data(cc, iprofile):
    iprofile.memory = cc.iprofile.list_imemorys(iprofile.uuid)
    iprofile.nodes = cc.iprofile.list_inodes(iprofile.uuid)
    iprofile.platform_reserved_mib = get_memoryconfig_platform(iprofile)
    iprofile.application_hugepages_2M = get_memoryconfig_2M(iprofile)
    iprofile.application_hugepages_1G = get_memoryconfig_1G(iprofile)
    iprofile.vswitch_hugepages_nr = get_memoryconfig_vswitch_nr(iprofile)
    iprofile.vswitch_hugepages_size_mib = get_memoryconfig_vswitch_size(iprofile)


def do_memprofile_list(cc, args):
    """List memory profiles."""
    profiles = cc.iprofile.list_memory_profiles()
    for profile in profiles:
        profile.platform_reserved_mib = get_memoryconfig_platform(profile)
        profile.application_hugepages_2M = get_memoryconfig_2M(profile)
        profile.application_hugepages_1G = get_memoryconfig_1G(profile)
        profile.vswitch_hugepages_nr = get_memoryconfig_vswitch_nr(profile)
        profile.vswitch_hugepages_size_mib = get_memoryconfig_vswitch_size(profile)

    field_labels = ['uuid', 'name', 'platform_reserved_mib',
                    'application_hugepages_2M', 'application_hugepages_1G',
                    'vswitch_hugepages_nr', 'vswitch_hugepages_size_mib']
    fields = ['uuid', 'profilename', 'platform_reserved_mib',
              'application_hugepages_2M', 'application_hugepages_1G',
              'vswitch_hugepages_nr', 'vswitch_hugepages_size_mib']
    utils.print_list(profiles, fields, field_labels, sortby=0)


def _print_memprofile_show(memoryprofile):
    fields = ['profilename', 'platform_reserved_mib', 'application_hugepages_2M',
              'application_hugepages_1G', 'vswitch_hugepages_nr',
              'vswitch_hugepages_size_mib', 'uuid', 'created_at', 'updated_at']
    labels = ['name', 'platform_reserved_mib', 'application_hugepages_2M',
              'application_hugepages_1G', 'vswitch_hugepages_nr',
              'vswitch_hugepages_size_mib', 'uuid', 'created_at', 'updated_at']

    data = [(f, getattr(memoryprofile, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


@utils.arg('iprofilenameoruuid',
           metavar='<memory profile name or uuid>',
           help="Name or UUID of memory profile")
def do_memprofile_show(cc, args):
    """Show memory profile attributes."""
    iprofile = iprofile_utils._find_iprofile(cc, args.iprofilenameoruuid)

    get_memprofile_data(cc, iprofile)
    if not iprofile.memory:  # not a memory profile
        raise exc.CommandError('Memory Profile not found: %s' % args.ifprofilenameoruuid)

    _print_memprofile_show(iprofile)


@utils.arg('iprofilename',
           metavar='<memory profile name>',
           help="Name of memory profile [REQUIRED]")
@utils.arg('hostnameoruuid',
           metavar='<hostname or id>',
           help='Name or ID of the host [REQUIRED]')
def do_memprofile_add(cc, args):
    """Add a memory profile."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameoruuid)

    # create new memory profile
    data = {}
    data['profilename'] = args.iprofilename
    data['profiletype'] = constants.PROFILE_TYPE_MEMORY
    data['ihost_uuid'] = ihost.uuid

    try:
        iprofile = cc.iprofile.create(**data)
    except Exception as e:
        raise exc.CommandError(str(e))

    suuid = getattr(iprofile, 'uuid', '')
    try:
        iprofile = cc.iprofile.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Memory profile not found: %s' % suuid)
    else:
        get_memprofile_data(cc, iprofile)
        _print_memprofile_show(iprofile)


@utils.arg('iprofilenameoruuid',
           metavar='<memory profile name or uuid>',
           nargs='+',
           help="Name or UUID of memory profile")
def do_memprofile_delete(cc, args):
    """Delete a memory profile."""
    for n in args.iprofilenameoruuid:
        iprofile = iprofile_utils._find_iprofile(cc, n)
        try:
            cc.iprofile.delete(iprofile.uuid)
        except exc.HTTPNotFound:
            raise exc.CommandError('Memory profile delete failed: %s' % n)
        print('Deleted memory profile %s' % n)


@utils.arg('profilefilename',
           metavar='<profile file name>',
           nargs='+',
           help="Full path of the profile file to be imported")
def do_profile_import(cc, args):
    """Import a profile file."""
    filename = args.profilefilename[0]

    try:
        file = open(filename, 'rb')
    except Exception:
        raise exc.CommandError("Error: Could not open file %s for read." % filename)

    results = cc.iprofile.import_profile(file)
    if results:
        for result in results:
            if(result['result'] == 'Invalid'):
                print('error: %s is not a valid profile file.' % (filename))
            else:
                print(result['msg'])

            if result['detail']:
                print('       %s' % (result['detail']))
